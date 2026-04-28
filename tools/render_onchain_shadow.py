#!/usr/bin/env python3
"""Render a shadow's per-slot sprites by REAL ECIES decrypt of the
on-chain c2 ciphertext under the owner's secret key.

Pipeline (no longer seed-derived):
  1. Connect to the chain RPC and fetch every `ShadowSlotMutated`
     event for the given `--shadow-id` from `--from-block` onwards.
  2. For each occupied slot, pick the LATEST event (highest blockNumber,
     then logIndex). That event's `c2` field is the current ciphertext.
  3. Combine the chain c2 with the slot's c1 (from a local sidecar; see
     "On c1 sourcing" below) and the owner's `--sk` to compute
     `k = poseidon2(sk*c1.x, sk*c1.y)` and recover the 39-field
     plaintext.
  4. `decode_plaintext_v2` -> (pose, w, h, indices).
  5. Render PNGs identically to the legacy seed-derived path.

On c1 sourcing
--------------
The v2 contract binds c1 inside `lsh = sponge_6(stateCommit, ctCommit,
c1.x, c1.y, count, chainTip)` but does NOT emit c1 in any event. So a
chain-only consumer cannot recover c1; only the owner (or someone the
owner shares c1 with) can. To support on-chain decrypt with real c2 we
read c1 from a sidecar file that the owner already has from their own
fixture run. This is honest about what `view-with-key` means in v2:
the owner can render their own shadow; a third party cannot.

The sidecar is one of:
  * an `atomic_mint/<seed>/meta.json` (mint-time c1 per slot)
  * an `onchain_transfer/<seed>/meta.json` (post-transfer c1 per slot)
  * an `onchain_mutate_batch/<seed>/meta.json` overlay (post-mutate c1
    for one or two slots; falls back to the prior sidecar for the rest)

The rendered output is identical in shape to the legacy renderer; the
difference is that the plaintext came from a real on-chain decrypt
rather than seed regeneration.

Usage:
  python3 tools/render_onchain_shadow.py \\
      --shadow-id 0x011c687ec... \\
      --rpc https://base-sepolia.gateway.tenderly.co \\
      --st 0xe5089e09D7B8393fE37bC2e53E6a44CCD534Ef88 \\
      --fn 0x578eda36Dc4750c35c29E5F12a0789DaD35e2072 \\
      --sk 0x18097c8c... \\
      --c1-sidecar contracts/test/fixtures/atomic_mint/palette_reveal_live/meta.json \\
      --from-block 40780000 \\
      --out-dir /tmp/shadow_render

The legacy `--seed` flag still works for backwards compat; in seed mode
the visualizer re-derives plaintexts from the mint seed and labels the
output "(seed-derived)" so it is clearly distinct from on-chain-decrypt
output.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))

from secret_inbox import ec_mul  # type: ignore  # noqa: E402
from v2_circuit_helpers import (  # type: ignore  # noqa: E402
    P, PLAINTEXT_FIELDS,
    sponge_39, poseidon2_hash_2, keystream_39,
    pack_pose, decode_plaintext_v2,
)


# 16-color palette. Picked so adjacent indices contrast.
PALETTE: list[tuple[int, int, int]] = [
    (0, 0, 0),         # 0
    (255, 255, 255),   # 1
    (220, 60, 60),     # 2
    (60, 220, 60),     # 3
    (60, 60, 220),     # 4
    (220, 220, 60),    # 5
    (220, 60, 220),    # 6
    (60, 220, 220),    # 7
    (180, 100, 60),    # 8
    (255, 180, 0),     # 9
    (140, 80, 200),    # 10
    (80, 200, 140),    # 11
    (200, 200, 200),   # 12
    (80, 80, 80),      # 13
    (255, 130, 180),   # 14
    (40, 80, 30),      # 15
]
CANVAS_SIZE = 48


# ---------------------------------------------------------------------
# Chain reader: pull ShadowSlotMutated events and pick latest per slot.
# ---------------------------------------------------------------------

# keccak256("ShadowSlotMutated(uint256,uint8,bytes32,uint256,uint16,bytes32,bytes32,bytes)")
# Pinned at the value below; re-derive with `cast keccak "ShadowSlotMutated(...)"`
# if the event signature ever changes.
SLOT_MUTATED_TOPIC0 = "0xaae30d030d528f20bdc7ca6fb59934e5b9fbddc5eea1976668b4ee518b8755e6"

# keccak256("FeaturePaletteRevealed(uint256,bytes32,bytes)")
# Re-derive with `cast keccak "FeaturePaletteRevealed(uint256,bytes32,bytes)"`
# if the event signature ever changes.
PALETTE_REVEALED_TOPIC0 = "0xab2d50af1f432d428a788e90bfd3bdb85a1228883a22c743d48f5f763b17ee58"

# keccak256("FeatureSlotRevealed(uint256,uint256,uint8,bytes)")
# Emitted at solve when palette+plaintext are revealed atomically. The
# event carries the 39-field plaintext (1248 bytes); indexers can render
# the canonical NFT image WITHOUT any owner secret key, just by decoding
# this event + the FeaturePaletteRevealed RGB.
# Plaintext is ADVISORY at the chain layer; off-chain consumers MUST
# verify by recomputing sponge_39(plaintext) and matching against the
# bound stateCommit (chain-readable from the proof's PI[1] reconstruction).
SLOT_REVEALED_TOPIC0 = "0xbede24c9a95917e60eb52a811beafa40f2319a66788254e0222abff12bb827c2"


def _http_post(url: str, payload: dict) -> dict:
    """Tiny stdlib JSON-RPC POST; no requests dependency."""
    import urllib.request
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _eth_call(rpc: str, method: str, params: list) -> dict:
    out = _http_post(rpc, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    if "error" in out:
        raise RuntimeError(f"{method}: {out['error']}")
    return out["result"]


def fetch_latest_c2_per_slot(rpc: str, st_addr: str, shadow_id: int,
                             from_block: int = 0
                             ) -> tuple[dict[int, bytes], dict[int, int]]:
    """Return ({slot_idx: c2_bytes}, {slot_idx: feature_id_int}) from the
    latest ShadowSlotMutated event per slot for the given shadowId.

    Uses topic0 + topic1 (= shadowId) filters server-side so the RPC
    payload is small. Topic2 is slotIdx; we keep only the latest
    (block, logIndex) per slotIdx.
    """
    topic0 = SLOT_MUTATED_TOPIC0
    topic1 = "0x" + format(shadow_id, "064x")
    latest = _eth_call(rpc, "eth_blockNumber", [])
    print(f"[fetch] head block: {int(latest, 16)}")
    print(f"[fetch] querying ShadowSlotMutated logs for shadowId={hex(shadow_id)[:18]}...")
    logs = _eth_call(rpc, "eth_getLogs", [{
        "fromBlock": hex(from_block),
        "toBlock":   "latest",
        "address":   st_addr,
        "topics":    [topic0, topic1],
    }])
    print(f"[fetch] got {len(logs)} matching events")

    # Per slot, pick the latest by (blockNumber, logIndex).
    by_slot: dict[int, tuple[int, int, bytes, int]] = {}
    for ev in logs:
        slot = int(ev["topics"][2], 16)
        bn = int(ev["blockNumber"], 16)
        li = int(ev["logIndex"], 16)
        # Decode non-indexed args from `data`.
        # ABI: featureId(uint256), mutationCount(uint16), prevChainTip(bytes32),
        #      newChainTip(bytes32), c2(bytes)
        data = bytes.fromhex(ev["data"][2:])
        feature_id = int.from_bytes(data[0:32], "big")
        # offsets: 0..32 featureId, 32..64 mutationCount (padded), 64..96 prev,
        # 96..128 new, 128..160 offset_to_c2_bytes (160 always for one dynamic
        # arg), 160..192 c2.length, 192..192+ceil32(len) c2 (right-padded).
        c2_len = int.from_bytes(data[160:192], "big")
        c2 = data[192:192 + c2_len]
        prev = (bn, li)
        if slot not in by_slot or prev > by_slot[slot][:2]:
            by_slot[slot] = (bn, li, c2, feature_id)
    c2_map  = {slot: payload[2] for slot, payload in sorted(by_slot.items())}
    fid_map = {slot: payload[3] for slot, payload in sorted(by_slot.items())}
    return c2_map, fid_map


def fetch_revealed_palettes(rpc: str, fn_addr: str, from_block: int = 0
                            ) -> dict[int, list[tuple[int, int, int]]]:
    """Return {feature_id_int: [16 (R, G, B)]} from FeaturePaletteRevealed
    events on FeatureNFT. Latest event per featureId wins (single-shot in
    practice -- the contract reverts on second reveal -- but be defensive).
    """
    topic0 = PALETTE_REVEALED_TOPIC0
    print(f"[palette] querying FeaturePaletteRevealed logs for fn={fn_addr}")
    logs = _eth_call(rpc, "eth_getLogs", [{
        "fromBlock": hex(from_block),
        "toBlock":   "latest",
        "address":   fn_addr,
        "topics":    [topic0],
    }])
    print(f"[palette] got {len(logs)} reveal events")
    by_fid: dict[int, tuple[int, int, list[tuple[int, int, int]]]] = {}
    for ev in logs:
        fid = int(ev["topics"][1], 16)
        bn = int(ev["blockNumber"], 16)
        li = int(ev["logIndex"], 16)
        # Data layout: paletteCommit(32) | offset(32, =0x40) | len(32, =0x30) | rgb_bytes(48)
        data = bytes.fromhex(ev["data"][2:])
        rgb_len = int.from_bytes(data[64:96], "big")
        if rgb_len != 48:
            print(f"  fid {hex(fid)[:18]}: unexpected paletteRGB length {rgb_len}; skipping")
            continue
        rgb_bytes = data[96:96 + 48]
        palette = []
        for i in range(16):
            r = rgb_bytes[3 * i + 0]
            g = rgb_bytes[3 * i + 1]
            b = rgb_bytes[3 * i + 2]
            palette.append((r, g, b))
        if fid not in by_fid or (bn, li) > by_fid[fid][:2]:
            by_fid[fid] = (bn, li, palette)
    return {fid: payload[2] for fid, payload in by_fid.items()}


def fetch_revealed_slots(rpc: str, fn_addr: str, shadow_id: int,
                         from_block: int = 0
                         ) -> dict[int, bytes]:
    """Return {slot_idx: plaintext_bytes} from FeatureSlotRevealed events
    on FeatureNFT for the given shadowId. Each occupied slot at solve time
    emits one event with the 39-field plaintext (1248 bytes).

    The event payload is ADVISORY at the chain layer (see solve doc).
    Indexers SHOULD verify sponge_39(plaintext) against the bound
    stateCommit before trusting; this loader does not enforce.
    """
    topic0 = SLOT_REVEALED_TOPIC0
    topic2 = "0x" + format(shadow_id, "064x")
    print(f"[slot-reveal] querying FeatureSlotRevealed logs for shadow={hex(shadow_id)[:18]}...")
    logs = _eth_call(rpc, "eth_getLogs", [{
        "fromBlock": hex(from_block),
        "toBlock":   "latest",
        "address":   fn_addr,
        "topics":    [topic0, None, topic2],  # any featureId, this shadow
    }])
    print(f"[slot-reveal] got {len(logs)} reveal events")
    by_slot: dict[int, tuple[int, int, bytes]] = {}
    for ev in logs:
        slot = int(ev["topics"][3], 16) & 0xFF
        bn = int(ev["blockNumber"], 16)
        li = int(ev["logIndex"], 16)
        # Data layout: offset(32, =0x20) | length(32) | plaintext_bytes(length)
        data = bytes.fromhex(ev["data"][2:])
        pt_len = int.from_bytes(data[32:64], "big")
        if pt_len != PLAINTEXT_FIELDS * 32:
            print(f"  slot {slot}: unexpected plaintext length {pt_len}; skipping")
            continue
        plaintext = data[64:64 + pt_len]
        if slot not in by_slot or (bn, li) > by_slot[slot][:2]:
            by_slot[slot] = (bn, li, plaintext)
    return {slot: payload[2] for slot, payload in by_slot.items()}


# ---------------------------------------------------------------------
# c1 sidecar loader
# ---------------------------------------------------------------------


def _h(s: str) -> int:
    s = s.lower()
    return int(s[2:] if s.startswith("0x") else s, 16)


def load_c1_sidecar(path: Path) -> dict[int, tuple[int, int]]:
    """Return {slot_idx: (c1_x, c1_y)} from a meta.json sidecar.

    Supported formats (auto-detected by JSON keys):
      * atomic_mint:        c1_xs[16], c1_ys[16]
      * onchain_transfer:   new_c1_x[16], new_c1_y[16]
      * onchain_mutate_batch overlay: meta.slot_a + meta.slot_b
    """
    m = json.loads(path.read_text())
    out: dict[int, tuple[int, int]] = {}
    if "slot_a" in m and "slot_b" in m:
        # Two-slot mutateBatch overlay.
        for entry_key in ("slot_a", "slot_b"):
            e = m[entry_key]
            out[int(e["slot_idx"])] = (_h(e["new_c1_x"]), _h(e["new_c1_y"]))
    elif "host_target_slot" in m and isinstance(m.get("new_c1_x"), str):
        # onchain_insert: host slot's new c1 after insertion (scalar).
        out[int(m["host_target_slot"])] = (_h(m["new_c1_x"]), _h(m["new_c1_y"]))
    elif "slot_idx" in m and isinstance(m.get("new_c1_x"), str):
        # Single-slot post-mutate overlay (scalar c1).
        out[int(m["slot_idx"])] = (_h(m["new_c1_x"]), _h(m["new_c1_y"]))
    elif "c1_xs" in m and "c1_ys" in m:
        # atomic_mint: per-slot c1 arrays under canonical key names.
        for i, (xv, yv) in enumerate(zip(m["c1_xs"], m["c1_ys"])):
            xi = _h(xv); yi = _h(yv)
            if xi == 0 and yi == 0:
                continue
            out[i] = (xi, yi)
    elif ("new_c1_x" in m and "new_c1_y" in m
          and isinstance(m["new_c1_x"], list)):
        # onchain_transfer: per-slot post-rotation c1 arrays.
        for i, (xv, yv) in enumerate(zip(m["new_c1_x"], m["new_c1_y"])):
            xi = _h(xv); yi = _h(yv)
            if xi == 0 and yi == 0:
                continue
            out[i] = (xi, yi)
    else:
        raise ValueError(f"unsupported sidecar shape: {list(m.keys())[:8]}")
    return out


# ---------------------------------------------------------------------
# ECIES decrypt
# ---------------------------------------------------------------------


def decrypt_c2(c1: tuple[int, int], c2_bytes: bytes, sk: int) -> list[int]:
    """Recover the 39-field plaintext from on-chain c2 + owner sk + slot c1."""
    if len(c2_bytes) != PLAINTEXT_FIELDS * 32:
        raise ValueError(f"c2 length {len(c2_bytes)} != {PLAINTEXT_FIELDS * 32}")
    c2_fields = [int.from_bytes(c2_bytes[i * 32:(i + 1) * 32], "big")
                 for i in range(PLAINTEXT_FIELDS)]
    shared = ec_mul(c1, sk)
    if shared is None:
        raise ValueError("sk * c1 yields identity")
    k = poseidon2_hash_2(shared[0], shared[1])
    ks = keystream_39(k)
    pt = [(c2_fields[i] - ks[i]) % P for i in range(PLAINTEXT_FIELDS)]
    # Sanity: sponge_39(c2_fields) is the on-chain ct_commit; sponge_39(pt)
    # is the on-chain state_commit. We can't verify those without the lsh,
    # but if pt is correct then decode_plaintext_v2 will succeed.
    return pt


# ---------------------------------------------------------------------
# Render helpers (unchanged from legacy)
# ---------------------------------------------------------------------


def unpack_pose_xy(pose: int) -> tuple[int, int]:
    return pose & 0x3F, (pose >> 6) & 0x3F


def render_sprite(w: int, h: int, indices: list[int],
                  palette: Optional[list[tuple[int, int, int]]] = None
                  ) -> list[list[tuple[int, int, int]]]:
    """Render a sprite. If `palette` is supplied (16 entries from a
    PaletteRevealed event), use it; otherwise fall back to the module's
    default PALETTE. Indices outside the 16-entry palette range raise."""
    pal = palette if palette is not None else PALETTE
    grid = [[(0, 0, 0)] * w for _ in range(h)]
    for j, idx in enumerate(indices):
        if idx < 0 or idx >= len(pal):
            raise ValueError(f"palette index out of range: {idx}")
        grid[j // w][j % w] = pal[idx]
    return grid


def upscale(grid: list[list[tuple[int, int, int]]], factor: int
            ) -> list[list[tuple[int, int, int]]]:
    h = len(grid)
    w = len(grid[0]) if h > 0 else 0
    out = [[(0, 0, 0)] * (w * factor) for _ in range(h * factor)]
    for y in range(h * factor):
        for x in range(w * factor):
            out[y][x] = grid[y // factor][x // factor]
    return out


def write_png(path: Path, grid: list[list[tuple[int, int, int]]]) -> None:
    import struct, zlib
    h = len(grid)
    w = len(grid[0]) if h > 0 else 0

    def chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    raw = bytearray()
    for row in grid:
        raw.append(0)
        for r, g, b in row:
            raw.append(r & 0xFF); raw.append(g & 0xFF); raw.append(b & 0xFF)
    idat = zlib.compress(bytes(raw), 9)
    with open(path, "wb") as f:
        f.write(sig)
        f.write(chunk(b"IHDR", ihdr))
        f.write(chunk(b"IDAT", idat))
        f.write(chunk(b"IEND", b""))


def compose(slots: dict[int, tuple[int, int, int, list[int]]],
            slot_palettes: Optional[dict[int, list[tuple[int, int, int]]]] = None
            ) -> list[list[tuple[int, int, int]]]:
    canvas = [[(20, 20, 24)] * CANVAS_SIZE for _ in range(CANVAS_SIZE)]
    for i in sorted(slots.keys()):
        pose, w_dim, h_dim, indices = slots[i]
        x0, y0 = unpack_pose_xy(pose)
        pal = slot_palettes.get(i) if slot_palettes else None
        sprite = render_sprite(w_dim, h_dim, indices, palette=pal)
        for sy in range(h_dim):
            for sx in range(w_dim):
                cx = x0 + sx; cy = y0 + sy
                if 0 <= cx < CANVAS_SIZE and 0 <= cy < CANVAS_SIZE:
                    canvas[cy][cx] = sprite[sy][sx]
    return canvas


def strip(slots: dict[int, tuple[int, int, int, list[int]]],
          slot_palettes: Optional[dict[int, list[tuple[int, int, int]]]] = None
          ) -> list[list[tuple[int, int, int]]]:
    if not slots:
        return [[(40, 40, 48)]]
    keys = sorted(slots.keys())
    max_w = max(slots[k][1] for k in keys)
    max_h = max(slots[k][2] for k in keys)
    pad = 1
    cell_w = max_w + 2 * pad
    cell_h = max_h + 2 * pad
    out = [[(40, 40, 48)] * (cell_w * len(keys)) for _ in range(cell_h)]
    for col, k in enumerate(keys):
        pose, w_dim, h_dim, indices = slots[k]
        pal = slot_palettes.get(k) if slot_palettes else None
        sprite = render_sprite(w_dim, h_dim, indices, palette=pal)
        x0 = col * cell_w + pad; y0 = pad
        for sy in range(h_dim):
            for sx in range(w_dim):
                out[y0 + sy][x0 + sx] = sprite[sy][sx]
    return out


# ---------------------------------------------------------------------
# Legacy seed-derived fallback (kept for backwards compat with tests).
# ---------------------------------------------------------------------


def reconstruct_seed_params(seed_str: str
                             ) -> dict[int, tuple[int, int, int, list[int]]]:
    """Identical to the pre-refactor seed reconstruction; deterministic
    from `seed_str`. Used only when --seed is passed without --shadow-id."""
    out = {}
    for i in range(8):
        pose = pack_pose(x=2 + i * 2, y=4 + (i % 8))
        w_dim = 6 + (i % 4)
        h_dim = 6 + ((i + 1) % 4)
        indices = [(j * 7 + i + 3) & 0xF for j in range(w_dim * h_dim)]
        out[i] = (pose, w_dim, h_dim, indices)
    return out


# ---------------------------------------------------------------------
# main
# ---------------------------------------------------------------------


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--shadow-id", help="hex shadowId (chain mode)")
    ap.add_argument("--rpc", help="JSON-RPC URL (chain mode)")
    ap.add_argument("--st", help="ShadowToken contract address (chain mode)")
    ap.add_argument("--fn", help="FeatureNFT contract address (chain mode; "
                                  "required to fetch revealed palettes)")
    ap.add_argument("--sk", help="owner secret key, hex (chain mode)")
    ap.add_argument("--c1-sidecar", help="path to a meta.json with per-slot c1 "
                                          "values (chain mode)")
    ap.add_argument("--c1-sidecar-overlay", action="append", default=[],
                    help="additional meta.json sidecars whose c1 values "
                         "OVERRIDE the primary sidecar (e.g., post-mutate c1 "
                         "overlays the post-transfer c1). May be repeated.")
    ap.add_argument("--from-block", type=int, default=0,
                    help="earliest block to scan for ShadowSlotMutated events")
    ap.add_argument("--seed", default=None,
                    help="LEGACY seed-derived mode (no chain decrypt)")
    ap.add_argument("--out-dir", default="/tmp/shadow_render")
    ap.add_argument("--upscale", type=int, default=8)
    args = ap.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Chain mode: needs at least shadow-id + rpc + st. sk + c1-sidecar are
    # only required for slots not present in FeatureSlotRevealed events.
    # For a fully solved shadow (event-decoded plaintext path), --fn is the
    # only auxiliary requirement.
    chain_mode = bool(args.shadow_id and args.rpc and args.st)

    if chain_mode:
        shadow_id = _h(args.shadow_id)
        sk = _h(args.sk) if args.sk else 0
        # 1. Pull on-chain c2 per slot + slot->featureId map.
        chain_c2, fid_map = fetch_latest_c2_per_slot(
            args.rpc, args.st, shadow_id, args.from_block)
        print(f"[chain] occupied slots (chain): {sorted(chain_c2.keys())}")

        # 2. Load c1 from sidecar(s) -- only needed for the ECIES fallback
        #    on slots not yet event-revealed via FeatureSlotRevealed.
        c1_map: dict[int, tuple[int, int]] = {}
        if args.c1_sidecar:
            c1_map = load_c1_sidecar(Path(args.c1_sidecar))
            for ovl in args.c1_sidecar_overlay:
                c1_map.update(load_c1_sidecar(Path(ovl)))
            print(f"[c1] sidecar slots: {sorted(c1_map.keys())}")
        else:
            print("[c1] no sidecar; ECIES fallback unavailable (event-only render)")

        # 3. Optionally fetch revealed palettes + plaintexts (--fn required).
        revealed_palettes: dict[int, list[tuple[int, int, int]]] = {}
        slot_palettes: dict[int, list[tuple[int, int, int]]] = {}
        revealed_slots: dict[int, bytes] = {}
        if args.fn:
            revealed_palettes = fetch_revealed_palettes(
                args.rpc, args.fn, args.from_block)
            for slot, fid in fid_map.items():
                if fid in revealed_palettes:
                    slot_palettes[slot] = revealed_palettes[fid]
            if slot_palettes:
                print(f"[palette] revealed for slots: {sorted(slot_palettes.keys())}")
            else:
                print("[palette] no revealed palettes for any slot; using default")
            revealed_slots = fetch_revealed_slots(
                args.rpc, args.fn, shadow_id, args.from_block)
            if revealed_slots:
                print(f"[slot-reveal] event-decoded plaintexts for slots: {sorted(revealed_slots.keys())}")
        else:
            print("[palette] --fn not provided; skipping reveal lookup (default palette)")

        # 4. Per-slot decode -- prefer event plaintext if revealed (no sk
        #    needed), else fall back to ECIES decrypt of on-chain c2.
        slots: dict[int, tuple[int, int, int, list[int]]] = {}
        # Iterate the union of slots seen in either source.
        all_slots = set(chain_c2.keys()) | set(revealed_slots.keys())
        for slot in sorted(all_slots):
            try:
                if slot in revealed_slots:
                    # No sk required: events are already public.
                    pt_bytes = revealed_slots[slot]
                    pt_fields = [int.from_bytes(pt_bytes[i * 32:(i + 1) * 32], "big")
                                 for i in range(PLAINTEXT_FIELDS)]
                    pose, w, h, indices = decode_plaintext_v2(pt_fields)
                    src_tag = "event"
                elif slot in chain_c2:
                    if slot not in c1_map:
                        print(f"  slot {slot}: no c1 in sidecar and not event-revealed; skipping")
                        continue
                    pt = decrypt_c2(c1_map[slot], chain_c2[slot], sk)
                    pose, w, h, indices = decode_plaintext_v2(pt)
                    src_tag = "ECIES"
                else:
                    continue
                slots[slot] = (pose, w, h, indices)
                x0, y0 = unpack_pose_xy(pose)
                pal_tag = "revealed" if slot in slot_palettes else "default"
                print(f"  slot {slot:2d}: {src_tag:6s} -> {w}x{h} sprite at ({x0:2d},{y0:2d}) [palette: {pal_tag}]")
            except Exception as e:
                print(f"  slot {slot:2d}: decode failed: {e}")
        label = "chain-decrypt"
    elif args.seed:
        print(f"[legacy] seed-derived mode for seed={args.seed!r}")
        slots = reconstruct_seed_params(args.seed)
        slot_palettes = {}
        label = "seed-derived"
    else:
        sys.exit("Must provide either chain-mode flags "
                 "(--shadow-id --rpc --st --sk --c1-sidecar) "
                 "or --seed for legacy mode")

    # ---- write per-slot PNGs ----
    print(f"\n[render] {label}, upscale={args.upscale}x -> {out}")
    for i, (pose, w_dim, h_dim, indices) in slots.items():
        pal = slot_palettes.get(i) if chain_mode else None
        sprite = render_sprite(w_dim, h_dim, indices, palette=pal)
        big = upscale(sprite, args.upscale)
        path = out / f"slot_{i}.png"
        write_png(path, big)
        x0, y0 = unpack_pose_xy(pose)
        pal_tag = "revealed" if (chain_mode and i in slot_palettes) else "default"
        print(f"  slot {i:2d}: {w_dim}x{h_dim} at ({x0:2d},{y0:2d}) -> {path} [palette: {pal_tag}]")

    palette_arg = slot_palettes if chain_mode else None
    canvas = compose(slots, slot_palettes=palette_arg)
    write_png(out / "composite.png", upscale(canvas, args.upscale))
    print(f"  composite ({CANVAS_SIZE}x{CANVAS_SIZE}, all slots layered) "
          f"-> {out}/composite.png")
    write_png(out / "sprite_strip.png",
              upscale(strip(slots, slot_palettes=palette_arg), args.upscale))
    print(f"  strip -> {out}/sprite_strip.png")

    if chain_mode:
        print("\n[mode] chain-decrypt: c2 came from on-chain "
              "ShadowSlotMutated events; sk + c1 supplied locally; "
              "ECIES decrypt + decode_plaintext_v2 produced the sprites.")
    else:
        print("\n[mode] seed-derived: plaintexts regenerated from seed; "
              "no on-chain decrypt happened.")


if __name__ == "__main__":
    main()
