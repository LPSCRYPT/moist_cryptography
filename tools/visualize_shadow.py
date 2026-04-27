#!/usr/bin/env python3
# =====================================================================
# **STALE — v1 visualizer.** Reads v1 events (ShadowMinted, SlotMutated,
# ShadowT10Updated, ShadowCiphertext) and the v1 monolithic-c2 shape.
# v2 emits per-slot encryption (ShadowSlotMutated, ShadowFeatureInserted,
# SlotExtracted, ShadowZIndexCommitSet, ShadowSolved, ShadowT10Updated)
# with `c2[16]` per shadow. A v2 rewrite needs:
#   - per-slot ECIES decrypt (39-Field plaintext, 4-bit palette indices)
#   - palette table from chain (TODO: where lives?)
#   - z-index composition: pre-solve uses zIndexCommit (opaque), post-solve
#     uses zIndexRevealed permutation
#   - T10 byte-equal reproduction via sponge_18 of the post-write state
# Tracked as Phase 10 in `STAGING_REFACTOR/PROGRESS.md`.
# =====================================================================
"""
visualize_shadow.py - read on-chain shadow state and render its visual form.

The artistic claim of this project is that visual outputs are
chain-derived: the public T10 silhouette comes from `shadowT10[hi,lo]`
storage; the private RGB face comes from ECIES-decrypting the c2
emitted in the `ShadowCiphertext` event. This script makes that claim
auditable by anyone with:

  * an RPC URL pointing at the chain (anvil or Sepolia);
  * the deployed `ShadowToken` address;
  * the `shadowId`;
  * the owner's Grumpkin sk (the only off-chain secret).

Two modes:

  snapshot  : pull the CURRENT state of one shadow and render
              one DATA_FLOW.png with [regions strip] + [PUBLIC T10] +
              [SECRET composite].

  history   : walk every ShadowMinted / SlotMutated / ShadowT10Updated
              event for a given shadowId and produce the per-step
              labeled montage (as in runs/anvil_disc_*/DATA_FLOW.png).

Usage examples:

  # Snapshot current Anvil state:
  python3 tools/visualize_shadow.py snapshot \\
      --rpc http://127.0.0.1:8545 \\
      --shadow-token 0x8A791620dd6260079BF849Dc5567aDC3F2FdC318 \\
      --shadow-id <SHADOW_ID> \\
      --owner-sk-hex 0x22c5760834a390353d... \\
      --out runs/snapshot.png

  # Replay full history of a shadow:
  python3 tools/visualize_shadow.py history \\
      --rpc https://sepolia.base.org \\
      --shadow-token 0x0887012dC44009085BC3a21Dc23aD0829F055fFc \\
      --shadow-id 0x1039d4890975c7b307ec39da0d6e3480182ab4583cf16481d7db1fa5d385a601 \\
      --owner-sk-hex 0x22c5760834a390353d... \\
      --out runs/history.png

  # Snapshot from a saved fixture (offline; for demos / CI):
  python3 tools/visualize_shadow.py snapshot \\
      --from-fixture contracts/test/fixtures/mint_shadow/alice0 \\
      --out runs/snapshot.png
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np
from PIL import Image, ImageDraw, ImageFont

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from mint_decrypt import (  # noqa: E402
    decrypt_mint_envelope,
    unpack_fields_to_recolored,
    split_into_regions,
)
from t10 import (  # noqa: E402
    composite_canvas,
    grid_to_grayscale_image,
    hi_lo_to_grid,
    unpack_pose,
    REGION_W,
    REGION_H,
    SLOT_KIND_ORIGINAL,
    SLOT_KIND_EMPTY,
)

REGION_NAMES = ["forehead", "eye L", "eye R", "nose",
                "ear L", "ear R", "mouth", "chin"]

# event topic0 hashes
TOPIC_SHADOW_CIPHERTEXT = "0x126e572da2b938847165c6f546420ac7b1ec28d8d60b379e7805f2bd32ab5566"
TOPIC_SHADOW_MINTED     = "0xeaa746f56077785cbbb46022ad2cf9bc2f07934192fb2e7f55cd6b1f0dd0f4fa"
TOPIC_SLOT_MUTATED      = "0x9d20bee0c4d3a4b06402d8d4e9eafa8b86bdfb3f5ec9ed0bc52ddec85b9eebd5"
TOPIC_T10_UPDATED       = "0x126e572da2b938847165c6f546420ac7b1ec28d8d60b379e7805f2bd32ab5566"  # placeholder; resolved at runtime if needed


# ============================================================================
# Chain readers
# ============================================================================

def _cast(args: list[str], rpc: str, retries: int = 5) -> str:
    """Run cast and return stdout. Retries on transient public-RPC failures."""
    import time
    last_err = ""
    for attempt in range(retries):
        p = subprocess.run(
            ["cast"] + args + ["--rpc-url", rpc],
            capture_output=True, text=True, timeout=90,
        )
        if p.returncode == 0:
            return p.stdout.strip()
        last_err = (p.stderr or p.stdout).strip()
        # Retry on transient public-RPC errors (502, timeout, rate limit, etc).
        if any(s in last_err.lower() for s in (
            "502", "503", "504", "timed out", "timeout",
            "rate limit", "too many requests", "connection", "reset",
        )):
            time.sleep(3 + attempt * 4)
            continue
        # Permanent error -- abort immediately.
        raise SystemExit(f"cast failed:\n  args={args}\n  err={last_err}")
    raise SystemExit(f"cast failed after {retries} retries:\n  args={args}\n  err={last_err}")


@dataclass
class ChainState:
    """A snapshot of one shadow at one block."""
    shadow_id: int
    boxes_packed: int
    state_nonce: int
    t10_hi: int
    t10_lo: int
    poses: list[int]            # 16 manifest poses (uint64 each)
    kinds: list[int]            # 16 slot kinds (0=EMPTY, 1=ORIGINAL, 2=INSERTED)
    c1_x: int
    c1_y: int
    c2: bytes                    # 7968-byte ciphertext (latest emitted)
    block_number: int


def read_chain_state(
    rpc: str,
    shadow_token: str,
    shadow_id: int,
    block_hint: int = 0,
) -> ChainState:
    """Pull the full visible state of a shadow at the latest block."""
    sid_hex = f"0x{shadow_id:064x}"

    # boxes_packed
    bp = int(_cast(["call", shadow_token, "boxesPackedOf(uint256)(bytes32)", sid_hex], rpc), 16)

    # state nonce
    sn = int(_cast(["call", shadow_token, "stateNonce(uint256)(uint64)", sid_hex], rpc))

    # T10 hi, lo. shadowT10 is `mapping(uint256 => bytes32[2])` so cast
    # signature is `(uint256,uint256)(bytes32)` taking key + array index.
    t10_hi = int(_cast(["call", shadow_token,
                        "shadowT10(uint256,uint256)(bytes32)",
                        sid_hex, "0"], rpc), 16)
    t10_lo = int(_cast(["call", shadow_token,
                        "shadowT10(uint256,uint256)(bytes32)",
                        sid_hex, "1"], rpc), 16)

    # manifest poses + kinds. manifestOf returns ManifestEntry[16].
    # cast prints each tuple on its own line; we parse line-by-line.
    mf_raw = _cast([
        "call", shadow_token,
        "manifestOf(uint256)((uint8,uint8,uint256,uint64)[16])",
        sid_hex,
    ], rpc)
    poses = []
    kinds = []
    # Output is one big '[(...), (...), ...]' string. Strip outer brackets,
    # split on '), (', clean each tuple.
    cleaned = mf_raw.strip().lstrip("[").rstrip("]")
    chunks = cleaned.split("), (")
    for c in chunks:
        c = c.strip().lstrip("(").rstrip(")")
        # fields: kind (uint8), origTypeIdx (uint8), insertedFeatureId (uint256), pose (uint64)
        fields = [f.strip() for f in c.split(",")]
        kinds.append(int(fields[0]))
        pose_str = fields[3]
        poses.append(int(pose_str, 16) if pose_str.startswith("0x") else int(pose_str.split()[0]))
    if len(poses) != 16:
        raise SystemExit(f"manifestOf parse failure: got {len(poses)} entries (want 16)")

    # ShadowCiphertext event lookup (latest log for this shadowId)
    # event ShadowCiphertext(uint256 indexed shadowId, bytes32 indexed ctCommit, bytes c2)
    # topic1 = shadowId
    logs_raw = _cast([
        "logs",
        "ShadowCiphertext(uint256,bytes32,bytes)",
        "--from-block", str(block_hint - 5_000) if block_hint else "earliest",
        "--address", shadow_token,
        sid_hex,   # filter by topic1 (shadowId)
    ], rpc)

    # parse cast logs output for the LAST entry's data + c1 ephemeral pubkey is not in event;
    # we need it via the Shadow struct (mint stores ecdhPubX/Y for current owner; not the same as c1).
    # Actually c1 is in PI[12,13] of the mint proof. After transfer, c1 rotates and is in transfer PI.
    # For the LATEST c2 we need the latest c1 too: read it from the (most recent) transfer event,
    # or for never-transferred shadows from the mint event's PI (which we don't store on chain).
    # Simpler: ShadowToken stores the CURRENT recipient pk (ecdhPubX/Y) but NOT c1. The decryption
    # actually uses the recipient sk + sender's c1. Anyone holding sk needs to know c1 separately.
    #
    # For the snapshot tool we expect the caller to provide c1 OR the fixture file. If not
    # provided, we error.

    last_data = ""
    last_block = 0
    for blk in logs_raw.split("- "):
        if "data:" not in blk:
            continue
        for line in blk.split("\n"):
            if "data:" in line:
                last_data = line.split("data:", 1)[1].strip()
            elif "blockNumber:" in line:
                try:
                    last_block = int(line.split("blockNumber:", 1)[1].strip())
                except ValueError:
                    pass
    if not last_data:
        raise SystemExit(f"no ShadowCiphertext event for shadowId {sid_hex}")

    # Event data layout: abi.encode(c2 bytes) -> [offset(32)] [length(32)] [c2 bytes padded]
    raw = bytes.fromhex(last_data[2:])
    # Slot 0 = offset (always 0x20). Slot 1 = length. Then payload.
    length = int.from_bytes(raw[32:64], "big")
    c2 = raw[64:64 + length]

    return ChainState(
        shadow_id=shadow_id,
        boxes_packed=bp,
        state_nonce=sn,
        t10_hi=t10_hi,
        t10_lo=t10_lo,
        poses=poses,
        kinds=kinds,
        c1_x=0,  # filled by caller
        c1_y=0,
        c2=c2,
        block_number=last_block,
    )


# ============================================================================
# Decrypt + render
# ============================================================================

def decode_boxes_packed(boxes_packed: int) -> list[tuple[int, int, int, int]]:
    """Return [(x, y, w, h)] for each of the 8 region slots."""
    out = []
    for i in range(8):
        slot = (boxes_packed >> (24 * i)) & 0xFFFFFF
        x = slot & 0x3F
        y = (slot >> 6) & 0x3F
        w = (slot >> 12) & 0x3F
        h = (slot >> 18) & 0x3F
        out.append((x, y, w, h))
    return out


def decrypt_regions(
    c2: bytes,
    sk: int,
    c1_x: int,
    c1_y: int,
) -> list[bytes]:
    """ECIES-decrypt c2 with owner sk and split into the 8 region byte arrays."""
    if len(c2) != 7968:
        raise SystemExit(f"c2 wrong length: {len(c2)} (want 7968 = 249*32)")
    c2_fields = [int.from_bytes(c2[i*32:(i+1)*32], "big") for i in range(249)]
    plaintext = decrypt_mint_envelope(
        recipient_sk=sk, c1_x=c1_x, c1_y=c1_y, c2=c2_fields,
    )
    concat = unpack_fields_to_recolored(plaintext)
    return list(split_into_regions(concat))


def render_region_atom(region: bytes, w: int, h: int) -> Image.Image:
    """Render one region's recolored bytes as a small RGB image."""
    if w == 0 or h == 0:
        return Image.new("RGB", (4, 4), (40, 40, 40))
    needed = w * h * 3
    raw = region[:needed]
    if len(raw) < needed:
        raw = raw + bytes([0] * (needed - len(raw)))
    return Image.frombytes("RGB", (w, h), raw)


def render_t10(hi: int, lo: int, scale: int = 8) -> Image.Image:
    """16x16 4-level grayscale silhouette decoded from chain hi/lo."""
    grid = hi_lo_to_grid(hi, lo)
    arr = grid_to_grayscale_image(grid, scale=scale)
    return Image.fromarray(arr).convert("RGB")


def render_secret_composite(
    regions: list[bytes],
    boxes_packed: int,
    poses: list[int],
    kinds: list[int],
) -> Image.Image:
    """Render the 48x48 RGB composite with regions placed under chain poses."""
    # Pad regions list to 16 slots (slots 8..15 are EMPTY by default at mint;
    # those are for InsertFeature later -- not handled by this tool).
    per_slot = list(regions) + [b""] * 8
    box_dims = decode_boxes_packed(boxes_packed)
    max_dims = [(w, h) for (_x, _y, w, h) in box_dims] + [(0, 0)] * 8

    # composite_canvas requires scale_q88 to be a power of 2. Some chain
    # state may carry intermediate scales (e.g. 384 = 1.5x). Clamp to the
    # nearest legal power of 2 so the renderer doesn't crash. This is a
    # display-time approximation only -- the chain holds the exact value.
    poses = list(poses)
    legal_scales = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192]
    for i, p in enumerate(poses):
        if p == 0:
            continue
        try:
            cx, cy, sc, co, si = unpack_pose(p)
        except Exception:
            continue
        if sc not in legal_scales and sc > 0:
            nearest = min(legal_scales, key=lambda s: abs(s - sc))
            # PoseLib layout: x[0..5] y[6..11] scaleQ88[12..27] cos[28..43] sin[44..59]
            new_p = (cx & 0x3F) | ((cy & 0x3F) << 6) | ((nearest & 0xFFFF) << 12) \
                    | ((co & 0xFFFF) << 28) | ((si & 0xFFFF) << 44)
            poses[i] = new_p

    canvas = composite_canvas(
        per_slot_bytes=per_slot,
        kinds=list(kinds),
        poses=list(poses),
        slot_dims_wh=max_dims,
        slot_max_dims_wh=max_dims,
    )
    return Image.fromarray(canvas).convert("RGB")


# ============================================================================
# Layout
# ============================================================================

def _font(size: int) -> ImageFont.ImageFont:
    for p in [
        "/System/Library/Fonts/Supplemental/Menlo.ttc",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/Library/Fonts/Arial.ttf",
    ]:
        if Path(p).exists():
            try:
                return ImageFont.truetype(p, size)
            except Exception:
                pass
    return ImageFont.load_default()


def render_snapshot_montage(
    state: ChainState,
    regions: list[bytes],
    title: str,
    out_path: Path,
) -> None:
    """One-page snapshot: regions strip + T10 + composite + chain metadata."""
    F_TITLE = _font(22)
    F_HDR   = _font(15)
    F_LBL   = _font(13)
    F_NOTE  = _font(11)

    UPSCALE = 192
    REGION_TILE = 72
    PADDING = 18

    box_dims = decode_boxes_packed(state.boxes_packed)

    # Width: 8 region tiles in a row OR PUBLIC + SECRET pair, whichever wider
    strip_w = 8 * (REGION_TILE + 12) + 12
    pair_w  = UPSCALE + PADDING + UPSCALE + PADDING + 360
    WIDTH = max(strip_w, pair_w) + PADDING * 2

    HEIGHT = (
        PADDING + 60                          # title
        + 32                                   # "STEP -1: ECIES decrypt" header
        + REGION_TILE + 36                     # region strip + labels
        + 30                                   # spacing
        + 32                                   # PUBLIC/SECRET headers
        + UPSCALE                              # the two big tiles
        + 50                                   # footer metadata
    )

    img = Image.new("RGB", (WIDTH, HEIGHT), (15, 15, 18))
    d = ImageDraw.Draw(img)

    # Title
    d.text((PADDING, PADDING), title, fill=(240, 240, 240), font=F_TITLE)
    d.text((PADDING, PADDING + 28),
           f"shadowId  {state.shadow_id:#066x}",
           fill=(170, 170, 175), font=F_NOTE)
    d.text((PADDING, PADDING + 42),
           f"block     {state.block_number}     state_nonce {state.state_nonce}",
           fill=(170, 170, 175), font=F_NOTE)

    y = PADDING + 70
    d.text((PADDING, y), "STEP -1: ECIES DECRYPT  (sk -> c2 plaintext)  -  these 8 region byte-arrays are FROZEN by mint c2_commit",
           fill=(255, 200, 100), font=F_HDR)
    y += 22

    for i in range(8):
        w, h = box_dims[i][2], box_dims[i][3]
        rim = render_region_atom(regions[i], w, h).resize(
            (REGION_TILE, REGION_TILE), Image.NEAREST,
        )
        x = PADDING + i * (REGION_TILE + 12)
        img.paste(rim, (x, y))
        d.rectangle([(x-1, y-1), (x+REGION_TILE, y+REGION_TILE)],
                    outline=(70, 70, 80), width=1)
        d.text((x, y + REGION_TILE + 2),
               f"slot {i}: {REGION_NAMES[i]}", fill=(220, 220, 220), font=F_NOTE)
        d.text((x, y + REGION_TILE + 14),
               f"{w}x{h} px", fill=(170, 170, 180), font=F_NOTE)

    y += REGION_TILE + 50

    # PUBLIC + SECRET pair
    x_pub = PADDING
    x_sec = PADDING + UPSCALE + PADDING

    d.text((x_pub, y),       "PUBLIC T10",                             fill=(255, 200, 100), font=F_HDR)
    d.text((x_pub, y + 16),  "(chain shadowT10[hi,lo])",               fill=(170, 170, 175), font=F_NOTE)
    d.text((x_sec, y),       "SECRET composite",                        fill=(255, 200, 100), font=F_HDR)
    d.text((x_sec, y + 16),  "(decrypted regions + chain poses)",       fill=(170, 170, 175), font=F_NOTE)

    y += 32

    pub = render_t10(state.t10_hi, state.t10_lo).resize((UPSCALE, UPSCALE), Image.NEAREST)
    img.paste(pub, (x_pub, y))
    d.rectangle([(x_pub-1, y-1), (x_pub+UPSCALE, y+UPSCALE)], outline=(70,70,80), width=1)

    sec = render_secret_composite(
        regions, state.boxes_packed, state.poses, state.kinds,
    ).resize((UPSCALE, UPSCALE), Image.NEAREST)
    img.paste(sec, (x_sec, y))
    d.rectangle([(x_sec-1, y-1), (x_sec+UPSCALE, y+UPSCALE)], outline=(70,70,80), width=1)

    # Chain metadata sidebar
    x_meta = x_sec + UPSCALE + PADDING
    d.text((x_meta, y),         "CHAIN STATE",                fill=(255, 200, 100), font=F_HDR)
    d.text((x_meta, y + 22),    f"T10 hi  {state.t10_hi:#066x}",  fill=(200, 200, 210), font=F_NOTE)
    d.text((x_meta, y + 36),    f"T10 lo  {state.t10_lo:#066x}",  fill=(200, 200, 210), font=F_NOTE)
    d.text((x_meta, y + 56),    "current poses (manifest):", fill=(255, 200, 100), font=F_NOTE)
    for i in range(8):
        if state.kinds[i] == SLOT_KIND_ORIGINAL:
            cx, cy, scale_q88, cos_q15, sin_q15 = unpack_pose(state.poses[i])
            d.text((x_meta, y + 74 + i*12),
                   f"  slot {i} {REGION_NAMES[i]:<9} "
                   f"pos=({cx:>2},{cy:>2}) scale={scale_q88/256:.2f}",
                   fill=(180, 180, 195), font=F_NOTE)

    img.save(out_path, optimize=True)


def render_history_montage(
    states: list[tuple[str, ChainState]],     # (label, state) per step
    regions: list[bytes],                     # constant after mint
    title: str,
    out_path: Path,
) -> None:
    """Multi-row montage similar to runs/anvil_disc_*/DATA_FLOW.png but
    rendered from arbitrary chain reads."""
    # Layout follows DATA_FLOW.png produced inline in earlier dev sessions.
    # ... (uses the same constants; wrapped here in one call so users get
    # one tool, not three.)
    F_TITLE = _font(22); F_HDR = _font(14); F_LBL = _font(15)
    F_OP = _font(13); F_NOTE = _font(11); F_GAS = _font(12)
    UPSCALE = 128; PADDING = 16; LABEL_W = 110; TEXT_COL_W = 360
    REGION_TILE = 80; ROW_H = UPSCALE + PADDING * 2
    WIDTH  = PADDING + LABEL_W + PADDING + UPSCALE + PADDING + UPSCALE + PADDING + TEXT_COL_W + PADDING
    HEIGHT = PADDING + 60 + (REGION_TILE + 90) + 50 + (ROW_H + 4) * len(states) + PADDING + 60

    img = Image.new("RGB", (WIDTH, HEIGHT), (15, 15, 18))
    d = ImageDraw.Draw(img)

    box_dims = decode_boxes_packed(states[0][1].boxes_packed)

    d.text((PADDING, PADDING), title, fill=(240, 240, 240), font=F_TITLE)
    d.text((PADDING, PADDING + 30),
           f"shadowId {states[0][1].shadow_id:#x}  /  history of {len(states)} state(s)",
           fill=(170, 170, 175), font=F_NOTE)

    # Top: region atoms strip
    y = PADDING + 60
    d.text((PADDING, y),
           "STEP -1: ECIES DECRYPT  (regions are constant across mutateSlot history)",
           fill=(255, 200, 100), font=F_HDR)
    y += 22
    for i in range(8):
        w, h = box_dims[i][2], box_dims[i][3]
        rim = render_region_atom(regions[i], w, h).resize(
            (REGION_TILE, REGION_TILE), Image.NEAREST,
        )
        x = PADDING + i * (REGION_TILE + 12)
        img.paste(rim, (x, y))
        d.rectangle([(x-1, y-1), (x+REGION_TILE, y+REGION_TILE)], outline=(70,70,80), width=1)
        d.text((x, y + REGION_TILE + 2), f"slot {i}: {REGION_NAMES[i]}", fill=(220,220,220), font=F_NOTE)
        d.text((x, y + REGION_TILE + 14), f"{w}x{h} px", fill=(170,170,180), font=F_NOTE)

    # Per-step rows
    y_table = y + REGION_TILE + 50
    x_label  = PADDING
    x_public = PADDING + LABEL_W + PADDING
    x_secret = x_public + UPSCALE + PADDING
    x_text   = x_secret + UPSCALE + PADDING

    d.text((x_label,  y_table),      "STEP",                       fill=(255, 200, 100), font=F_HDR)
    d.text((x_public, y_table),      "PUBLIC T10",                 fill=(255, 200, 100), font=F_HDR)
    d.text((x_public, y_table + 14), "(chain shadowT10[hi,lo])",   fill=(170, 170, 175), font=F_NOTE)
    d.text((x_secret, y_table),      "SECRET composite",           fill=(255, 200, 100), font=F_HDR)
    d.text((x_secret, y_table + 14), "(decrypted + chain poses)",  fill=(170, 170, 175), font=F_NOTE)
    d.text((x_text,   y_table),      "OPERATION  /  CHAIN BLOCK",  fill=(255, 200, 100), font=F_HDR)

    y = y_table + 36
    for step_no, (label, state) in enumerate(states):
        is_mint = step_no == 0
        if step_no % 2 == 0:
            d.rectangle([(0, y - 4), (WIDTH, y + ROW_H - 8)], fill=(22, 22, 28))
        if is_mint:
            d.rectangle([(0, y - 4), (6, y + ROW_H - 8)], fill=(120, 230, 140))

        d.text((x_label, y + PADDING + 4),
               f"step {step_no:02d}",
               fill=(120, 230, 140) if is_mint else (180, 220, 200), font=F_LBL)
        d.text((x_label, y + PADDING + 26), label[:14], fill=(220, 220, 220), font=F_OP)
        if is_mint:
            d.text((x_label, y + PADDING + 46), "PROOFS x2", fill=(120, 230, 140), font=F_NOTE)

        pub = render_t10(state.t10_hi, state.t10_lo).resize((UPSCALE, UPSCALE), Image.NEAREST)
        img.paste(pub, (x_public, y + PADDING))
        d.rectangle([(x_public-1, y+PADDING-1), (x_public+UPSCALE, y+PADDING+UPSCALE)],
                    outline=(120, 230, 140) if is_mint else (70, 70, 80),
                    width=2 if is_mint else 1)

        sec = render_secret_composite(
            regions, state.boxes_packed, state.poses, state.kinds,
        ).resize((UPSCALE, UPSCALE), Image.NEAREST)
        img.paste(sec, (x_secret, y + PADDING))
        d.rectangle([(x_secret-1, y+PADDING-1), (x_secret+UPSCALE, y+PADDING+UPSCALE)],
                    outline=(120, 230, 140) if is_mint else (70, 70, 80),
                    width=2 if is_mint else 1)

        d.text((x_text, y + PADDING + 4),  label, fill=(230, 230, 230), font=F_OP)
        d.text((x_text, y + PADDING + 24),
               f"block {state.block_number}  state_nonce {state.state_nonce}",
               fill=(170, 170, 180), font=F_NOTE)

        y += ROW_H + 4

    img.save(out_path, optimize=True)


# ============================================================================
# Modes
# ============================================================================

def cmd_snapshot(args: argparse.Namespace) -> int:
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if args.from_fixture:
        # Offline path: use saved fixture files (mint_shadow/<seed>/)
        fix = Path(args.from_fixture)
        meta = json.loads((fix / "fixture.json").read_text())
        sk = int(meta["witness"]["recipient_sk"], 16)
        pi = [int(x, 16) for x in meta["public_inputs"]]
        c2 = (fix / "c2.bin").read_bytes()
        regions = decrypt_regions(c2, sk, pi[12], pi[13])
        # No live chain; reconstruct a ChainState from PI alone (T10/poses default)
        state = ChainState(
            shadow_id=int(pi[8], 16) if isinstance(pi[8], str) else pi[8],
            boxes_packed=pi[9],
            state_nonce=0,
            t10_hi=0, t10_lo=0,                # no T10 in fixture
            poses=[(state_pose := 0)] * 16,    # identity
            kinds=[SLOT_KIND_ORIGINAL]*8 + [SLOT_KIND_EMPTY]*8,
            c1_x=pi[12], c1_y=pi[13],
            c2=c2,
            block_number=0,
        )
        # Use the canonical identity poses derived from boxes_packed
        from chain_ids import shadow_id_for, ANVIL_CHAIN_ID  # noqa: F401
        from build_shadow_t10_fixture import pack_pose
        state.poses = []
        for i in range(8):
            x, y = (pi[9] >> (24 * i)) & 0x3F, ((pi[9] >> (24 * i + 6)) & 0x3F)
            state.poses.append(pack_pose(x, y, 256, 32767, 0))
        state.poses += [0] * 8
        title = f"SNAPSHOT (from fixture {fix.name}) - face_disc gated"
    else:
        if not args.shadow_token or args.shadow_id is None or not args.owner_sk_hex:
            raise SystemExit("snapshot mode needs --rpc, --shadow-token, --shadow-id, --owner-sk-hex")
        shadow_id = int(args.shadow_id, 16) if args.shadow_id.startswith("0x") else int(args.shadow_id)
        sk = int(args.owner_sk_hex, 16)
        if not args.c1_x_hex or not args.c1_y_hex:
            raise SystemExit("snapshot mode also needs --c1-x-hex / --c1-y-hex (the ECIES ephemeral pubkey "
                             "from the most recent mint or transferShadow PI; the chain doesn't store it).")
        state = read_chain_state(args.rpc, args.shadow_token, shadow_id, block_hint=args.from_block)
        state.c1_x = int(args.c1_x_hex, 16)
        state.c1_y = int(args.c1_y_hex, 16)
        regions = decrypt_regions(state.c2, sk, state.c1_x, state.c1_y)
        title = f"SNAPSHOT  block {state.block_number}  shadow {shadow_id:#x}"

    render_snapshot_montage(state, regions, title, out_path)
    print(f"wrote {out_path}")
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    """Walk SlotMutated + ShadowT10Updated event history for a shadow.

    Without a live RPC this falls back to reading a saved run dir's
    step receipts (`runs/<run>/step_NN_setT10.txt`) which already
    contain the chain hi/lo per step.
    """
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if args.from_run_dir:
        run = Path(args.from_run_dir)
        # Expects step_NN_setT10.txt receipts AND a sibling fixture for c2 + sk
        fix = Path(args.from_fixture or "contracts/test/fixtures/mint_shadow/alice0")
        meta = json.loads((fix / "fixture.json").read_text())
        sk = int(meta["witness"]["recipient_sk"], 16)
        pi = [int(x, 16) for x in meta["public_inputs"]]
        c2 = (fix / "c2.bin").read_bytes()
        regions = decrypt_regions(c2, sk, pi[12], pi[13])

        states = []
        # Walk step_00 .. step_07
        from build_shadow_t10_fixture import pack_pose
        # initial poses from boxes_packed
        identity_poses = []
        for i in range(8):
            x = (pi[9] >> (24 * i)) & 0x3F
            y = (pi[9] >> (24 * i + 6)) & 0x3F
            identity_poses.append(pack_pose(x, y, 256, 32767, 0))
        identity_poses += [0] * 8
        cur_poses = list(identity_poses)
        labels = ["MINT", "EYE L", "EYE R", "NOSE", "MOUTH", "FOREHEAD", "CHIN", "EYE L /2"]
        # PROGRAMME slot indices, mirrors build_shadow_t10_fixture.py
        prog = [
            (1, 15, 19, 256, 32767,      0),
            (2, 22, 19, 256, 32767,      0),
            (3,  5, 10, 512, 32767,      0),
            (6, 15, 33, 256, 28377,  16383),
            (0,  0,  4, 256, 32767,      0),
            (7, 13, 35, 256, 32767,      0),
            (1, 12, 19, 128, 28377, -16383),
        ]
        for step in range(8):
            t10_path = run / f"step_{step:02d}_setT10.txt"
            if not t10_path.exists():
                print(f"  missing {t10_path}, skipping")
                continue
            txt = t10_path.read_text()
            # crude parse for "chain hi:" and "chain lo:" lines we wrote earlier;
            # if absent, default to zeros.
            hi = lo = 0
            # actually read the storage call output stored by anvil_t10_e2e
            for line in txt.split("\n"):
                if "chain hi" in line.lower() and "0x" in line:
                    hi = int(line.split("0x", 1)[1].strip()[:64], 16)
                if "chain lo" in line.lower() and "0x" in line:
                    lo = int(line.split("0x", 1)[1].strip()[:64], 16)
            # If not parseable, recompute from current poses
            if hi == 0 and lo == 0:
                from t10 import compute_t10
                # compute_t10 expects per_slot, kinds, poses, max_dims
                box_dims = decode_boxes_packed(pi[9])
                max_dims = [(w, h) for (_, _, w, h) in box_dims] + [(0, 0)] * 8
                t10 = compute_t10(
                    per_slot_bytes=list(regions) + [b""] * 8,
                    kinds=[SLOT_KIND_ORIGINAL]*8 + [SLOT_KIND_EMPTY]*8,
                    poses=cur_poses,
                    slot_dims_wh=max_dims,
                    slot_max_dims_wh=max_dims,
                )
                hi, lo = t10.hi, t10.lo

            state = ChainState(
                shadow_id=int(pi[8], 16) if isinstance(pi[8], str) else pi[8],
                boxes_packed=pi[9],
                state_nonce=step,
                t10_hi=hi, t10_lo=lo,
                poses=list(cur_poses),
                kinds=[SLOT_KIND_ORIGINAL]*8 + [SLOT_KIND_EMPTY]*8,
                c1_x=pi[12], c1_y=pi[13],
                c2=c2,
                block_number=step,
            )
            states.append((labels[step], state))

            # Apply the next mutateSlot to cur_poses for the NEXT iteration
            if step < len(prog):
                slot, cx, cy, scale, cos15, sin15 = prog[step]
                cur_poses[slot] = pack_pose(cx, cy, scale,
                                            cos15 & 0xFFFF, sin15 & 0xFFFF)

        title = f"HISTORY (replay from {run.name})"
        render_history_montage(states, regions, title, out_path)
    else:
        raise SystemExit("history mode currently requires --from-run-dir; "
                         "live event walk over RPC is TODO.")
    print(f"wrote {out_path}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("snapshot", help="render one shadow's current state")
    s.add_argument("--rpc")
    s.add_argument("--shadow-token", help="ShadowToken contract address")
    s.add_argument("--shadow-id",    help="hex 0x... or decimal")
    s.add_argument("--owner-sk-hex", help="Grumpkin sk in hex")
    s.add_argument("--c1-x-hex",     help="ECIES c1.x (from latest mint/transfer PI)")
    s.add_argument("--c1-y-hex",     help="ECIES c1.y")
    s.add_argument("--from-block", type=int, default=0,
                   help="hint for eth_getLogs range (e.g. mint block); needed for RPCs with range limits")
    s.add_argument("--from-fixture", help="offline mode: read a saved fixtures/mint_shadow/<seed>/ dir")
    s.add_argument("--out", required=True)
    s.set_defaults(func=cmd_snapshot)

    h = sub.add_parser("history", help="render every state transition for a shadow")
    h.add_argument("--rpc")
    h.add_argument("--shadow-token")
    h.add_argument("--shadow-id")
    h.add_argument("--owner-sk-hex")
    h.add_argument("--from-run-dir", help="offline replay from a runs/<run>/ dir")
    h.add_argument("--from-fixture", help="alongside --from-run-dir; mint fixture for sk + c2")
    h.add_argument("--out", required=True)
    h.set_defaults(func=cmd_history)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
