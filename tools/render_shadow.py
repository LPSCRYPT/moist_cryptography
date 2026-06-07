#!/usr/bin/env python3
# **STALE — v1 renderer.** v2 renders per-slot palette-indexed sprites,
# z-composed via revealed (post-solve) or hidden (pre-solve) permutation.
"""Off-chain renderer: reproduce a 48x48 RGB face from chain state alone.

Inputs (from a deployed ShadowToken):
  - shadow's c2 bytes (from ShadowCiphertext event log)
  - manifest[16] (from shadowToken.manifestOf(shadowId))
  - origPose[8] (from shadowToken.origPoseOf(shadowId, i))
  - inserted FeatureNFT c2 bytes (from FeatureCiphertext events)
  - recipient's secret key (off-chain, of course)

Pipeline:
  1. Decrypt shadow c2 -> 249-Field plaintext -> 7,716 bytes -> 8 region bytes.
  2. For each manifest slot 0..15 (in slot order):
       if EMPTY: skip
       if ORIGINAL: take shadow's region[originalTypeIdx] bytes
       if INSERTED: decrypt that FeatureNFT's c2 -> 42 Fields ->
                    unpack -> per-region bytes via PACKED_COUNTS table
       Apply slot pose as nearest-neighbour scale plus exact 90-degree rotation,
       keeping the scaled feature center fixed, and draw onto canvas.
       (Later slots paint over earlier -- "render in slot order, ignore overlap".)
  3. Save PNG.

Usage:
    python3 render_shadow.py \
        --c2-file <shadow_c2_bytes> \
        --recipient-sk <hex> \
        --c1 <c1.x>,<c1.y> \
        --c2-scalar <hex>            (transfer_shadow envelopes; for mint use 0)
        --is-mint                    (use mint convention: k = mask)
        --manifest <json file>       (manifest[16] from chain)
        --feature-c2s <dir>          (one .bin per inserted feature)
        --out face.png

For self-contained testing without a chain, see `validate_pixels.py` which
runs the same decrypt path against the alice0 fixture.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from mint_decrypt import (  # noqa: E402
    decrypt_mint_envelope, unpack_fields_to_recolored, split_into_regions,
    poseidon2_keystream_249, poseidon2_hash_2, P, REGION_BYTES,
)
from build_extract_slot_fixture import poseidon2_keystream_42  # noqa: E402
from mint_pipeline import REGION_W, REGION_H, REGION_NAMES, PACKED_COUNTS  # noqa: E402
from secret_inbox import ec_mul  # noqa: E402

ROOT = REPO.parent

SLOT_KIND_EMPTY    = 0
SLOT_KIND_ORIGINAL = 1
SLOT_KIND_INSERTED = 2


def parse_pose(pose: int) -> tuple[int, int, int, int]:
    """Unpack a uint64 pose word per PoseLib.sol layout."""
    cx = pose & 0x3F
    cy = (pose >> 6) & 0x3F
    scale_q88 = (pose >> 12) & 0xFFFF
    quarter_turns = (pose >> 28) & 0x03
    if pose >> 30:
        raise ValueError(f"pose reserved bits set: 0x{pose:016x}")
    return cx, cy, scale_q88, quarter_turns


def decrypt_shadow_c2(
    c2_bytes: bytes,
    recipient_sk: int,
    c1_x: int, c1_y: int,
    *,
    is_mint: bool = False,
    c2_scalar: int = 0,
) -> list[bytes]:
    """Decrypt shadow c2 -> 8 per-region byte buffers.

    For mint envelopes (is_mint=True), uses k = Poseidon2(shared.x, shared.y).
    For transfer envelopes (is_mint=False), recovers k = c2_scalar - mask.
    """
    c2 = [int.from_bytes(c2_bytes[i*32:(i+1)*32], "big") for i in range(249)]

    if is_mint:
        plaintext_packed = decrypt_mint_envelope(
            recipient_sk=recipient_sk, c1_x=c1_x, c1_y=c1_y, c2=c2,
        )
    else:
        shared = ec_mul((c1_x, c1_y), recipient_sk)
        k_mask = poseidon2_hash_2(shared[0], shared[1])
        new_k = (c2_scalar - k_mask) % P
        ks = poseidon2_keystream_249(new_k)
        plaintext_packed = [(c2[i] - ks[i]) % P for i in range(249)]

    concat_bytes = unpack_fields_to_recolored(plaintext_packed)
    per_region = split_into_regions(concat_bytes)
    return per_region


def decrypt_feature_c2(
    c2_bytes: bytes,
    recipient_sk: int,
    c1_x: int, c1_y: int,
    c2_scalar: int,
    feature_type: int,
) -> bytes:
    """Decrypt a 42-Field FeatureNFT c2 -> per-region byte buffer."""
    assert len(c2_bytes) == 42 * 32, f"feature c2 must be 1344 bytes, got {len(c2_bytes)}"
    c2 = [int.from_bytes(c2_bytes[i*32:(i+1)*32], "big") for i in range(42)]
    shared = ec_mul((c1_x, c1_y), recipient_sk)
    k_mask = poseidon2_hash_2(shared[0], shared[1])
    new_k = (c2_scalar - k_mask) % P
    ks = poseidon2_keystream_42(new_k)
    payload = [(c2[i] - ks[i]) % P for i in range(42)]

    # Unpack 42 Fields -> region bytes. Each Field carries 31 bytes LSB-first.
    K = PACKED_COUNTS[feature_type]
    n_bytes = REGION_BYTES[feature_type]
    raw = bytearray()
    for f_idx in range(K):
        raw.extend(payload[f_idx].to_bytes(31, "little"))
    return bytes(raw[:n_bytes])


def render_to_canvas(
    per_region_bytes: list[bytes],
    geom: list[tuple[int, int, int, int]],  # (x1, y1, w, h) per slot 0..15
    poses: list[int],                        # uint64 pose per slot
    manifest_kinds: list[int],               # SlotKind per slot
    out_path: Path,
):
    """Composite per-slot region bytes onto a 48x48 canvas under the slot pose.

    Pose rotation is discrete: quarterTurns in {0,1,2,3} means clockwise
    0/90/180/270 degrees. The renderer scales by nearest-neighbour, rotates
    the scaled pixel grid as an exact permutation, then places the rotated
    bounding box so its center matches the unrotated scaled feature center.
    """
    try:
        from PIL import Image
    except ImportError:
        print("(PIL not installed; skipping render)")
        return
    import numpy as np

    canvas = np.zeros((48, 48, 3), dtype=np.uint8)
    n_slots = len(per_region_bytes)
    assert len(geom) == n_slots
    assert len(poses) == n_slots
    assert len(manifest_kinds) == n_slots

    for slot in range(n_slots):
        kind = manifest_kinds[slot]
        if kind == SLOT_KIND_EMPTY:
            continue
        region_bytes = per_region_bytes[slot]
        if region_bytes is None or len(region_bytes) == 0:
            continue
        x1, y1, w, h = geom[slot]
        if w == 0 or h == 0:
            continue
        cx, cy, scale_q88, quarter_turns = parse_pose(poses[slot])

        # Decode source frame size: slots 0..7 use canonical REGION_W/H;
        # slots 8..15 (INSERTED) carry their max-bbox via geom (w, h).
        if slot < 8:
            max_w = REGION_W[slot]; max_h = REGION_H[slot]
        else:
            max_w = w; max_h = h
        expected = max_w * max_h * 3
        if len(region_bytes) != expected:
            continue
        try:
            arr = np.frombuffer(region_bytes, dtype=np.uint8).reshape(max_h, max_w, 3)[:h, :w]
        except Exception as e:
            print(f"  slot {slot}: reshape error: {e}")
            continue

        if scale_q88 == 0:
            continue
        out_h_unrot = max(1, (h * scale_q88 + 255) >> 8)
        out_w_unrot = max(1, (w * scale_q88 + 255) >> 8)
        ys = np.minimum((np.arange(out_h_unrot, dtype=np.int64) * 256) // scale_q88, h - 1)
        xs = np.minimum((np.arange(out_w_unrot, dtype=np.int64) * 256) // scale_q88, w - 1)
        scaled = arr[ys[:, None], xs[None, :]]
        rotated = np.rot90(scaled, k=-(quarter_turns & 3))
        out_h, out_w = rotated.shape[:2]

        x0 = (2 * cx + out_w_unrot - out_w) // 2
        y0 = (2 * cy + out_h_unrot - out_h) // 2
        x1 = x0 + out_w
        y1 = y0 + out_h

        dst_x0 = max(0, x0); dst_y0 = max(0, y0)
        dst_x1 = min(48, x1); dst_y1 = min(48, y1)
        if dst_x1 <= dst_x0 or dst_y1 <= dst_y0:
            continue

        src_x0 = dst_x0 - x0; src_y0 = dst_y0 - y0
        src_x1 = src_x0 + (dst_x1 - dst_x0)
        src_y1 = src_y0 + (dst_y1 - dst_y0)
        canvas[dst_y0:dst_y1, dst_x0:dst_x1] = rotated[src_y0:src_y1, src_x0:src_x1]

    Image.fromarray(canvas).save(out_path)
    print(f"  wrote {out_path}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", default="alice0",
                    help="Fixture name to render from. Currently supports 'alice0'.")
    ap.add_argument("--out", default=None,
                    help="Output PNG path (default: phase2/logs/render_<fixture>.png)")
    ap.add_argument("--mutate-slot", default=None, metavar="IDX:CX:CY:SCALEQ88:QUARTER_TURNS",
                    help=("Override one slot's pose for testing rotation/scale. "
                          "Five colon-separated ints: slot index, cx, cy, scaleQ88 "
                          "(256=1.0), quarterTurns clockwise in [1,3]."))
    args = ap.parse_args()

    if args.fixture != "alice0":
        sys.exit("only --fixture alice0 supported in v0 renderer")

    # Load alice0 mint state.
    fix_dir = ROOT / "contracts" / "test" / "fixtures" / "mint_shadow" / args.fixture
    fix = json.loads((fix_dir / "fixture.json").read_text())
    pi = [int.from_bytes((fix_dir / "public_inputs").read_bytes()[i*32:(i+1)*32], "big") for i in range(17)]
    c2_bytes = (fix_dir / "c2.bin").read_bytes()

    sk = int(fix["witness"]["recipient_sk"], 16)
    c1_x = pi[12]; c1_y = pi[13]

    print(f"Rendering shadow {args.fixture} from chain c2 + sk")
    per_region = decrypt_shadow_c2(c2_bytes, sk, c1_x, c1_y, is_mint=True)
    for ftype, b in enumerate(per_region):
        print(f"  region {ftype} ({REGION_NAMES[ftype]}): {len(b)} bytes")

    # Decode boxes_packed (PI[9]) to per-slot (x1, y1, w, h).
    boxes_packed = pi[9]
    geom = []
    poses = []
    kinds = []
    for slot in range(16):
        if slot < 8:
            slot_data = (boxes_packed >> (24 * slot)) & 0xFFFFFF
            x = slot_data & 0x3F
            y = (slot_data >> 6) & 0x3F
            w = (slot_data >> 12) & 0x3F
            h = (slot_data >> 18) & 0x3F
            geom.append((x, y, w, h))
            # Identity pose (matches mint_shadow's origPose[i]).
            pose = (x & 0x3F) | ((y & 0x3F) << 6) | (256 << 12)
            poses.append(pose)
            kinds.append(SLOT_KIND_ORIGINAL)
        else:
            geom.append((0, 0, 0, 0))
            poses.append(0)
            kinds.append(SLOT_KIND_EMPTY)

    # Pad per_region to 16 slots (slots 8..15 are EMPTY).
    while len(per_region) < 16:
        per_region.append(b"")

    # Manual pose override (testing rotation/scale).
    if args.mutate_slot:
        try:
            parts = args.mutate_slot.split(":")
            if len(parts) != 5:
                raise ValueError("need 5 colon-separated ints")
            idx, mcx, mcy, msc, mturns = (int(p) for p in parts)
        except Exception as e:
            sys.exit(f"--mutate-slot parse error: {e}")
        if not (0 <= idx < 16):
            sys.exit(f"--mutate-slot idx {idx} out of range [0,16)")
        if not (1 <= mturns < 4):
            sys.exit(f"--mutate-slot quarterTurns {mturns} out of range [1,4)")
        # Pack pose word per PoseLib layout.
        pose = ((mcx & 0x3F)
                | ((mcy & 0x3F) << 6)
                | ((msc & 0xFFFF) << 12)
                | ((mturns & 0x03) << 28))
        poses[idx] = pose
        # If the slot was EMPTY (e.g. for visual experiments), upgrade to ORIGINAL.
        if kinds[idx] == SLOT_KIND_EMPTY:
            kinds[idx] = SLOT_KIND_ORIGINAL
        print(f"  mutate slot {idx}: pose=0x{pose:016x}")

    out_path = Path(args.out) if args.out else ROOT / "runs" / f"render_{args.fixture}.png"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    render_to_canvas(per_region, geom, poses, kinds, out_path)
    print(f"\ndone -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
