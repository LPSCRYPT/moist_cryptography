#!/usr/bin/env python3
# **STALE — v1 ten-turn demo.** Targets v1 surface. v2 demo flow is
# different (atomic-T10, no setShadowT10 user call). Pending Phase 10.
"""Visualize 10 turns of add + mutate operations on a freshly-minted shadow.

Renders two rows of 10 images each (PNG grid):

  PUBLIC  : what an outside observer sees on chain. The slot manifest
            (positions, kinds, poses) is fully readable, but the pixel
            content is the c2 ciphertext bytes -- noise without the
            recipient's secret key. Each slot's footprint moves with
            its pose, so observers can track WHERE landmarks are, but
            never WHAT they look like.
  SECRET  : what the owner sees. Same poses, decrypted face plaintext.

This is the headline visualisation of the system's selective-reveal
property: the chain knows the shape, the owner knows the picture.

Usage:
    python3 demo_ten_turns.py [--out PATH]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from mint_decrypt import (  # noqa: E402
    decrypt_mint_envelope, unpack_fields_to_recolored, split_into_regions,
    REGION_BYTES, ALL_PIXELS_BYTES,
)
from mint_pipeline import REGION_W, REGION_H, REGION_NAMES  # noqa: E402
from render_shadow import (  # noqa: E402
    SLOT_KIND_EMPTY, SLOT_KIND_ORIGINAL, SLOT_KIND_INSERTED,
)

ROOT = REPO.parent
ALICE_FIXTURE = ROOT / "contracts" / "test" / "fixtures" / "mint_shadow" / "alice0"


# =============================================================================
# Pose helpers (mirror PoseLib.sol)
# =============================================================================

def pack_pose(cx: int, cy: int, scale_q88: int = 256, quarter_turns: int = 0) -> int:
    """Pack into a uint64 matching PoseLib.pack."""
    if not (0 <= quarter_turns < 4):
        raise ValueError(f"quarter_turns out of range: {quarter_turns}")
    return ((cx & 0x3F)
            | ((cy & 0x3F) << 6)
            | ((scale_q88 & 0xFFFF) << 12)
            | ((quarter_turns & 0x03) << 28))


def unpack_pose(p: int) -> tuple[int, int, int, int]:
    cx = p & 0x3F
    cy = (p >> 6) & 0x3F
    sc = (p >> 12) & 0xFFFF
    turns = (p >> 28) & 0x03
    if p >> 30:
        raise ValueError(f"pose reserved bits set: 0x{p:016x}")
    return cx, cy, sc, turns


# =============================================================================
# Renderer (single-canvas; same code path for SECRET and PUBLIC, only the
# region byte arrays differ)
# =============================================================================

def render_canvas(per_region_bytes: list[bytes],
                  manifest_kinds: list[int],
                  poses: list[int],
                  slot_dims_wh: list[tuple[int, int]],
                  inserted_dims: list[tuple[int, int]] | None = None) -> np.ndarray:
    """Composite 16 slots onto a 48x48 RGB canvas.

    Per slot:
      - kind == EMPTY: skip
      - kind in {ORIGINAL, INSERTED}: scale by nearest-neighbor, rotate by an
        exact clockwise quarter-turn, and keep the scaled feature center fixed.
        Source extent is the slot's ACTUAL (w, h) -- NOT the recolored buffer's
        max (max_w, max_h). The recolored buffer carries OOB padding past
        (h, w) that must NOT be painted onto the canvas.

    slot_dims_wh[i] = (w, h) of slot i's actual landmark bbox
                     (from boxes_packed for ORIGINAL slots; from the
                     FeatureNFT for INSERTED slots).
    inserted_dims[i] = (max_h, max_w) of slot i's recolored buffer if
                       INSERTED (mirrors source feature type's max dims).
    """
    canvas = np.zeros((48, 48, 3), dtype=np.uint8)
    inserted_dims = inserted_dims or [(0, 0)] * 16

    for slot in range(16):
        kind = manifest_kinds[slot]
        if kind == SLOT_KIND_EMPTY:
            continue
        rb = per_region_bytes[slot]
        if rb is None or len(rb) == 0:
            continue
        cx, cy, sc_q88, turns = unpack_pose(poses[slot])
        if slot < 8:
            max_w, max_h = REGION_W[slot], REGION_H[slot]
        else:
            max_h, max_w = inserted_dims[slot]
        if max_w == 0 or max_h == 0:
            continue
        if len(rb) < max_w * max_h * 3:
            continue
        w, h = slot_dims_wh[slot]
        if w == 0 or h == 0 or w > max_w or h > max_h:
            continue
        # Reshape to FULL max-bbox, then slice to the in-bounds (h, w)
        # rectangle. Anything past (h, w) is OOB padding from recolor and
        # must not be sampled.
        arr_full = np.frombuffer(rb[: max_w * max_h * 3], dtype=np.uint8).reshape(max_h, max_w, 3)
        arr = arr_full[:h, :w]

        if sc_q88 == 0:
            continue
        out_h_unrot = max(1, (h * sc_q88 + 255) >> 8)
        out_w_unrot = max(1, (w * sc_q88 + 255) >> 8)
        ys = np.minimum((np.arange(out_h_unrot, dtype=np.int64) * 256) // sc_q88, h - 1)
        xs = np.minimum((np.arange(out_w_unrot, dtype=np.int64) * 256) // sc_q88, w - 1)
        scaled = arr[ys[:, None], xs[None, :]]
        rotated = np.rot90(scaled, k=-(turns & 3))
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

    return canvas


# =============================================================================
# Demo
# =============================================================================

# 10 turn programme. Each entry is one of:
#   ("mutate", slot_idx, (cx, cy, scale_q88, quarter_turns), label)
#   ("insert", dst_slot, src_slot, (cx, cy, scale_q88, quarter_turns), label)
#                                ^ src slot's bytes get bound into dst (visual demo;
#                                  on chain this would be a FeatureNFT id)
PROGRAMME = [
    ("mutate", 1, (15,  19, 256, 1), "eye L\n+3 right +90°"),
    ("mutate", 2, (22,  19, 256, 2), "eye R\n-3 left +180°"),
    ("mutate", 3, ( 5,  10, 384, 3), "nose\n1.5x +270°"),
    ("insert", 8, 1, (32, 5, 256, 1), "+ extra eye\n@(32,5) +90°"),
    ("insert", 9, 6, (10, 38, 256, 2), "+ extra mouth\n@(10,38) +180°"),
    ("mutate", 6, (15, 33, 256, 1), "mouth\nrotate 90°"),
    ("mutate", 0, ( 0,  4, 256, 2), "forehead\nup 4 +180°"),
    ("insert",10, 4, ( 0,  0, 256, 3), "+ cheek L\n@(0,0) +270°"),
    ("mutate", 8, (28,  9, 192, 3), "extra eye\n0.75x rot 270°"),
    ("mutate", 7, (13, 35, 256, 1), "chin\nup 4 +90°"),
]

assert len(PROGRAMME) == 10


def upscale(canvas: np.ndarray, scale: int = 8) -> np.ndarray:
    """Nearest-neighbor upscale 48×48 -> (48*scale)×(48*scale) for visibility."""
    return canvas.repeat(scale, axis=0).repeat(scale, axis=1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None,
                    help="Output PNG path (default: runs/demo_ten_turns.png)")
    ap.add_argument("--scale", type=int, default=8,
                    help="Upscale factor for each 48x48 cell (default 8 -> 384px)")
    args = ap.parse_args()

    out_path = Path(args.out) if args.out else ROOT / "runs" / "demo_ten_turns.png"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # ---- Load alice0 ciphertext + sk -------------------------------------
    print(f"loading alice0 mint fixture from {ALICE_FIXTURE}")
    pi_bytes = (ALICE_FIXTURE / "public_inputs").read_bytes()
    pi = [int.from_bytes(pi_bytes[i*32:(i+1)*32], "big") for i in range(17)]
    c2_bytes = (ALICE_FIXTURE / "c2.bin").read_bytes()
    import json as _json
    fix = _json.loads((ALICE_FIXTURE / "fixture.json").read_text())
    sk = int(fix["witness"]["recipient_sk"], 16)

    # ---- Decrypt c2 -> SECRET per-region bytes (the real face data) -----
    c2 = [int.from_bytes(c2_bytes[i*32:(i+1)*32], "big") for i in range(249)]
    plaintext_packed = decrypt_mint_envelope(
        recipient_sk=sk, c1_x=pi[12], c1_y=pi[13], c2=c2,
    )
    secret_concat = unpack_fields_to_recolored(plaintext_packed)
    secret_per_region = list(split_into_regions(secret_concat))
    assert sum(len(r) for r in secret_per_region) == ALL_PIXELS_BYTES

    # ---- PUBLIC per-region bytes: take the raw c2 ciphertext bytes and  --
    # ---- chunk them into the same per-region sizes. With no decryption  --
    # ---- key, an observer literally sees these bytes as the slot data.  --
    public_concat = c2_bytes[:ALL_PIXELS_BYTES]  # 7716 of the 7968 c2 bytes
    public_per_region = []
    off = 0
    for n in REGION_BYTES:
        public_per_region.append(public_concat[off:off+n])
        off += n

    # ---- Decode origPoses + per-slot (w, h) from boxes_packed (PI[9]) ---
    # PI[9] packs slot 0..7 each as 24 bits = (x:6 | y:6 | w:6 | h:6).
    # The (x, y) seeds origPose; the (w, h) is the actual landmark bbox.
    # The renderer needs (w, h) to slice past OOB-recolored padding (the
    # circuit packs a fixed max_w * max_h * 3 buffer per region; pixels past
    # the (h, w) sub-rect are filled with `nearest_in_palette(0,0,0)`).
    boxes_packed = pi[9]
    origPoses: list[int] = []
    orig_dims_wh: list[tuple[int, int]] = []
    for i in range(8):
        slot_data = (boxes_packed >> (24 * i)) & 0xFFFFFF
        x = slot_data & 0x3F
        y = (slot_data >> 6) & 0x3F
        w = (slot_data >> 12) & 0x3F
        h = (slot_data >> 18) & 0x3F
        origPoses.append(pack_pose(x, y))
        orig_dims_wh.append((w, h))
    print(f"  origPoses : {[hex(p)[:14] for p in origPoses]}")
    print(f"  orig wh   : {orig_dims_wh}")

    # ---- Initial state: slots 0..7 ORIGINAL at origPose, 8..15 EMPTY ----
    secret_slots: list[bytes] = list(secret_per_region) + [b""] * 8
    public_slots: list[bytes] = list(public_per_region) + [b""] * 8
    poses = list(origPoses) + [0] * 8
    kinds = [SLOT_KIND_ORIGINAL] * 8 + [SLOT_KIND_EMPTY] * 8
    inserted_dims: list[tuple[int, int]] = [(0, 0)] * 16
    # slot_dims_wh tracks the ACTUAL landmark bbox (w, h) per slot.
    # Mutations don't change (w, h); inserts copy from the source slot.
    slot_dims_wh: list[tuple[int, int]] = list(orig_dims_wh) + [(0, 0)] * 8

    # Step 0 = initial state (no op yet); we render 10 frames AFTER each op.
    secret_frames: list[np.ndarray] = []
    public_frames: list[np.ndarray] = []
    labels: list[str] = []

    # Render the initial state as step 0.
    secret_frames.append(render_canvas(secret_slots, kinds, poses, slot_dims_wh, inserted_dims))
    public_frames.append(render_canvas(public_slots, kinds, poses, slot_dims_wh, inserted_dims))
    labels.append("step 0\n(mint)")

    # ---- Apply 10 turns --------------------------------------------------
    for turn_idx, op in enumerate(PROGRAMME, start=1):
        if op[0] == "mutate":
            _, slot, (cx, cy, sc, co, si), label = op
            assert kinds[slot] != SLOT_KIND_EMPTY, (
                f"can't mutate slot {slot}: still EMPTY"
            )
            poses[slot] = pack_pose(cx, cy, sc, co)
        elif op[0] == "insert":
            _, dst, src, (cx, cy, sc, co, si), label = op
            assert kinds[dst] == SLOT_KIND_EMPTY, (
                f"can't insert into slot {dst}: not EMPTY"
            )
            assert kinds[src] != SLOT_KIND_EMPTY, (
                f"src slot {src} is EMPTY"
            )
            # Bind the src slot's bytes into the dst slot. On chain this
            # would be insertFeature(dst_slot, featureNftId, pose) with the
            # FeatureNFT carrying the c2_feat bytes; here we reuse the src
            # bytes directly for the visualisation.
            kinds[dst] = SLOT_KIND_INSERTED
            secret_slots[dst] = secret_slots[src]
            public_slots[dst] = public_slots[src]
            inserted_dims[dst] = (REGION_H[src % 8], REGION_W[src % 8])
            # The inserted slot inherits the source slot's actual (w, h)
            # since the demo reuses the source bytes verbatim.
            slot_dims_wh[dst] = slot_dims_wh[src]
            poses[dst] = pack_pose(cx, cy, sc, co)
        else:
            raise ValueError(f"unknown op: {op}")

        secret_frames.append(render_canvas(secret_slots, kinds, poses, slot_dims_wh, inserted_dims))
        public_frames.append(render_canvas(public_slots, kinds, poses, slot_dims_wh, inserted_dims))
        labels.append(f"step {turn_idx}\n{label}")

    # ---- Compose grid PNG ------------------------------------------------
    n = len(secret_frames)             # 11 frames (step 0 + 10 turns)
    cell = 48 * args.scale             # px per cell
    label_h = 44                       # px reserved for label text under each cell
    row_h = cell + label_h
    margin = 12
    title_h = 36
    row_label_w = 80                   # PUBLIC / SECRET column on the left
    total_w = row_label_w + n * cell + (n + 1) * margin
    total_h = 2 * row_h + 3 * margin + title_h

    img = Image.new("RGB", (total_w, total_h), (16, 16, 18))
    draw = ImageDraw.Draw(img)
    try:
        font       = ImageFont.truetype("/System/Library/Fonts/SFNSMono.ttf", 12)
        title_font = ImageFont.truetype("/System/Library/Fonts/SFNSMono.ttf", 16)
        rowlbl_font = ImageFont.truetype("/System/Library/Fonts/SFNSMono.ttf", 14)
    except (IOError, OSError):
        font = ImageFont.load_default()
        title_font = font
        rowlbl_font = font

    draw.text((margin, 8),
              "SHADOW TOKEN  --  10 turns of add + mutate from a single mint",
              fill=(230, 230, 230), font=title_font)
    draw.text((margin, 8 + 18),
              "top row = PUBLIC (chain-visible ciphertext at slot poses)    "
              "bottom row = SECRET (owner-decrypted face under same poses)",
              fill=(150, 150, 150), font=font)

    y_public = title_h + margin
    y_secret = title_h + margin + row_h + margin

    # Row labels in the left column.
    draw.text((margin, y_public + cell // 2 - 8),  "PUBLIC",
              fill=(255, 80, 80), font=rowlbl_font)
    draw.text((margin, y_public + cell // 2 + 6), "(chain)",
              fill=(180, 80, 80), font=font)
    draw.text((margin, y_secret + cell // 2 - 8),  "SECRET",
              fill=(80, 220, 80), font=rowlbl_font)
    draw.text((margin, y_secret + cell // 2 + 6), "(owner)",
              fill=(80, 160, 80), font=font)

    for i, (pub_c, sec_c, lbl) in enumerate(zip(public_frames, secret_frames, labels)):
        x = row_label_w + margin + i * (cell + margin)
        pub_up = upscale(pub_c, args.scale)
        sec_up = upscale(sec_c, args.scale)
        img.paste(Image.fromarray(pub_up), (x, y_public))
        img.paste(Image.fromarray(sec_up), (x, y_secret))
        # Label below each pair (under SECRET).
        for li, line in enumerate(lbl.split("\n")):
            draw.text((x, y_secret + cell + 6 + li * 14),
                      line, fill=(220, 220, 220), font=font)

    img.save(out_path)
    print(f"\nwrote {out_path}  ({total_w}x{total_h} px)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
