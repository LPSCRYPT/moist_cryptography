"""Python reference for the v5 mint pipeline (`circuits/landmark_regions`).

This module produces the per-face data needed to construct trio (relay-geom /
shadow / solve) fixtures aligned with a real on-chain mint output.

Specifically, given the same (image, caller_nonce) inputs that mint takes,
this module returns:

    - The 5 CNN landmarks (via fixed_point_infer -- bit-exact to the circuit)
    - The 8 v5 region boxes (via v5_geometry -- canonical Python ref)
    - The post-recolor bytes for each region's MAX_W_i x MAX_H_i x 3 buffer
    - The K_i packed Fields per region (31 bytes/Field LSB-first)
    - The packed_padded buffer (zero-padded to MAX_K = 42) for trio circuits

Crucially, the trio circuits' witnesses MUST use exactly these packed buffers
for their `prev_state_commit` to equal the mint-emitted `stateCommit_i`.

Notes:
    - Palette selection is NOT recomputed here. Instead, the CALLER passes
      `color` (from mint PI[10]). This avoids a 6912-element Poseidon2 sponge
      we would otherwise have to evaluate via shell-out. Behavior is
      deterministic given (image, color).
    - faceOriginId / state_commit / pixel_commit are NOT recomputed here.
      They live in mint's PI; the trio circuits re-derive them from witness
      and PI must match.
    - boxes_packed in mint PI is 24-bit/slot (x|y|w|h). Shadow's PI is
      12-bit/slot (x|y only). The two differ; trio fixture builders should
      decode mint PI[9] and repack as needed.

Usage:
    from mint_pipeline import compute_face_state
    state = compute_face_state(face_path, color=3)
    # state["regions"][i] = {"x1", "y1", "w", "h", "packed", "packed_padded", ...}
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

import cv2
import numpy as np

REPO = Path(__file__).resolve().parent

# Landmark + palette helpers under tools/landmark/ (vendored, no external deps)
sys.path.insert(0, str(REPO / "landmark"))
from fixed_point_infer import fixed_point_landmarks  # noqa: E402
from v5_geometry import v5_boxes, REGION_NAMES  # noqa: E402
from palette_quantizer import PALETTES, PALETTE_RANK  # noqa: E402

# Canonical packing (relay_geom is the v5 source of truth)
sys.path.insert(0, str(REPO))
from relay_geom import (  # noqa: E402
    REGION_W, REGION_H, PACKED_COUNTS, MAX_K,
    pack_feature_to_fields, pad_to_max_k,
)

DEFAULT_WEIGHTS = REPO / "landmark" / "weights" / "landmark_v3_5point.json"


# =============================================================================
# Recolor: Manhattan-distance nearest-neighbor over a 10-color palette.
# Bit-identical to circuits/landmark_regions/src/main.nr::nearest_in_palette.
# Ties resolve to the lowest index (the circuit's `take = d < best_dist` only
# updates on STRICTLY less).
# =============================================================================
def nearest_in_palette(r: int, g: int, b: int, palette: Sequence[tuple[int, int, int]]) -> tuple[int, int, int]:
    best_r, best_g, best_b = palette[0]
    best_d = abs(r - best_r) + abs(g - best_g) + abs(b - best_b)
    for i in range(1, 10):
        pr, pg, pb = palette[i]
        d = abs(r - pr) + abs(g - pg) + abs(b - pb)
        if d < best_d:
            best_r, best_g, best_b = pr, pg, pb
            best_d = d
    return best_r, best_g, best_b


# =============================================================================
# Per-region recolor + pack
# =============================================================================
@dataclass
class RegionState:
    name: str
    feature_type: int
    x1: int
    y1: int
    w: int
    h: int
    max_w: int
    max_h: int
    K: int
    recolored: bytes        # length = max_w * max_h * 3 (in-bounds + OOB-zero recolored)
    packed: list[int]       # length K; 31 bytes/Field LSB
    packed_padded: list[int]  # length MAX_K = 42 (trailing zeros)


@dataclass
class FaceState:
    face_path: str
    color: int
    palette_name: str
    landmarks: list[tuple[int, int]]
    regions: list[RegionState]
    img_rgb: np.ndarray  # 48x48x3 uint8
    img_chw: np.ndarray  # flat 6912 uint8


def _recolor_region(
    img_chw: np.ndarray,
    feature_type: int,
    x1: int, y1: int, w: int, h: int,
    palette: Sequence[tuple[int, int, int]],
) -> bytes:
    """Build the MAX_W_i x MAX_H_i x 3 recolored buffer for region i.

    Bit-exact match to the circuit:
      - Allocate buffer of MAX_W*MAX_H*3 bytes (zeros).
      - For dy in [0..MAX_H), dx in [0..MAX_W):
          - If (dy < h and dx < w): copy image[c, y1+dy, x1+dx] for c in 0..2
            into buffer at offset (dy * MAX_W + dx) * 3 + c.
          - Otherwise: byte stays 0.
        (See circuit's `region_orig_i[dy * MAX_W * 3 + dx * 3 + c] = image[...]`
        guarded by `(dy < box_h_i) & (dx < box_w_i)`.)
      - For p in [0..MAX_W*MAX_H): recolor (cr, cg, cb) = buffer[p*3..p*3+2]
        via nearest_in_palette(cr, cg, cb, chosen_palette). OOB positions
        recolor as nearest_in_palette(0, 0, 0, palette).

    Linear `p` index iterates flat dy-major rows (matches circuit's `for p in
    0..MAX_W*MAX_H`).
    """
    max_w = REGION_W[feature_type]
    max_h = REGION_H[feature_type]
    n_bytes = max_w * max_h * 3

    # Step 1: extract original bytes (zeros for OOB)
    orig = bytearray(n_bytes)
    for dy in range(max_h):
        for dx in range(max_w):
            if dy < h and dx < w:
                ix = x1 + dx
                iy = y1 + dy
                base = dy * max_w * 3 + dx * 3
                # CHW indexing: img_chw[c * 2304 + iy * 48 + ix]
                orig[base + 0] = int(img_chw[0 * 2304 + iy * 48 + ix])
                orig[base + 1] = int(img_chw[1 * 2304 + iy * 48 + ix])
                orig[base + 2] = int(img_chw[2 * 2304 + iy * 48 + ix])

    # Step 2: recolor every pixel (linear p over all max_w*max_h positions)
    recolored = bytearray(n_bytes)
    n_px = max_w * max_h
    for p in range(n_px):
        cr = orig[p * 3 + 0]
        cg = orig[p * 3 + 1]
        cb = orig[p * 3 + 2]
        nr, ng, nb = nearest_in_palette(cr, cg, cb, palette)
        recolored[p * 3 + 0] = nr
        recolored[p * 3 + 1] = ng
        recolored[p * 3 + 2] = nb

    return bytes(recolored)


# =============================================================================
# Public entrypoint
# =============================================================================
def compute_face_state(
    face_path: str | Path,
    color: int,
    weights_path: str | Path = DEFAULT_WEIGHTS,
) -> FaceState:
    """Run the v5 mint pipeline (CNN + v5 boxes + per-region recolor + pack).

    Args:
        face_path: 48x48 RGB face image (any reader; cv2 used here).
        color: palette ID 0..22 (= alice0 mintPI[10] for matching mint output).
        weights_path: CNN weights JSON (default: landmark_v3_5point.json).

    Returns:
        FaceState with per-region recolored bytes and packed Fields, plus
        landmarks and image buffers for use by trio fixture builders.
    """
    if not (0 <= color < len(PALETTE_RANK)):
        raise ValueError(f"color {color} out of range 0..{len(PALETTE_RANK) - 1}")

    weights = json.loads(Path(weights_path).read_text())
    palette_name = PALETTE_RANK[color]
    palette = PALETTES[palette_name]
    if len(palette) != 10:
        raise ValueError(f"palette {palette_name} has {len(palette)} entries (expected 10)")

    # Load image as 48x48x3 RGB uint8
    bgr = cv2.imread(str(face_path))
    if bgr is None:
        raise SystemExit(f"could not read {face_path}")
    if bgr.shape[:2] != (48, 48):
        bgr = cv2.resize(bgr, (48, 48), interpolation=cv2.INTER_AREA)
    img_rgb = cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)

    # CHW flat for circuit-aligned indexing
    img_chw = img_rgb.transpose(2, 0, 1).flatten().astype(np.uint8)
    assert img_chw.size == 6912

    # CNN -> 5 (x, y) landmarks (bit-exact to circuit)
    landmarks = fixed_point_landmarks(img_rgb, weights)

    # v5 boxes (canonical Python ref)
    boxes = v5_boxes(landmarks)
    by_name = {b[0]: b for b in boxes}
    ordered = [by_name[n] for n in REGION_NAMES]

    # Per-region: recolor + pack
    regions: list[RegionState] = []
    for ftype, (name, x1, y1, w, h) in enumerate(ordered):
        max_w = REGION_W[ftype]
        max_h = REGION_H[ftype]
        K = PACKED_COUNTS[ftype]
        if not (1 <= w <= max_w and 1 <= h <= max_h):
            raise ValueError(f"region {ftype} ({name}) w/h ({w}, {h}) out of range "
                             f"[(1, {max_w}), (1, {max_h})]")
        if not (0 <= x1 <= 48 - w and 0 <= y1 <= 48 - h):
            raise ValueError(f"region {ftype} ({name}) x1/y1 ({x1}, {y1}) out of bounds "
                             f"for w={w}, h={h}")

        recolored = _recolor_region(img_chw, ftype, x1, y1, w, h, palette)
        packed = pack_feature_to_fields(recolored, K)
        packed_padded = pad_to_max_k(packed)
        if len(packed_padded) != MAX_K:
            raise AssertionError(f"packed_padded length {len(packed_padded)} != MAX_K {MAX_K}")

        regions.append(RegionState(
            name=name, feature_type=ftype,
            x1=x1, y1=y1, w=w, h=h,
            max_w=max_w, max_h=max_h, K=K,
            recolored=recolored,
            packed=packed,
            packed_padded=packed_padded,
        ))

    return FaceState(
        face_path=str(face_path),
        color=color,
        palette_name=palette_name,
        landmarks=landmarks,
        regions=regions,
        img_rgb=img_rgb,
        img_chw=img_chw,
    )


# =============================================================================
# CLI: dump alice0's per-region state
# =============================================================================
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--face",
        default=str(ROOT / "examples" / "faces" / "alice0.png"),
    )
    ap.add_argument("--color", type=int, default=3)
    args = ap.parse_args()

    state = compute_face_state(args.face, args.color)
    print(f"face        : {state.face_path}")
    print(f"color       : {state.color} ({state.palette_name})")
    print(f"landmarks   : {state.landmarks}")
    print()
    for r in state.regions:
        print(f"  region {r.feature_type} ({r.name:11s}) "
              f"box=({r.x1}, {r.y1}, {r.w}, {r.h})  "
              f"max=({r.max_w}, {r.max_h})  K={r.K}  "
              f"first_packed={hex(r.packed[0])[:18]}...")
