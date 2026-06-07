"""T10 4-level grayscale shadow — Python reference.

Canonical, byte-exact spec for the `shadow_t10` Noir circuit. Anyone
who can read the chain (manifest, ct_commit, c2 events, inserted
FeatureNFT c2 events) and holds the recipient's secret key can run
this and reconstruct the public T10 bitmap.

Pipeline:
  1. Decrypt shadow c2  ->  8 region byte buffers (in-bounds (h, w) per slot).
  2. For each INSERTED slot, decrypt the FeatureNFT c2  ->  region byte buffer.
  3. Composite 16 slots onto a 48x48 RGB canvas. Per-slot bytes are scaled by
     nearest-neighbour and then rotated by an exact clockwise quarter-turn
     (0/90/180/270 degrees). Rotation preserves source-pixel adjacency and
     keeps the scaled feature center fixed. Out-of-pose pixels remain zero.
     Slot order matters: later slots overwrite earlier (slot 15 wins ties).
  4. T10 quantize: for each cell (by, bx) in [0..16, 0..16]:
       sum_y = sum over (dy, dx) in [0..3, 0..3] of luma(canvas[3by+dy, 3bx+dx])
       avg   = sum_y / 9   (integer)
       level = (avg > 64) + (avg > 128) + (avg > 192)   in [0..3]
     where luma(r, g, b) = (77*r + 150*g + 29*b) >> 8.
  5. Pack: cell_idx = by * 16 + bx;  quarter = cell_idx / 64;  bit = (cell_idx % 64) * 2;
     shadow_q[quarter] |= level << bit
  6. Output: shadow_q0..q3, each a Field with up to 128 bits set.

Manifest hash:
  manifest_hash = poseidon2_sponge_48(
    slot0.kind, slot0.pose_u64, slot0.feature_id_u256,
    slot1.kind, slot1.pose_u64, slot1.feature_id_u256,
    ...
    slot15.kind, slot15.pose_u64, slot15.feature_id_u256,
  )
  EMPTY slots have all three = 0.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from mint_decrypt import poseidon2_state, P  # noqa: E402

# Slot kinds -- match Solidity SlotKind enum and render_shadow.py constants.
SLOT_KIND_EMPTY    = 0
SLOT_KIND_ORIGINAL = 1
SLOT_KIND_INSERTED = 2

# Region max-bbox dims (slot 0..7 = ORIGINAL feature types; same indexing
# applies to inserted features by their feature_type 0..7).
REGION_W: list[int] = [48, 33, 33, 24, 14, 14, 48, 48]
REGION_H: list[int] = [ 9,  8,  8, 11, 19, 19,  9,  8]


# =============================================================================
# Pose unpack
# =============================================================================
def unpack_pose(p: int) -> tuple[int, int, int, int]:
    """Unpack a uint64 pose word per PoseLib.sol layout."""
    cx = p & 0x3F
    cy = (p >> 6) & 0x3F
    sc = (p >> 12) & 0xFFFF
    turns = (p >> 28) & 0x03
    if p >> 30:
        raise ValueError(f"pose reserved bits set: 0x{p:016x}")
    return cx, cy, sc, turns


# =============================================================================
# Composite under poses (nearest-neighbour scale + exact quarter-turn rotation)
# =============================================================================


def _scale_nearest(arr: np.ndarray, scale_q88: int) -> np.ndarray:
    if scale_q88 == 0:
        raise ValueError("scale_q88 must be non-zero")
    out_h = max(1, (arr.shape[0] * scale_q88 + 255) >> 8)
    out_w = max(1, (arr.shape[1] * scale_q88 + 255) >> 8)
    ys = np.minimum((np.arange(out_h, dtype=np.int64) * 256) // scale_q88, arr.shape[0] - 1)
    xs = np.minimum((np.arange(out_w, dtype=np.int64) * 256) // scale_q88, arr.shape[1] - 1)
    return arr[ys[:, None], xs[None, :]]


def _centered_top_left(anchor: int, unrotated_extent: int, rotated_extent: int) -> int:
    # Floor is deterministic when the exact center lands between pixel columns.
    return (2 * anchor + unrotated_extent - rotated_extent) // 2


def composite_canvas(
    per_slot_bytes: list[bytes],
    kinds: list[int],
    poses: list[int],
    slot_dims_wh: list[tuple[int, int]],     # ACTUAL (w, h) per slot
    slot_max_dims_wh: list[tuple[int, int]], # MAX (w, h) per slot's recolored buffer
) -> np.ndarray:
    """Composite 16 slots onto a 48x48 RGB canvas under their poses.

    Rotation is restricted to exact clockwise quarter-turns. We first apply
    nearest-neighbour scale to the source sprite, then rotate the scaled pixel
    grid with `np.rot90(..., k=-turns)`. That is a one-to-one pixel permutation
    for rotation itself; no affine resampling or interpolation is performed.
    Slot order: later slots overwrite earlier.
    """
    canvas = np.zeros((48, 48, 3), dtype=np.uint8)
    for slot in range(16):
        kind = kinds[slot]
        if kind == SLOT_KIND_EMPTY:
            continue
        rb = per_slot_bytes[slot]
        if rb is None or len(rb) == 0:
            continue
        cx_anchor, cy_anchor, sc_q88, turns = unpack_pose(poses[slot])
        max_w, max_h = slot_max_dims_wh[slot]
        if max_w == 0 or max_h == 0:
            continue
        if len(rb) < max_w * max_h * 3:
            continue
        w, h = slot_dims_wh[slot]
        if w == 0 or h == 0 or w > max_w or h > max_h:
            continue
        arr = np.frombuffer(rb[: max_w * max_h * 3], dtype=np.uint8).reshape(max_h, max_w, 3)[:h, :w]
        scaled = _scale_nearest(arr, sc_q88)
        rotated = np.rot90(scaled, k=-(turns & 3))
        out_h, out_w = rotated.shape[:2]

        x0 = _centered_top_left(cx_anchor, scaled.shape[1], out_w)
        y0 = _centered_top_left(cy_anchor, scaled.shape[0], out_h)
        x1 = x0 + out_w
        y1 = y0 + out_h

        dst_x0 = max(0, x0)
        dst_y0 = max(0, y0)
        dst_x1 = min(48, x1)
        dst_y1 = min(48, y1)
        if dst_x1 <= dst_x0 or dst_y1 <= dst_y0:
            continue

        src_x0 = dst_x0 - x0
        src_y0 = dst_y0 - y0
        src_x1 = src_x0 + (dst_x1 - dst_x0)
        src_y1 = src_y0 + (dst_y1 - dst_y0)
        canvas[dst_y0:dst_y1, dst_x0:dst_x1] = rotated[src_y0:src_y1, src_x0:src_x1]
    return canvas


# =============================================================================
# T10 quantization (matches phase-1 shadow.nr::t10_compute exactly)
# =============================================================================

def t10_compute(canvas: np.ndarray) -> tuple[int, int, int, int]:
    """48x48 RGB canvas -> 4 Field elements (shadow_q0..q3).

    Matches phase-1 shadow.nr::t10_compute:
      luma(r, g, b) = (77*r + 150*g + 29*b) >> 8     (ITU-601, integer)
      avg = sum_over_3x3(luma) / 9                   (integer)
      level = (avg > 64) + (avg > 128) + (avg > 192) (in 0..3)
      cell_idx = by * 16 + bx
      shadow_q[cell_idx / 64] |= level << ((cell_idx % 64) * 2)
    """
    if canvas.shape != (48, 48, 3) or canvas.dtype != np.uint8:
        raise ValueError(f"canvas: expected (48, 48, 3) uint8, got {canvas.shape} {canvas.dtype}")
    quarters: list[int] = [0, 0, 0, 0]
    arr = canvas.astype(np.int64)
    luma = (77 * arr[..., 0] + 150 * arr[..., 1] + 29 * arr[..., 2]) >> 8  # (48, 48) int64
    for by in range(16):
        for bx in range(16):
            sum_y = int(luma[3*by:3*by+3, 3*bx:3*bx+3].sum())
            avg = sum_y // 9
            level = (1 if avg > 64 else 0) + (1 if avg > 128 else 0) + (1 if avg > 192 else 0)
            cell_idx = by * 16 + bx
            q = cell_idx // 64
            bit_in_q = (cell_idx - q * 64) * 2
            quarters[q] |= (level & 0x3) << bit_in_q
    return tuple(quarters)


def quarters_to_hi_lo(q: tuple[int, int, int, int]) -> tuple[int, int]:
    """Pack 4 quarter-Fields (128 bits each) into (shadowHi, shadowLo) uint256.

    shadowHi = q[0] | (q[1] << 128)
    shadowLo = q[2] | (q[3] << 128)

    The contract recombines this way; a uint256 view is convenient for
    storage and for indexers.
    """
    hi = (q[0] & ((1 << 128) - 1)) | ((q[1] & ((1 << 128) - 1)) << 128)
    lo = (q[2] & ((1 << 128) - 1)) | ((q[3] & ((1 << 128) - 1)) << 128)
    return hi, lo


def hi_lo_to_grid(hi: int, lo: int) -> np.ndarray:
    """Inverse: (shadowHi, shadowLo) -> 16x16 uint8 grid of levels in 0..3.

    Used by the renderer to decode chain T10 bytes into a displayable
    grayscale image.
    """
    full = (hi & ((1 << 256) - 1)) | ((lo & ((1 << 256) - 1)) << 256)
    grid = np.zeros((16, 16), dtype=np.uint8)
    for by in range(16):
        for bx in range(16):
            cell_idx = by * 16 + bx
            bit = cell_idx * 2
            grid[by, bx] = (full >> bit) & 0x3
    return grid


def grid_to_grayscale_image(grid: np.ndarray, scale: int = 16) -> np.ndarray:
    """16x16 4-level grid -> upscaled 8-bit grayscale RGB image (3-channel)."""
    if grid.shape != (16, 16):
        raise ValueError(f"grid shape {grid.shape}, expected (16, 16)")
    palette = np.array([0, 85, 170, 255], dtype=np.uint8)  # 4 evenly-spaced grey levels
    intensities = palette[grid]                              # (16, 16) uint8
    rgb = np.repeat(intensities[..., None], 3, axis=-1)      # (16, 16, 3)
    return rgb.repeat(scale, axis=0).repeat(scale, axis=1)


# =============================================================================
# Manifest hash
# =============================================================================

def manifest_hash_inputs(
    kinds: list[int],
    poses: list[int],
    feature_ids: list[int],
) -> list[int]:
    """48-element flat list: per slot 0..15, [kind, pose_u64, feature_id]."""
    if not (len(kinds) == len(poses) == len(feature_ids) == 16):
        raise ValueError("manifest_hash_inputs: need 16 entries each")
    out: list[int] = []
    for i in range(16):
        out.append(kinds[i] & 0xFF)
        out.append(poses[i] & ((1 << 64) - 1))
        out.append(feature_ids[i] % P)
    assert len(out) == 48
    return out


def poseidon2_sponge(elems: list[int]) -> int:
    """Generic Poseidon2 sponge: rate=3, capacity=1, sentinel=1.

    Absorbs N Fields. floor(N / 3) full blocks, then a partial block
    with sentinel=1 in the next free rate slot. Matches the Noir
    sponge_K helpers in phase 2 / phase 1 circuits.
    """
    s = [0, 0, 0, 0]
    n = len(elems)
    full = n // 3
    tail = n - full * 3
    for b in range(full):
        s[0] = (s[0] + elems[b * 3 + 0]) % P
        s[1] = (s[1] + elems[b * 3 + 1]) % P
        s[2] = (s[2] + elems[b * 3 + 2]) % P
        s[0], s[1], s[2], s[3] = poseidon2_state(*s)
    # Tail + sentinel padding.
    if tail >= 1: s[0] = (s[0] + elems[full * 3 + 0]) % P
    if tail >= 2: s[1] = (s[1] + elems[full * 3 + 1]) % P
    s[tail] = (s[tail] + 1) % P  # sentinel=1 in next free slot
    s[0], s[1], s[2], s[3] = poseidon2_state(*s)
    return s[0]


def manifest_hash(kinds: list[int], poses: list[int], feature_ids: list[int]) -> int:
    """Poseidon2 sponge_48 over the 48-element manifest field list."""
    return poseidon2_sponge(manifest_hash_inputs(kinds, poses, feature_ids))


# =============================================================================
# Top-level helper for fixture builders + e2e tests
# =============================================================================

@dataclass(frozen=True)
class T10Result:
    canvas: np.ndarray              # 48x48 RGB uint8
    grid: np.ndarray                # 16x16 uint8 in 0..3
    quarters: tuple[int, int, int, int]    # 4 Field elements
    hi: int                          # uint256
    lo: int                          # uint256


def compute_t10(
    per_slot_bytes: list[bytes],
    kinds: list[int],
    poses: list[int],
    slot_dims_wh: list[tuple[int, int]],
    slot_max_dims_wh: list[tuple[int, int]],
) -> T10Result:
    canvas = composite_canvas(per_slot_bytes, kinds, poses, slot_dims_wh, slot_max_dims_wh)
    quarters = t10_compute(canvas)
    hi, lo = quarters_to_hi_lo(quarters)
    grid = np.zeros((16, 16), dtype=np.uint8)
    for by in range(16):
        for bx in range(16):
            cell_idx = by * 16 + bx
            grid[by, bx] = (quarters[cell_idx // 64] >> ((cell_idx % 64) * 2)) & 0x3
    return T10Result(canvas=canvas, grid=grid, quarters=quarters, hi=hi, lo=lo)


# =============================================================================
# Self-test: compute alice0 T10 from the canonical mint pipeline and confirm
# (a) round-trip pack/unpack, (b) decode-from-hi-lo matches grid.
# =============================================================================

if __name__ == "__main__":
    import json
    from mint_decrypt import (
        decrypt_mint_envelope, unpack_fields_to_recolored, split_into_regions,
    )

    ROOT = REPO.parent
    ALICE = ROOT / "contracts" / "test" / "fixtures" / "mint_shadow" / "alice0"
    pi_bytes = (ALICE / "public_inputs").read_bytes()
    pi = [int.from_bytes(pi_bytes[i*32:(i+1)*32], "big") for i in range(17)]
    c2_bytes = (ALICE / "c2.bin").read_bytes()
    c2 = [int.from_bytes(c2_bytes[i*32:(i+1)*32], "big") for i in range(249)]
    fix = json.loads((ALICE / "fixture.json").read_text())
    sk = int(fix["witness"]["recipient_sk"], 16)

    plaintext_packed = decrypt_mint_envelope(
        recipient_sk=sk, c1_x=pi[12], c1_y=pi[13], c2=c2,
    )
    concat = unpack_fields_to_recolored(plaintext_packed)
    regions = list(split_into_regions(concat))

    # Decode boxes_packed into per-slot (x, y, w, h)
    boxes_packed = pi[9]
    poses = []
    dims_wh = []
    for i in range(8):
        sd = (boxes_packed >> (24 * i)) & 0xFFFFFF
        x = sd & 0x3F; y = (sd >> 6) & 0x3F
        w = (sd >> 12) & 0x3F; h = (sd >> 18) & 0x3F
        # Identity pose (no rotation, unit scale)
        poses.append((x & 0x3F) | ((y & 0x3F) << 6) | (256 << 12))
        dims_wh.append((w, h))

    # Pad to 16 slots: 8 ORIGINAL + 8 EMPTY.
    per_slot = list(regions) + [b""] * 8
    kinds = [SLOT_KIND_ORIGINAL] * 8 + [SLOT_KIND_EMPTY] * 8
    poses_full = list(poses) + [0] * 8
    dims_full = list(dims_wh) + [(0, 0)] * 8
    max_dims = [(REGION_W[i], REGION_H[i]) for i in range(8)] + [(0, 0)] * 8

    print(f"alice0 mint state, computing T10:")
    print(f"  poses     : {[hex(p)[:14] for p in poses]}")
    print(f"  dims_wh   : {dims_wh}")

    res = compute_t10(per_slot, kinds, poses_full, dims_full, max_dims)
    print(f"  shadow_q0 : 0x{res.quarters[0]:032x}")
    print(f"  shadow_q1 : 0x{res.quarters[1]:032x}")
    print(f"  shadow_q2 : 0x{res.quarters[2]:032x}")
    print(f"  shadow_q3 : 0x{res.quarters[3]:032x}")
    print(f"  shadowHi  : 0x{res.hi:064x}")
    print(f"  shadowLo  : 0x{res.lo:064x}")

    # Round-trip: decode hi_lo back to grid, assert equal.
    decoded = hi_lo_to_grid(res.hi, res.lo)
    assert (decoded == res.grid).all(), "hi/lo decode mismatch"
    print(f"  grid round-trip: OK")

    # Print the 16x16 grid as 4-level chars for quick eyeball.
    chars = ".-+#"
    print(f"\n  T10 grid:")
    for row in res.grid:
        print("    " + "".join(chars[v] for v in row))

    # Also save a PNG of the canvas + grid.
    try:
        from PIL import Image
        out_dir = ROOT / "runs" / "t10_self_test"
        out_dir.mkdir(parents=True, exist_ok=True)
        Image.fromarray(res.canvas).save(out_dir / "alice0_canvas.png")
        Image.fromarray(grid_to_grayscale_image(res.grid, scale=24)).save(out_dir / "alice0_t10.png")
        print(f"\n  wrote {out_dir / 'alice0_canvas.png'}")
        print(f"  wrote {out_dir / 'alice0_t10.png'}")
    except ImportError:
        pass

    # Also test manifest_hash:
    feature_ids = [0] * 16  # ORIGINAL slots have feature_id = 0 in our convention
    mh = manifest_hash(kinds, poses_full, feature_ids)
    print(f"\n  manifest_hash : 0x{mh:064x}")
