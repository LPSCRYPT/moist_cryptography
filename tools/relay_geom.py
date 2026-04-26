"""Per-feature pack/unpack and Poseidon2 helpers shared across the Python harness.

Imported by:
  - mint_pipeline.py            -- builds shadow plaintext + state commits at mint
  - build_solve_fixture.py      -- regenerates the per-region recolored bytes for solve PI
  - build_landmark_mint_fixture.py (transitively, via mint_pipeline)

This file is the single source of truth for:
  - per-feature MAX_W / MAX_H / MAX_BYTES / packed-Field count (K_i)
  - byte<->Field packing (31 bytes/Field LSB-first)
  - canonical pixelCommit (sponge_K_i over recolored fields)
  - canonical stateCommit (sponge_11 over face_origin_id, type, color, w, h, pose, pixel_commit)

Bit-equivalent to the in-circuit Noir helpers under circuits/landmark_regions/
and circuits/solve_shadow/. Any change here MUST be mirrored in those circuits
(and vice versa) or fixture-build will diverge from on-chain verification.
----------------------------------------------------------------------
Per-feature geometry (v5 IOD/EMD-proportional, max bounds from sweep
over IOD,EMD in [4,47]^2):

|i|name        |MAX_W|MAX_H|MAX_BYTES|K_i (packed Fields)|
|-|------------|----:|----:|--------:|------------------:|
|0|forehead    |   48|    9|     1296|                42 |
|1|left_eye    |   33|    8|      792|                26 |
|2|right_eye   |   33|    8|      792|                26 |
|3|nose        |   24|   11|      792|                26 |
|4|left_cheek  |   14|   19|      798|                26 |
|5|right_cheek |   14|   19|      798|                26 |
|6|mouth       |   48|    9|     1296|                42 |
|7|chin        |   48|    8|     1152|                38 |

Per-face actual (w_i, h_i) <= (MAX_W_i, MAX_H_i) and is computed in
mint from CNN landmarks. The packed-Field count K_i is fixed per
featureType (independent of actual runtime w, h) so commits are
verifiable without the contract knowing runtime dims.

----------------------------------------------------------------------
Canonical pixelCommit (post-recolor, shared with all 4 circuits):

    pixelCommit_i = poseidon2_sponge_K_i(packed_recolored_fields_i)

where `packed_recolored_fields_i` is the per-feature post-recolor byte
buffer packed 31 bytes/Field LSB-first. K_i = PACKED_COUNTS[i].
Bytes [w*h*3 .. K_i*31-1] are zero (asserted by byte-padding asserts
in-circuit). Tail Fields beyond K_i are also zero (asserted).

----------------------------------------------------------------------
Canonical stateCommit (post-recolor, sponge_11):

    stateCommit_i = poseidon2_sponge_11(
        faceOriginId,
        featureType,
        color,
        cur_x,
        cur_y,
        cur_w,
        cur_h,
        cur_scale_q88,
        cur_cos_q15_u16,
        cur_sin_q15_u16,
        pixel_commit_i,
    )

`cur_w, cur_h` are immutable post-mint (set by mint based on per-face
IOD/EMD). All ops (TRANSLATE, SCALE, ROTATE) preserve them.
"""

from __future__ import annotations

import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from secret_inbox import poseidon2_state  # type: ignore  # noqa: E402

# ---------- Constants ----------

# Per-feature max W, H. Actual per-face (w, h) <= (MAX_W_i, MAX_H_i).
REGION_W: list[int] = [48, 33, 33, 24, 14, 14, 48, 48]
REGION_H: list[int] = [ 9,  8,  8, 11, 19, 19,  9,  8]

# Per-feature packed Field counts. K_i = ceil(MAX_W_i * MAX_H_i * 3 / 31).
PACKED_COUNTS: list[int] = [42, 26, 26, 26, 26, 26, 42, 38]

# Per-feature byte capacity = K_i * 31 (== sponge input width in bytes).
PACKED_BYTES: list[int] = [k * 31 for k in PACKED_COUNTS]

BYTES_PER_FIELD: int = 31

# Buffer sizing.
#
# `MAX_BYTES = MAX_W * MAX_H * 3 = 2736` is the per-feature pixel buffer
# size in BOTH the Python ref and the Noir circuit. The buffer is
# intentionally wider than the largest meaningful feature data
# (forehead/mouth = 1296 bytes) so apply_pixel_op's iteration over
# (MAX_H, MAX_W) cells can write to either the COMPACT layout
# `(dy*w+dx)*3+c` (in-bounds) or the UNIFORM layout `(dy*MAX_W+dx)*3+c`
# (OOB) without ever indexing past the array end. OOB writes are no-ops by
# construction (they write the input byte value back). The pixel_commit
# only sponges the first K_i Fields (= K_i*31 bytes), so anything beyond
# byte K_i*31 is irrelevant to the on-chain commit.
MAX_W: int = 48        # max(REGION_W)
MAX_H: int = 19        # max(REGION_H)
MAX_BYTES: int = MAX_W * MAX_H * 3  # 2736

# Max packed Fields per feature (forehead/mouth = 42).
MAX_K: int = 42

# BN254 scalar field modulus.
FP: int = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# Op kinds (must match Noir + Solidity).
OP_TRANSLATE: int = 1
OP_SCALE: int = 2
OP_ROTATE: int = 3


# ---------- Packing ----------

def pack_feature_to_fields(feat_bytes: bytes, n_fields: int) -> list[int]:
    """Pack feature bytes into n_fields Fields, 31 bytes/Field LSB-first.
    Last Field may be partial; high bytes are zero."""
    fields: list[int] = []
    for i in range(n_fields):
        chunk = feat_bytes[i * BYTES_PER_FIELD:(i + 1) * BYTES_PER_FIELD]
        v = 0
        for j, b in enumerate(chunk):
            v |= int(b) << (8 * j)
        fields.append(v)
    return fields


def pad_to_max_k(packed: list[int]) -> list[int]:
    """Zero-pad a per-feature packed-Field list to MAX_K (= 42).
    The trailing Fields beyond K_i must be zero -- asserted in-circuit."""
    if len(packed) > MAX_K:
        raise ValueError(f"packed Field list longer than {MAX_K}: {len(packed)}")
    return packed + [0] * (MAX_K - len(packed))


def unpack_fields_to_bytes(fields: list[int], n_fields: int) -> bytes:
    """Inverse of pack_feature_to_fields. Returns the byte buffer
    (concatenated chunks of 31 bytes per Field, last possibly partial)."""
    out = bytearray()
    for f in fields[:n_fields]:
        out.extend(int(f).to_bytes(BYTES_PER_FIELD, "little"))
    return bytes(out)


def patch_to_max_layout(patch_hwc: bytes, w: int, h: int, ftype: int) -> bytes:
    """Lay out a compact (h, w, 3) row-major byte buffer at per-feature MAX-layout
    offsets. Output is REGION_W[ftype] * REGION_H[ftype] * 3 bytes; in-bounds
    positions copy from `patch_hwc`, OOB positions stay zero.

    Mirrors mint's region_orig_i layout (stride = REGION_W[ftype] * 3) so the
    resulting bytes, when packed via `pack_feature_to_fields`, produce the same
    Field representation that mint emits via sponge_K_i.
    """
    if not (0 <= ftype < 8):
        raise ValueError(f"ftype out of range: {ftype}")
    if len(patch_hwc) != w * h * 3:
        raise ValueError(f"patch length {len(patch_hwc)} != w*h*3 = {w * h * 3}")
    mw = REGION_W[ftype]
    mh = REGION_H[ftype]
    if w > mw or h > mh:
        raise ValueError(f"(w, h) = ({w}, {h}) exceeds MAX = ({mw}, {mh}) for ftype {ftype}")
    out = bytearray(mw * mh * 3)
    for dy in range(h):
        for dx in range(w):
            src_base = (dy * w + dx) * 3
            dst_base = (dy * mw + dx) * 3
            out[dst_base + 0] = patch_hwc[src_base + 0]
            out[dst_base + 1] = patch_hwc[src_base + 1]
            out[dst_base + 2] = patch_hwc[src_base + 2]
    return bytes(out)


# ---------- Poseidon2 sponge ----------

def poseidon2_sponge(elems: list[int]) -> int:
    """Rate-3 sponge with sentinel padding -- matches Noir sponge_N functions."""
    state = [0, 0, 0, 0]
    n = len(elems)
    full = n // 3
    rem = n % 3
    for b in range(full):
        state[0] = (state[0] + elems[b * 3 + 0]) % FP
        state[1] = (state[1] + elems[b * 3 + 1]) % FP
        state[2] = (state[2] + elems[b * 3 + 2]) % FP
        state = list(poseidon2_state(*state))
    if rem == 0:
        state[0] = (state[0] + 1) % FP
    elif rem == 1:
        state[0] = (state[0] + elems[full * 3]) % FP
        state[1] = (state[1] + 1) % FP
    else:
        state[0] = (state[0] + elems[full * 3 + 0]) % FP
        state[1] = (state[1] + elems[full * 3 + 1]) % FP
        state[2] = (state[2] + 1) % FP
    state = list(poseidon2_state(*state))
    return state[0]


def poseidon2_h2(x: int, y: int) -> int:
    """Poseidon2([x, y, 0, 0])[0] -- matches Noir poseidon2_hash_2."""
    return poseidon2_state(x, y, 0, 0)[0]


def poseidon2_keystream(k: int, n: int) -> list[int]:
    """n-Field Poseidon2-CTR keystream; matches Noir poseidon2_keystream_N.
    Each block produces 3 Fields via Poseidon2(k, b, 0, 0); blocks numbered
    from 0; we take the first 3 outputs of each block until n Fields are
    accumulated."""
    ks: list[int] = []
    b = 0
    while len(ks) < n:
        block = poseidon2_state(k, b, 0, 0)
        for j in range(3):
            if len(ks) < n:
                ks.append(block[j])
        b += 1
    return ks


def poseidon2_keystream_25(k: int) -> list[int]:
    """Legacy alias for the 25-Field keystream used by the v1 ECIES envelope.
    Kept so existing consumers don't break. New code should call
    poseidon2_keystream(k, n) directly."""
    return poseidon2_keystream(k, 25)


# ---------- Canonical commits ----------

def pixel_commit_for_type(feature_type: int, packed_padded: list[int]) -> int:
    """sponge_K_i(packed_padded[:K_i]) where K_i = PACKED_COUNTS[feature_type].
    Bytes beyond w*h*3 in the meaningful Fields must be zero (asserted in-circuit).
    Trailing Fields beyond K_i must be zero (asserted in-circuit)."""
    if feature_type < 0 or feature_type > 7:
        raise ValueError(f"feature_type out of range: {feature_type}")
    K = PACKED_COUNTS[feature_type]
    if len(packed_padded) < K:
        raise ValueError(f"packed buffer shorter than K_i={K}: {len(packed_padded)}")
    return poseidon2_sponge(packed_padded[:K])


def state_commit(face_origin_id: int, feature_type: int, color: int,
                 cur_x: int, cur_y: int,
                 cur_w: int, cur_h: int,
                 cur_scale_q88: int,
                 cur_cos_q15_u16: int, cur_sin_q15_u16: int,
                 pixel_commit: int) -> int:
    """Canonical sponge_11 stateCommit. cur_w, cur_h are runtime-per-face
    (set at mint from IOD/EMD, immutable post-mint). cos/sin pass as raw u16
    bit pattern (Noir disallows signed-to-Field cast)."""
    return poseidon2_sponge([
        face_origin_id, feature_type, color,
        cur_x, cur_y, cur_w, cur_h,
        cur_scale_q88, cur_cos_q15_u16, cur_sin_q15_u16,
        pixel_commit,
    ])


# ---------- Op application (Python ref of Noir apply_*_op) ----------

def trunc_div(a: int, b: int) -> int:
    """C-style integer division: rounds toward zero. Matches Noir's `/` on signed i64."""
    q = abs(a) // abs(b)
    if (a < 0) != (b < 0):
        q = -q
    return q


def clamp(v: int, lo: int, hi: int) -> int:
    return lo if v < lo else (hi if v > hi else v)


def apply_box_op(op_kind: int, op_params: int,
                 prev_x: int, prev_y: int,
                 w: int, h: int) -> tuple[int, int]:
    """TRANSLATE: clamp((prev + dx/dy), 0, 48 - W/H). SCALE/ROTATE: identity.
    `w, h` are the per-face actual feature dims (not the MAX_W/MAX_H box)."""
    pbytes = (op_params & 0xFFFFFFFF).to_bytes(4, "little")
    dx_raw = pbytes[0]
    dy_raw = pbytes[1]
    dx = dx_raw - 256 if dx_raw >= 128 else dx_raw
    dy = dy_raw - 256 if dy_raw >= 128 else dy_raw
    max_x = 48 - w
    max_y = 48 - h
    new_x = clamp(prev_x + dx, 0, max_x)
    new_y = clamp(prev_y + dy, 0, max_y)
    if op_kind == OP_TRANSLATE:
        return (new_x, new_y)
    return (prev_x, prev_y)


def apply_pixel_op(op_kind: int, op_params: int, pixels: bytes,
                   w: int, h: int, mw: int) -> bytes:
    """Apply identity (TRANSLATE) / scale / rotate to the per-feature MAX_BYTES
    buffer in MAX-layout. Iterates (MAX_H, MAX_W); writes only when in_bounds
    (dx < w and dy < h); out-of-bounds positions stay at their input values.

    Layout: byte at MAX-layout offset (dy * mw + dx) * 3 + c, where mw =
    REGION_W[ftype]. Source and destination indexing both use mw.

    For SCALE: nearest-neighbor resample, src = (out_centered * 256) / scale.
    For ROTATE: nearest-neighbor resample, src = R(-theta) * out_centered.
    """
    if len(pixels) != MAX_BYTES:
        raise ValueError(f"expected {MAX_BYTES}-byte buffer, got {len(pixels)}")
    out = bytearray(pixels)
    pbytes = (op_params & 0xFFFFFFFF).to_bytes(4, "little")

    scale_raw = pbytes[0] + 256 * pbytes[1]
    scale_div = scale_raw if scale_raw != 0 else 256

    cos_raw = pbytes[0] + 256 * pbytes[1]
    sin_raw = pbytes[2] + 256 * pbytes[3]
    cos_q15 = cos_raw - 65536 if cos_raw >= 32768 else cos_raw
    sin_q15 = sin_raw - 65536 if sin_raw >= 32768 else sin_raw

    half_w = w // 2
    half_h = h // 2

    for dy in range(MAX_H):
        for dx in range(MAX_W):
            in_bounds = (dx < w) and (dy < h)

            dxc = dx - half_w
            dyc = dy - half_h

            s_src_x = trunc_div(dxc * 256, scale_div) + half_w
            s_src_y = trunc_div(dyc * 256, scale_div) + half_h
            s_src_xc = clamp(s_src_x, 0, w - 1)
            s_src_yc = clamp(s_src_y, 0, h - 1)

            r_src_x = trunc_div(cos_q15 * dxc + sin_q15 * dyc, 32768) + half_w
            r_src_y = trunc_div(-sin_q15 * dxc + cos_q15 * dyc, 32768) + half_h
            r_src_xc = clamp(r_src_x, 0, w - 1)
            r_src_yc = clamp(r_src_y, 0, h - 1)

            for c in range(3):
                # MAX-layout indexing for both source and destination.
                dst_idx = (dy * mw + dx) * 3 + c
                scale_idx = (s_src_yc * mw + s_src_xc) * 3 + c
                rot_idx = (r_src_yc * mw + r_src_xc) * 3 + c

                if op_kind == OP_SCALE:
                    chosen = pixels[scale_idx]
                elif op_kind == OP_ROTATE:
                    chosen = pixels[rot_idx]
                else:
                    chosen = pixels[dst_idx]

                # In-bounds: write chosen. OOB: write pixels[dst_idx] back (no-op).
                if in_bounds:
                    out[dst_idx] = chosen
                else:
                    out[dst_idx] = pixels[dst_idx]

    return bytes(out)
