"""v5 geometry: per-face proportional region boxes, integer-only.

Canonical Python reference for the Noir mint v2 circuit. All arithmetic is
pure integer with HALF-UP rounding (round half away from zero); no floats,
no Python `int(round(.))` (which is banker's, would diverge from the circuit
at exact .5 inputs).

Two scale measurements per face:
  IOD = |lm[1].x - lm[0].x|             (inter-ocular distance, horizontal)
  EMD = mouth_mid_y - eye_mid_y         (eye-to-mouth distance, vertical)

Box widths and heights are integer fractions of IOD or EMD. Close-up faces
get bigger boxes; far-away faces get smaller boxes. Anatomical coverage is
preserved at every face scale.

Base proportions (calibrated against a typical LFW face IOD=13, EMD=13):
  forehead    1.6  IOD x 0.45 EMD
  eye         0.7  IOD x 0.40 EMD   (each)
  nose        0.5  IOD x 0.55 EMD
  cheek       0.3  IOD x 0.95 EMD   (tall vertical strip)
  mouth       1.1  IOD x 0.45 EMD
  chin        1.4  IOD x 0.40 EMD

Widths are also clamped at the 48 px image dimension so the geometry never
asks the circuit to extract more pixels than the image holds.

Y-budget: the five stacked regions (forehead, eyes, nose, mouth, chin) plus
gap math must fit in <=44 rows of the 48 px image. When their unscaled sum
exceeds 44, every height (including cheek, even though cheek is excluded
from the sum) is multiplied by 44/stacked. This shrinks the whole face's
vertical proportions uniformly while leaving the cheek strip's relative
height tied to the rest.

Cap-free design: IOD and EMD are clamped to [4, 47] only. The circuit has
no IOD_CAP / EMD_CAP module constants; max region buffer sizes are derived
from the worst-case sweep of IOD,EMD in [4, 47]^2 (computed by
`max_region_dims()` in this module). Max total: 2572 pixels = 7716 bytes
= 250 packed Fields.

Design source of truth lives in `MAX_REGION_DIMS` below; the circuit
generator imports them.
"""

from __future__ import annotations

REGION_NAMES = ["forehead", "left_eye", "right_eye", "nose",
                "left_cheek", "right_cheek", "mouth", "chin"]


# Maximum (w, h) per region across IOD,EMD in [4, 47]^2.
# Derived once; circuit generator imports this. See `max_region_dims()`.
MAX_REGION_DIMS = {
    "forehead":    (48,  9),
    "left_eye":    (33,  8),
    "right_eye":   (33,  8),
    "nose":        (24, 11),
    "left_cheek":  (14, 19),
    "right_cheek": (14, 19),
    "mouth":       (48,  9),
    "chin":        (48,  8),
}

# Ordered (W_max, H_max) pairs in REGION_NAMES order.
MAX_W = [MAX_REGION_DIMS[n][0] for n in REGION_NAMES]
MAX_H = [MAX_REGION_DIMS[n][1] for n in REGION_NAMES]
MAX_REGION_BYTES = sum(W * H * 3 for W, H in zip(MAX_W, MAX_H))   # 7716
PACKED_FIELDS = (MAX_REGION_BYTES + 30) // 31                     # 250
TAIL_BYTES = MAX_REGION_BYTES - 31 * (PACKED_FIELDS - 1)          # 6


def round_half_up(num: int, denom: int) -> int:
    """Half-up integer division: round(num/denom) toward +infinity at .5.

    Matches Noir integer math `(num + denom/2) / denom`.

    Both `num` and `denom` must be non-negative, `denom > 0`. The v5
    geometry never produces signed-divisions because all dimensions are
    derived from non-negative landmark coordinates and positive factor
    constants.
    """
    if denom <= 0:
        raise ValueError(f"denom must be positive, got {denom}")
    if num < 0:
        # geometry never hits this; fail loudly
        raise ValueError(f"num must be non-negative, got {num}")
    return (num + denom // 2) // denom


def v5_boxes(lm):
    """Compute 8 region boxes from 5 (x, y) landmark integer pairs.

    Input:  lm = [(eye_l_x, eye_l_y), (eye_r_x, eye_r_y), (nose_x, nose_y),
                  (mouth_l_x, mouth_l_y), (mouth_r_x, mouth_r_y)]
            All coords are integers in [0, 47].

    Output: list of (name, x1, y1, w, h) tuples in REGION_NAMES order.
            x1, y1 in [0, 48); w, h in [3, 48]; (x1+w) <= 48 and (y1+h) <= 48.
    """
    eye_mid_x   = (lm[0][0] + lm[1][0]) // 2
    mouth_mid_x = (lm[3][0] + lm[4][0]) // 2
    eye_mid_y   = (lm[0][1] + lm[1][1]) // 2
    mouth_mid_y = (lm[3][1] + lm[4][1]) // 2

    # Face-scale measurements (lower bound 4 prevents degenerate dims)
    IOD = max(4, abs(lm[1][0] - lm[0][0]))
    EMD = max(4, mouth_mid_y - eye_mid_y)

    # ---- Stage 1: desired heights (pre Y-budget) ----
    fh_des    = max( 4, round_half_up(EMD * 45, 100))
    eye_des   = max( 4, round_half_up(EMD * 40, 100))
    nose_des  = max( 4, round_half_up(EMD * 55, 100))
    cheek_des = max( 6, round_half_up(EMD * 95, 100))
    mouth_des = max( 4, round_half_up(EMD * 45, 100))
    chin_des  = max( 4, round_half_up(EMD * 40, 100))

    # ---- Stage 2: Y-budget (stacked sum excludes cheek but cheek IS scaled) ----
    stacked = fh_des + eye_des + nose_des + mouth_des + chin_des
    if stacked <= 44:
        fh_h, eye_h, nose_h, cheek_h, mouth_h, chin_h = (
            fh_des, eye_des, nose_des, cheek_des, mouth_des, chin_des)
    else:
        fh_h    = round_half_up(fh_des    * 44, stacked)
        eye_h   = round_half_up(eye_des   * 44, stacked)
        nose_h  = round_half_up(nose_des  * 44, stacked)
        cheek_h = round_half_up(cheek_des * 44, stacked)
        mouth_h = round_half_up(mouth_des * 44, stacked)
        chin_h  = round_half_up(chin_des  * 44, stacked)
    fh_h    = max(3, fh_h)
    eye_h   = max(4, eye_h)
    nose_h  = max(4, nose_h)
    cheek_h = max(6, cheek_h)
    mouth_h = max(3, mouth_h)
    chin_h  = max(3, chin_h)

    # ---- Stage 3: widths (independent of Y-budget; clamp to 48) ----
    fh_w     = min(48, max(10, round_half_up(IOD * 16, 10)))
    eye_w    = max( 4, round_half_up(IOD *  7, 10))
    nose_w   = max( 4, round_half_up(IOD *  5, 10))
    cheek_w  = max( 3, round_half_up(IOD *  3, 10))
    mouth_w  = min(48, max( 8, round_half_up(IOD * 11, 10)))
    chin_w   = min(48, max( 9, round_half_up(IOD * 14, 10)))

    # Auto-shrink eye width if eyes are very close (preserves non-overlap)
    eye_sep = abs(lm[1][0] - lm[0][0])
    eye_w = max(4, min(eye_w, eye_sep - 1))

    # ---- Stage 4: raw cy (anatomy-tracking) ----
    fh_cy_raw    = min(lm[0][1], lm[1][1]) - max(4, round_half_up(EMD * 55, 100))
    eye_cy_raw   = eye_mid_y
    nose_cy_raw  = lm[2][1]
    mouth_cy_raw = mouth_mid_y
    chin_cy_raw  = max(lm[3][1], lm[4][1]) + max(3, round_half_up(EMD * 35, 100))

    def gap(prev_h, next_h):
        return (prev_h - prev_h // 2) + next_h // 2

    # ---- Stage 5: top-down vertical spacing (touching, non-overlapping) ----
    fh_cy   = max(fh_h // 2, fh_cy_raw)
    eye_cy  = max(eye_cy_raw,  fh_cy   + gap(fh_h, eye_h))
    nose_cy = max(nose_cy_raw, eye_cy  + gap(eye_h, nose_h))
    cheek_cy = eye_cy + gap(eye_h, cheek_h)
    mouth_cy = max(mouth_cy_raw, nose_cy + gap(nose_h, mouth_h))
    chin_cy  = max(chin_cy_raw,
                   cheek_cy + gap(cheek_h, chin_h),
                   mouth_cy + gap(mouth_h, chin_h))

    # ---- Stage 6: cheek x with nose+mouth clearance ----
    nose_x_left   = lm[2][0] - nose_w // 2
    nose_x_right  = lm[2][0] - nose_w // 2 + nose_w
    mouth_x_left  = mouth_mid_x - mouth_w // 2
    mouth_x_right = mouth_mid_x - mouth_w // 2 + mouth_w
    cheek_outboard_offset = max(4, round_half_up(IOD * 30, 100))

    left_max = min(nose_x_left, mouth_x_left) - (cheek_w - cheek_w // 2)
    left_cheek_cx = min(lm[0][0] - cheek_outboard_offset, left_max)
    left_cheek_cx = max(cheek_w // 2, left_cheek_cx)

    right_min = max(nose_x_right, mouth_x_right) + cheek_w // 2
    right_cheek_cx = max(lm[1][0] + cheek_outboard_offset, right_min)
    right_cheek_cx = min(48 - (cheek_w - cheek_w // 2), right_cheek_cx)

    specs = [
        ("forehead",    fh_w,    fh_h,    (eye_mid_x,        fh_cy)),
        ("left_eye",    eye_w,   eye_h,   (lm[0][0],         eye_cy)),
        ("right_eye",   eye_w,   eye_h,   (lm[1][0],         eye_cy)),
        ("nose",        nose_w,  nose_h,  (lm[2][0],         nose_cy)),
        ("left_cheek",  cheek_w, cheek_h, (left_cheek_cx,    cheek_cy)),
        ("right_cheek", cheek_w, cheek_h, (right_cheek_cx,   cheek_cy)),
        ("mouth",       mouth_w, mouth_h, (mouth_mid_x,      mouth_cy)),
        ("chin",        chin_w,  chin_h,  (mouth_mid_x,      chin_cy)),
    ]
    out = []
    for name, w, h, (cx, cy) in specs:
        x1 = max(0, min(48 - w, cx - w // 2))
        y1 = max(0, min(48 - h, cy - h // 2))
        out.append((name, x1, y1, w, h))
    by_name = {b[0]: b for b in out}
    return [by_name[n] for n in REGION_NAMES]


def max_region_dims():
    """Re-derive MAX_REGION_DIMS by sweeping IOD,EMD in [4, 47]^2.

    Useful for verifying the hard-coded `MAX_REGION_DIMS` table above
    after factor edits. Do not call from hot paths.
    """
    maxes = {n: (0, 0) for n in REGION_NAMES}
    for iod in range(4, 48):
        for emd in range(4, 48):
            # synthesize landmarks that yield this IOD, EMD
            eye_y = 20
            mouth_y = eye_y + emd
            cx = 24
            half = iod // 2
            lm = [
                (cx - half,     eye_y),     # left eye
                (cx - half + iod, eye_y),   # right eye (forces exact IOD)
                (cx,            (eye_y + mouth_y) // 2),   # nose
                (cx - 4,        mouth_y),   # left mouth
                (cx + 4,        mouth_y),   # right mouth
            ]
            for name, _, _, w, h in v5_boxes(lm):
                maxes[name] = (max(maxes[name][0], w), max(maxes[name][1], h))
    return maxes


if __name__ == "__main__":
    derived = max_region_dims()
    print("Derived max dims (IOD,EMD sweep [4, 47]):")
    total = 0
    for n in REGION_NAMES:
        w, h = derived[n]
        px = w * h
        total += px
        canon_w, canon_h = MAX_REGION_DIMS[n]
        ok = "OK" if (w, h) == (canon_w, canon_h) else f"MISMATCH (canon: {canon_w}x{canon_h})"
        print(f"  {n:12s}  {w:2d}x{h:2d}  px={px}  {ok}")
    print(f"  total pixels: {total}")
    print(f"  total bytes:  {total * 3}")
    print(f"  fields (31B): {(total * 3 + 30) // 31}")
    print(f"  module:       MAX_REGION_BYTES={MAX_REGION_BYTES} PACKED_FIELDS={PACKED_FIELDS} TAIL={TAIL_BYTES}")
