"""Integer fixed-point inference — bit-exact match to the Noir circuit.

Mirrors the exact arithmetic in test_pipeline/circuits/landmark_face/src/main.nr:
  - Pixels scaled [0,255] -> [0,1000] via integer division
  - Conv2d with stride=2, padding=1 (iy = oy*2+ky-1, bounds check)
  - acc = acc // scale + bias  (integer division, truncation)
  - x^2 activation: acc = acc * acc // scale
  - Global avg pool: sum // (H*W)
  - Linear(16 -> 10): raw = raw // scale + fc_bias
  - Clamp to [0, scale], then coord = v * 48 // scale
"""

import json
import numpy as np


def _idiv(a, b):
    """Integer division with C/Rust/Noir semantics: truncate toward zero.
    Python '//' floors toward -inf; Noir i64 '/' truncates toward zero.
    These differ when dividend and divisor have opposite signs.
    """
    q = a // b
    if (a % b != 0) and ((a < 0) != (b < 0)):
        q += 1
    return q


def fixed_point_landmarks(img_rgb, weights):
    """Input: 48x48x3 uint8 RGB. Output: [(x, y), ...] 5 landmark pairs."""
    scale = weights["scale"]
    channels = weights["channels"]
    img_size = weights["img_size"]

    # Scale pixels: [0,255] -> [0,1000]
    pixels = img_rgb.transpose(2, 0, 1).flatten().astype(np.int64)
    scaled = np.array([_idiv(int(p) * scale, 255) for p in pixels], dtype=np.int64)

    prev = scaled
    prev_h = img_size
    spatial = [img_size // 2, img_size // 4, img_size // 8, img_size // 16]

    for li, ch_out in enumerate(channels):
        ch_in = 3 if li == 0 else channels[li - 1]
        oh = ow = spatial[li]
        w = np.array(weights[f"conv{li}_weight"], dtype=np.int64).flatten()
        b = np.array(weights[f"conv{li}_bias"], dtype=np.int64).flatten()
        out = np.zeros(ch_out * oh * ow, dtype=np.int64)
        for oc in range(ch_out):
            for oy in range(oh):
                for ox in range(ow):
                    acc = 0
                    for ic in range(ch_in):
                        for ky in range(4):
                            for kx in range(4):
                                iy = oy * 2 + ky - 1  # padding=1 offset
                                ix = ox * 2 + kx - 1
                                if 0 <= iy < prev_h and 0 <= ix < prev_h:
                                    pi = ic * prev_h * prev_h + iy * prev_h + ix
                                    wi = oc * ch_in * 16 + ic * 16 + ky * 4 + kx
                                    acc += int(prev[pi]) * int(w[wi])
                    acc = _idiv(int(acc), scale) + int(b[oc])
                    acc = _idiv(int(acc) * int(acc), scale)  # x^2
                    out[oc * oh * ow + oy * ow + ox] = acc
        prev = out
        prev_h = oh

    # Global average pool
    last_ch = channels[-1]
    last_spatial_sq = spatial[-1] * spatial[-1]
    pooled = np.zeros(last_ch, dtype=np.int64)
    for c in range(last_ch):
        pooled[c] = _idiv(int(np.sum(prev[c * last_spatial_sq:(c + 1) * last_spatial_sq])), last_spatial_sq)

    # Linear(16 -> 10)
    fc_w = np.array(weights["fc_weight"], dtype=np.int64).flatten()
    fc_b = np.array(weights["fc_bias"], dtype=np.int64).flatten()
    raw = np.zeros(10, dtype=np.int64)
    for out_i in range(10):
        acc = np.int64(0)
        for c in range(last_ch):
            acc += pooled[c] * fc_w[out_i * last_ch + c]
        raw[out_i] = _idiv(int(acc), scale) + int(fc_b[out_i])

    # Clamp [0, scale] and scale to pixel coords [0, 48]
    coords = np.zeros(10, dtype=np.int64)
    for i in range(10):
        v = raw[i]
        if v < 0:
            v = 0
        if v > scale:
            v = scale
        coords[i] = _idiv(int(v) * 48, scale)

    return [(int(coords[i * 2]), int(coords[i * 2 + 1])) for i in range(5)]


def fixed_point_regions(img_rgb, weights):
    """Bit-exact mirror of test_pipeline/circuits/landmark_face_v3/src/main.nr.

    Returns a tuple (regions, regions_packed):
      regions[i]      = (cx, cy) for region i in 0..7
      regions_packed  = single int holding 16 coords x 6 bits
                        (matches the circuit's regions_packed Field output)

    Region indices: 0 forehead, 1 left_eye, 2 right_eye, 3 nose,
                    4 left_cheek, 5 right_cheek, 6 mouth, 7 chin
    Centers are clamped to [0, 47] (same policy as the circuit).
    """
    lm = fixed_point_landmarks(img_rgb, weights)  # 5 (x, y) tuples
    # YuNet order: lm[0]=right_eye, lm[1]=left_eye, lm[2]=nose,
    #              lm[3]=right_mouth, lm[4]=left_mouth
    lm0x, lm0y = lm[0]
    lm1x, lm1y = lm[1]
    lm2x, lm2y = lm[2]
    lm3x, lm3y = lm[3]
    lm4x, lm4y = lm[4]

    raw_centers = [
        # 0 forehead
        ((lm0x + lm1x) // 2, min(lm0y, lm1y) - 8),
        # 1 left_eye  (lm0 pass-through)
        (lm0x, lm0y),
        # 2 right_eye (lm1 pass-through)
        (lm1x, lm1y),
        # 3 nose      (lm2 pass-through)
        (lm2x, lm2y),
        # 4 left_cheek
        (lm0x - 2, (lm0y + lm3y) // 2),
        # 5 right_cheek
        (lm1x + 2, (lm1y + lm4y) // 2),
        # 6 mouth
        ((lm3x + lm4x) // 2, (lm3y + lm4y) // 2),
        # 7 chin
        ((lm3x + lm4x) // 2, max(lm3y, lm4y) + 6),
    ]

    # Clamp each coord to [0, 47] for 6-bit packing
    clamped = [(max(0, min(47, cx)), max(0, min(47, cy))) for (cx, cy) in raw_centers]

    # Pack 16 coords (8 pairs) x 6 bits each = 96 bits LSB-first
    packed = 0
    for i, (cx, cy) in enumerate(clamped):
        packed |= (cx & 0x3F) << (i * 12)         # x at bit i*12
        packed |= (cy & 0x3F) << (i * 12 + 6)     # y at bit i*12 + 6
    return clamped, packed


def unpack_regions(regions_packed):
    """Inverse of the circuit's packing. Returns list of 8 (cx, cy) tuples."""
    out = []
    for i in range(8):
        cx = (regions_packed >> (i * 12)) & 0x3F
        cy = (regions_packed >> (i * 12 + 6)) & 0x3F
        out.append((cx, cy))
    return out



if __name__ == "__main__":
    import sys, cv2
    from pathlib import Path
    W = json.load(open(Path(__file__).resolve().parent / "weights/landmark_v3_5point.json"))
    img = cv2.imread(sys.argv[1] if len(sys.argv) > 1
                     else str(Path(__file__).resolve().parents[2] / "examples/faces/alice0.png"))
    rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    print(fixed_point_landmarks(rgb, W))
