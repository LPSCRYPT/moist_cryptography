// shadow_t10 -- public T10 16x16 4-level grayscale shadow circuit.
//
// Restores the phase-1 "shadow" public artifact for phase-2's framed-shadow
// architecture. Outsiders read the on-chain T10 to see a degraded silhouette
// of the assembled face; only the owner with the recipient sk can decrypt
// c2 to see the full RGB.
//
// MVP scope (mutate-only):
//   - Slots 0..7 are ORIGINAL (bytes from shadow_plaintext at fixed offsets).
//   - Slots 8..15 are EMPTY (skipped).
//   - Insert/extract: deferred to v2.
//   - Scale_q88: must be a power of 2 in {32, 64, 128, 256, 512, 1024, 2048, 4096}
//     for exact integer inversion. The fixture builder enforces this.
//
// Public inputs (9 Fields):
//   PI[0]   shadow_id          (chain-level transcript binding only)
//   PI[1]   state_nonce        (chain-level transcript binding only)
//   PI[2]   prev_ct_commit     (sponge_249 of shadow's c2 -- binds plaintext)
//   PI[3]   boxes_packed       (8 * (x|y|w|h) at 6 bits each = 192 bits)
//   PI[4]   poses_hash         (sponge_18 over [16 current pose words, 0, 0])
//   PI[5..8] shadow_q0..q3     (the T10 bitmap; 4 * 128-bit fields)
//
// Private witness:
//   shadow_plaintext: [Field; 249]
//   shadow_prev_k:    Field
//   poses:            [Field; 16]    -- bound by poses_hash
//   pose_cx, pose_cy, pose_scale, pose_cos, pose_sin: per-slot decoded fields
//   pose_scale_inv: per-slot inverse-scale Q24 (= 2^24 / pose_scale)
//
// Algorithm: see tools/t10.py for canonical reference.

use std::hash::poseidon2_permutation;

global SHADOW_FIELDS: u32 = 249;
global SHADOW_BLOCKS: u32 = 83;

global REGION_W: [u32; 8] = [48, 33, 33, 24, 14, 14, 48, 48];
global REGION_H: [u32; 8] = [9, 8, 8, 11, 19, 19, 9, 8];
global REGION_OFFSETS: [u32; 8] = [0, 1296, 2088, 2880, 3672, 4470, 5268, 6564];

global CANVAS_W: u32 = 48;
global CANVAS_H: u32 = 48;

// ---------- Poseidon2 sponges ----------

fn sponge_249(e: [Field; 249]) -> Field {
    let mut s: [Field; 4] = [0, 0, 0, 0];
    for b in 0..SHADOW_BLOCKS {
        s[0] = s[0] + e[b * 3];
        s[1] = s[1] + e[b * 3 + 1];
        s[2] = s[2] + e[b * 3 + 2];
        s = poseidon2_permutation(s, 4);
    }
    s[0] = s[0] + 1;
    s = poseidon2_permutation(s, 4);
    s[0]
}

fn sponge_18(e: [Field; 18]) -> Field {
    // 18 = 6 full rate-3 blocks (multiple of 3, no tail). Sentinel=1 added
    // after final block. Yul-sponge compatible: same algorithm as the on-chain
    // Poseidon2YulSponge for inputs of length divisible by 3.
    let mut s: [Field; 4] = [0, 0, 0, 0];
    for b in 0..6 {
        s[0] = s[0] + e[b * 3];
        s[1] = s[1] + e[b * 3 + 1];
        s[2] = s[2] + e[b * 3 + 2];
        s = poseidon2_permutation(s, 4);
    }
    s[0] = s[0] + 1; // sentinel after final full block
    s = poseidon2_permutation(s, 4);
    s[0]
}

fn keystream_249(k: Field) -> [Field; 249] {
    let mut ks: [Field; 249] = [0; 249];
    for b in 0..SHADOW_BLOCKS {
        let block = poseidon2_permutation([k, b as Field, 0, 0], 4);
        ks[b * 3]     = block[0];
        ks[b * 3 + 1] = block[1];
        ks[b * 3 + 2] = block[2];
    }
    ks
}

// ---------- Plaintext unpack ----------

fn unpack_shadow_bytes(plaintext: [Field; 249]) -> [u8; 7719] {
    let mut out: [u8; 7719] = [0; 7719];
    for f_idx in 0..SHADOW_FIELDS {
        let chunk: [u8; 31] = plaintext[f_idx].to_le_bytes();
        for j in 0..31 {
            out[f_idx * 31 + j] = chunk[j];
        }
    }
    out
}

// ---------- Pose word -> raw fields ----------
//
// Pose layout (uint64):
//   bits  0.. 5  cx (6 bits)
//   bits  6..11  cy (6 bits)
//   bits 12..27  scale_q88 (16 bits, Q8.8; 256 = 1.0)
//   bits 28..43  cos_q15 (16 bits, Q1.15 signed; 32767 ~= 1.0)
//   bits 44..59  sin_q15 (16 bits, Q1.15 signed)
//   bits 60..63  unused
//
// Rather than decode in-circuit (expensive), we accept the unpacked
// components as private witness and assert they reassemble to the bound
// pose word. Cheaper.
fn assert_pose_decode(
    pose: Field,
    cx: u32, cy: u32, scale_q88: u32,
    cos_q15_u16: u32, sin_q15_u16: u32,
) {
    // Bound checks.
    assert(cx < 64);
    assert(cy < 64);
    assert(scale_q88 < (1 << 16));
    assert(cos_q15_u16 < (1 << 16));
    assert(sin_q15_u16 < (1 << 16));
    // Reassemble.
    let pow6  : Field = 64;
    let pow12 : Field = 4096;
    let pow28 : Field = 268435456;
    let pow44 : Field = 17592186044416;
    let recombined: Field =
          (cx as Field)
        + (cy as Field) * pow6
        + (scale_q88 as Field) * pow12
        + (cos_q15_u16 as Field) * pow28
        + (sin_q15_u16 as Field) * pow44;
    assert(recombined == pose);
}

// Sign-extend a u16 to i32 (2's complement).
fn u16_to_i32(v: u32) -> i32 {
    if v >= 0x8000 { (v as i32) - 0x10000 } else { v as i32 }
}

// ---------- Inverse-affine NEAREST-NEIGHBOUR for one slot ----------
//
// Maps canvas (cy, cx) -> source (sy, sx) for slot k under pose.
// All math integer; nearest-neighbour rounding.
//
// Forward (for reference):
//   src_centred_y = sy - h/2   (integer * 2 to avoid fractional)
//   src_centred_x = sx - w/2
//   rot_y = (cos * src_centred_y + sin * src_centred_x) >> 15  (Q1.15)
//   rot_x = (-sin * src_centred_y + cos * src_centred_x) >> 15
//   scaled_y = (rot_y * scale_q88) >> 8
//   scaled_x = (rot_x * scale_q88) >> 8
//   cy = cy_anchor + h/2 + scaled_y
//   cx = cx_anchor + w/2 + scaled_x
//
// Inverse:
//   dy = cy - cy_anchor - h/2  (integer * 2)
//   dx = cx - cx_anchor - w/2
//   inv_R @ (dy, dx) = ( cos*dy + sin*dx, -sin*dy + cos*dx)  (Q1.15)
//   div by scale (uses scale_inv_q24 = 2^24 / scale_q88, exact for power-of-2):
//   sy_q39 = (cos*dy + sin*dx) * scale_inv_q24                 (Q15+24 = Q39)
//   sx_q39 = (-sin*dy + cos*dx) * scale_inv_q24
//   sy = round(sy_q39 / 2^39) + h/2
//   sx = round(sx_q39 / 2^39) + w/2
//
// To handle h/2 with h possibly odd, we work with sy_2 = 2*sy throughout.

fn inv_affine_for_slot(
    cy: u32, cx: u32,
    cx_anchor: u32, cy_anchor: u32,
    w: u32, h: u32,
    cos_q15: i32, sin_q15: i32,
    scale_inv_q24: i64,
) -> (i64, i64, bool) {
    // Centre offsets in (sy_2, sx_2) space.
    let dy_2: i32 = (2 * (cy as i32)) - (2 * (cy_anchor as i32)) - (h as i32);
    let dx_2: i32 = (2 * (cx as i32)) - (2 * (cx_anchor as i32)) - (w as i32);

    // Rotated (Q1.15 result): max |cos|*|dy_2| <= 32767 * 96 ~= 3.1M, sum < 6.3M.
    let rot_y: i64 = (cos_q15 as i64) * (dy_2 as i64) + (sin_q15 as i64) * (dx_2 as i64);
    let rot_x: i64 = (-(sin_q15 as i64)) * (dy_2 as i64) + (cos_q15 as i64) * (dx_2 as i64);

    // Apply scale_inv_q24: (cos*dy_2 + sin*dx_2) * scale_inv_q24 / 2^31 = src_centered_2.
    let sy_q31: i64 = rot_y * scale_inv_q24;
    let sx_q31: i64 = rot_x * scale_inv_q24;

    // NN-round /2^31 with FLOOR semantics (matches Python's arithmetic >>).
    // Equivalent to: floor((x + 2^30) / 2^31).
    let sy_centred_2: i64 = floor_div_2pow31(sy_q31 + (1 << 30));
    let sx_centred_2: i64 = floor_div_2pow31(sx_q31 + (1 << 30));

    let sy_2: i64 = sy_centred_2 + (h as i64);
    let sx_2: i64 = sx_centred_2 + (w as i64);

    // NN halve: floor((sy_2 + 1) / 2).
    let sy: i64 = floor_div_2(sy_2 + 1);
    let sx: i64 = floor_div_2(sx_2 + 1);

    let valid: bool = (sy >= 0) & (sy < (h as i64)) & (sx >= 0) & (sx < (w as i64));
    (sy, sx, valid)
}

// floor(x / 2). Matches Python's `x >> 1`.
fn floor_div_2(x: i64) -> i64 {
    if x >= 0 {
        x / 2
    } else {
        -(((-x) + 1) / 2)
    }
}

// floor(x / 2^31). Matches Python's `x >> 31`.
fn floor_div_2pow31(x: i64) -> i64 {
    if x >= 0 {
        x / 2147483648  // 2^31
    } else {
        -(((-x) + 2147483647) / 2147483648)  // 2^31 - 1
    }
}

// ---------- Composite onto 48x48 RGB canvas ----------

fn composite_canvas(
    shadow_bytes: [u8; 7719],
    pose_cx: [u32; 8], pose_cy: [u32; 8],   // current anchor (from pose)
    box_w: [u32; 8], box_h: [u32; 8],       // original geometry (from boxes_packed)
    pose_cos: [i32; 8], pose_sin: [i32; 8],
    pose_scale_inv_q24: [i64; 8],
) -> [u8; 6912] {
    let mut canvas: [u8; 6912] = [0; 6912];
    for k in 0..8 {
        let cx_anchor = pose_cx[k];
        let cy_anchor = pose_cy[k];
        let w = box_w[k];
        let h = box_h[k];
        let mw = REGION_W[k];
        let region_off = REGION_OFFSETS[k];
        let cos_q15 = pose_cos[k];
        let sin_q15 = pose_sin[k];
        let scale_inv = pose_scale_inv_q24[k];

        for cy in 0..CANVAS_H {
            for cx in 0..CANVAS_W {
                let (sy, sx, valid) = inv_affine_for_slot(
                    cy, cx, cx_anchor, cy_anchor, w, h, cos_q15, sin_q15, scale_inv,
                );
                // Noir evaluates both branches of `if`. Clamp sy/sx via
                // select so the negative-i64-to-u32 cast never trips when
                // valid=false. The actual write is still gated by `if valid`.
                let sy_safe: u32 = if valid { sy as u32 } else { 0 };
                let sx_safe: u32 = if valid { sx as u32 } else { 0 };
                let src_off = region_off + sy_safe * mw * 3 + sx_safe * 3;
                let dst_off = (cy * CANVAS_W + cx) * 3;
                if valid {
                    canvas[dst_off + 0] = shadow_bytes[src_off + 0];
                    canvas[dst_off + 1] = shadow_bytes[src_off + 1];
                    canvas[dst_off + 2] = shadow_bytes[src_off + 2];
                }
            }
        }
    }
    canvas
}

// ---------- T10 quantize ----------

fn t10_quantize(canvas: [u8; 6912]) -> [Field; 4] {
    let mut quarters: [Field; 4] = [0; 4];
    for by in 0..16 {
        for bx in 0..16 {
            let mut sum_y: u32 = 0;
            for dy in 0..3 {
                for dx in 0..3 {
                    let cy: u32 = (by * 3 + dy) as u32;
                    let cx: u32 = (bx * 3 + dx) as u32;
                    let pix: u32 = (cy * 48 + cx) * 3;
                    let r: u32 = canvas[pix + 0] as u32;
                    let g: u32 = canvas[pix + 1] as u32;
                    let b: u32 = canvas[pix + 2] as u32;
                    let y: u32 = (77 * r + 150 * g + 29 * b) >> 8;
                    sum_y = sum_y + y;
                }
            }
            let avg: u32 = sum_y / 9;
            let mut level: u32 = 0;
            if avg > 64 { level = level + 1; }
            if avg > 128 { level = level + 1; }
            if avg > 192 { level = level + 1; }

            let cell_idx: u32 = (by as u32) * 16 + (bx as u32);
            let q: u32 = cell_idx / 64;
            let bit_in_q: u32 = (cell_idx - q * 64) * 2;

            let mut multiplier: Field = 1;
            for _ in 0..bit_in_q { multiplier = multiplier * 2; }
            quarters[q] = quarters[q] + (level as Field) * multiplier;
        }
    }
    quarters
}

// ---------- Boxes_packed -> per-slot (x, y, w, h) ----------

fn unpack_boxes_packed(boxes_packed: Field) -> ([u32; 8], [u32; 8], [u32; 8], [u32; 8]) {
    let bp_bytes: [u8; 32] = boxes_packed.to_le_bytes();
    let mut box_x: [u32; 8] = [0; 8];
    let mut box_y: [u32; 8] = [0; 8];
    let mut box_w: [u32; 8] = [0; 8];
    let mut box_h: [u32; 8] = [0; 8];
    for k in 0..8 {
        let b0 = bp_bytes[3 * k] as u32;
        let b1 = bp_bytes[3 * k + 1] as u32;
        let b2 = bp_bytes[3 * k + 2] as u32;
        let slot24 = b0 | (b1 << 8) | (b2 << 16);
        box_x[k] = slot24 & 0x3F;
        box_y[k] = (slot24 >> 6) & 0x3F;
        box_w[k] = (slot24 >> 12) & 0x3F;
        box_h[k] = (slot24 >> 18) & 0x3F;
        assert(box_w[k] >= 1);
        assert(box_h[k] >= 1);
        assert(box_w[k] <= REGION_W[k]);
        assert(box_h[k] <= REGION_H[k]);
    }
    (box_x, box_y, box_w, box_h)
}

// ---------- Main ----------

fn main(
    // Public inputs.
    shadow_id:        pub Field,
    state_nonce:      pub Field,
    prev_ct_commit:   pub Field,
    boxes_packed:     pub Field,
    poses_hash:       pub Field,
    shadow_q0:        pub Field,
    shadow_q1:        pub Field,
    shadow_q2:        pub Field,
    shadow_q3:        pub Field,

    // Private witness.
    shadow_plaintext: [Field; 249],
    shadow_prev_k:    Field,
    poses:            [Field; 16],
    pose_cx:          [u32; 8],
    pose_cy:          [u32; 8],
    pose_scale_q88:   [u32; 8],
    pose_cos_q15_u16: [u32; 8],
    pose_sin_q15_u16: [u32; 8],
    pose_scale_inv_q24: [i64; 8],
) {
    let _ = shadow_id;
    let _ = state_nonce;

    // ---- 1. Bind: shadow_plaintext encrypts via shadow_prev_k to prev_ct_commit ----
    let prev_ks = keystream_249(shadow_prev_k);
    let mut shadow_ct: [Field; 249] = [0; 249];
    for i in 0..SHADOW_FIELDS {
        shadow_ct[i] = shadow_plaintext[i] + prev_ks[i];
    }
    assert(sponge_249(shadow_ct) == prev_ct_commit);

    // ---- 2. Bind: poses encode to poses_hash ----
    let mut padded_poses: [Field; 18] = [0; 18];
    for i in 0..16 {
        padded_poses[i] = poses[i];
    }
    // padded_poses[16] and [17] stay zero -- pads to multiple of 3.
    assert(sponge_18(padded_poses) == poses_hash);

    // ---- 3. Bind: per-slot decoded fields match poses[k] ----
    for k in 0..8 {
        assert_pose_decode(
            poses[k],
            pose_cx[k], pose_cy[k], pose_scale_q88[k],
            pose_cos_q15_u16[k], pose_sin_q15_u16[k],
        );
        // Power-of-2 scale binding: scale_inv_q24 * scale_q88 == 2^24 (exact).
        // For non-power-of-2 scales, the prover cannot satisfy this assertion
        // (deferred to v2 with division-with-remainder gadget).
        assert(pose_scale_inv_q24[k] > 0);
        assert((pose_scale_inv_q24[k] as i64) * (pose_scale_q88[k] as i64) == (1 << 24));
    }
    // For slots 8..15 (EMPTY in MVP), the pose is 0 and not used in compositing.
    // Still, the poses[8..15] entries are bound by poses_hash, so the prover
    // can't smuggle non-zero values through.
    for k in 8..16 {
        assert(poses[k] == 0);
    }

    // ---- 4. Decode boxes_packed -> per-slot (x, y, w, h) ----
    let (_box_x, _box_y, box_w, box_h) = unpack_boxes_packed(boxes_packed);

    // ---- 5. Composite canvas ----
    let shadow_bytes = unpack_shadow_bytes(shadow_plaintext);
    let mut pose_cos: [i32; 8] = [0; 8];
    let mut pose_sin: [i32; 8] = [0; 8];
    for k in 0..8 {
        pose_cos[k] = u16_to_i32(pose_cos_q15_u16[k]);
        pose_sin[k] = u16_to_i32(pose_sin_q15_u16[k]);
    }
    let canvas = composite_canvas(
        shadow_bytes,
        pose_cx, pose_cy, box_w, box_h,
        pose_cos, pose_sin,
        pose_scale_inv_q24,
    );

    // ---- 6. T10 quantize and assert outputs ----
    let computed = t10_quantize(canvas);
    // Bind computed T10 to public inputs.
    assert(computed[0] == shadow_q0);
    assert(computed[1] == shadow_q1);
    assert(computed[2] == shadow_q2);
    assert(computed[3] == shadow_q3);
}
