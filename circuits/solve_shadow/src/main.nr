// =====================================================================
// **STALE — v1 circuit, not used by v2 staging contracts.**
// The v2 solve path is unimplemented (Phase 9 pending). When it lands
// it will reveal 16 × 39-Field plaintexts + the z-permutation; PI count
// is the EIP-170 risk and likely needs hash-root packing similar to
// transferShadow. The contract path `ShadowToken.solve` currently
// reverts NotImplementedYet. See `STAGING_REFACTOR/PROGRESS.md` Phase 9
// for the v2 design sketch.
// =====================================================================

// ZK Solve Circuit (v5 IOD/EMD-proportional geometry)
//
// One-way reveal of an amalgam's plaintext pixel data. The owner provides
// the canonical 252 packed-Field payload as PUBLIC input; the circuit
// computes per-feature pixelCommit_i (sponge_K_i over the relevant slice)
// and the canonical stateCommit_i (sponge_11 over the full feature state
// including runtime per-face cur_w, cur_h) and asserts PI[i] ==
// stateCommit_i. The contract checks PI[i] equals `feature.stateCommit`
// so a malicious prover cannot reveal a face that does not match the
// on-chain state.
//
// This is a degenerate ZK statement (no secret pixels): every revealed
// pixel Field is public. The non-public witness is the per-feature state
// (face_origin_id, color, cur_x, cur_y, cur_w, cur_h, scale, cos, sin)
// which is needed to reconstruct stateCommit_i. The point of the circuit
// is to outsource the Poseidon2 computation off-chain so the on-chain
// `solve` verifier remains cheap (one Honk verifier call). The contract
// emits `revealed_payload` in the `Solved` event for permanent on-chain
// reveal of the actual face.
//
// Public inputs (261 Fields):
//   PI[0..7]      state_commit_i   -- per-feature stateCommit (matches feature.stateCommit, or 0 for empty)
//   PI[8]         presence_byte    -- 8-bit slot mask (bit i = 1 iff feature i is bound)
//   PI[9..260]    revealed_pixels  -- 252 packed Fields, layout (cumulative K_i):
//                                     forehead   0..41   (K=42)
//                                     left_eye  42..67   (K=26)
//                                     right_eye 68..93   (K=26)
//                                     nose      94..119  (K=26)
//                                     left_cheek 120..145 (K=26)
//                                     right_cheek 146..171 (K=26)
//                                     mouth     172..213 (K=42)
//                                     chin      214..251 (K=38)
//
// Private witness:
//   face_origin_id:  Field (single, shared across all 8 slots in this amalgam)
//   color[8]:        Field (palette id)
//   cur_x[8]:        Field (box x in [0..47])
//   cur_y[8]:        Field (box y in [0..47])
//   cur_w[8]:        Field (per-face box width, set at mint)
//   cur_h[8]:        Field (per-face box height, set at mint)
//   scale_q88[8]:    Field (u16)
//   cos_q15[8]:      Field (i16 cast via raw u16 bit pattern)
//   sin_q15[8]:      Field (i16 cast via raw u16 bit pattern)
//
// Asserts:
//   - For each feature i with presence bit set:
//       byte-padding zeros in the last partial Field per featureType
//       pixel_commit_i = poseidon2_sponge_K_i(revealed_pixels[OFF_i..OFF_i+K_i])
//       state_commit_i = poseidon2_sponge_11(
//           face_origin_id, i, color_i, cur_x_i, cur_y_i, cur_w_i, cur_h_i,
//           scale_q88_i, cos_q15_i, sin_q15_i, pixel_commit_i,
//       )
//       assert PI[i] == state_commit_i
//   - For each empty slot i:
//       revealed_pixels[OFF_i..OFF_i+K_i] all-zero AND PI[i] == 0
//       (no sponge is computed, so the witness for that slot is unconstrained
//        and cannot leak which arbitrary pre-image was used).
//
// Canonical commit definitions (shared with shadow + region_relay_geom + landmark_regions):
//   K_i = PACKED_COUNTS = [42, 26, 26, 26, 26, 26, 42, 38]
//   pixel_commit_i = poseidon2_sponge_K_i(packed_fields_i)
//   state_commit   = poseidon2_sponge_11(
//       face_origin_id, feature_type, color,
//       cur_x, cur_y, cur_w, cur_h,
//       cur_scale_q88, cur_cos_q15, cur_sin_q15,
//       pixel_commit,
//   )

use std::hash::poseidon2_permutation;

global OFF_FOREHEAD:    u32 =   0;
global OFF_LEFT_EYE:    u32 =  42;
global OFF_RIGHT_EYE:   u32 =  68;
global OFF_NOSE:        u32 =  94;
global OFF_LEFT_CHEEK:  u32 = 120;
global OFF_RIGHT_CHEEK: u32 = 146;
global OFF_MOUTH:       u32 = 172;
global OFF_CHIN:        u32 = 214;

// ---------- Poseidon2 sponges (rate-3 over width-4 state, sentinel padding) ----------
// Bit-identical to landmark_regions / relay_geom.py.

// Sponge over exactly 11 Fields: rate-3, 3 full block(s) + 2 tail + sentinel.
fn poseidon2_sponge_11(elems: [Field; 11]) -> Field {
    let mut state: [Field; 4] = [0, 0, 0, 0];
    for b in 0..3 {
        state[0] = state[0] + elems[b * 3];
        state[1] = state[1] + elems[b * 3 + 1];
        state[2] = state[2] + elems[b * 3 + 2];
        state = poseidon2_permutation(state, 4);
    }
    state[0] = state[0] + elems[9];
    state[1] = state[1] + elems[10];
    state[2] = state[2] + 1;  // sentinel
    state = poseidon2_permutation(state, 4);
    state[0]
}

// Sponge over exactly 26 Fields: rate-3, 8 full block(s) + 2 tail + sentinel.
fn poseidon2_sponge_26(elems: [Field; 26]) -> Field {
    let mut state: [Field; 4] = [0, 0, 0, 0];
    for b in 0..8 {
        state[0] = state[0] + elems[b * 3];
        state[1] = state[1] + elems[b * 3 + 1];
        state[2] = state[2] + elems[b * 3 + 2];
        state = poseidon2_permutation(state, 4);
    }
    state[0] = state[0] + elems[24];
    state[1] = state[1] + elems[25];
    state[2] = state[2] + 1;  // sentinel
    state = poseidon2_permutation(state, 4);
    state[0]
}

// Sponge over exactly 38 Fields: rate-3, 12 full block(s) + 2 tail + sentinel.
fn poseidon2_sponge_38(elems: [Field; 38]) -> Field {
    let mut state: [Field; 4] = [0, 0, 0, 0];
    for b in 0..12 {
        state[0] = state[0] + elems[b * 3];
        state[1] = state[1] + elems[b * 3 + 1];
        state[2] = state[2] + elems[b * 3 + 2];
        state = poseidon2_permutation(state, 4);
    }
    state[0] = state[0] + elems[36];
    state[1] = state[1] + elems[37];
    state[2] = state[2] + 1;  // sentinel
    state = poseidon2_permutation(state, 4);
    state[0]
}

// Sponge over exactly 42 Fields: rate-3, 14 full block(s) + 0 tail + sentinel.
fn poseidon2_sponge_42(elems: [Field; 42]) -> Field {
    let mut state: [Field; 4] = [0, 0, 0, 0];
    for b in 0..14 {
        state[0] = state[0] + elems[b * 3];
        state[1] = state[1] + elems[b * 3 + 1];
        state[2] = state[2] + elems[b * 3 + 2];
        state = poseidon2_permutation(state, 4);
    }
    state[0] = state[0] + 1;  // sentinel
    state = poseidon2_permutation(state, 4);
    state[0]
}

// ---------- State commit ----------

fn state_commit_of(
    face_origin_id: Field,
    feature_type: Field,
    color: Field,
    cur_x: Field,
    cur_y: Field,
    cur_w: Field,
    cur_h: Field,
    cur_scale_q88: Field,
    cur_cos_q15: Field,
    cur_sin_q15: Field,
    pixel_commit: Field,
) -> Field {
    let elems: [Field; 11] = [
        face_origin_id,
        feature_type,
        color,
        cur_x,
        cur_y,
        cur_w,
        cur_h,
        cur_scale_q88,
        cur_cos_q15,
        cur_sin_q15,
        pixel_commit,
    ];
    poseidon2_sponge_11(elems)
}

// ---------- Padding-zero asserts ----------
//
// Each feature's last Field is partial. The unused high bytes MUST be zero
// or the prover could hide data. Per featureType (last_field index = K-1):
//   forehead (K=42, 1296 B): last Field uses 25 bytes -> zero  bytes 25..30
//   eye      (K=26,  792 B): last Field uses 17 bytes -> zero  bytes 17..30
//   nose     (K=26,  792 B): same as eye               -> zero  bytes 17..30
//   cheek    (K=26,  798 B): last Field uses 23 bytes -> zero  bytes 23..30
//   mouth    (K=42, 1296 B): same as forehead          -> zero  bytes 25..30
//   chin     (K=38, 1152 B): last Field uses  5 bytes -> zero  bytes  5..30

fn assert_pad_zero_forehead_or_mouth(last_field: Field) {
    let raw: [u8; 31] = last_field.to_le_bytes();
    for j in 25..31 { assert(raw[j] == 0); }
}

fn assert_pad_zero_eye_or_nose(last_field: Field) {
    let raw: [u8; 31] = last_field.to_le_bytes();
    for j in 17..31 { assert(raw[j] == 0); }
}

fn assert_pad_zero_cheek(last_field: Field) {
    let raw: [u8; 31] = last_field.to_le_bytes();
    for j in 23..31 { assert(raw[j] == 0); }
}

fn assert_pad_zero_chin(last_field: Field) {
    let raw: [u8; 31] = last_field.to_le_bytes();
    for j in 5..31 { assert(raw[j] == 0); }
}

// ---------- Empty-slot zero-checks ----------

fn assert_zero_fields_26(e: [Field; 26]) {
    for i in 0..26 { assert(e[i] == 0); }
}

fn assert_zero_fields_38(e: [Field; 38]) {
    for i in 0..38 { assert(e[i] == 0); }
}

fn assert_zero_fields_42(e: [Field; 42]) {
    for i in 0..42 { assert(e[i] == 0); }
}

// ---------- Main ----------

fn main(
    state_commit_0: pub Field,
    state_commit_1: pub Field,
    state_commit_2: pub Field,
    state_commit_3: pub Field,
    state_commit_4: pub Field,
    state_commit_5: pub Field,
    state_commit_6: pub Field,
    state_commit_7: pub Field,
    presence:       pub Field,
    revealed_pixels: pub [Field; 252],

    // Private per-feature state used to reconstruct stateCommit_i.
    face_origin_id: Field,
    color:      [Field; 8],
    cur_x:      [Field; 8],
    cur_y:      [Field; 8],
    cur_w:      [Field; 8],
    cur_h:      [Field; 8],
    scale_q88:  [Field; 8],
    cos_q15:    [Field; 8],
    sin_q15:    [Field; 8],
) {
    let presence_bytes: [u8; 1] = presence.to_le_bytes();
    let p: u8 = presence_bytes[0];

    // Forehead (i=0, K=42)
    {
        let mut e: [Field; 42] = [0; 42];
        for k in 0..42 { e[k] = revealed_pixels[OFF_FOREHEAD + k]; }
        let bound: u8 = (p >> 0) & 1;
        if bound == 1 {
            assert_pad_zero_forehead_or_mouth(e[41]);
            let pixel_commit = poseidon2_sponge_42(e);
            let sc = state_commit_of(
                face_origin_id, 0 as Field, color[0],
                cur_x[0], cur_y[0], cur_w[0], cur_h[0],
                scale_q88[0], cos_q15[0], sin_q15[0],
                pixel_commit,
            );
            assert(sc == state_commit_0);
        } else {
            assert_zero_fields_42(e);
            assert(state_commit_0 == 0);
        }
    }
    // Left eye (i=1, K=26)
    {
        let mut e: [Field; 26] = [0; 26];
        for k in 0..26 { e[k] = revealed_pixels[OFF_LEFT_EYE + k]; }
        let bound: u8 = (p >> 1) & 1;
        if bound == 1 {
            assert_pad_zero_eye_or_nose(e[25]);
            let pixel_commit = poseidon2_sponge_26(e);
            let sc = state_commit_of(
                face_origin_id, 1 as Field, color[1],
                cur_x[1], cur_y[1], cur_w[1], cur_h[1],
                scale_q88[1], cos_q15[1], sin_q15[1],
                pixel_commit,
            );
            assert(sc == state_commit_1);
        } else {
            assert_zero_fields_26(e);
            assert(state_commit_1 == 0);
        }
    }
    // Right eye (i=2, K=26)
    {
        let mut e: [Field; 26] = [0; 26];
        for k in 0..26 { e[k] = revealed_pixels[OFF_RIGHT_EYE + k]; }
        let bound: u8 = (p >> 2) & 1;
        if bound == 1 {
            assert_pad_zero_eye_or_nose(e[25]);
            let pixel_commit = poseidon2_sponge_26(e);
            let sc = state_commit_of(
                face_origin_id, 2 as Field, color[2],
                cur_x[2], cur_y[2], cur_w[2], cur_h[2],
                scale_q88[2], cos_q15[2], sin_q15[2],
                pixel_commit,
            );
            assert(sc == state_commit_2);
        } else {
            assert_zero_fields_26(e);
            assert(state_commit_2 == 0);
        }
    }
    // Nose (i=3, K=26)
    {
        let mut e: [Field; 26] = [0; 26];
        for k in 0..26 { e[k] = revealed_pixels[OFF_NOSE + k]; }
        let bound: u8 = (p >> 3) & 1;
        if bound == 1 {
            assert_pad_zero_eye_or_nose(e[25]);
            let pixel_commit = poseidon2_sponge_26(e);
            let sc = state_commit_of(
                face_origin_id, 3 as Field, color[3],
                cur_x[3], cur_y[3], cur_w[3], cur_h[3],
                scale_q88[3], cos_q15[3], sin_q15[3],
                pixel_commit,
            );
            assert(sc == state_commit_3);
        } else {
            assert_zero_fields_26(e);
            assert(state_commit_3 == 0);
        }
    }
    // Left cheek (i=4, K=26)
    {
        let mut e: [Field; 26] = [0; 26];
        for k in 0..26 { e[k] = revealed_pixels[OFF_LEFT_CHEEK + k]; }
        let bound: u8 = (p >> 4) & 1;
        if bound == 1 {
            assert_pad_zero_cheek(e[25]);
            let pixel_commit = poseidon2_sponge_26(e);
            let sc = state_commit_of(
                face_origin_id, 4 as Field, color[4],
                cur_x[4], cur_y[4], cur_w[4], cur_h[4],
                scale_q88[4], cos_q15[4], sin_q15[4],
                pixel_commit,
            );
            assert(sc == state_commit_4);
        } else {
            assert_zero_fields_26(e);
            assert(state_commit_4 == 0);
        }
    }
    // Right cheek (i=5, K=26)
    {
        let mut e: [Field; 26] = [0; 26];
        for k in 0..26 { e[k] = revealed_pixels[OFF_RIGHT_CHEEK + k]; }
        let bound: u8 = (p >> 5) & 1;
        if bound == 1 {
            assert_pad_zero_cheek(e[25]);
            let pixel_commit = poseidon2_sponge_26(e);
            let sc = state_commit_of(
                face_origin_id, 5 as Field, color[5],
                cur_x[5], cur_y[5], cur_w[5], cur_h[5],
                scale_q88[5], cos_q15[5], sin_q15[5],
                pixel_commit,
            );
            assert(sc == state_commit_5);
        } else {
            assert_zero_fields_26(e);
            assert(state_commit_5 == 0);
        }
    }
    // Mouth (i=6, K=42)
    {
        let mut e: [Field; 42] = [0; 42];
        for k in 0..42 { e[k] = revealed_pixels[OFF_MOUTH + k]; }
        let bound: u8 = (p >> 6) & 1;
        if bound == 1 {
            assert_pad_zero_forehead_or_mouth(e[41]);
            let pixel_commit = poseidon2_sponge_42(e);
            let sc = state_commit_of(
                face_origin_id, 6 as Field, color[6],
                cur_x[6], cur_y[6], cur_w[6], cur_h[6],
                scale_q88[6], cos_q15[6], sin_q15[6],
                pixel_commit,
            );
            assert(sc == state_commit_6);
        } else {
            assert_zero_fields_42(e);
            assert(state_commit_6 == 0);
        }
    }
    // Chin (i=7, K=38)
    {
        let mut e: [Field; 38] = [0; 38];
        for k in 0..38 { e[k] = revealed_pixels[OFF_CHIN + k]; }
        let bound: u8 = (p >> 7) & 1;
        if bound == 1 {
            assert_pad_zero_chin(e[37]);
            let pixel_commit = poseidon2_sponge_38(e);
            let sc = state_commit_of(
                face_origin_id, 7 as Field, color[7],
                cur_x[7], cur_y[7], cur_w[7], cur_h[7],
                scale_q88[7], cos_q15[7], sin_q15[7],
                pixel_commit,
            );
            assert(sc == state_commit_7);
        } else {
            assert_zero_fields_38(e);
            assert(state_commit_7 == 0);
        }
    }
}
