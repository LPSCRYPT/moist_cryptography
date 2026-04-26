// extract_slot: prove that the prover knew alice's shadow plaintext AND that
// the witnessed `feature_payload` is the byte-correct slice of that shadow's
// per-feature bytes for the requested slot.
//
// Compared to v0, this circuit adds full byte-level equality between the
// unpacked shadow plaintext bytes and the unpacked feature_payload bytes:
//   shadow_bytes[REGION_OFFSETS[slot] .. REGION_OFFSETS[slot] + K_BYTES[slot]]
//   == feature_bytes[0 .. K_BYTES[slot]]
//   AND feature_bytes[K_BYTES[slot] .. 1302] == 0  (zero pad)
//
// This closes the audit gap from the v0 design: the chain now cryptographically
// guarantees that the new FeatureNFT's c2 contains exactly the same bytes
// that alice's shadow encodes for that slot. A malicious extractor cannot
// substitute different bytes.
//
// Public inputs (10 Fields, unchanged from v0):
//   PI[0]   shadow_id              (chain-level binding only; transcript-only here)
//   PI[1]   slot_idx               (0..7)
//   PI[2]   feature_type           (must equal slot_idx in the 8-slot canonical layout)
//   PI[3]   prev_shadow_ct_commit
//   PI[4]   next_pk_x              (recipient pk x)
//   PI[5]   next_pk_y
//   PI[6]   c1_x                   (ECIES ephemeral pk x)
//   PI[7]   c1_y
//   PI[8]   c2_scalar              (= feature_new_k + Poseidon2(shared.x, shared.y))
//   PI[9]   feature_ct_commit      (= sponge_42 of new FeatureNFT's c2)
//
// Witness (unchanged from v0):
//   shadow_plaintext[249], shadow_prev_k, feature_payload[42], feature_new_k, feature_new_r

use std::hash::poseidon2_permutation;
use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar,
    multi_scalar_mul, fixed_base_scalar_mul,
};

global SHADOW_FIELDS: u32 = 249;
global SHADOW_BLOCKS: u32 = 83;
global SHADOW_BYTES: u32 = 7719;     // 249 * 31 (last 3 are zero pad in mint)
global FEATURE_FIELDS: u32 = 42;
global FEATURE_BLOCKS: u32 = 14;
global FEATURE_BYTES_MAX: u32 = 1302; // 42 * 31

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

fn sponge_42(e: [Field; 42]) -> Field {
    let mut s: [Field; 4] = [0, 0, 0, 0];
    for b in 0..FEATURE_BLOCKS {
        s[0] = s[0] + e[b * 3];
        s[1] = s[1] + e[b * 3 + 1];
        s[2] = s[2] + e[b * 3 + 2];
        s = poseidon2_permutation(s, 4);
    }
    s[0] = s[0] + 1;
    s = poseidon2_permutation(s, 4);
    s[0]
}

fn poseidon2_hash_2(x: Field, y: Field) -> Field {
    let out = poseidon2_permutation([x, y, 0, 0], 4);
    out[0]
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

fn keystream_42(k: Field) -> [Field; 42] {
    let mut ks: [Field; 42] = [0; 42];
    for b in 0..FEATURE_BLOCKS {
        let block = poseidon2_permutation([k, b as Field, 0, 0], 4);
        ks[b * 3]     = block[0];
        ks[b * 3 + 1] = block[1];
        ks[b * 3 + 2] = block[2];
    }
    ks
}

// Unpack a Field array into a byte array, 31 LSB bytes per Field. Each
// to_le_bytes call constrains the Field to fit in 31 bytes (< 2^248), which
// is the canonical packing rule from mint_pipeline / mint_decrypt.
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

fn unpack_feature_bytes(payload: [Field; 42]) -> [u8; 1302] {
    let mut out: [u8; 1302] = [0; 1302];
    for f_idx in 0..FEATURE_FIELDS {
        let chunk: [u8; 31] = payload[f_idx].to_le_bytes();
        for j in 0..31 {
            out[f_idx * 31 + j] = chunk[j];
        }
    }
    out
}

// Check that, for the given feature_type, the bytes in feature_bytes match the
// corresponding slice of shadow_bytes per REGION_OFFSETS / REGION_BYTES.
//
// Implementation: enumerate all 8 candidate types, mask-multiply the asserts
// so only the matching type's checks are non-trivial. Sized to the maximum
// region (forehead/mouth = 1296 bytes) for uniformity; remaining 1302 - 1296
// = 6 entries are zero-padded for ALL types.
//
// REGION_OFFSETS = [0, 1296, 2088, 2880, 3672, 4470, 5268, 6564]
// REGION_BYTES   = [1296, 792, 792, 792, 798, 798, 1296, 1152]
fn check_byte_equality(
    shadow_bytes: [u8; 7719],
    feature_bytes: [u8; 1302],
    feature_type: u8,
) {
    // Match indicators: exactly one is 1, the rest are 0.
    let m0: Field = if feature_type == 0 { 1 } else { 0 };
    let m1: Field = if feature_type == 1 { 1 } else { 0 };
    let m2: Field = if feature_type == 2 { 1 } else { 0 };
    let m3: Field = if feature_type == 3 { 1 } else { 0 };
    let m4: Field = if feature_type == 4 { 1 } else { 0 };
    let m5: Field = if feature_type == 5 { 1 } else { 0 };
    let m6: Field = if feature_type == 6 { 1 } else { 0 };
    let m7: Field = if feature_type == 7 { 1 } else { 0 };

    // Sanity: exactly one match (gate against feature_type out of [0, 7]).
    assert(m0 + m1 + m2 + m3 + m4 + m5 + m6 + m7 == 1);

    // Type 0: forehead. Offset 0, 1296 bytes.
    for j in 0..1296 {
        let fb = feature_bytes[j] as Field;
        let sb = shadow_bytes[0 + j] as Field;
        assert(m0 * (fb - sb) == 0);
    }
    // Type 0: padding (j in [1296, 1302))
    for j in 1296..1302 {
        let fb = feature_bytes[j] as Field;
        assert(m0 * fb == 0);
    }

    // Type 1: leye. Offset 1296, 792 bytes.
    for j in 0..792 {
        let fb = feature_bytes[j] as Field;
        let sb = shadow_bytes[1296 + j] as Field;
        assert(m1 * (fb - sb) == 0);
    }
    for j in 792..1302 {
        let fb = feature_bytes[j] as Field;
        assert(m1 * fb == 0);
    }

    // Type 2: reye. Offset 2088, 792 bytes.
    for j in 0..792 {
        let fb = feature_bytes[j] as Field;
        let sb = shadow_bytes[2088 + j] as Field;
        assert(m2 * (fb - sb) == 0);
    }
    for j in 792..1302 {
        let fb = feature_bytes[j] as Field;
        assert(m2 * fb == 0);
    }

    // Type 3: nose. Offset 2880, 792 bytes.
    for j in 0..792 {
        let fb = feature_bytes[j] as Field;
        let sb = shadow_bytes[2880 + j] as Field;
        assert(m3 * (fb - sb) == 0);
    }
    for j in 792..1302 {
        let fb = feature_bytes[j] as Field;
        assert(m3 * fb == 0);
    }

    // Type 4: lcheek. Offset 3672, 798 bytes.
    for j in 0..798 {
        let fb = feature_bytes[j] as Field;
        let sb = shadow_bytes[3672 + j] as Field;
        assert(m4 * (fb - sb) == 0);
    }
    for j in 798..1302 {
        let fb = feature_bytes[j] as Field;
        assert(m4 * fb == 0);
    }

    // Type 5: rcheek. Offset 4470, 798 bytes.
    for j in 0..798 {
        let fb = feature_bytes[j] as Field;
        let sb = shadow_bytes[4470 + j] as Field;
        assert(m5 * (fb - sb) == 0);
    }
    for j in 798..1302 {
        let fb = feature_bytes[j] as Field;
        assert(m5 * fb == 0);
    }

    // Type 6: mouth. Offset 5268, 1296 bytes.
    for j in 0..1296 {
        let fb = feature_bytes[j] as Field;
        let sb = shadow_bytes[5268 + j] as Field;
        assert(m6 * (fb - sb) == 0);
    }
    for j in 1296..1302 {
        let fb = feature_bytes[j] as Field;
        assert(m6 * fb == 0);
    }

    // Type 7: chin. Offset 6564, 1152 bytes.
    for j in 0..1152 {
        let fb = feature_bytes[j] as Field;
        let sb = shadow_bytes[6564 + j] as Field;
        assert(m7 * (fb - sb) == 0);
    }
    for j in 1152..1302 {
        let fb = feature_bytes[j] as Field;
        assert(m7 * fb == 0);
    }
}

fn main(
    shadow_id:                  pub Field,
    slot_idx:                   pub Field,
    feature_type_pub:           pub Field,
    prev_shadow_ct_commit:      pub Field,
    next_pk_x:                  pub Field,
    next_pk_y:                  pub Field,
    c1_x:                       pub Field,
    c1_y:                       pub Field,
    c2_scalar:                  pub Field,
    feature_ct_commit:          pub Field,

    shadow_plaintext:           [Field; 249],
    shadow_prev_k:              Field,
    feature_payload:            [Field; 42],
    feature_new_k:              Field,
    feature_new_r:              Field,
) {
    let _ = shadow_id;
    assert(slot_idx == feature_type_pub);

    let feature_type: u8 = feature_type_pub as u8;
    assert(feature_type < 8);

    // ---- 1. Bind: shadow_plaintext encrypts to prev_shadow_ct_commit ----
    let prev_ks = keystream_249(shadow_prev_k);
    let mut shadow_ct: [Field; 249] = [0; 249];
    for i in 0..SHADOW_FIELDS {
        shadow_ct[i] = shadow_plaintext[i] + prev_ks[i];
    }
    assert(sponge_249(shadow_ct) == prev_shadow_ct_commit);

    // ---- 2. NEW: byte-level equality between shadow plaintext and feature payload ----
    // Unpack both arrays to bytes via to_le_bytes (constrains Fields < 2^248).
    let shadow_bytes  = unpack_shadow_bytes(shadow_plaintext);
    let feature_bytes = unpack_feature_bytes(feature_payload);
    check_byte_equality(shadow_bytes, feature_bytes, feature_type);

    // ---- 3. Encrypt feature_payload under feature_new_k ----
    let new_ks = keystream_42(feature_new_k);
    let mut feature_ct: [Field; 42] = [0; 42];
    for i in 0..FEATURE_FIELDS {
        feature_ct[i] = feature_payload[i] + new_ks[i];
    }
    assert(sponge_42(feature_ct) == feature_ct_commit);

    // ---- 4. ECIES envelope ----
    let r_scalar = EmbeddedCurveScalar::from_field(feature_new_r);
    let c1 = fixed_base_scalar_mul(r_scalar);
    assert(c1.x == c1_x);
    assert(c1.y == c1_y);

    let next_pk = EmbeddedCurvePoint {
        x: next_pk_x,
        y: next_pk_y,
        is_infinite: false,
    };
    let shared = multi_scalar_mul([next_pk], [r_scalar]);
    let k_mask = poseidon2_hash_2(shared.x, shared.y);
    assert(c2_scalar == feature_new_k + k_mask);
}
