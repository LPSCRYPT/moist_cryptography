// transfer_feature: re-encrypt a 42-Field FeatureNFT ciphertext to a new owner.
//
// Same shape as transfer_shadow but the underlying payload is 42 Fields (one
// feature's recolored-pixels buffer) instead of 249 (whole shadow's). 42 is a
// multiple of 3, matching the rate-3 sponge.
//
// Public inputs (8 Fields):
//   PI[0]      feature_nft_id
//   PI[1,2]    next_pk_x, next_pk_y
//   PI[3,4]    c1_x, c1_y
//   PI[5]      c2_scalar
//   PI[6]      new_ct_commit  (= sponge_42(re-encrypted ct))
//   PI[7]      prev_ct_commit (must match chain)
//
// Witness:
//   plaintext[42], prev_k, new_k, new_r

use std::hash::poseidon2_permutation;
use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar,
    multi_scalar_mul, fixed_base_scalar_mul,
};

global N_FIELDS: u32 = 42;
global N_BLOCKS: u32 = 14;

fn sponge_42(e: [Field; 42]) -> Field {
    let mut s: [Field; 4] = [0, 0, 0, 0];
    for b in 0..N_BLOCKS {
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

fn keystream_42(k: Field) -> [Field; 42] {
    let mut ks: [Field; 42] = [0; 42];
    for b in 0..N_BLOCKS {
        let block = poseidon2_permutation([k, b as Field, 0, 0], 4);
        ks[b * 3]     = block[0];
        ks[b * 3 + 1] = block[1];
        ks[b * 3 + 2] = block[2];
    }
    ks
}

fn main(
    feature_nft_id:   pub Field,
    next_pk_x:        pub Field,
    next_pk_y:        pub Field,
    c1_x:             pub Field,
    c1_y:             pub Field,
    c2_scalar:        pub Field,
    new_ct_commit:    pub Field,
    prev_ct_commit:   pub Field,

    plaintext:        [Field; 42],
    prev_k:           Field,
    new_k:            Field,
    new_r:            Field,
) {
    let _ = feature_nft_id;

    let prev_ks = keystream_42(prev_k);
    let mut prev_ct: [Field; 42] = [0; 42];
    for i in 0..N_FIELDS {
        prev_ct[i] = plaintext[i] + prev_ks[i];
    }
    assert(sponge_42(prev_ct) == prev_ct_commit);

    let new_ks = keystream_42(new_k);
    let mut new_ct: [Field; 42] = [0; 42];
    for i in 0..N_FIELDS {
        new_ct[i] = plaintext[i] + new_ks[i];
    }
    assert(sponge_42(new_ct) == new_ct_commit);

    let r_scalar = EmbeddedCurveScalar::from_field(new_r);
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
    assert(c2_scalar == new_k + k_mask);
}
