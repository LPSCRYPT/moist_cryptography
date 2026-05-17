// transfer_feature_v2: re-encrypt a held FeatureNFT carrier's slot state
// to a new owner's pubkey, advancing the carrier's lsh by one rotation
// step. Replaces the v1 `circuits/transfer_feature/` (marked STALE).
//
// Spec: STAGING_REFACTOR/2026-04-27_transfer_feature_v2_design.md
//
// Public inputs (9 Fields, frozen by FeatureNFT.transferFeature):
//   PI[0]   feature_id         (transcript-only here; chain checks storage)
//   PI[1]   next_pk_x          (recipient pubkey x)
//   PI[2]   next_pk_y          (recipient pubkey y)
//   PI[3]   old_lsh            (asserted to recompute from witness)
//   PI[4]   new_lsh            (asserted to equal recomputed lsh)
//   PI[5]   palette_commit     (transcript-only; chain immutability check)
//   PI[6]   type_idx           (chain-tip salt + transcript)
//   PI[7]   origin_face_id     (chain-tip salt + transcript)
//   PI[8]   new_ct_commit      (audit H-02: contract recomputes sponge_39(c2)
//                              and asserts equality with this PI so the
//                              emitted ciphertext is proof-bound at the byte
//                              level, not just transitively via new_lsh)
//
// Witness (private):
//   plaintext[39]              (unchanged through rotation)
//   old_state_commit, old_ct_commit, old_c1_x, old_c1_y, old_count,
//   old_chain_tip              (folded into old_lsh)
//   old_k                      (old keystream key)
//   owner_sk                   (current owner's encryption sk; ECIES proof)
//   new_k, new_r               (new keystream key + ECIES ephemeral scalar)

use std::hash::poseidon2_permutation;
use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar,
    multi_scalar_mul, fixed_base_scalar_mul,
};

global PLAINTEXT_FIELDS: u32 = 39;
global N_BLOCKS: u32 = 13;

// ---- Poseidon2 sponge variants (byte-equivalent to mutate_slot) ----

// Generic absorb-rate-3, capacity-1 sponge over 39 field elements with
// one trailing length-tag absorb. Matches the v2 on-chain Yul Poseidon2
// sponge byte-for-byte.
fn sponge_39(e: [Field; 39]) -> Field {
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

// Hash of (a, b) with capacity 0.
fn poseidon2_hash_2(a: Field, b: Field) -> Field {
    let out = poseidon2_permutation([a, b, 0, 0], 4);
    out[0]
}

// poseidon2_sponge over a fixed 6-element tuple. Used both for
// liveStateHash assembly and for chain-tip extension. Matches the v2
// schema:
//   liveStateHash = sponge_6(stateCommit, ctCommit, c1X, c1Y,
//                            count, chainTip)
fn sponge_6(a: Field, b: Field, c: Field, d: Field, e: Field, f: Field) -> Field {
    let mut s: [Field; 4] = [0, 0, 0, 0];
    s[0] = s[0] + a;
    s[1] = s[1] + b;
    s[2] = s[2] + c;
    s = poseidon2_permutation(s, 4);
    s[0] = s[0] + d;
    s[1] = s[1] + e;
    s[2] = s[2] + f;
    s = poseidon2_permutation(s, 4);
    s[0] = s[0] + 1;
    s = poseidon2_permutation(s, 4);
    s[0]
}

// ECIES-Pohlig keystream: 13 blocks of 3 Fields each = 39 Fields.
fn keystream_39(k: Field) -> [Field; 39] {
    let mut ks: [Field; 39] = [0; 39];
    for b in 0..N_BLOCKS {
        let block = poseidon2_permutation([k, b as Field, 0, 0], 4);
        ks[b * 3]     = block[0];
        ks[b * 3 + 1] = block[1];
        ks[b * 3 + 2] = block[2];
    }
    ks
}

// ---- main ----

fn main(
    // public inputs (9) -- order matches FeatureNFT PI[0..9]
    feature_id:        pub Field,
    next_pk_x:         pub Field,
    next_pk_y:         pub Field,
    old_lsh:           pub Field,
    new_lsh:           pub Field,
    palette_commit:    pub Field,
    type_idx:          pub Field,
    origin_face_id:    pub Field,
    new_ct_commit_pi:  pub Field,

    // witness
    plaintext:        [Field; 39],
    old_state_commit: Field,
    old_ct_commit:    Field,
    old_c1_x:         Field,
    old_c1_y:         Field,
    old_count:        Field,
    old_chain_tip:    Field,
    old_k:            Field,
    owner_sk:         Field,
    new_k:            Field,
    new_r:            Field,
) {
    // ---- 0. transcript-only PI hooks ----
    // feature_id and palette_commit are bound by the contract against
    // storage; they're not folded into the lsh schema.
    let _ = feature_id;
    let _ = palette_commit;

    // ---- 1. old_lsh integrity ----
    let lsh_old_recomputed = sponge_6(
        old_state_commit,
        old_ct_commit,
        old_c1_x,
        old_c1_y,
        old_count,
        old_chain_tip,
    );
    assert(lsh_old_recomputed == old_lsh);

    // ---- 2. plaintext commitment binding ----
    assert(sponge_39(plaintext) == old_state_commit);

    // ---- 3. old ciphertext binding ----
    let old_ks = keystream_39(old_k);
    let mut old_ct: [Field; 39] = [0; 39];
    for i in 0..PLAINTEXT_FIELDS {
        old_ct[i] = plaintext[i] + old_ks[i];
    }
    assert(sponge_39(old_ct) == old_ct_commit);

    // ---- 4. ownership proof via ECIES decryption authority ----
    // ECIES gives old_k = hash2(owner_sk * old_c1) when (old_c1, old_k)
    // were produced as old_c1 = old_r * G and shared = old_r * owner_pk
    // = owner_sk * old_c1. Knowing owner_sk such that this matches
    // old_k (which is fixed by old_ct_commit, fixed by old_lsh) proves
    // ownership of the encryption sk for this carrier's last envelope.
    //
    // We do NOT separately bind owner_pk because it isn't in PI; the
    // lsh chain transitively binds it through old_c1 (anchored at
    // extractFromShadow time on chain).
    let owner_sk_scalar = EmbeddedCurveScalar::from_field(owner_sk);
    let old_c1_pt = EmbeddedCurvePoint {
        x: old_c1_x,
        y: old_c1_y,
        is_infinite: false,
    };
    let shared_old = multi_scalar_mul([old_c1_pt], [owner_sk_scalar]);
    let k_old_derived = poseidon2_hash_2(shared_old.x, shared_old.y);
    assert(old_k == k_old_derived);

    // ---- 5. recipient envelope binding ----
    let r_scalar = EmbeddedCurveScalar::from_field(new_r);
    let new_c1 = fixed_base_scalar_mul(r_scalar);
    let next_pk_pt = EmbeddedCurvePoint {
        x: next_pk_x,
        y: next_pk_y,
        is_infinite: false,
    };
    let shared_new = multi_scalar_mul([next_pk_pt], [r_scalar]);
    let k_new_derived = poseidon2_hash_2(shared_new.x, shared_new.y);
    assert(new_k == k_new_derived);

    // ---- 6. new ciphertext encoding ----
    let new_ks = keystream_39(new_k);
    let mut new_ct: [Field; 39] = [0; 39];
    for i in 0..PLAINTEXT_FIELDS {
        new_ct[i] = plaintext[i] + new_ks[i];
    }
    let new_state_commit = sponge_39(plaintext); // == old_state_commit
    let new_ct_commit    = sponge_39(new_ct);
    // Bind the public new_ct_commit to the witness sponge (audit H-02).
    // The contract recomputes sponge_39(c2) over emitted bytes and
    // asserts equality with PI[8]; this assert closes the circuit-side
    // half of that binding.
    assert(new_ct_commit == new_ct_commit_pi);

    // ---- 7. counter advance ----
    let new_count = old_count + 1;

    // ---- 8. chain tip extension ----
    // Salts are (origin_face_id, type_idx) -- type_idx replaces the
    // mutate_slot schema's slot_idx since held carriers have no slot.
    let new_chain_tip = sponge_6(
        old_chain_tip,
        new_state_commit,
        new_ct_commit,
        new_count,
        origin_face_id,
        type_idx,
    );

    // ---- 9. new_lsh assembly + binding ----
    let lsh_new_recomputed = sponge_6(
        new_state_commit,
        new_ct_commit,
        new_c1.x,
        new_c1.y,
        new_count,
        new_chain_tip,
    );
    assert(lsh_new_recomputed == new_lsh);
}
