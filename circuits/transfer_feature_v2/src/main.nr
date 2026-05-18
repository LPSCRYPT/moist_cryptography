// transfer_feature_v2: re-encrypt a held FeatureNFT carrier's slot state
// to a new owner's pubkey, advancing the carrier's lsh by one rotation
// step. Replaces the v1 `circuits/transfer_feature/` (marked STALE).
//
// Spec: STAGING_REFACTOR/2026-04-27_transfer_feature_v2_design.md
//
// Public inputs (11 Fields, frozen by FeatureNFT.transferFeature):
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
//   PI[9]   new_c1_x           (audit F-01: proof-bound ECIES envelope c1.x)
//   PI[10]  new_c1_y           (audit F-01: proof-bound ECIES envelope c1.y)
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
// ---- KDF domain separation (audit L-01) ----
//
// Single global domain tag for every ECIES shared-secret -> keystream-key
// derivation in the v2 pipeline. Mirrors v2_circuit_helpers.py::kdf and
// every other v2 circuit's `kdf` byte-for-byte. See landmark_regions_v2
// for full rationale.
global KDF_DOMAIN_V2: Field = 0x4d4f495354_4b44465632; // ASCII "MOISTKDFV2"
global KDF_ROLE_PLAINTEXT: Field = 1;

fn kdf(role: Field, shared_x: Field, shared_y: Field) -> Field {
    let out = poseidon2_permutation([KDF_DOMAIN_V2, role, shared_x, shared_y], 4);
    out[0]
}

// ---- ECIES well-formedness (audit M-06) ----
//
// Assert (x, y) lies on Grumpkin (y^2 = x^3 - 17 in Field arithmetic,
// which is mod P). Rejects (0, 0) since 0 != -17 mod P, so identity-
// at-infinity coordinates cannot pass. Both next_pk (PI) and old_c1
// (witness, bound to old_lsh via sponge_6) are consumed as MSM inputs
// below; both must be on-curve before MSM produces a well-defined
// shared point.
fn assert_on_grumpkin(x: Field, y: Field) {
    assert(y * y == x * x * x - 17);
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
    // public inputs (11) -- order matches FeatureNFT PI[0..10]
    feature_id:        pub Field,
    next_pk_x:         pub Field,
    next_pk_y:         pub Field,
    old_lsh:           pub Field,
    new_lsh:           pub Field,
    palette_commit:    pub Field,
    type_idx:          pub Field,
    origin_face_id:    pub Field,
    new_ct_commit_pi:  pub Field,
    new_c1_x_pi:       pub Field,
    new_c1_y_pi:       pub Field,
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

    // M-06: both old_c1 (witness, just sponge-bound above) and next_pk
    // (PI from contract) feed multi_scalar_mul below; assert on-curve so
    // MSM operates on real Grumpkin points. r != 0 asserted at section 5.
    assert_on_grumpkin(old_c1_x, old_c1_y);
    assert_on_grumpkin(next_pk_x, next_pk_y);

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
    let k_old_derived = kdf(KDF_ROLE_PLAINTEXT, shared_old.x, shared_old.y);
    assert(old_k == k_old_derived);

    // ---- 5. recipient envelope binding ----
    // M-06: r != 0 rejects the degenerate (c1 = O, shared = O) envelope.
    assert(new_r != 0);
    let r_scalar = EmbeddedCurveScalar::from_field(new_r);
    let new_c1 = fixed_base_scalar_mul(r_scalar);
    assert(new_c1.x == new_c1_x_pi);
    assert(new_c1.y == new_c1_y_pi);
    let next_pk_pt = EmbeddedCurvePoint {
        x: next_pk_x,
        y: next_pk_y,
        is_infinite: false,
    };
    let shared_new = multi_scalar_mul([next_pk_pt], [r_scalar]);
    let k_new_derived = kdf(KDF_ROLE_PLAINTEXT, shared_new.x, shared_new.y);
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
