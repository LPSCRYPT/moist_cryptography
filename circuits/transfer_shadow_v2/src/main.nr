// transfer_shadow_v2: rotate ECIES encryption of all 16 slots to a new owner.
//
// One proof per shadow transfer. Per slot i in 0..16:
//   - if old slot is OCCUPIED (prev_lsh[i] != 0):
//       * the prover knows the old plaintext and the old keystream key
//       * the new c2 is (plaintext + keystream(new_k[i])) under a fresh
//         ephemeral c1[i] bound to the recipient's pubkey via ECIES
//       * the per-slot mutation count and chain tip extend by exactly one
//         transfer event
//       * new_lsh[i] = sponge_6(prev_state_commit, new_ct_commit, new_c1.x,
//         new_c1.y, new_count, new_chain_tip)
//   - if old slot is EMPTY (prev_lsh[i] == 0):
//       * new_lsh[i] = 0
//       * all per-slot work skipped via boolean selector
//
// The proof additionally binds the *current* (pre-transfer) owner: prover
// supplies prev_owner_sk, derived prev_owner_pk_x/y matches PI.
//
// PI compaction (9 fields):
//   PI[0]  shadow_id
//   PI[1]  recipient_pk_x
//   PI[2]  recipient_pk_y
//   PI[3]  prev_lsh_root         = sponge_16(prev_lsh[16])
//   PI[4]  new_lsh_root          = sponge_16(new_lsh[16])
//   PI[5]  prev_owner_pk_x
//   PI[6]  prev_owner_pk_y
//   PI[7]  new_chain_tips_root   = sponge_16(new_chain_tip[16])
//   PI[8]  new_ct_commits_root   = sponge_16(new_ct_commit[16]) (audit H-02:
//                                  contract recomputes sponge_39 per occupied
//                                  slot and asserts equality with the
//                                  caller-supplied newCtCommits, which is
//                                  itself sponge_16-bound to this PI)
//
// The contract reconstructs prev_lsh_root from chain manifest, supplies
// per-slot calldata (new_lsh, new_c1_x, new_c1_y, new_ct_commit,
// new_chain_tip, new_mutation_count) for hash-rooting, then verifies the
// proof and writes the manifest. An additional `shadow_t10` proof is
// bundled at the contract level for atomic-T10 refresh.

use std::hash::poseidon2_permutation;
use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar,
    multi_scalar_mul, fixed_base_scalar_mul,
};

global PLAINTEXT_FIELDS: u32 = 39;
global N_SLOTS: u32 = 16;

// Domain-separation tag for the transfer chain-step. Distinguishes a
// transfer from a mutation in the per-slot chain_tip history. Picked as
// a public, gas-cheap constant; same tag is hardcoded in the contract.
global TRANSFER_TAG: Field = 0x1ad75ff_a_e4_711a5_fe_a7_e_ed; // arbitrary nonzero

// ---- Poseidon2 sponge variants ----

fn sponge_39(e: [Field; 39]) -> Field {
    let mut s: [Field; 4] = [0, 0, 0, 0];
    for b in 0..13 {
        s[0] = s[0] + e[b * 3];
        s[1] = s[1] + e[b * 3 + 1];
        s[2] = s[2] + e[b * 3 + 2];
        s = poseidon2_permutation(s, 4);
    }
    s[0] = s[0] + 1;
    s = poseidon2_permutation(s, 4);
    s[0]
}

fn keystream_39(k: Field) -> [Field; 39] {
    let mut ks: [Field; 39] = [0; 39];
    for b in 0..13 {
        let block = poseidon2_permutation([k, b as Field, 0, 0], 4);
        ks[b * 3]     = block[0];
        ks[b * 3 + 1] = block[1];
        ks[b * 3 + 2] = block[2];
    }
    ks
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

// sponge over 16 fields: 5 rate-3 absorb blocks + 1 rate-1 absorb + sentinel.
// Distinct shape from sponge_18 (used by shadow_t10) so transcripts cannot
// collide.
fn sponge_16(e: [Field; 16]) -> Field {
    let mut s: [Field; 4] = [0, 0, 0, 0];
    for b in 0..5 {
        s[0] = s[0] + e[b * 3];
        s[1] = s[1] + e[b * 3 + 1];
        s[2] = s[2] + e[b * 3 + 2];
        s = poseidon2_permutation(s, 4);
    }
    s[0] = s[0] + e[15];
    s = poseidon2_permutation(s, 4);
    s[0] = s[0] + 1;
    s = poseidon2_permutation(s, 4);
    s[0]
}

// ---- main ----

fn main(
    // public inputs (9)
    shadow_id:             pub Field,
    recipient_pk_x:        pub Field,
    recipient_pk_y:        pub Field,
    prev_lsh_root:         pub Field,
    new_lsh_root:          pub Field,
    prev_owner_pk_x:       pub Field,
    prev_owner_pk_y:       pub Field,
    new_chain_tips_root:   pub Field,
    new_ct_commits_root:   pub Field,

    // ---- per-slot witness (private) ----
    prev_lsh:            [Field; 16],
    is_occupied:         [Field; 16],   // boolean, 0 or 1
    plaintexts:          [[Field; 39]; 16],
    prev_state_commit:   [Field; 16],
    prev_ct_commit:      [Field; 16],
    prev_c1_x:           [Field; 16],
    prev_c1_y:           [Field; 16],
    prev_mutation_count: [Field; 16],
    prev_chain_tip:      [Field; 16],
    prev_k:              [Field; 16],
    new_k:               [Field; 16],
    new_r:               [Field; 16],

    prev_owner_sk:       Field,
) {
    // shadow_id is transcript-only; chain binds via PI[0] equality.
    let _ = shadow_id;

    // ---- 0. binder: caller is current owner ----
    let sk_scalar = EmbeddedCurveScalar::from_field(prev_owner_sk);
    let derived_pk = fixed_base_scalar_mul(sk_scalar);
    assert(derived_pk.x == prev_owner_pk_x);
    assert(derived_pk.y == prev_owner_pk_y);

    // ---- 1. recipient pubkey point ----
    let recipient_pk = EmbeddedCurvePoint {
        x: recipient_pk_x,
        y: recipient_pk_y,
        is_infinite: false,
    };

    // ---- 2. per-slot ----
    let mut new_lsh: [Field; 16] = [0; 16];
    let mut new_chain_tips: [Field; 16] = [0; 16];
    let mut new_ct_commits: [Field; 16] = [0; 16];

    for i in 0..N_SLOTS {
        // is_occupied is boolean
        let occ = is_occupied[i];
        assert(occ * (occ - 1) == 0);
        let inv = 1 - occ;

        // 2a. prev_lsh consistency:
        //   if empty: prev_lsh[i] must be 0
        //   if occupied: prev_lsh[i] must equal sponge_6 of the witnessed prev fields
        let computed_old_lsh = sponge_6(
            prev_state_commit[i],
            prev_ct_commit[i],
            prev_c1_x[i],
            prev_c1_y[i],
            prev_mutation_count[i],
            prev_chain_tip[i],
        );
        assert(inv * prev_lsh[i] == 0);
        assert(occ * (computed_old_lsh - prev_lsh[i]) == 0);

        // 2b. plaintext sponge-hashes to old state_commit (occupied only).
        let pt_state_commit = sponge_39(plaintexts[i]);
        assert(occ * (pt_state_commit - prev_state_commit[i]) == 0);

        // 2c. plaintext + keystream(prev_k) sponge-hashes to old ct_commit (occupied only).
        let prev_ks = keystream_39(prev_k[i]);
        let mut prev_ct: [Field; 39] = [0; 39];
        for j in 0..PLAINTEXT_FIELDS {
            prev_ct[j] = plaintexts[i][j] + prev_ks[j];
        }
        let prev_ct_commit_recomputed = sponge_39(prev_ct);
        assert(occ * (prev_ct_commit_recomputed - prev_ct_commit[i]) == 0);

        // 2d. new ECIES envelope to recipient.
        let r_scalar = EmbeddedCurveScalar::from_field(new_r[i]);
        let new_c1 = fixed_base_scalar_mul(r_scalar);
        let shared = multi_scalar_mul([recipient_pk], [r_scalar]);
        let mask_new = kdf(KDF_ROLE_PLAINTEXT, shared.x, shared.y);
        // For occupied slots: new_k must equal the deterministic mask key.
        assert(occ * (new_k[i] - mask_new) == 0);

        // 2e. new c2 ciphertext.
        let new_ks = keystream_39(new_k[i]);
        let mut new_ct: [Field; 39] = [0; 39];
        for j in 0..PLAINTEXT_FIELDS {
            new_ct[j] = plaintexts[i][j] + new_ks[j];
        }
        let new_ct_commit_local = sponge_39(new_ct);

        // 2f. new chain tip extends old chain tip with a TRANSFER event.
        let new_count = prev_mutation_count[i] + 1;
        let new_chain_tip_local = sponge_6(
            prev_chain_tip[i],
            TRANSFER_TAG,
            recipient_pk_x,
            recipient_pk_y,
            new_count,
            i as Field,
        );

        // 2g. new_lsh: zero for empty, computed for occupied.
        let computed_new_lsh = sponge_6(
            prev_state_commit[i],   // unchanged by re-encryption
            new_ct_commit_local,
            new_c1.x,
            new_c1.y,
            new_count,
            new_chain_tip_local,
        );
        new_lsh[i] = occ * computed_new_lsh;
        new_chain_tips[i] = occ * new_chain_tip_local;
        new_ct_commits[i] = occ * new_ct_commit_local;
    }

    // ---- 3. hash-roots bind the per-slot arrays into single PI fields ----
    assert(sponge_16(prev_lsh) == prev_lsh_root);
    assert(sponge_16(new_lsh) == new_lsh_root);
    assert(sponge_16(new_chain_tips) == new_chain_tips_root);
    assert(sponge_16(new_ct_commits) == new_ct_commits_root);
}
