// solve_shadow_v2: reveal the full plaintext of all 16 slots + the z-permutation.
//
// Solve is a one-shot operation: once successful, the shadow is frozen
// (no further mutate/insert/extract/setZIndexCommit), every inserted
// FeatureNFT is auto-extracted, and the manifest's per-slot plaintexts
// + z-perm become public.
//
// In-circuit checks per slot i in 0..16:
//   - if occupied:
//       sponge_39(plaintext[i]) == prev_state_commit[i]
//       (plaintext[i] + keystream(owner_k[i])) sponge == prev_ct_commit[i]
//       lsh[i] = sponge_6(prev_state_commit, prev_ct_commit, prev_c1.x,
//                         prev_c1.y, prev_mutation_count, prev_chain_tip)
//   - else:
//       prev_lsh[i] must be 0
// Plus:
//   - z_perm is a permutation of 0..15 (distinctness via 16-bit bitmap)
//   - z_perm_packed encodes the 16 x 4-bit indices in one field
//   - sponge_16(z_perm) == z_index_commit  (matches chain)
//   - sponge_16(state_commit[16]) == state_commits_root
//   - sponge_16(prev_lsh[16])     == lsh_root
//   - owner_pk derived from owner_sk
//
// PI is 7 fields. Per-slot plaintexts are revealed via contract calldata
// hash-checked against state_commits_root.

use std::hash::poseidon2_permutation;
use std::embedded_curve_ops::{
    EmbeddedCurveScalar,
    fixed_base_scalar_mul,
};

global PLAINTEXT_FIELDS: u32 = 39;
global N_SLOTS: u32 = 16;

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
    // public inputs (7)
    shadow_id:           pub Field,
    state_commits_root:  pub Field,
    z_perm_packed_pi:    pub Field,
    z_index_commit:      pub Field,
    lsh_root:            pub Field,
    owner_pk_x:          pub Field,
    owner_pk_y:          pub Field,

    // ---- per-slot witness ----
    is_occupied:         [Field; 16],
    plaintexts:          [[Field; 39]; 16],
    prev_ct_commit:      [Field; 16],
    prev_c1_x:           [Field; 16],
    prev_c1_y:           [Field; 16],
    prev_mutation_count: [Field; 16],
    prev_chain_tip:      [Field; 16],
    owner_k:             [Field; 16],
    prev_lsh:            [Field; 16],

    z_perm:              [Field; 16],
    owner_sk:            Field,
) {
    let _ = shadow_id;

    // ---- 0. caller-is-owner binding ----
    let sk_scalar = EmbeddedCurveScalar::from_field(owner_sk);
    let derived_pk = fixed_base_scalar_mul(sk_scalar);
    assert(derived_pk.x == owner_pk_x);
    assert(derived_pk.y == owner_pk_y);

    // ---- 1. z-perm distinctness via 16-bit bitmap ----
    let mut bitmap: u32 = 0;
    let mut packed: Field = 0;
    let mut mul: Field = 1;
    let sixteen: Field = 16;
    for i in 0..N_SLOTS {
        let v: u32 = z_perm[i] as u32;
        assert(v < N_SLOTS);
        let bit: u32 = (1 as u32) << v;
        assert((bitmap & bit) == 0);
        bitmap = bitmap | bit;
        // pack as base-16 little-endian
        packed = packed + z_perm[i] * mul;
        mul = mul * sixteen;
    }
    assert(bitmap == 0xFFFF);
    assert(packed == z_perm_packed_pi);

    // ---- 2. z_index_commit matches chain (zindex_commit circuit's
    //         output shape: sponge_16(perm)) ----
    assert(sponge_16(z_perm) == z_index_commit);

    // ---- 3. per-slot plaintext + ciphertext + lsh checks ----
    let mut state_commits: [Field; 16] = [0; 16];

    for i in 0..N_SLOTS {
        let occ = is_occupied[i];
        assert(occ * (occ - 1) == 0);
        let inv = 1 - occ;

        // 3a. state_commit recomputed.
        let sc = sponge_39(plaintexts[i]);

        // 3b. encryption check (occupied only).
        let ks = keystream_39(owner_k[i]);
        let mut ct: [Field; 39] = [0; 39];
        for j in 0..PLAINTEXT_FIELDS {
            ct[j] = plaintexts[i][j] + ks[j];
        }
        let ct_commit_recomputed = sponge_39(ct);
        assert(occ * (ct_commit_recomputed - prev_ct_commit[i]) == 0);

        // 3c. lsh reconstruction (occupied only).
        let lsh_recomputed = sponge_6(
            sc,
            prev_ct_commit[i],
            prev_c1_x[i],
            prev_c1_y[i],
            prev_mutation_count[i],
            prev_chain_tip[i],
        );
        assert(inv * prev_lsh[i] == 0);
        assert(occ * (lsh_recomputed - prev_lsh[i]) == 0);

        // 3d. expose state_commit only for occupied; empty contributes 0.
        state_commits[i] = occ * sc;
    }

    // ---- 4. roots ----
    assert(sponge_16(state_commits) == state_commits_root);
    assert(sponge_16(prev_lsh) == lsh_root);
}
