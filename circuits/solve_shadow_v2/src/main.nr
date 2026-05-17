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
    EmbeddedCurvePoint, EmbeddedCurveScalar,
    multi_scalar_mul, fixed_base_scalar_mul,
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

// ---- KDF domain separation (audit L-01) ----
//
// solve_shadow_v2 doesn't ENCRYPT a new envelope, but it must VERIFY that
// the witnessed owner_k[i] is the same value the previous holder derived
// from ECDH(owner_sk, prev_c1[i]). To do that check it needs the same
// global domain tag and role tag used everywhere else in the v2 pipeline.
// MUST stay byte-for-byte identical with v2_circuit_helpers.py::kdf and
// every other v2 circuit's `kdf`.
global KDF_DOMAIN_V2: Field = 0x4d4f495354_4b44465632; // ASCII "MOISTKDFV2"
global KDF_ROLE_PLAINTEXT: Field = 1;

fn kdf(role: Field, shared_x: Field, shared_y: Field) -> Field {
    let out = poseidon2_permutation([KDF_DOMAIN_V2, role, shared_x, shared_y], 4);
    out[0]
}

// ---- ECIES well-formedness (audit M-06) ----
//
// The on-curve check for prev_c1[i] (y^2 = x^3 - 17) is inlined inside
// the per-slot loop, gated on occ, because empty slots may carry
// off-curve zero coordinates and the MSM output is irrelevant in that
// case. owner_pk is constrained on-curve transitively via owner_sk * G
// == owner_pk_x/y below.
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
    // Validates the permutation and returns its base-16 packed form.
    // Factored into `validate_and_pack_zperm` so the canonical-cast guard
    // is testable in isolation (see #[test] block at end of file).
    let packed: Field = validate_and_pack_zperm(z_perm);
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

        // M-05: bind owner_k[i] to ECDH(owner_sk, prev_c1[i]) for occupied
        // slots. Without this, owner_k is a freestanding witness and a
        // non-owner who leaked any past keystream key could publish a
        // solve proof that reveals the slot under a forged "key".
        // Empty slots: the fixture builder seeds prev_c1 with Grumpkin
        // generator G so the multi_scalar_mul blackbox accepts the input
        // (Noir's blackbox rejects off-curve points at proof-gen time --
        // gating is not enough). The `occ * ...` gate masks the equality
        // constraint for empty slots whose witness owner_k is meaningless.
        let prev_c1_curve_lhs =
            prev_c1_y[i] * prev_c1_y[i] - prev_c1_x[i] * prev_c1_x[i] * prev_c1_x[i] + 17;
        assert(occ * prev_c1_curve_lhs == 0);
        let prev_c1_pt = EmbeddedCurvePoint {
            x: prev_c1_x[i],
            y: prev_c1_y[i],
            is_infinite: false,
        };
        let shared_prev = multi_scalar_mul([prev_c1_pt], [sk_scalar]);
        let owner_k_derived = kdf(KDF_ROLE_PLAINTEXT, shared_prev.x, shared_prev.y);
        assert(occ * (owner_k[i] - owner_k_derived) == 0);

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

// Validate that `z_perm` is a true permutation of [0..16) and return its
// base-16 little-endian packed encoding. Three invariants:
//   (1) range:        each entry's low 32 bits lie in [0..16)
//   (2) canonical:    each entry as Field equals its low-32-bit cast
//                     (this rejects high-bit-set Fields whose low bits
//                     happen to fall in range -- pre-fix bug)
//   (3) distinct:     16-bit bitmap accumulator must end at 0xFFFF
fn validate_and_pack_zperm(z_perm: [Field; N_SLOTS]) -> Field {
    let mut bitmap: u32 = 0;
    let mut packed: Field = 0;
    let mut mul: Field = 1;
    let sixteen: Field = 16;
    for i in 0..N_SLOTS {
        let v: u32 = z_perm[i] as u32;
        assert(z_perm[i] == v as Field);   // canonical-cast guard
        assert(v < N_SLOTS);                // range
        let bit: u32 = (1 as u32) << v;
        assert((bitmap & bit) == 0);        // distinctness
        bitmap = bitmap | bit;
        packed = packed + z_perm[i] * mul;  // base-16 LE pack
        mul = mul * sixteen;
    }
    assert(bitmap == 0xFFFF);
    packed
}

// ---- Canonical-cast regression tests ----
// `nargo test` only; not compiled into the proving artifact.

fn identity_zperm() -> [Field; 16] {
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
}

#[test]
fn test_zperm_happy_path_canonical() {
    let z_perm = identity_zperm();
    let packed = validate_and_pack_zperm(z_perm);
    // identity perm packs to 0xFEDCBA9876543210 (base-16 LE: slot 0 = lowest nibble)
    let expected: Field = 0xFEDCBA9876543210;
    assert(packed == expected);
}

#[test(should_fail)]
fn test_zperm_rejects_high_bit_field_with_canonical_low_bits() {
    // Pre-fix bug: a Field with high bits set whose low 32 bits are in [0..16)
    // could pass the bitmap check. The canonical-cast guard MUST reject it.
    let mut z_perm = identity_zperm();
    let high_bits_seven: Field = 4294967303;  // (1 << 32) + 7
    z_perm[0] = high_bits_seven;  // was 0
    z_perm[7] = 0;                // was 7; keeps low-bit bitmap distinct
    let _ = validate_and_pack_zperm(z_perm);
}

#[test(should_fail)]
fn test_zperm_rejects_oversized_value() {
    let mut z_perm = identity_zperm();
    z_perm[0] = 16;  // out of range
    let _ = validate_and_pack_zperm(z_perm);
}
