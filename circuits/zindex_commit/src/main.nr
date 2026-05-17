// zindex_commit: prove `new_z_commit = sponge_16(perm)` where `perm` is a
// permutation of [0..15].
//
// Public inputs (2 Fields):
//   PI[0]   shadow_id      (transcript-only)
//   PI[1]   new_z_commit   (= sponge_16(perm))
//
// Witness (private):
//   perm : [Field; 16]      (each in [0..15], all distinct)

use std::hash::poseidon2_permutation;

global N_SLOTS: u32 = 16;

// poseidon2 sponge over 16 fields, rate=3 capacity=1, sentinel padding.
// 16 = 5 full blocks (15 elems) + 1 tail elem; same shape as v1's sponge_42.
fn sponge_16(e: [Field; 16]) -> Field {
    let mut s: [Field; 4] = [0, 0, 0, 0];
    // 5 full blocks: e[0..15].
    for b in 0..5 {
        s[0] = s[0] + e[b * 3];
        s[1] = s[1] + e[b * 3 + 1];
        s[2] = s[2] + e[b * 3 + 2];
        s = poseidon2_permutation(s, 4);
    }
    // Last partial block: e[15], two zero pads.
    s[0] = s[0] + e[15];
    s = poseidon2_permutation(s, 4);
    // Sentinel pad.
    s[0] = s[0] + 1;
    s = poseidon2_permutation(s, 4);
    s[0]
}

fn main(
    shadow_id:    pub Field,
    new_z_commit: pub Field,

    perm:         [Field; 16],
) {
    let _ = shadow_id;

    // Each entry must be in [0..16); accumulate a 16-bit bitmap to
    // assert distinctness. After 16 distinct entries the bitmap == 0xFFFF.
    let mut bitmap: u32 = 0;
    for i in 0..N_SLOTS {
        let v: u32 = perm[i] as u32;
        // Canonical-cast guard: the bitmap is checked against `v` but the
        // sponge below absorbs the original `perm[i]: Field`. Without this
        // assert a hostile prover could supply a Field whose low 32 bits are
        // in [0..16) while higher field bits carry arbitrary content, passing
        // the bitmap check while committing a non-canonical permutation.
        assert(perm[i] == v as Field);
        assert(v < N_SLOTS);
        // Power-of-two for `1 << v` without bit-shift on Field (use a u32
        // table-style pow2 since N_SLOTS is small).
        let bit: u32 = (1 as u32) << v;
        // Distinctness: bit must NOT already be set.
        assert((bitmap & bit) == 0);
        bitmap = bitmap | bit;
    }
    // All 16 distinct values in [0..16) sets every bit.
    assert(bitmap == 0xFFFF);

    // Bind the public commit.
    assert(sponge_16(perm) == new_z_commit);
}

// ---- Canonical-cast regression tests ----
// `nargo test` only; not compiled into the proving artifact.

fn identity_perm() -> [Field; 16] {
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
}

#[test]
fn test_happy_path_canonical_perm() {
    let perm = identity_perm();
    let commit = sponge_16(perm);
    main(0, commit, perm);
}

#[test(should_fail)]
fn test_rejects_high_bit_field_with_canonical_low_bits() {
    // Hostile witness: perm[0] has low 32 bits == 7 (which would pass the
    // bitmap check pre-fix) but high field bits non-zero. The sponge would
    // absorb the full field value, producing a commitment that does NOT
    // correspond to a permutation of [0..15]. The canonical-cast assert
    // `perm[i] == v as Field` MUST reject this.
    let mut perm: [Field; 16] = identity_perm();
    // (1 << 32) + 7 -- low 32 bits = 7 (slot 0 is currently 0; we swap 0<->7)
    let high_bits_seven: Field = 4294967303;
    perm[0] = high_bits_seven;  // was 0
    perm[7] = 0;                // was 7, keeps bitmap distinct under truncation
    let commit = sponge_16(perm);
    main(0, commit, perm);
}

#[test(should_fail)]
fn test_rejects_oversized_canonical_value() {
    // perm[i] outside [0..16) must fail the range check. Pre-fix this might
    // have failed already via `v < N_SLOTS`; we keep the test for coverage.
    let mut perm = identity_perm();
    perm[0] = 16;
    perm[1] = 1;  // currently 1; collision -- but range check fires first.
    let commit = sponge_16(perm);
    main(0, commit, perm);
}
