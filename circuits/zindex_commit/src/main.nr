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
