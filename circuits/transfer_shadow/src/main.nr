// =====================================================================
// **STALE — v1 circuit, not used by v2 staging contracts.**
// The v2 transferShadow path is unimplemented (Phase 7 pending). When it
// lands it will operate per-slot (16 × 39-Field plaintexts), packing PI
// via paired-poseidon2 hash roots to stay under EIP-170. The contract
// path `ShadowToken.transferShadow` currently reverts NotImplementedYet.
// See `STAGING_REFACTOR/PROGRESS.md` Phase 7 for the v2 design sketch.
// =====================================================================

// transfer_shadow: re-encrypt a 249-Field shadow ciphertext to a new owner.
//
// Replaces the legacy 8 x sponge_48 envelope of `transfer_amalgam_8` with a
// single sponge_249 envelope: the entire shadow's encrypted payload is one
// monolithic blob (the same shape mint_shadow / landmark_regions emits at
// mint), so transfer needs only one ECIES envelope.
//
// Public inputs (8 Fields):
//   PI[0]      shadow_id            (binds the proof to a specific shadow on chain)
//   PI[1]      next_pk_x            (recipient Grumpkin pk x)
//   PI[2]      next_pk_y            (recipient Grumpkin pk y)
//   PI[3]      c1_x                 (ECIES ephemeral pk x = G * new_r)
//   PI[4]      c1_y                 (ECIES ephemeral pk y)
//   PI[5]      c2_scalar            (= new_k + Poseidon2(shared.x, shared.y))
//   PI[6]      new_ct_commit        (= sponge_249(re-encrypted ct))
//   PI[7]      prev_ct_commit       (must match chain.shadows[shadow_id].c2Commit)
//
// Witness (private):
//   plaintext[249]                  (the underlying recolored-pixels payload)
//   prev_k                          (previous owner's keystream secret)
//   new_k                           (new owner's keystream secret)
//   new_r                           (new ECIES randomness)
//
// What's proved:
//   1. sponge_249(plaintext + keystream(prev_k)) == prev_ct_commit
//      (the witness plaintext IS the value the previous c2_commit binds to;
//       only someone who could decrypt the previous c2 can know plaintext)
//   2. new_ct = plaintext + keystream(new_k); sponge_249(new_ct) == new_ct_commit
//      (the new c2 encrypts the SAME plaintext under the new owner's pk)
//   3. c1 = G * new_r; c2_scalar = new_k + Poseidon2(shared.x, shared.y) where
//      shared = next_pk * new_r
//      (well-formed ECIES envelope to recipient pk)
//
// shadow_id is bound to the proof at the contract level via a PI equality check
// (the contract reads stored c2Commit and asserts pi[7] == it; the proof binds
//  pi[7] to the witness plaintext).

use std::hash::poseidon2_permutation;
use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar,
    multi_scalar_mul, fixed_base_scalar_mul,
};

global N_FIELDS: u32 = 249;
global N_KEYSTREAM_BLOCKS: u32 = 83; // 249 = 83 * 3, multiple of 3 for rate-3 sponge

// ---------- Poseidon2 sponge_249 (rate 3, sentinel padding) ----------
// 83 absorb blocks + sentinel pad. Bit-exact with the Yul Poseidon2YulSponge
// contract over 7,968 bytes of calldata.
fn sponge_249(e: [Field; 249]) -> Field {
    let mut s: [Field; 4] = [0, 0, 0, 0];
    for b in 0..N_KEYSTREAM_BLOCKS {
        s[0] = s[0] + e[b * 3];
        s[1] = s[1] + e[b * 3 + 1];
        s[2] = s[2] + e[b * 3 + 2];
        s = poseidon2_permutation(s, 4);
    }
    s[0] = s[0] + 1; // sentinel
    s = poseidon2_permutation(s, 4);
    s[0]
}

fn poseidon2_hash_2(x: Field, y: Field) -> Field {
    let out = poseidon2_permutation([x, y, 0, 0], 4);
    out[0]
}

// Generate 249 keystream Fields from a single seed `k`.
// Block i = Poseidon2([k, i, 0, 0]); take its first 3 outputs as elements
// (i*3, i*3+1, i*3+2). 83 blocks * 3 = 249.
fn keystream_249(k: Field) -> [Field; 249] {
    let mut ks: [Field; 249] = [0; 249];
    for b in 0..N_KEYSTREAM_BLOCKS {
        let block = poseidon2_permutation([k, b as Field, 0, 0], 4);
        ks[b * 3]     = block[0];
        ks[b * 3 + 1] = block[1];
        ks[b * 3 + 2] = block[2];
    }
    ks
}

fn main(
    // Public inputs (8)
    shadow_id:        pub Field,
    next_pk_x:        pub Field,
    next_pk_y:        pub Field,
    c1_x:             pub Field,
    c1_y:             pub Field,
    c2_scalar:        pub Field,
    new_ct_commit:    pub Field,
    prev_ct_commit:   pub Field,

    // Private witness
    plaintext:        [Field; 249],
    prev_k:           Field,
    new_k:            Field,
    new_r:            Field,
) {
    // shadow_id is just bound to the proof transcript -- the contract maps it
    // to chain state via pi[0] equality. We do nothing in-circuit with it.
    let _ = shadow_id;

    // ---- 1. Verify previous binding: plaintext + keystream(prev_k) hashes
    //         to prev_ct_commit ----
    let prev_ks = keystream_249(prev_k);
    let mut prev_ct: [Field; 249] = [0; 249];
    for i in 0..N_FIELDS {
        prev_ct[i] = plaintext[i] + prev_ks[i];
    }
    assert(sponge_249(prev_ct) == prev_ct_commit);

    // ---- 2. Re-encrypt under new_k; verify new sponge ----
    let new_ks = keystream_249(new_k);
    let mut new_ct: [Field; 249] = [0; 249];
    for i in 0..N_FIELDS {
        new_ct[i] = plaintext[i] + new_ks[i];
    }
    assert(sponge_249(new_ct) == new_ct_commit);

    // ---- 3. ECIES envelope to recipient pk ----
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
