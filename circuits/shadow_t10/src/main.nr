// shadow_t10: per-shadow public T10 hash, refreshed atomically on every
// state-changing operation per the v2 "no public lie" rule.
//
// In v1 the T10 was a 4-quartet rasterized grayscale silhouette. v2 spec
// downgrades T10 to a 2-quartet opaque hash that covers all 16 slots'
// current `liveStateHash` plus the per-shadow `zIndexCommit`. The property
// the contract relies on is:
//
//   "Two consecutive T10 hashes can be diffed to learn *something* changed
//    about the visible composition. None of those leaks reveal the *what*
//    of any mutation: pose deltas, pixel deltas, and timing-of-content are
//    all still hidden inside successive c2 ciphertexts."
//
// (The visual rasterization shadow_pixels is a follow-up circuit; T10 in v2
//  is solely the change-detection commitment.)
//
// Public inputs (20 Fields):
//   PI[0]       shadow_id
//   PI[1]       z_index_commit
//   PI[2]       new_t10_hi    (state_hash high 128 bits, in low 128 bits of Field)
//   PI[3]       new_t10_lo    (state_hash low 128 bits)
//   PI[4..19]   live_state_hash[0..15]
//
// Witness: none. The circuit is purely a hash check; the chain must
// recompute `new_t10` from public state and assert proof binds it.
//
// Algorithm:
//   acc      = poseidon2_sponge_19(shadow_id, z_index_commit, lsh[0..15])
//   acc_low  = acc mod 2^128
//   acc_high = acc / 2^128
//   assert new_t10_lo == acc_low
//   assert new_t10_hi == acc_high
//
// Why split high/low: the contract stores T10 as `bytes32[2]` packed as
// two 128-bit quartets per word for indexer convenience (hi, lo). The
// circuit emits the same packing.

use std::hash::poseidon2_permutation;

global N_SLOTS: u32 = 16;
// Sponge inputs: shadow_id || z_commit || 16 x liveStateHash = 18 fields.
// 18 / 3 = 6 full rate-3 blocks (no tail). Sentinel pad after.

fn sponge_18(e: [Field; 18]) -> Field {
    let mut s: [Field; 4] = [0, 0, 0, 0];
    for b in 0..6 {
        s[0] = s[0] + e[b * 3];
        s[1] = s[1] + e[b * 3 + 1];
        s[2] = s[2] + e[b * 3 + 2];
        s = poseidon2_permutation(s, 4);
    }
    s[0] = s[0] + 1;
    s = poseidon2_permutation(s, 4);
    s[0]
}

// Split a Field into (hi, lo) such that field == hi * 2^128 + lo, with
// hi, lo < 2^128. The circuit asserts both halves' bit-widths via
// to_le_bytes (32 bytes total -> 16 bytes lo + 16 bytes hi).
fn split_128(v: Field) -> (Field, Field) {
    let bytes: [u8; 32] = v.to_le_bytes();
    let mut lo: Field = 0;
    let mut hi: Field = 0;
    let mut mul: Field = 1;
    for i in 0..16 {
        lo = lo + (bytes[i] as Field) * mul;
        mul = mul * 256;
    }
    let mut mul_h: Field = 1;
    for i in 16..32 {
        hi = hi + (bytes[i] as Field) * mul_h;
        mul_h = mul_h * 256;
    }
    (hi, lo)
}

fn main(
    shadow_id:       pub Field,
    z_index_commit:  pub Field,
    new_t10_hi:      pub Field,
    new_t10_lo:      pub Field,
    live_state_hash: pub [Field; 16],
) {
    let mut buf: [Field; 18] = [0; 18];
    buf[0] = shadow_id;
    buf[1] = z_index_commit;
    for i in 0..N_SLOTS {
        buf[2 + i] = live_state_hash[i];
    }
    let acc = sponge_18(buf);
    let (hi, lo) = split_128(acc);
    assert(hi == new_t10_hi);
    assert(lo == new_t10_lo);
}
