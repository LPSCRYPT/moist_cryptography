// solve_shadow_v2: incrementally reveal one hidden occupied feature slot.
//
// The contract supplies the current manifest entry and palette commitment as
// public inputs. The circuit proves the current owner can decrypt the slot and
// that the emitted plaintext opens the slot's current liveStateHash.

use std::hash::poseidon2_permutation;
use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar,
    multi_scalar_mul, fixed_base_scalar_mul,
};

global PLAINTEXT_FIELDS: u32 = 39;

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

// KDF domain separation. MUST stay byte-for-byte identical with the v2
// mutation/transfer circuits and v2_circuit_helpers.py::kdf.
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

fn assert_plaintext_palette_indices_10(plaintext: [Field; 39]) {
    let f0_bytes: [u8; 31] = plaintext[0].to_le_bytes();
    let w_byte = f0_bytes[8];
    let h_byte = f0_bytes[9];
    assert(w_byte != 0);
    assert(h_byte != 0);
    assert(w_byte as u32 <= 48);
    assert(h_byte as u32 <= 48);

    // Canonical palette membership. Padding nibbles after w*h are ignored.
    let pixel_count = (w_byte as u32) * (h_byte as u32);
    for f in 0..PLAINTEXT_FIELDS {
        let bytes: [u8; 31] = plaintext[f].to_le_bytes();
        for j in 0..31 {
            let offset = f * 31 + j;
            if (offset >= 10) & (offset < 1162) {
                let pixel0 = (offset - 10) * 2;
                if pixel0 < pixel_count {
                    assert((bytes[j] & 0x0f) <= 9);
                }
                if (pixel0 + 1) < pixel_count {
                    assert(((bytes[j] >> 4) & 0x0f) <= 9);
                }
            }
        }
    }
}

fn main(
    // public inputs (9), matched by ShadowToken._verifyRevealSlotProof
    shadow_id:           pub Field,
    slot_idx:            pub Field,
    feature_id:          pub Field,
    live_state_hash:     pub Field,
    state_commit:        pub Field,
    palette_commit:      pub Field,
    owner_pk_x:          pub Field,
    owner_pk_y:          pub Field,
    revealed_rank:       pub Field,

    // private witness for the current hidden slot
    plaintext:           [Field; 39],
    prev_ct_commit:      Field,
    prev_c1_x:           Field,
    prev_c1_y:           Field,
    prev_mutation_count: Field,
    prev_chain_tip:      Field,
    owner_k:             Field,
    owner_sk:            Field,
) {
    // These public inputs are contract-bound metadata. They are intentionally
    // part of the verifier transcript even though they do not have private
    // witness relations inside this slot-opening circuit.
    let _ = shadow_id;
    let _ = slot_idx;
    let _ = feature_id;
    let _ = palette_commit;
    let _ = revealed_rank;

    // Caller-is-owner binding.
    let sk_scalar = EmbeddedCurveScalar::from_field(owner_sk);
    let derived_pk = fixed_base_scalar_mul(sk_scalar);
    assert(derived_pk.x == owner_pk_x);
    assert(derived_pk.y == owner_pk_y);

    // The emitted plaintext must be the exact state commitment in PI[4].
    let sc = sponge_39(plaintext);
    assert(sc == state_commit);
    assert_plaintext_palette_indices_10(plaintext);

    // Verify ciphertext commitment under the owner-derived keystream.
    let ks = keystream_39(owner_k);
    let mut ct: [Field; 39] = [0; 39];
    for j in 0..PLAINTEXT_FIELDS {
        ct[j] = plaintext[j] + ks[j];
    }
    assert(sponge_39(ct) == prev_ct_commit);

    // Bind owner_k to ECDH(owner_sk, prev_c1). This prevents anyone who merely
    // knows an old plaintext/keystream from fabricating an owner reveal proof.
    let prev_c1_curve_lhs = prev_c1_y * prev_c1_y - prev_c1_x * prev_c1_x * prev_c1_x + 17;
    assert(prev_c1_curve_lhs == 0);
    let prev_c1_pt = EmbeddedCurvePoint {
        x: prev_c1_x,
        y: prev_c1_y,
        is_infinite: false,
    };
    let shared_prev = multi_scalar_mul([prev_c1_pt], [sk_scalar]);
    let owner_k_derived = kdf(KDF_ROLE_PLAINTEXT, shared_prev.x, shared_prev.y);
    assert(owner_k == owner_k_derived);

    // Reconstruct the liveStateHash that the contract read from the manifest.
    let lsh = sponge_6(sc, prev_ct_commit, prev_c1_x, prev_c1_y, prev_mutation_count, prev_chain_tip);
    assert(lsh == live_state_hash);
}
