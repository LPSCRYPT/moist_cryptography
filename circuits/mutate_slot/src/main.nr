// mutate_slot: canonical v2 mutation primitive.
//
// Prove that:
//   1. The prover knows owner_sk such that the owner's pubkey is the same
//      one bound into both the old and the new ECIES encryptions.
//   2. The prover knows the OLD plaintext (i.e. they decrypted the on-chain
//      ciphertext) and that plaintext sponge-hashes to the old_state_commit
//      folded inside old_live_state_hash.
//   3. The NEW plaintext is well-formed: 1 <= w, h <= 48; the affine
//      bounding box of (pose, w, h) is contained in [0, 48)^2.
//   4. The NEW c2 is the symmetric-keystream encryption of new plaintext
//      under a fresh ephemeral c1 + the SAME owner pubkey.
//   5. new_live_state_hash = poseidon2_sponge(new_state_commit, new_ct_commit,
//      new_c1_x, new_c1_y, new_count, new_chain_tip), where new_chain_tip
//      extends old_chain_tip by exactly one mutation event.
//
// Mutation is deliberately pose-only. The new plaintext must preserve the
// feature's dimensions and packed palette-index payload byte-for-byte; exactly
// one pose class may change: rotation, scale, or x/y translation.
//
// Public inputs (16 Fields):
//   PI[0]   shadow_id              (chain-level binding only; transcript-only here)
//   PI[1]   slot_idx               (0..15)
//   PI[2]   feature_id             (must match manifest[slot].featureId on chain)
//   PI[3]   type_idx               (0..7; asserted unchanged from FeatureNFT)
//   PI[4]   origin_face_id         (asserted unchanged from FeatureNFT)
//   PI[5]   palette_commit         (asserted unchanged from FeatureNFT)
//   PI[6]   old_live_state_hash    (== chain manifest[slot].liveStateHash)
//   PI[7]   new_live_state_hash    (written to chain on success)
//   PI[8]   new_ct_commit          (= sponge_39 of new c2; for chain calldata bind)
//   PI[9]   c2_field_count         (used field count of new c2 plaintext; contract length-checks calldata)
//   PI[10]  owner_pk_x             (== KeyRegistry pk for the caller)
//   PI[11]  owner_pk_y
//   PI[12]  prev_chain_tip         (= old_chain_tip; for ShadowSlotMutated event indexer chain reconstruction)
//   PI[13]  new_chain_tip          (post-extension)
//   PI[14]  prev_mutation_count    (uint16 in chain semantics)
//   PI[15]  new_mutation_count     (== prev + 1)
//
// Witness (private):
//   old_plaintext, new_plaintext        : [Field; 39]    (pose | w | h | indices | zero pad)
//   old_state_commit, old_ct_commit     : Field          (folded into old_live_state_hash)
//   old_c1_x, old_c1_y                  : Field
//   old_mutation_count                  : Field          (uint16 in upper logic)
//   old_chain_tip                       : Field
//   old_k                               : Field          (old keystream key)
//   new_k                               : Field          (new keystream key, fresh)
//   new_r                               : Field          (new ECIES ephemeral scalar)
//   owner_sk                            : Field          (owner secret key)
//
// Out-of-scope (consumed elsewhere):
//   - palette membership: 4-bit indices are by construction in [0, 16); the
//     paletteCommit is asserted unchanged via PI binding only.
//   - per-slot c2 calldata sponge binding: contract checks
//     sponge(c2_calldata) == PI[new_ct_commit].
//   - replay resistance: PI[6] (old_live_state_hash) must equal the chain's
//     current value; replay of stale (old, new) pair fails because chain
//     advances past `old`.

use std::hash::poseidon2_permutation;
use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar,
    multi_scalar_mul, fixed_base_scalar_mul,
};

// ---- size constants ----

// 39 fields = 13 sponge blocks (rate-3, capacity-1, sentinel pad). Multiple
// of 3 by construction so the on-chain Yul Poseidon2 sponge can hash the
// c2 calldata directly without padding gymnastics. Field 38 is reserved as
// a hard-coded zero pad to keep the encoding deterministic.
global PLAINTEXT_FIELDS: u32 = 39;

global CANVAS_W: u32 = 48;
global CANVAS_H: u32 = 48;

// Q-formats used inside `pose`:
//   bits 0..5    x             (uint6)
//   bits 6..11   y             (uint6)
//   bits 12..27  scaleQ88      (uint16; 256 = 1.0)
//   bits 28..29  quarterTurns  (uint2; clockwise 90-degree turns)
//   bits 30..63  reserved      (must be zero)
// Canvas containment uses the scaled extent and swaps width/height for
// 90/270-degree turns while keeping the scaled feature center fixed.

// ---- Poseidon2 sponge variants ----

// Generic absorb-rate-3, capacity-1 sponge over `n` field elements
// (with one trailing absorb of the constant 1 to act as a length tag).
// Mirrors the v1 sponge_249/sponge_42 pattern so prover/verifier
// implementations on chain (Yul Poseidon2 sponge) can match byte-for-byte.
fn sponge_39(e: [Field; 39]) -> Field {
    let mut s: [Field; 4] = [0, 0, 0, 0];
    // 13 full rate-3 blocks. No tail.
    for b in 0..13 {
        s[0] = s[0] + e[b * 3];
        s[1] = s[1] + e[b * 3 + 1];
        s[2] = s[2] + e[b * 3 + 2];
        s = poseidon2_permutation(s, 4);
    }
    // Final length-tag absorb.
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
// which is mod P). Rejects (0, 0) automatically since 0 != -17 mod P,
// so identity-at-infinity coordinates cannot pass. owner_pk is bound
// on-curve by construction below via owner_sk * G == owner_pk; the
// witness `old_c1` is checked here so M-05's owner_sk * old_c1 bind
// operates on a real Grumpkin point.
fn assert_on_grumpkin(x: Field, y: Field) {
    assert(y * y == x * x * x - 17);
}

// poseidon2_sponge over a fixed 6-element tuple; matches the
// liveStateHash schema:
//   liveStateHash = sponge_6(stateCommit, ctCommit, c1X, c1Y, count, chainTip).
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

// poseidon2_sponge over the chain-step preimage:
//   newChainTip = sponge_6(prev_chain_tip, new_state_commit, new_ct_commit,
//                          new_count, origin_face_id, slot_idx).
// Same shape as `sponge_6` but distinct inputs; reuses the function.

// ---- ECIES-Pohlig keystream ----

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

// ---- pose decode + canvas containment ----
//
// Decode `pose` from plaintext[0] (its low 64 bits) into x/y, scale, and
// a discrete quarter-turn orientation. Arbitrary cos/sin rotation is not a
// protocol state anymore; bits 30..63 are reserved and must be zero.
//
// `x`/`y` are the unrotated top-left. Rotation is around the scaled feature
// center, so 90/270-degree turns swap the scaled width/height around that
// center before the frame-bound check.

fn decode_pose(pose_low_bits: Field) -> (u8, u8, u32, u8) {
    let bytes: [u8; 8] = pose_low_bits.to_le_bytes();
    let x: u8 = bytes[0] & 0x3F;
    let y: u8 = ((bytes[0] >> 6) | ((bytes[1] & 0x0F) << 2)) & 0x3F;
    let scale_q88: u32 = ((bytes[1] >> 4) as u32)
        + ((bytes[2] as u32) << 4)
        + (((bytes[3] & 0x0F) as u32) << 12);
    let quarter_turns: u8 = (bytes[3] >> 4) & 0x03;
    assert((bytes[3] & 0xC0) == 0);
    assert(bytes[4] == 0);
    assert(bytes[5] == 0);
    assert(bytes[6] == 0);
    assert(bytes[7] == 0);
    (x, y, scale_q88, quarter_turns)
}

fn ceil_scale(dim: u32, scale_q88: u32) -> u32 {
    ((dim * scale_q88) + 255) / 256
}

fn pose_low64_from_field0(field0: Field) -> Field {
    let f0_bytes: [u8; 31] = field0.to_le_bytes();
    let mut pose_acc: Field = 0;
    let mut mul: Field = 1;
    for i in 0..8 {
        pose_acc = pose_acc + (f0_bytes[i] as Field) * mul;
        mul = mul * 256;
    }
    pose_acc
}


fn assert_pose_byte_dims(plaintext: [Field; 39], w_pub: u32, h_pub: u32) {
    // Plaintext layout in field 0 (low 31 bytes):
    //   bytes 0..7   pose (8 B, uint64 packed)
    //   byte 8       w
    //   byte 9       h
    //   bytes 10..30 first 21 indices
    let f0_bytes: [u8; 31] = plaintext[0].to_le_bytes();
    let (x, y, scale_q88, quarter_turns) = decode_pose(pose_low64_from_field0(plaintext[0]));
    let w_byte = f0_bytes[8];
    let h_byte = f0_bytes[9];

    // w, h must match what the witness reported (so PI binds them too).
    assert(w_byte as u32 == w_pub);
    assert(h_byte as u32 == h_pub);

    // Range checks.
    assert(w_byte != 0);
    assert(h_byte != 0);
    assert(scale_q88 != 0);
    assert(w_byte as u32 <= CANVAS_W);
    assert(h_byte as u32 <= CANVAS_H);

    // Center-fixed scaled quarter-turn canvas containment.
    let scaled_w = ceil_scale(w_byte as u32, scale_q88);
    let scaled_h = ceil_scale(h_byte as u32, scale_q88);
    let is_sideways = (quarter_turns & 1) == 1;
    let extent_w = if is_sideways { scaled_h } else { scaled_w };
    let extent_h = if is_sideways { scaled_w } else { scaled_h };
    let center2_x = (x as u32) * 2 + scaled_w;
    let center2_y = (y as u32) * 2 + scaled_h;
    assert(center2_x >= extent_w);
    assert(center2_y >= extent_h);
    assert((center2_x + extent_w + 1) / 2 <= CANVAS_W);
    assert((center2_y + extent_h + 1) / 2 <= CANVAS_H);
}

fn assert_pose_only_single_mutation(old_plaintext: [Field; 39], new_plaintext: [Field; 39]) {
    let old_f0_bytes: [u8; 31] = old_plaintext[0].to_le_bytes();
    let new_f0_bytes: [u8; 31] = new_plaintext[0].to_le_bytes();

    // Bytes after the 8-byte pose in field 0 are dimensions + packed pixels.
    // They are not mutable through mutate_slot.
    for i in 8..31 {
        assert(old_f0_bytes[i] == new_f0_bytes[i]);
    }
    for i in 1..PLAINTEXT_FIELDS {
        assert(old_plaintext[i] == new_plaintext[i]);
    }

    let (old_x, old_y, old_scale_q88, old_quarter_turns) = decode_pose(pose_low64_from_field0(old_plaintext[0]));
    let (new_x, new_y, new_scale_q88, new_quarter_turns) = decode_pose(pose_low64_from_field0(new_plaintext[0]));

    let rotation_changed: Field = if old_quarter_turns == new_quarter_turns { 0 } else { 1 };
    let scale_changed: Field = if old_scale_q88 == new_scale_q88 { 0 } else { 1 };
    let translation_changed: Field = if (old_x == new_x) & (old_y == new_y) { 0 } else { 1 };

    // Exactly one class may change. Rejects exact no-ops and combined transforms.
    assert(rotation_changed + scale_changed + translation_changed == 1);
}


// ---- main ----

fn main(
    // public inputs (12)
    shadow_id:           pub Field,
    slot_idx:            pub Field,
    feature_id:          pub Field,
    type_idx:            pub Field,
    origin_face_id:      pub Field,
    palette_commit:      pub Field,
    old_live_state_hash: pub Field,
    new_live_state_hash: pub Field,
    new_ct_commit:       pub Field,
    c2_field_count:      pub Field,
    owner_pk_x:          pub Field,
    owner_pk_y:          pub Field,
    prev_chain_tip:      pub Field,
    new_chain_tip_pi:    pub Field,
    prev_mutation_count: pub Field,
    new_mutation_count_pi: pub Field,

    // witness
    old_plaintext:       [Field; 39],
    new_plaintext:       [Field; 39],
    old_state_commit:    Field,
    old_ct_commit:       Field,
    old_c1_x:            Field,
    old_c1_y:            Field,
    old_mutation_count:  Field,
    old_chain_tip:       Field,
    old_k:               Field,
    new_k:               Field,
    new_r:               Field,
    owner_sk:            Field,

    // public dims (witness, not PI; folded into new_state_commit via plaintext)
    w_new:               Field,
    h_new:               Field,
    c2_field_count_w:    Field,  // mirror of PI[c2_field_count] passed as witness for deterministic encoding
) {
    // ---- 0. transcript-only PI hooks (silence unused warnings) ----
    let _ = shadow_id;
    let _ = feature_id;
    let _ = type_idx;
    let _ = origin_face_id;
    let _ = palette_commit;
    // slot_idx is used in chain-tip extension (below).

    assert(c2_field_count == c2_field_count_w);

    // ---- 1. old_live_state_hash binds the witness's view of the old slot ----
    let lsh_old_recomputed = sponge_6(
        old_state_commit,
        old_ct_commit,
        old_c1_x,
        old_c1_y,
        old_mutation_count,
        old_chain_tip,
    );
    assert(lsh_old_recomputed == old_live_state_hash);

    // ---- 2. old plaintext sponge-hashes to old_state_commit ----
    assert(sponge_39(old_plaintext) == old_state_commit);

    // ---- 3. old plaintext, encrypted under old_k, is the chain's c2 ----
    let old_ks = keystream_39(old_k);
    let mut old_ct: [Field; 39] = [0; 39];
    for i in 0..PLAINTEXT_FIELDS {
        old_ct[i] = old_plaintext[i] + old_ks[i];
    }
    assert(sponge_39(old_ct) == old_ct_commit);

    // ---- 4. owner_sk binding + old_k ECDH derivation ----
    //
    // Two bindings, both required for soundness of "the caller is the
    // current owner AND knew the previous ciphertext's key":
    //
    //   (a) owner_sk * G == owner_pk_x/y
    //       Caller controls the secret key matching the on-chain owner pk.
    //
    //   (b) owner_sk * old_c1 -> kdf -> equals witnessed old_k
    //       (audit M-05) Asserts old_k was actually derivable from
    //       (old_c1, owner_sk) via ECIES-Pohlig, not just supplied as a
    //       freestanding witness. Without this, a non-owner who leaked a
    //       past keystream key could mutate the slot. Pairs with M-06's
    //       on-curve check on old_c1.
    let sk_scalar = EmbeddedCurveScalar::from_field(owner_sk);
    let derived_pk = fixed_base_scalar_mul(sk_scalar);
    assert(derived_pk.x == owner_pk_x);
    assert(derived_pk.y == owner_pk_y);

    // M-06: old_c1 must be on Grumpkin before feeding MSM below.
    assert_on_grumpkin(old_c1_x, old_c1_y);

    // M-05: derive old_k from (owner_sk, old_c1) and bind to witness.
    let old_c1_pt = EmbeddedCurvePoint {
        x: old_c1_x,
        y: old_c1_y,
        is_infinite: false,
    };
    let shared_old = multi_scalar_mul([old_c1_pt], [sk_scalar]);
    let old_k_derived = kdf(KDF_ROLE_PLAINTEXT, shared_old.x, shared_old.y);
    assert(old_k == old_k_derived);

    // ---- 5. new plaintext well-formedness ----
    assert_pose_byte_dims(new_plaintext, w_new as u32, h_new as u32);

    // Mutate is pose-only and permits exactly one transform class per proof:
    // rotation, scale, or translation. This rejects no-ops, combined transforms,
    // dimension changes, and repaint/recolor/payload rewrites.
    assert_pose_only_single_mutation(old_plaintext, new_plaintext);

    // ---- 6. new c2 = encrypt(new_plaintext, new_k, owner_pk) ----
    let new_ks = keystream_39(new_k);
    let mut new_ct: [Field; 39] = [0; 39];
    for i in 0..PLAINTEXT_FIELDS {
        new_ct[i] = new_plaintext[i] + new_ks[i];
    }
    let new_state_commit_local = sponge_39(new_plaintext);
    let new_ct_commit_local = sponge_39(new_ct);
    assert(new_ct_commit_local == new_ct_commit);

    // ---- 7. fresh ECIES ephemeral c1 + ECDH binding ----
    // The new c1 is computed from new_r * G (fixed-base scalar mul).
    // M-06: r != 0 rejects the degenerate (c1 = O, shared = O) envelope.
    assert(new_r != 0);
    let r_scalar = EmbeddedCurveScalar::from_field(new_r);
    let new_c1 = fixed_base_scalar_mul(r_scalar);

    // The owner pubkey, on Grumpkin, is owner_sk * G; we already asserted it
    // equals (owner_pk_x, owner_pk_y) above. Recompute the shared point
    // shared = new_c1 * owner_sk for keystream key derivation.
    let owner_pk_pt = EmbeddedCurvePoint {
        x: owner_pk_x,
        y: owner_pk_y,
        is_infinite: false,
    };
    let shared = multi_scalar_mul([owner_pk_pt], [r_scalar]);
    let mask_new = kdf(KDF_ROLE_PLAINTEXT, shared.x, shared.y);

    // Bind: new_k must equal the mask-derived key for the new envelope.
    // (Equivalently: c2_scalar = new_k + mask is = 2 * mask, but here we just
    //  enforce new_k == mask, simplifying the envelope to a deterministic
    //  per-(c1, owner_pk) keystream.)
    assert(new_k == mask_new);

    // ---- 8. new chain tip extends old chain tip ----
    let new_count = old_mutation_count + 1;
    let new_chain_tip = sponge_6(
        old_chain_tip,
        new_state_commit_local,
        new_ct_commit_local,
        new_count,
        origin_face_id,
        slot_idx,
    );
    // Bind: PI must commit to the same chain step the witness derived.
    assert(prev_chain_tip == old_chain_tip);
    assert(new_chain_tip_pi == new_chain_tip);
    assert(prev_mutation_count == old_mutation_count);
    assert(new_mutation_count_pi == new_count);

    // ---- 9. new_live_state_hash binds new state ----
    let lsh_new_recomputed = sponge_6(
        new_state_commit_local,
        new_ct_commit_local,
        new_c1.x,
        new_c1.y,
        new_count,
        new_chain_tip,
    );
    assert(lsh_new_recomputed == new_live_state_hash);
}
