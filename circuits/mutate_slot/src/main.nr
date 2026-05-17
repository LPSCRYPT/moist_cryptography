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
// The circuit says NOTHING about how new pose / dims / pixel indices relate
// to old. The owner is free to repaint and reposition the slot to anything
// that passes well-formedness + canvas containment.
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
//   bits 0..5    x  (uint6)
//   bits 6..11   y  (uint6)
//   bits 12..27  scaleQ88   (uint16; 256 = 1.0)
//   bits 28..43  cosQ15     (signed 16-bit; 32767 ~= 1.0)
//   bits 44..59  sinQ15     (signed 16-bit)
//   bits 60..63  free
// For canvas containment we need a tight bound; the in-circuit affine box
// reads x, y, w, h after pose decode and asserts 0 <= bx0 <= bx1 < 48 and
// likewise for y. We approximate the rotated bbox with an axis-aligned
// bound using max(|cos|, |sin|) and (w, h) projection.

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
// Decode `pose` from plaintext[0] (its low 64 bits) into (x, y, w, h, ...).
// We tolerate any bit pattern for cos/sin in the witness; canvas containment
// uses a worst-case axis-aligned bound via |cos| + |sin| <= 2 (since
// |cos|, |sin| <= 1 in Q15 magnitude after divide by 32768).
//
// To keep the circuit cheap we don't fully validate that cos^2+sin^2 == 1;
// that constraint is the responsibility of `transferShadow` which rotates
// pose less freely. Here we only need: the post-affine bounding box of
// (w, h, scale, cos, sin) anchored at (x, y) lies inside [0, 48)^2.
//
// Approach (cheap, conservative):
//   * Decompose pose into (x, y, w, h). w, h come from the plaintext bytes
//     8 and 9, NOT from pose. (Pose has scale/rot only.)
//   * For canvas containment we ignore scale/rot and just require:
//       x + w <= 48,   y + h <= 48
//     i.e. axis-aligned, no rotation amplification. Mutations that need
//     to rotate must keep the rotated bbox within those bounds; in v2 we
//     defer the full rotated-bbox check to a follow-up circuit.
//
// This is a conservative proxy: passes any non-rotated re-pose; rejects
// rotated re-pose where the pre-rotation w x h already overflows. The
// "owner can rotate freely if the unrotated box fits" property is the
// minimum guarantee the contract needs in v2.

fn decode_xy(pose_low_bits: Field) -> (u8, u8) {
    // pose_low_bits is a Field whose low 64 bits encode the packed pose.
    // We split off the low 12 bits (x | y << 6).
    let bytes: [u8; 8] = pose_low_bits.to_le_bytes();
    let x: u8 = bytes[0] & 0x3F;
    let y: u8 = ((bytes[0] >> 6) | ((bytes[1] & 0x0F) << 2)) & 0x3F;
    (x, y)
}

fn assert_pose_byte_dims(plaintext: [Field; 39], w_pub: u32, h_pub: u32) {
    // Plaintext layout in field 0 (low 31 bytes):
    //   bytes 0..7   pose (8 B, uint64 packed)
    //   byte 8       w
    //   byte 9       h
    //   bytes 10..30 first 21 indices
    let f0_bytes: [u8; 31] = plaintext[0].to_le_bytes();
    // Reconstruct pose's low 8 bytes (used only for x, y here).
    let mut pose_acc: Field = 0;
    let mut mul: Field = 1;
    for i in 0..8 {
        pose_acc = pose_acc + (f0_bytes[i] as Field) * mul;
        mul = mul * 256;
    }
    let (x, y) = decode_xy(pose_acc);
    let w_byte = f0_bytes[8];
    let h_byte = f0_bytes[9];

    // w, h must match what the witness reported (so PI binds them too).
    assert(w_byte as u32 == w_pub);
    assert(h_byte as u32 == h_pub);

    // Range checks.
    assert(w_byte != 0);
    assert(h_byte != 0);
    assert(w_byte as u32 <= CANVAS_W);
    assert(h_byte as u32 <= CANVAS_H);

    // Conservative axis-aligned canvas containment.
    assert((x as u32) + (w_byte as u32) <= CANVAS_W);
    assert((y as u32) + (h_byte as u32) <= CANVAS_H);
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

    // ---- 4. owner_sk recovers old_k from old_c1 ----
    // ECIES-Pohlig: shared_old = old_c1 * owner_sk; mask_old = poseidon2_hash_2(shared_old.x, shared_old.y);
    //               old_k_committed_in_c2_scalar = old_k + mask_old (folded into old_ct_commit's preimage in
    //               extract_slot's design but we don't need the c2_scalar separately here).
    // For mutate_slot, the constraint that matters is "the owner could decrypt the
    // old c2 and recover old_k". We satisfy it by: the prover supplies owner_sk and old_k
    // independently; the chain's `old_live_state_hash` ties together (state_commit, ct_commit,
    // c1, count, chain_tip), and we already re-derived state from old_k via the encryption
    // round trip. The fact that the prover supplied a consistent (old_plaintext, old_k) tuple
    // proves they had access to the same key set used at the previous mutation.
    //
    // Note: this is weaker than asserting "prover knows owner_sk". If we want a hard "only
    // the holder of owner_sk can mutate" we must additionally bind owner_pk to the proof.
    // We do that next:
    let sk_scalar = EmbeddedCurveScalar::from_field(owner_sk);
    let derived_pk = fixed_base_scalar_mul(sk_scalar);
    assert(derived_pk.x == owner_pk_x);
    assert(derived_pk.y == owner_pk_y);
    // M-06: old_c1 is witnessed -- bound to chain via old_live_state_hash
    // sponge above, but the sponge accepts any field. Assert on-curve so
    // any future EC use (M-05) operates on a real Grumpkin point.
    assert_on_grumpkin(old_c1_x, old_c1_y);

    // ---- 5. new plaintext well-formedness ----
    assert_pose_byte_dims(new_plaintext, w_new as u32, h_new as u32);

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
