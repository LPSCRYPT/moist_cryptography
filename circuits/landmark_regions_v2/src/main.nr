// landmark_regions_v2: emit 8 origin per-slot ECIES bundles for a fresh
// shadow mint.
//
// Design split (v2): the original v1 `landmark_regions` circuit fused
// (a) the CNN landmark detector and (b) the per-slot bundle emitter
// into a single proof. v2 splits these:
//
//   - `face_disc` proves the input image is a face (CNN classifier),
//     output: image_commit.
//   - `landmark_regions_v2` (this circuit) proves a fresh shadow's
//     8 origin slots are well-formed ECIES bundles to a given owner_pk.
//
// The two proofs are bound at the contract level: both expose
// image_commit and the contract asserts equality.
//
// Slots filled at mint: indices 0..7. Slots 8..15 stay EMPTY
// (lsh = 0, manifest entry zero-valued).
//
// Per-slot work for i in 0..8:
//   - state_commit[i] = sponge_39(plaintext[i])
//   - new ECIES: c1[i] = G * r[i]; shared = owner_pk * r[i]
//                k[i]  = kdf(KDF_ROLE_PLAINTEXT, shared.x, shared.y)   (audit L-01)
//   - ks[i] = keystream_39(k[i])
//   - ct[i] = plaintext[i] + ks[i]
//   - ct_commit[i] = sponge_39(ct[i])
//   - origin_face_id[i] = poseidon2_hash_2(image_commit, i)
//   - chain_tip[i] = sponge_4(MINT_TAG, origin_face_id[i], owner_pk_x, owner_pk_y)
//   - lsh_init[i]  = sponge_6(state_commit[i], ct_commit[i],
//                             c1.x, c1.y, /*mut_count=*/0, chain_tip[i])
//
// Hash-roots fold the 8 per-slot arrays into single PI fields so the
// total PI count stays at 7 (well under EIP-170 budget).
//
// PI shape (7):
//   PI[0]  shadow_id            (transcript only; chain binds via PI[0] equality)
//   PI[1]  image_commit         (binds to face_disc proof; supplied as pub)
//   PI[2]  owner_pk_x
//   PI[3]  owner_pk_y
//   PI[4]  lsh_inits_root       = sponge_8_pad16(lsh_init[0..7])
//   PI[5]  ct_commits_root      = sponge_8_pad16(ct_commit[0..7])
//   PI[6]  chain_tips_root      = sponge_8_pad16(chain_tip[0..7])
//
// Notes:
//   - palette_commit per slot is owner-supplied calldata; the contract
//     stores it on each FeatureNFT directly. No proof binding needed
//     since the owner is the only party who knows the palette anyway;
//     mis-committing a palette only breaks rendering for the owner.
//   - state_commits are NOT exposed in PI; they are recovered by anyone
//     who knows the plaintext (post-solve). Mid-flight, only the owner
//     can recompute them. They're embedded inside lsh_init.
//   - origin_face_id uses image_commit so all 8 carriers minted from
//     the same image share a face-binding; the contract verifies via
//     poseidon2_hash_2 in Solidity (PoseLib).
//   - MINT_TAG is a chain-tip domain separator distinct from
//     TRANSFER_TAG (transfer_shadow_v2) so that mint and transfer
//     events cannot collide in chain-tip space.

use std::hash::poseidon2_permutation;
use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar,
    multi_scalar_mul, fixed_base_scalar_mul,
};

global PLAINTEXT_FIELDS: u32 = 39;
global N_MINT_SLOTS: u32 = 8;

// Domain-separation tag for the mint chain-tip. Distinct from
// TRANSFER_TAG (= 0x1ad75ff_a_e4_711a5_fe_a7_e_ed) used by
// transfer_shadow_v2. Picked as a public, gas-cheap nonzero constant;
// same tag is hardcoded in the contract.
global MINT_TAG: Field = 0x9100_15_e_5_a_b_a_d_4_3_e_0_a_d_d_e_d_d_a_7_a; // arbitrary nonzero, distinct

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

fn poseidon2_hash_2(a: Field, b: Field) -> Field {
    let out = poseidon2_permutation([a, b, 0, 0], 4);
    out[0]
}

// ---- KDF domain separation (audit L-01) ----
//
// Single global domain tag for every ECIES shared-secret -> keystream-key
// derivation in the v2 pipeline. Distinguishes KDF outputs from any other
// Poseidon2 hash use (chain-tip extension, lineage IDs, state commits) so
// a chance collision between an ECDH shared x-coord and an unrelated
// Poseidon2 output cannot leak the keystream key.
//
// Role tags distinguish the plaintext keystream KDF from the salt-envelope
// KDF so the same (c1, owner_pk) pair derives two cryptographically
// independent keys. The mint circuit only uses ROLE_PLAINTEXT (the salt
// envelope is encrypted off-chain in tools/v2_circuit_helpers.py).
//
// MUST stay byte-for-byte identical with v2_circuit_helpers.py::kdf and
// with every other v2 circuit's `kdf`. Changing the constant requires
// pipeline redeploy + full fixture regen.
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
// so identity-at-infinity coordinates cannot pass. Without this check,
// `multi_scalar_mul([owner_pk], [r])` will operate on attacker-supplied
// coordinates and produce a shared point under the attacker's control.
fn assert_on_grumpkin(x: Field, y: Field) {
    assert(y * y == x * x * x - 17);
}

// 4-element absorb: 1 rate-3 block + 1-element partial absorb + sentinel.
// Used for chain_tip[i] = sponge_4(MINT_TAG, origin_face_id, pk_x, pk_y).
// Distinct shape from sponge_6 (mutate/transfer LSH) so transcripts
// cannot collide.
fn sponge_4(a: Field, b: Field, c: Field, d: Field) -> Field {
    let mut s: [Field; 4] = [0, 0, 0, 0];
    s[0] = s[0] + a;
    s[1] = s[1] + b;
    s[2] = s[2] + c;
    s = poseidon2_permutation(s, 4);
    s[0] = s[0] + d;
    s = poseidon2_permutation(s, 4);
    s[0] = s[0] + 1;
    s = poseidon2_permutation(s, 4);
    s[0]
}

// 6-element absorb: 2 rate-3 blocks + sentinel. Same as transfer/solve
// per-slot lsh sponge.
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

// 16-element absorb (reused on chain via Poseidon2YulSponge16). 5
// rate-3 blocks + rate-1 partial absorb + sentinel. Identical
// permutation transcript to transfer_shadow_v2's sponge_16 -- safe
// because the contract feeds the same 16-field buffer to its
// yulSponge16 staticcall in both flows.
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

// Fold an 8-element array into a single field by zero-padding to 16
// elements and feeding through sponge_16. Reuses on-chain
// Poseidon2YulSponge16 with the trailing 8 fields = 0.
fn sponge_8_pad16(e: [Field; 8]) -> Field {
    let mut padded: [Field; 16] = [0; 16];
    for i in 0..8 {
        padded[i] = e[i];
    }
    sponge_16(padded)
}

// ---- plaintext geometry validation (audit H-04) ----
//
// Mirrors mutate_slot's `assert_pose_byte_dims` but reads (w, h) from
// the plaintext bytes directly instead of taking them as separate
// witness inputs. The mint circuit doesn't bind external (w, h) PIs --
// it just needs to ensure each freshly-minted plaintext is renderable
// (non-zero, bounded by the 48x48 canvas, axis-aligned containment).
//
// Without this check, a malicious minter could commit to plaintexts
// that the recipient cannot render but still pass `solve` reveal
// because the bytes match the chain-bound ct_commit. H-04 closes that:
// every minted slot's geometry is constraint-checked at mint time.
//
// Conservative axis-aligned containment: the pose's rotation/scale bits
// are intentionally NOT validated here. Mutations are free to repose;
// any rotation that overflows the unrotated bbox is rejected by
// `mutate_slot::assert_pose_byte_dims`.
global CANVAS_W: u32 = 48;
global CANVAS_H: u32 = 48;

fn decode_xy(pose_low_bits: Field) -> (u8, u8) {
    // pose_low_bits encodes packed pose in its low 64 bits. Low 12 bits
    // are (x: 6bit, y: 6bit).
    let bytes: [u8; 8] = pose_low_bits.to_le_bytes();
    let x: u8 = bytes[0] & 0x3F;
    let y: u8 = ((bytes[0] >> 6) | ((bytes[1] & 0x0F) << 2)) & 0x3F;
    (x, y)
}

fn validate_plaintext_v2(plaintext: [Field; 39]) {
    // Plaintext field 0 layout (low 31 bytes):
    //   bytes 0..7   pose (8 B, uint64 packed)
    //   byte 8       w
    //   byte 9       h
    //   bytes 10..30 first 21 of (w * h) palette indices (4-bit packed)
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

    // (1) range: w, h in [1, 48].
    assert(w_byte != 0);
    assert(h_byte != 0);
    assert(w_byte as u32 <= CANVAS_W);
    assert(h_byte as u32 <= CANVAS_H);

    // (2) canvas containment: anchor + extent must fit in 48x48.
    assert((x as u32) + (w_byte as u32) <= CANVAS_W);
    assert((y as u32) + (h_byte as u32) <= CANVAS_H);
}

// ---- main ----

fn main(
    // public inputs (7)
    shadow_id:           pub Field,
    image_commit:        pub Field,
    owner_pk_x:          pub Field,
    owner_pk_y:          pub Field,
    lsh_inits_root:      pub Field,
    ct_commits_root:     pub Field,
    chain_tips_root:     pub Field,

    // ---- per-slot witness (private) ----
    plaintexts:          [[Field; 39]; 8],
    new_r:               [Field; 8],
) {
    // shadow_id and image_commit are transcript-only; the contract
    // binds via PI[0]/PI[1] equality (image_commit also matches the
    // face_disc proof's PI).
    let _ = shadow_id;
    let _ = image_commit;

    // ---- 1. owner pubkey point ----
    let owner_pk = EmbeddedCurvePoint {
        x: owner_pk_x,
        y: owner_pk_y,
        is_infinite: false,
    };
    // M-06: owner_pk arrives as PI from the contract; assert on-curve so
    // the MSM below operates on a real Grumpkin point.
    assert_on_grumpkin(owner_pk_x, owner_pk_y);

    // ---- 2. per-slot ----
    let mut lsh_inits:  [Field; 8] = [0; 8];
    let mut ct_commits: [Field; 8] = [0; 8];
    let mut chain_tips: [Field; 8] = [0; 8];

    for i in 0..N_MINT_SLOTS {
        // 2a. plaintext -> state_commit
        let state_commit_i = sponge_39(plaintexts[i]);

        // H-04: validate plaintext geometry before committing to it.
        validate_plaintext_v2(plaintexts[i]);

        // M-06: r != 0 rejects the degenerate (c1 = O, shared = O) envelope
        // that collapses k to kdf(role, 0, 0) -- a deterministic, attacker-
        // known key independent of owner_pk.
        assert(new_r[i] != 0);

        // 2b. ECIES envelope: c1 = G * r; shared = owner_pk * r
        let r_scalar = EmbeddedCurveScalar::from_field(new_r[i]);
        let c1 = fixed_base_scalar_mul(r_scalar);
        let shared = multi_scalar_mul([owner_pk], [r_scalar]);
        let k_i = kdf(KDF_ROLE_PLAINTEXT, shared.x, shared.y);

        // 2c. keystream + ciphertext
        let ks = keystream_39(k_i);
        let mut ct: [Field; 39] = [0; 39];
        for j in 0..PLAINTEXT_FIELDS {
            ct[j] = plaintexts[i][j] + ks[j];
        }
        let ct_commit_i = sponge_39(ct);

        // 2d. origin face id binds slot to image
        let origin_face_id_i = poseidon2_hash_2(image_commit, i as Field);

        // 2e. mint chain-tip seeds the chain history with one MINT event
        let chain_tip_i = sponge_4(
            MINT_TAG,
            origin_face_id_i,
            owner_pk_x,
            owner_pk_y,
        );

        // 2f. lsh_init: mutation_count = 0 at mint
        let lsh_init_i = sponge_6(
            state_commit_i,
            ct_commit_i,
            c1.x,
            c1.y,
            0,
            chain_tip_i,
        );

        lsh_inits[i]  = lsh_init_i;
        ct_commits[i] = ct_commit_i;
        chain_tips[i] = chain_tip_i;
    }

    // ---- 3. fold into PI roots ----
    assert(sponge_8_pad16(lsh_inits)  == lsh_inits_root);
    assert(sponge_8_pad16(ct_commits) == ct_commits_root);
    assert(sponge_8_pad16(chain_tips) == chain_tips_root);
}
