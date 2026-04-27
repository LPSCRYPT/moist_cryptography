// palette_reveal_v2: prove a feature's stored paletteCommit opens to a
// concrete 16-color palette + salt, packing the colors into 8 PI Fields
// for cheap on-chain emission as 48 raw RGB bytes.
//
// Spec: STAGING_REFACTOR/2026-04-27_palette_reveal_working.md
//       (revised this session - no in-circuit ECIES; off-chain decrypt
//        + commitment binding + ownership gate at the contract layer.)
//
// Public inputs (10 Fields):
//   PI[0]       feature_id          (transcript-only here; chain checks via storage)
//   PI[1]       palette_commit      (chain checks vs storage; binds palette + salt)
//   PI[2..10]   palette_packed[8]   (each Field = palette[2i] + palette[2i+1] * 2^24;
//                                    contract emits the low 48 bits of each as RGB)
//
// Witness (private):
//   palette[16]  16 colors as 24-bit Fields (high bits ignored by contract)
//   palette_salt one Field; the off-chain ECIES-decrypted secret salt
//
// The owner ECIES-decrypts the salt envelope (paletteSaltCt, salt_c1)
// off-chain using their KeyRegistry sk. The decrypted salt + the palette
// they chose at mint are the private witness here. The chain enforces:
//   1. _ownerOf(featureId) == msg.sender                  (anti-grief)
//   2. !f.paletteRevealed                                  (anti-replay)
//   3. pi[1] == f.paletteCommit                            (proof binds to mint commit)
//   4. proof verifies                                      (palette + salt actually open the commit)
//   5. emit FeaturePaletteRevealed with unpacked 48-byte RGB

use std::hash::poseidon2_permutation;

global PACKED_LEN: u32 = 8;

// Sponge over 17 Field elements (16 palette + 1 salt). Rate=3, capacity=1.
// Layout: 5 full rate-3 absorbs (palette[0..15]) + 1 partial absorb of
// (palette[15], salt) -- wait, 5 full = 15 elems consumed; we have 17.
//
// Re-laying out: 5 full rate-3 absorbs cover palette[0..15] = 15 elems;
// then 1 partial absorb of (palette[15], salt) into s[0], s[1] = 2 elems;
// then sentinel pad. Total = 5 + 1 + 1 = 7 permutations.
fn sponge_palette_salt(palette: [Field; 16], salt: Field) -> Field {
    let mut s: [Field; 4] = [0, 0, 0, 0];

    // 5 full rate-3 absorbs covering palette[0..15] (5*3 = 15 elements).
    for b in 0..5 {
        s[0] = s[0] + palette[b * 3];
        s[1] = s[1] + palette[b * 3 + 1];
        s[2] = s[2] + palette[b * 3 + 2];
        s = poseidon2_permutation(s, 4);
    }

    // Partial absorb: palette[15] and salt occupy the rate slots; the
    // third rate slot gets zero.
    s[0] = s[0] + palette[15];
    s[1] = s[1] + salt;
    s = poseidon2_permutation(s, 4);

    // Sentinel pad to disambiguate variable-length inputs from the same
    // sponge family. Mirrors mutate_slot's sponge_39 termination.
    s[0] = s[0] + 1;
    s = poseidon2_permutation(s, 4);

    s[0]
}

fn main(
    // public inputs (10) -- order matches FeatureNFT PI[0..10]
    feature_id:     pub Field,
    palette_commit: pub Field,
    palette_packed: pub [Field; 8],

    // witness
    palette:        [Field; 16],
    palette_salt:   Field,
) {
    // ---- 0. transcript-only PI hook ----
    // feature_id is bound by the contract against storage; not folded
    // into the commit derivation here.
    let _ = feature_id;

    // ---- 1. palette commitment binding ----
    let recomputed = sponge_palette_salt(palette, palette_salt);
    assert(recomputed == palette_commit);

    // ---- 2. packing constraint ----
    // Each Field carries two 24-bit colors:
    //   palette_packed[i] == palette[2i] + palette[2i+1] * 2^24
    // The contract emits the low 48 bits of each packed Field as 6 bytes
    // (2 colors * 3 bytes). High bits beyond 48 are ignored by the
    // indexer; an adversary can only "lie to themselves" because they're
    // the only one with the salt, and they're the one producing the proof.
    let two_24: Field = 16777216; // 2^24
    for i in 0..PACKED_LEN {
        assert(palette_packed[i] == palette[2 * i] + palette[2 * i + 1] * two_24);
    }
}
