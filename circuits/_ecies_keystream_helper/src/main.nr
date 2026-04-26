// Poseidon2 counter-mode keystream for SecretInbox (N=32 plaintext fields).
//
// Generates 32 keystream elements from a single Field key `k`:
//
//   for block in 0..11:
//       out = Poseidon2([k, block, 0, 0])
//       ks[3*block .. 3*block+3] = out[0..3]
//
// Used identically by both Alice (to encrypt: ct[i] = s[i] + ks[i])
// and Bob (to decrypt: s[i] = ct[i] - ks[i]).
//
// Implementation byte-for-byte matches the original bytes32_zkpod_v2
// circuit's generate_keystream -- keep in sync if that ever changes.

global N: u32 = 32;
global N_BLOCKS: u32 = 11;

fn main(k: Field) -> pub [Field; N] {
    let mut ks: [Field; N] = [0; N];
    for block_idx in 0..N_BLOCKS {
        let counter = block_idx as Field;
        let input: [Field; 4] = [k, counter, 0, 0];
        let out = std::hash::poseidon2_permutation(input, 4);
        for j in 0..3 {
            let idx = 3 * block_idx + j;
            if idx < N {
                ks[idx] = out[j];
            }
        }
    }
    ks
}
