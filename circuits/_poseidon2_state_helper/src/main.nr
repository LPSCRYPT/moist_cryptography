// Generic Poseidon2 4-element permutation helper.
// Used by secret_inbox.py to compute k_mask = Poseidon2(shared.x, shared.y, 0, 0).
// One invocation = one permutation, ~0.3s nargo execute.
fn main(a: Field, b: Field, c: Field, d: Field) -> pub [Field; 4] {
    let state: [Field; 4] = [a, b, c, d];
    std::hash::poseidon2_permutation(state, 4)
}
