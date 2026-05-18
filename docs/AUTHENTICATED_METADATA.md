# Authenticated Metadata and Byte-Binding Policy

This project distinguishes chain-authenticated data from fixture or indexing convenience data. Off-chain consumers must not promote advisory metadata into authority.

## Authoritative classes

1. **Proof-bound public inputs**
   - Values accepted by a generated verifier as public inputs and copied into contract state/events only after verification.
   - Examples: live-state hashes, ciphertext/state-commit roots, transfer `new_c1` roots, solve `zPermPacked`.

2. **Contract-derived authenticated values**
   - Values recomputed by Solidity/Yul from calldata or existing state before emission/storage.
   - Examples: `sponge_39(c2) == newCtCommit`, `sponge_16(newC1Xs) == transfer PI[9]`, `hash2(imageCommit, slotIdx) == originFaceId`.

3. **Chain state**
   - Values read from contract storage at the block being acted upon.
   - Examples: current manifest `liveStateHash`, `mutationCount`, `chainTip`, carrier checkpoint, owner public key.

## Advisory classes

1. **Fixture sidecars**
   - `meta.json`, `plaintexts.json`, `slot_specs/*.json`, and local run outputs are reconstruction inputs for tests/tools. They are not chain authority unless recomputed from proof inputs and state.

2. **Encrypted salt envelopes**
   - `FeaturePaletteSaltEnvelope` is an encrypted delivery channel. Palette correctness is authenticated later by `revealPaletteAtSolve` via `sponge_palette_salt(palette, salt) == paletteCommit`.

3. **Indexing history summaries**
   - Consumers may index mutation counts and tips from events, but should reconcile against contract state when making security decisions.

## Secret material handling

- `Prover.toml` files often contain plaintexts, owner secrets, ECDH scalars, and witness material.
- Tools that write secret-bearing witness files must:
  - create them with mode `0600` from file creation time or immediately `chmod 0600`;
  - delete them in `finally`/`atexit` after proof generation;
  - keep `circuits/*/Prover.toml` ignored.

## Toolchain authority

The proof toolchain is pinned in `tools/toolchain_manifest.json` and checked by `tools/check_toolchain.py`:

- `nargo 1.0.0-beta.19`
- `bb 5.0.0-nightly.20260419`

If these binaries are absent from `PATH`, the repo-standard fallback paths are `$HOME/.nargo/bin/nargo` and `$HOME/.bb/bb`.
