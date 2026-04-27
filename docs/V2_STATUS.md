# Moist Cryptography v2 — as-built status

Branch: `staging` (hard fork from `main` v1).
Date: 2026-04-26.
Spec: `STAGING_REFACTOR/2026-04-26_private_mutations_zindex_working.md` (local-only).

The v2 refactor moves the entire mutable state of a shadow — pixel content,
position, scale, rotation, dimensions, and z-order — into the **owner-private**
half of the system, while forcing the public T10 hash to refresh atomically
with every mutation. This document captures what is **as-built on
`staging`**; sections marked `TODO` are still pending.

---

## v2 design constraints

| | v1 (deployed) | v2 (staging) |
|---|---|---|
| Slot kinds | `EMPTY` / `ORIGINAL` / `INSERTED` (asymmetric) | **`EMPTY` / `OCCUPIED`** (all 16 equivalent) |
| Slot dims `(w, h)` | per-type capacity table | **private** (in-c2 plaintext, in `[1, 48]²`) |
| Slot pose | public, mutable | **private** (in-c2 plaintext) |
| Pixel content | RGB (24 bpp) inside one big shadow c2 | **4-bit palette indices**, per-slot c2 |
| Z-index | implicit slot order | **private commit, revealed at solve** |
| Public T10 | lazy-refreshed grayscale rasterization | **atomic-on-mutation 256-bit hash** |
| Mutation history | not exposed | **per-slot count + chain tip + indexed events** |
| Mint output | 1 shadow + per-slot original markers | **1 shadow + 8 FeatureNFTs** atomically |
| Extract / remove | two distinct ops (asymmetric) | **collapsed into one `extractSlot`** |
| `setShadowT10` | callable anytime; permits stale public view | **only inside bundled atomic txs** |

## Encrypted bundle layout (per slot, post-mint or post-mutate)

```
+--------------------------------------------------------------+
| pose                  (8 B)  — PoseLib-packed uint64        |
| width  w              (1 B)  — uint8, in [1, 48]            |
| height h              (1 B)  — uint8, in [1, 48]            |
| palette indices       (ceil(w*h / 2) B)  — 4 bits per pixel |
| zero pad to a multiple-of-3 field boundary                   |
+--------------------------------------------------------------+

PLAINTEXT_FIELDS_PER_SLOT = 39    # 13 sponge_3 blocks; on-chain Yul-friendly
MAX_PIXELS_PER_SLOT       = 48 * 48 = 2304
MAX_PLAINTEXT_BYTES       = 8 + 1 + 1 + 1152 = 1162 (well under 1209 budget)
```

## Per-slot `liveStateHash`

The chain stores **one `bytes32` per slot** (the `liveStateHash`) committing
the slot's full encrypted state:

```
liveStateHash = poseidon2_sponge_6(
    state_commit,    // sponge_39 of the plaintext fields
    ct_commit,       // sponge_39 of the encrypted fields
    c1_x, c1_y,      // ECIES ephemeral pubkey
    mutation_count,  // uint16, 0 at mint, +1 per mutate
    chain_tip        // poseidon2 chain over all prior mutations of this slot
)
```

Every mutate / insert / extract proves it knows a witness consistent with the
old `liveStateHash` and writes a new one. Replay-resistance falls out: a stale
proof's `old_liveStateHash` no longer matches the chain's current value once
any subsequent mutation has landed.

## Atomic-T10 invariant

Every state-changing operation in v2 — `mutateSlot`, `extractSlot`,
`insertFeature`, `setZIndexCommit` — bundles a `shadow_t10` proof whose PI is:

```
pi[0]    shadow_id
pi[1]    z_index_commit
pi[2,3]  newT10_hi, newT10_lo
pi[4..19] live_state_hash[0..15]  (chain's CURRENT post-write LSH array)
```

The contract reconstructs `pi[4..19]` from chain storage **after** applying
the operation's write, then verifies the proof. The proof's circuit asserts
`split_128(sponge_18(...)) == (newT10_hi, newT10_lo)`, so the chain's stored
`shadowT10[shadowId]` always faithfully reflects the post-write state.
This is the project's "no public lie" rule, enforced by the contract, not by
honest-prover convention.

## Function surface

| Function | Body | Bundled proofs | Status |
|---|---|---|---|
| `mintShadow` | mint shadow + 8 FeatureNFTs + atomic T10 | `landmark_regions` + `face_disc` + `shadow_t10` | **TODO (P3)** |
| `mutateSlot` | rewrite slot's c2 + liveStateHash + atomic T10 | `mutate_slot` + `shadow_t10` | ✅ |
| `mutateBatch` | N slots in one tx + 1 atomic T10 | N × `mutate_slot` + 1 × `shadow_t10` | TODO (signature stubbed) |
| `extractSlot` | unbind feature, sync checkpoint, zero slot, atomic T10 | proofless body + `shadow_t10` | ✅ |
| `insertFeature` | bind held feature into EMPTY slot, atomic T10 | `mutate_slot` (reused per Open Q2) + `shadow_t10` | ✅ |
| `transferShadow` | rotate all 16 slots' c2 to new owner | `transfer_shadow` (16-slot) | **TODO (P7)** |
| `setZIndexCommit` | commit z-perm, atomic T10 | `zindex_commit` + `shadow_t10` | ✅ |
| `solve` | reveal current per-slot states + z-perm, freeze | `solve_shadow` | **TODO (P9)** |
| `transferFeature` | rotate held FeatureNFT to new owner | `transfer_feature` | TODO (lives on FeatureNFT.sol) |
| `bridgeShadow` | lock + dispatch L1 mirror message | none (post-solve only) | ✅ (payload reshaped for v2) |

## Verifier deployments (EIP-170 24,576 B cap)

| Verifier | Deployed bytes | Headroom |
|---|---|---|
| `MutateSlotVerifier`  | 24,341 | 235 B |
| `T10ShadowVerifier`   | 24,339 | 237 B |
| `ZIndexCommitVerifier`| 24,341 | 235 B |
| `MintShadowVerifier`  | (TODO P3 — pi packing required) | |
| `TransferShadowVerifier` | (TODO P7) | |
| `SolveShadowVerifier`  | (TODO P9 — large PI) | |
| `TransferFeatureVerifier` | (TODO) | |

`ShadowToken` deployed bytecode: ~15 KB; `FeatureNFT`: ~12 KB. Both well
under cap.

## Test surface

Real-proof Forge tests, no mocks:

| Suite | Tests | Pass |
|---|---|---|
| `FeatureNFTv2Test` | 21 | 21/21 |
| `MutateSlotVerifierTest` | 4 | 4/4 |
| `T10ShadowVerifierTest` | 3 | 3/3 |
| `ZIndexCommitVerifierTest` | 3 | 3/3 |
| `MutateSlotE2ETest` | 7 | 7/7 |
| `ExtractSlotE2ETest` | 4 | 4/4 |
| `InsertFeatureE2ETest` | 4 | 4/4 |
| `SetZIndexCommitE2ETest` | 4 | 4/4 |
| `KeyRegistryTest` (carried over) | 5 | 5/5 |
| `PoseLibTest` (carried over) | 12 | 12/12 |
| **Total** | **67** | **67/67** |

Run via `cd contracts && forge test`.

## Test-only seeding pattern

The production contract surface (`ShadowToken`, `FeatureNFT`) keeps the
ZK-only state-transition path. Tests that need to set up arbitrary chain
state for real-proof verification use the `test/Testable.sol` subclasses
(`TestableShadowToken`, `TestableFeatureNFT`), which expose pinned-storage-slot
seed helpers (`seedShadowOnly`, `seedShadowAndSlot`, `seedFeature`). Storage
slots are verified via `forge inspect storageLayout` and pinned as
constants. **No production code path is mocked.**

## Off-chain tooling

| Script | Role |
|---|---|
| `tools/v2_circuit_helpers.py` | Python primitives byte-compatible with the v2 circuits (sponge_39, sponge_6, sponge_18, sponge_16, keystream_39, ECIES, plaintext encode/decode, pose pack, palette index pack) |
| `tools/build_mutate_slot_fixture.py` | Generates a stand-alone mutate_slot proof + verifier + JSON meta |
| `tools/build_zindex_commit_fixture.py` | Same for zindex_commit |
| `tools/build_shadow_t10_fixture.py` | Same for shadow_t10 |
| `tools/build_atomic_mutate_fixture.py` | Linked (mutate, T10) proof pair |
| `tools/build_atomic_extract_fixture.py` | Linked (T10) for extractSlot (proofless body) |
| `tools/build_atomic_zindex_fixture.py` | Linked (zindex, T10) pair |
| `tools/visualize_shadow.py` | **TODO (P10)** — needs rewrite for per-slot c2 + palette indexing |

## Pending phases

See `STAGING_REFACTOR/PROGRESS.md` for the full breakdown. Outstanding:

- **P3 — Mint circuit**: full `landmark_regions` rewrite emitting per-slot
  bundles. Heavy CNN-bearing circuit (~1700 lines today). PI count must
  stay under EIP-170 — likely needs paired-poseidon2 packing for 8
  ctCommits/paletteCommits.
- **P7 — `transferShadow`**: new circuit rotating all 16 slots' c2 to a new
  owner; contract-side rotation of inserted carriers' ERC-721 ownership
  alongside the shadow (single-host invariant).
- **P9 — `solve_shadow`**: new circuit revealing 16 × 39-field plaintexts
  + the z-permutation. Big PI count is the EIP-170 risk.
- **P10 — Tooling/docs**: `visualize_shadow.py` rewrite; sweep stale-grep
  on legacy v1 docs (this document is the canonical v2 doc until the
  legacy ones are replaced wholesale).
- **P11 — Sepolia redeploy + finalize**: fresh contract set; mint + mutate
  + setZIndexCommit + extract→insert + solve transactions linked from
  `docs/DEPLOYMENT.md`; rename working note `_done.md`.

## Migration / cutover

The v2 design is a **hard fork at the contract layer**; no on-chain
migration of v1 shadows is planned (per the working note's "Migration /
cutover" section). The current v1 deployment on Base Sepolia
(`0x9d3c178e...` mint tx) continues to exist as a frozen artifact. The
bridge is **not** updated to span v1 ↔ v2; v1 shadows can be transferred
but not mutated under v2's rules.
