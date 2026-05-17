# Security

This document describes the security model of the **pipeline #5
contract set** currently deployed to Base Sepolia (canonical addresses
in [`DEPLOYMENT.md`](DEPLOYMENT.md)).

This is the security posture as it actually behaves on chain today, not
as originally specified. Where current behaviour is weaker than the
project's design goal, this document says so explicitly under
"Advisory-payload boundary" and "Known limitations". An external audit
artefact lives in `/audit/` (local-only, gitignored) and informs the
limitations list.

## Cryptographic guarantees

The system rests on three primitives:

- **UltraHonk-Keccak** zero-knowledge proofs (Aztec/Barretenberg). One
  Solidity verifier contract is generated per circuit. Verification
  costs ~3-5M gas per proof. Every verifier fits under the EIP-170
  24,576 B runtime cap (see DEPLOYMENT.md for current sizes).
- **ECIES over Grumpkin** for slot encryption. Each slot's plaintext
  (39 BN254 field elements; pose + dimensions + 4-bit palette indices)
  is encrypted under the current owner's Grumpkin pk. Mutations and
  transfers re-encrypt inside the proof.
- **Poseidon2 sponge** for in-circuit hashing and chain-side
  commitments. Yul wrappers (`Poseidon2YulSponge`,
  `Poseidon2YulSponge16`, `Poseidon2YulSpongePaletteSalt`) replay the
  same sponge inside Solidity for `liveStateHash`, `shadowT10`, and
  `paletteCommit` opening.

## Replay-protection layers

| Layer | Mechanism | Prevents |
|---|---|---|
| Per-tx | `pi[k] == liveStateHash[slot]` checks against current chain state | replay of stale proofs against an updated slot |
| Per-shadow | `pi[shadowIdSlot] == shadowId` for all shadow-bound entries | use of one shadow's proof against a different shadow |
| Per-chain | every `shadowId` derives from `imageCommit % FR_MOD` and the registered-image set is per-chain | cross-chain replay of the same proof |
| Per-owner | `_ownerOf(shadowId) == msg.sender` for owner-gated entries (mutateSlot, mutateBatch, extractSlot, insertFeature, transferShadow, solve, bridgeShadow) | unauthorised callers |
| Per-batch | atomic-T10: every state-changing op refreshes `shadowT10` in the same tx via a bundled `shadow_t10` proof bound to the post-write LSH array | stale public view between mutation and T10 refresh |

## Advisory-payload boundary (current behaviour)

Several chain-emitted payloads are **proof-bound at the commitment level
but not at the byte level**. The contract verifies that a Poseidon2
commitment (`stateCommit`, `ctCommit`, `paletteCommit`) is consistent
with the proof, but does not recompute the commitment from the emitted
bytes inside the transaction. This means:

- **`FeatureSlotRevealed` plaintexts emitted by `solve()` are advisory.**
  The proof binds the per-slot `stateCommit`; the event-emitted
  39-field plaintext is not re-hashed on chain. Off-chain consumers
  MUST recompute `sponge_39(plaintext) == stateCommit` before
  rendering or trusting a reveal.
- **`c2` ciphertext bytes** emitted by mint / mutate / insert /
  transferShadow are also advisory in the same way. The proof binds
  `ctCommit = sponge_39(c2)`, but the emitted `c2` is not recomputed
  on chain. Off-chain decryption tooling must verify
  `sponge_39(c2) == ctCommit` before attempting decryption.
- **`c1.x / c1.y`** are folded into the proof's `liveStateHash` but
  are not emitted as standalone proof-bound fields on every operation.
  Consumers that need the ECIES ephemeral pubkey to decrypt must
  reconstruct it from the on-chain `liveStateHash` witness.

This is documented in `DEPLOYMENT.md` ("Reveal architecture") and
acknowledged in the local audit (High-01, High-02). A binding cutover —
recomputing emitted-byte digests on chain, or publishing a fully
proof-bound envelope structure — is on the remediation roadmap. Until
then, every consumer that displays or decrypts a chain-published
payload MUST treat it as untrusted sidecar data and verify it against
the proof-bound commitment.

## Pause + verifier rotation

`PausableMixin` provides:

- `pause()` / `unpause()` — gates all state-changing entries with
  `whenNotPaused`. Owner-only.
- `proposeVerifier(slot, addr)` — initiates a 7-day timelocked rotation
  of any verifier slot.
- `applyVerifier(slot)` — after the timelock, swaps the verifier in.
- `applyVerifierImmediate(slot)` — only when paused, bypasses timelock
  for emergency rotation.
- `cancelVerifier(slot)` — owner cancels a pending rotation.

The 7-day window gives users time to react to a planned rotation
(extracting their tokens, withdrawing, etc.) before a new verifier
becomes the source of truth.

## Trust assumptions

- **Verifier correctness.** Generated `*Verifier.sol` files are
  produced by `bb write_solidity_verifier` against the pinned Noir
  circuits. Reproducibility across rebuilds depends on toolchain
  pinning (`noirup`, `bbup`). CI currently does not byte-compare a
  fresh-build verifier against the checked-in copy — this is on the
  remediation roadmap. We trust Aztec's circuit compiler + verifier
  generator.
- **OP-Stack messenger.** `L1CrossDomainMessenger` and
  `L2CrossDomainMessenger` predeploys are trusted to deliver messages
  honestly. Same trust model as every OP-Stack bridge.
- **Off-chain decryption.** No oracle reveals plaintext before a
  self-initiated `solve`. `transferShadow` and `transferFeature`
  re-encrypt inside the proof, so the recipient's secret key is the
  only key that can decrypt the rotated `c2`.
- **face_disc as a soft gate.** `registerImage` requires a `face_disc`
  proof over an image whose `image_commit` is then required by
  `mintShadow`. The mint circuit itself (`landmark_regions_v2`) does
  not bind face semantics — it proves "I know an image with these
  per-region commitments". Face gating lives in the flow, not in the
  mint circuit. A `face_disc` verifier with weak discriminator
  thresholds therefore weakens mint gating without changing mint
  proofs.

## Static analysis

`slither-analyzer 0.11.5` is run per-file on the seven core source
files in CI. The pipeline-#4 baseline reported:

- Zero genuine MED+ findings on production code.
- One MED false positive: `address(0) == 0` strict-equality in
  `PausableMixin.applyVerifier` — intentional "no pending rotation"
  check.
- Three LOW findings: idiomatic leading-underscore parameter names.

A local code-and-cryptography audit (`/audit/`, gitignored) identified
several High-severity findings not visible to Slither, primarily
around the advisory-payload boundary described above, z-index Field
canonicality, mint plaintext geometry validation, and bridge
round-trip custody. See "Known limitations" below.

## Known limitations

1. **FeatureNFT's KeyRegistry pointer is unwired on the deployed
   contract set.** `DeployShadowPipeline.s.sol` calls
   `st.setKeyRegistry(kr)` but does not call `fn.setKeyRegistry(kr)`,
   so `FeatureNFT.keyRegistry == address(0)`. Combined with
   `_requirePkMatches`'s silent bypass on unset registry,
   `transferFeature` currently performs no recipient-pk enforcement on
   the live deployment. Workaround until remediated: the deployer
   account holds the role required to call `fn.setKeyRegistry(kr)` and
   should do so after every fresh pipeline deploy. The deploy script
   will be patched to wire both contracts in the same broadcast.

2. **Mint plaintext geometry is not validated in-circuit.**
   `landmark_regions_v2` hashes and encrypts the 39-field plaintext
   without decoding pose/dimensions/palette indices. The same
   validator exists in `mutate_slot` but is not shared with mint, so
   initial-state slots can commit to malformed plaintexts that later
   mutate operations would reject.

3. **Z-index circuits cast `Field` to `u32` before range-checking, but
   hash the original `Field`.** If a Noir cast truncates as documented,
   a witness with high field bits set and low bits in `[0,15]` can
   pass the bitmap permutation check while committing/packing a
   non-canonical value. Affects `zindex_commit` and `solve_shadow_v2`.

4. **Origin lineage IDs are caller-supplied on mint.** The
   `landmark_regions_v2` circuit derives them privately as
   `poseidon2(imageCommit, slotIdx)`, but `mintShadow` stores
   caller-provided IDs without recomputing on chain. Indexers that
   trust `originFaceId` for lineage claims need to recompute it
   off-chain from `(imageCommit, slotIdx)`.

5. **KeyRegistry accepts the `(0,0)` sentinel at registration.**
   `(0,0)` is documented as "unregistered", but `register` does not
   reject it, so an account can emit a `Registered` event while
   `isRegistered` still returns false.

6. **Bridge `mintedFromBridge` is permanent.** Burn-and-unbridge does
   not clear it, so a re-bridge after a legitimate L1→L2 unbridge
   will lock the L2 token in `ShadowBridgeL2` while the second L1
   `proveAndRelay` reverts `AlreadyMinted`.

7. **Bridge zero-address paths are unchecked.** `ShadowMirrorL1.burn`
   does not reject `l2Recipient == address(0)`, and `ShadowBridgeL2`
   always mints the L1 mirror to `msg.sender`. A contract-wallet L2
   sender whose address is unreachable on L1 will get a stranded
   mirror.

8. **ECIES inputs.** Circuits do not assert `new_r != 0` or that
   stored Grumpkin public keys are valid non-infinity points. Old
   keystream keys (`old_k` / `prev_k`) are witnessed and proven
   consistent with `ctCommit`, but not derived from `old_c1 * owner_sk`
   — so a leaked keystream key would let a non-owner forge mutations
   that pass the proof, provided they also know the owner's secret.

9. **Bridge round-trip via OP messenger has 7-day L2→L1 finality**
   (OP withdrawal challenge period). Fast bridges with external trust
   are not implemented.

10. **No external audit.** Forge surface is 184/184 with real proofs
    and no mocks. A third-party audit has not been commissioned.

## Reporting issues

Open a GitHub issue. For potentially high-impact disclosures, contact
the maintainers privately first (see repo metadata).
