# Security

This document describes the security model of the **pipeline #6
contract set** (envelope-binding cutover; canonical addresses in
[`DEPLOYMENT.md`](DEPLOYMENT.md)). Pipeline #5 is the prior live deployment
and remains functionally unchanged but does NOT carry the byte-level binding
this document describes.

This is the security posture as it actually behaves on chain today, not
as originally specified. Where current behaviour is weaker than the
project's design goal, this document says so explicitly under
"Envelope binding" and "Known limitations". An external audit
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

## Envelope binding (post-cutover)

Every byte payload the contract emits on a state-changing op is
**bound to the proof at the byte level**: the contract recomputes the
byte digest in the same transaction and asserts equality with the
proof-bound commitment, before any state write or event emission.
Tampering with the wire bytes after proof generation reverts the entire
tx; a partial state advance is impossible.

| Op | Bound bytes | Binding mechanism |
|---|---|---|
| `mintShadow` | per-slot `c2s[i]` (ECIES envelope) | contract `sponge_39(c2s[i]) == ctCommits[i]` (proof PI[5]) |
| `mintShadow` | per-slot `originFaceIds[i]` | contract `poseidon2_hash_2(imageCommit, i) == originFaceIds[i]` via Yul `hash_2` staticcall |
| `mutateSlot` | `c2` envelope | contract `sponge_39(c2) == newCtCommit` |
| `mutateBatch` | per-entry `c2` | per-entry contract `sponge_39(e.c2) == e.newCtCommit` |
| `insertFeature` | `c2` | contract `sponge_39(c2) == newCtCommit` |
| `transferShadow` | per-slot `c2s[i]` | contract `sponge_39(c2s[i]) == newCtCommits[i]`; per-slot `sponge_16` over `newCtCommits` matches new PI[8] |
| `transferFeature` | `c2` | contract `sponge_39(c2) == new_ct_commit_pi` (PI[8]) |
| `solve` | per-occupied-slot `plaintexts[i]` | contract `sponge_39(plaintexts[i]) == stateCommits[i]` (proof PI[1]) |

Empty slots (transferShadow, solve) require zero-length `c2`/`plaintexts`
and zero-valued commitments; the circuit zeros the unoccupied entries
(`new_ct_commits[i] = occupied * v`) and the chain-side sponge over those
arrays catches any tampering.

The salt envelope (`saltCt`, `c1.x`, `c1.y` in `transferFeature` calldata)
remains a wire-format sidecar emitted for the owner's benefit; it is
not byte-bound on chain because it is non-confidential and the owner
can reconstruct it locally. Consumers that need the ECIES ephemeral
pubkey for decryption recover it from the `liveStateHash` witness.

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
around z-index Field canonicality, mint plaintext geometry validation,
and bridge round-trip custody. See "Known limitations" below.

## Known limitations

1. **Mint plaintext geometry is not validated in-circuit.** (Audit H-04,
   deferred.) `landmark_regions_v2` hashes and encrypts the 39-field
   plaintext without decoding pose/dimensions/palette indices. The same
   validator exists in `mutate_slot` but is not shared with mint, so
   initial-state slots can commit to malformed plaintexts that later
   mutate operations would reject.

2. **KeyRegistry accepts the `(0,0)` sentinel at registration.**
   `(0,0)` is documented as "unregistered", but `register` does not
   reject it, so an account can emit a `Registered` event while
   `isRegistered` still returns false.

3. **ECIES inputs.** (Audit M-05, M-06, L-01, deferred to the same
   redeploy as the envelope-binding cutover.) Circuits do not assert
   `new_r != 0` or that stored Grumpkin public keys are valid
   non-infinity points. Old keystream keys (`old_k` / `prev_k`) are
   witnessed and proven consistent with `ctCommit`, but not derived
   from `old_c1 * owner_sk` — so a leaked keystream key would let a
   non-owner forge mutations that pass the proof, provided they also
   know the owner's secret.

4. **Bridge round-trip via OP messenger has 7-day L2→L1 finality**
   (OP withdrawal challenge period). Fast bridges with external trust
   are not implemented.

5. **No external audit.** Forge surface is 202/202 with real proofs
   and no mocks. A third-party audit has not been commissioned.

Closed by audit remediation pass 1 (pipeline #5):
- H-03 z-index Field canonicality (cast-and-range guard added in-circuit).
- H-06, M-07, M-08 bridge custody / zero-address / round-trip.
- M-01..M-04 contract fixes including KeyRegistry wiring in DeployShadowPipeline.

Closed by the envelope-binding cutover (pipeline #6):
- H-01 solve plaintext byte-binding via `sponge_39` re-hash.
- H-02 ECIES envelope byte-binding for every state-changing entry point.
- H-05 origin lineage ID binding via on-chain `poseidon2_hash_2`.

## Reporting issues

Open a GitHub issue. For potentially high-impact disclosures, contact
the maintainers privately first (see repo metadata).
