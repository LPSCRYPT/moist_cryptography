> **v1 historical document.** The threat model and invariants below
> apply to the v1 contracts deployed on Base Sepolia. The `staging`
> branch v2 contracts re-establish many of the same invariants in
> different shapes (notably the **atomic-T10 invariant**: every state
> change must refresh `shadowT10` in the same tx, gated by a real
> `shadow_t10` proof bound to the post-write LSH array). See
> [`V2_STATUS.md`](V2_STATUS.md) for the v2 surface.

---

# Security

## Cryptographic guarantees

The system rests on three primitives:

- **UltraHonk-Keccak** zero-knowledge proofs (Aztec). Soundness against the
  honest-verifier interactive zero-knowledge property of the underlying
  PLONK-style argument. Verifier execution is ~3-4M gas per proof, well
  under the 16,777,216 gas Base Sepolia per-tx cap.
- **ECIES on Grumpkin** for encryption. The current owner's secret key
  decrypts the shadow's plaintext. Transfers re-encrypt under the new
  owner's key inside the proof, so the plaintext is never revealed to
  anyone but the current owner — until `solve`.
- **Poseidon2 sponge** for in-circuit hashing and commitments. Used for
  state commits, ciphertext commitments (`sponge_249` for shadow,
  `sponge_42` for feature), and the ECIES keystream seed.

## Replay-protection layers

| Layer | Mechanism | Prevents |
|-------|-----------|----------|
| Per-tx | `pi[X] == c2Commit` checks against current chain state | replay of stale proofs against an updated shadow |
| Per-shadow | `pi[0] == bytes32(shadowId)` for transfer/extract/feature paths | use of one shadow's proof against a different shadow |
| Per-chain | `shadowId = keccak256(DOMAIN, block.chainid, faceOriginId) % FR_MOD` | cross-chain replay of the same proof |
| Per-owner | `_ownerOf(shadowId) == msg.sender` for owner-gated entries | unauthorised callers |

The chain-id binding means the same `faceOriginId` mints to *different*
`shadowId`s on different chains. A `transferShadow` proof generated for
chain A's `shadowId_A` will fail the contract's `pi[0] == bytes32(shadowId_B)`
check when submitted on chain B — the proof literally cannot be replayed
elsewhere.

## Trust assumptions

- **Verifier correctness**: the generated `*Verifier.sol` files are
  byte-equal across rebuilds and deterministically produced by `bb
  write_solidity_verifier`. We trust Aztec's circuit compiler + verifier
  generator. No custom verifier code was written.
- **Bridge messenger**: the OP-Stack `L1CrossDomainMessenger` and
  `L2CrossDomainMessenger` predeploys are trusted to deliver messages
  honestly. This is the same trust model as every OP-Stack bridge.
- **No plaintext-revealing oracles**: the system has no path through
  which the plaintext is revealed prior to a self-initiated `solve`. In
  particular `transferShadow` re-encrypts inside the proof, so the
  recipient's secret key is the only key that can decrypt the new c2.

## Pause + verifier rotation

`PausableMixin` provides:

- `pause()` / `unpause()` — gates all state-changing entries with
  `whenNotPaused`. Owner-only.
- `proposeVerifier(slot, addr)` — initiates a 7-day timelocked rotation
  of any verifier slot.
- `applyVerifier(slot)` — after the timelock, swaps the verifier in.
- `applyVerifierImmediate(slot)` — only when paused, bypasses timelock for
  emergency rotation.
- `cancelVerifier(slot)` — owner cancels a pending rotation.

The 7-day window gives users time to react to a planned rotation
(extracting their tokens, withdrawing, etc.) before a new verifier
becomes the source of truth.

## Static analysis

`slither-analyzer 0.11.5` per-file run on the seven core source files:

- **Zero genuine MED+ findings.**
- One MED false positive: `address(0) == 0` strict-equality check in
  `PausableMixin.applyVerifier` — intentional pattern for "no pending
  rotation" check.
- Three LOW findings: idiomatic leading-underscore parameter names
  (`_pkX`, `_l1Mirror`, `_l2Bridge`).

Full report: see `slither/report.md` in any local logs/ directory after
running slither against `contracts/`.

## Known limitations

1. **`KeyRegistry` is permissive by default**. The deploy script does not
   wire `setKeyRegistry` so any address can be a transfer recipient. For
   production: deploy + call `ShadowToken.setKeyRegistry(kr)` and
   `FeatureNFT.setKeyRegistry(kr)`, then require users to register their
   Grumpkin pk via `KeyRegistry.register(pkX, pkY)` before any state
   change that depends on pk-to-EOA binding.

2. **Bridge round-trip via OP messenger has 7-day L2->L1 finality**. This
   is by design (the OP withdrawal challenge period). Fast bridges with
   external trust assumptions (Hyperlane, LayerZero, custom relayer) are
   not implemented; if your application needs sub-day cross-chain
   finality, replace the messenger interface with a fast-path bridge.

3. **Mint circuit is face-AGNOSTIC by design** (see [`CIRCUITS.md`](CIRCUITS.md)).
   It proves "I know an image with these per-region commitments" — random
   noise, not a face, will also produce a valid proof. The application
   layer can decide whether to enforce a face-detector check off-chain.

4. **No external audit yet**. The system is forge-tested (111/111) and
   slither-clean, but has not undergone a third-party audit. Production
   use should commission one.

## Reporting issues

Open a GitHub issue. For potentially high-impact disclosures, please
contact the maintainers privately first (see repo metadata).
