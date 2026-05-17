# Envelope-Binding Cutover (audit H-01, H-02, H-04, H-05)

Status: **design accepted, implementation pending.**
Owner: pipeline-#6 deploy.
Predecessors: pipeline #5 (current live deploy).

## Why this exists

The local audit (`/audit/`, gitignored) identifies four High-severity
findings that share one root cause: **the chain emits or stores
payloads that are proof-bound at the Poseidon2-commitment level but not
at the byte/field level**. Off-chain consumers — indexers, renderers,
bridges, decryption tooling — are implicitly trusted to re-verify those
payloads against the on-chain commitments. The contract API and docs
imply stronger guarantees than the contract enforces.

The audit explicitly says: do not fix these with shims. Either the
chain publishes self-authenticating payloads, or the API + docs are
renamed to make "advisory sidecar" explicit. We are choosing the first
option for pipeline #6.

## In scope

| Finding | What the contract currently does | What pipeline #6 must do |
|---|---|---|
| **H-01** `solve` plaintext | Verifies `solve_shadow_v2` proof against `sponge_16(args.stateCommits)`. Emits `args.plaintexts[i]` in `FeatureSlotRevealed` without recomputing `sponge_39(plaintexts[i])`. | Recompute `sponge_39(plaintexts[i])` on chain and assert == `args.stateCommits[i]` for every occupied slot. Or: add a public root over all 16 plaintexts to the circuit; recompute that root via a cheaper calldata digest on chain. |
| **H-02** ECIES envelopes | `mutateSlot`, `mutateBatch`, `transferShadow`, `transferFeature`, `insertFeature` fold `c1.x`/`c1.y` into `liveStateHash` privately. `c2` is emitted in events but not recomputed. `c1` is not emitted as standalone proof-bound fields on every op. | Define a canonical on-chain `Envelope(c1.x, c1.y, ctCommit, fieldCount, mutationCount, chainTip)` digest. Bind as PI for every op that rotates encryption. Recompute the digest on chain from emitted bytes. |
| **H-04** mint plaintext geometry | `landmark_regions_v2` hashes/encrypts the 39-field plaintext without decoding `(pose, w, h, palette indices)`. `mutate_slot` validates the same shape strictly. Mint can permanently commit malformed slot state that mutate would reject. | Extract a shared `validate_slot_plaintext(plaintext)` helper used by `landmark_regions_v2`, `mutate_slot`, `solve_shadow_v2` (where it witnesses plaintexts), and any future circuit that touches a slot plaintext. |
| **H-05** origin lineage | Circuit derives `origin_face_id_i = poseidon2_hash_2(image_commit, i)` privately. `mintShadow` stores caller-supplied `args.originFaceIds[i]` without verifying. `originFaceIdOf` view returns a keccak placeholder that does not match the circuit. | Either (a) recompute `origin_face_id_i` on chain via a `Poseidon2YulHash2` Yul wrapper and assert equality with `args.originFaceIds[i]`, or (b) drop `args.originFaceIds` from `MintShadowArgs` entirely and compute on chain. (a) is the smaller diff. |

## Out of scope (deferred to later pipelines)

- The face_disc circuit's image byte-range constraints (audit's
  "non-face images cannot register if discriminator is sound" -
  Partial). Address with a stronger discriminator threshold once the
  current one has empirical coverage.
- Generated verifier reproducibility (audit P3 / step 7 below).
  Addressed separately under toolchain pinning.
- Bridge round-trip (H-06). Owned by step 6 of the remediation
  roadmap; independent design.

## Design — the `Envelope` digest

All ECIES-bearing operations (mutate, insert, transfer, mint) will
expose ONE additional public input: `envelope_root`, defined as

```
envelope_root = sponge_6(
    c1_x,
    c1_y,
    ct_commit,            // sponge_39(c2)
    field_count,          // PLAINTEXT_FIELDS_PER_SLOT = 39 (constant; included for explicitness)
    mutation_count,       // post-op value
    chain_tip             // post-op value
)
```

This is a slot-local digest. For multi-slot ops (`mutateBatch`,
`transferShadow`, `insertFeature` host-slot, `mintShadow` 8-slot
atom), the contract recomputes one digest per affected slot and
verifies against the PI.

Sponge choice: `sponge_6` is already used for `liveStateHash`. The
Yul wrapper exists (`Poseidon2YulSponge` for sponge_39 +
`Poseidon2YulSponge16` for sponge_16). A new `Poseidon2YulSponge6`
wrapper is needed if we want a single Yul call per envelope; or we
can replay sponge_6 inside the contract itself (Solidity-side
Poseidon2 via PoseLib's existing primitives — slower but no new Yul
artifact).

### Why a new digest and not just emit `c1` + `ctCommit` separately

Each op already binds `liveStateHash` as PI. `liveStateHash =
sponge_6(state_commit, ct_commit, c1_x, c1_y, mut_count, chain_tip)`.
That already binds `c1` and `ct_commit` to the proof — what's missing
is **the contract checking emitted bytes match the digest**, not new
PI fields.

So the actual cutover is simpler than the table suggests: **for every
op that emits c2 + (separately) c1, the contract recomputes
`sponge_39(c2) == ct_commit` (where `ct_commit` is the value already
inside the post-write `liveStateHash`) before the verifier accepts**.

For solve: same idea but on plaintext + `sponge_39(plaintext) ==
state_commit`.

The `Envelope` framing is a documentation/spec aid; the
implementation reuses existing PIs.

## Implementation sequence

### Stage A: H-05 (smallest; sets up the Yul hash_2 pattern)

1. New `contracts/src/Poseidon2YulHash2.sol` (~ 2000 LOC, mostly the
   verbatim permute() copy). Calldata = 2 fields (64 B). Returns 32 B
   = `permute([a, b, 0, 0])[0]`.
2. `ShadowToken.sol`:
   - Add `address public yulHash2;` + setter, wire in deploy.
   - In `_mintOneAtom`, recompute `expected = yulHash2(imageCommit, i)`
     via STATICCALL; require `expected == args.originFaceIds[i]`.
   - Replace `originFaceIdOf` body with the same STATICCALL so the
     view helper is self-consistent.
3. `Poseidon2YulHash2` invariant test in
   `contracts/test/Poseidon2YulHash2.t.sol` — compare to a fixture
   generated by `tools/v2_circuit_helpers.poseidon2_hash_2`.
4. Negative test: `mintShadow_reverts_when_originFaceIds_tampered`.

### Stage B: H-04 (Noir-only; no contract change)

1. Extract `slot_plaintext.nr` containing a single validator function:
   `validate_slot_plaintext(plaintext: [Field; 39]) ->
   PlaintextLayout` returning `(pose, w, h, palette_indices,
   used_field_count)` with hard asserts on:
   - `w in [1, 48]`, `h in [1, 48]`
   - all palette indices in `[0, 15]`
   - reserved padding fields == 0 (canonical encoding)
   - any field used as a packed-byte container fits in 31 bytes
2. Call from `landmark_regions_v2` (mint), `mutate_slot`,
   `solve_shadow_v2`, `transfer_shadow_v2`, `transfer_feature_v2`,
   `insert_feature_v2`.
3. Regenerate all affected verifiers + fixtures.
4. New Noir `#[test]` per validator: positive (identity_plaintext) +
   negative (oversized w, oversized palette index, non-zero pad).

### Stage C: H-02 + H-01 (the bulk; contract-side)

For each operation, add the on-chain re-hash before the verifier accept:

- `mintShadow`: after the proof verifies, for `i in 0..8`:
  `require(sponge39(args.c2s[i]) == args.ctCommits[i])`.
- `mutateSlot` / `mutateBatch` / `insertFeature`: same shape, using
  the post-write `ct_commit` recovered from the post-write
  `liveStateHash` reconstruction.
- `transferShadow`: per-slot re-hash for all 16 emitted `c2`.
- `transferFeature`: re-hash the rotated feature's `c2`.
- `solve`: per occupied slot,
  `require(sponge39(args.plaintexts[i]) == args.stateCommits[i])`.

Each re-hash is one STATICCALL to `Poseidon2YulSponge`. The 39-field
sponge is ~120k gas on chain. Solve at max occupancy: 16 × 120k = 1.92M
additional gas. Within budget (current measured solve is 12.6M at max
occupancy; cap is 16M).

Mint at 8 slots: 8 × 120k = 0.96M additional gas. Mint is currently
11M on chain; budget 16M; comfortable.

`transferShadow` max-occupancy: 16 × 120k = 1.92M additional gas.
Currently 9.97M; budget 16M; comfortable.

### Stage D: events & ABI

After Stage C lands, every emitted byte payload IS chain-authenticated.
Update event names and doc-comments accordingly:

- `FeatureSlotRevealed` -> retain name; add `// proof-bound` to NatSpec.
- `ShadowSlotMutated` -> retain name; same.
- Remove all "advisory" qualifiers from NatSpec, DEPLOYMENT.md,
  SECURITY.md. The advisory-payload section of SECURITY.md collapses
  to "all emitted payloads are proof-bound at the byte level".

### Stage E: cutover

1. Fresh pipeline #6 deploy via updated `DeployShadowPipeline.s.sol`.
2. Migrate working shadows C / D / E from pipeline #5 by burning on
   #5 and re-minting on #6 with their existing image_commits — only
   possible because mintedOrigins is per-deployment.
3. Promote `DEPLOYMENT.md` "Canonical live deployment" to pipeline #6.
4. Archive pipeline #5 to HISTORICAL_DEPLOYMENTS.md.

## Test coverage acceptance

- Each of H-01 / H-02 / H-05 has a positive forge e2e + a
  tamper-the-emitted-bytes negative test that asserts revert before
  ownership / chain state changes.
- H-04 has Noir `#[test]` coverage as described in Stage B.
- The `test_solve_plaintext_tamper_does_not_revert` test currently
  in `SolveShadow.t.sol` MUST be renamed `test_solve_reverts_when_
  plaintext_tampered` and inverted from "does not revert" to "reverts".
  This is the most visible behavioural change of the cutover.

## Gas budget summary (estimate; verify before merge)

| Op | Current | Cutover delta | Cutover total | Budget |
|---|---:|---:|---:|---:|
| mintShadow | 11.0 M | + ~1.0 M (8 × sponge39) + ~0.3 M (8 × hash2) | ~12.3 M | 16 M |
| mutateSlot | 7.1 M | + ~0.12 M | ~7.2 M | 16 M |
| mutateBatch N=8 | 21.4 M (forge) | + ~1.0 M | ~22.4 M | already over 16 M; cap N≤3 per existing doc |
| transferShadow max-occ | 10.0 M | + ~1.9 M | ~11.9 M | 16 M |
| solve max-occ | 12.6 M | + ~1.9 M | ~14.5 M | 16 M |

All ops stay within the 16 M per-tx target except mutateBatch at
N=8, which is already documented as caller-must-chunk.

## What this design rejects

- **Shims** that emit both proof-bound + legacy advisory fields in
  parallel during a "soft" cutover. The audit's principal point is
  that two representations of the same fact are themselves a defect.
- **Per-consumer verification SDKs** that re-hash off chain. Those
  exist (see `tools/validate_pixels.py`) and are useful, but they
  cannot replace on-chain enforcement — they apply only to consumers
  that opt in. Bridge / indexer / wallet that *don't* opt in still
  trust the advisory payload.
- **Soft deprecation of `originFaceIdOf`**. The function is renamed
  in-place (same selector, different implementation). Callers using
  the old keccak formula were already wrong about every minted
  shadow; promoting them to correctness is not a breaking change in
  any meaningful sense.

## What remains audit-flagged after this cutover

- **M-05** (mutate/solve/transfer prove knowledge of old keystreams,
  not derivation from owner secret). Separate fix in the same pipeline
  #6 cycle: derive `old_k = old_c1 * owner_sk` inside each affected
  circuit; assert equality with the keystream-verification key.
- **M-06** (ECIES nonzero / on-curve). Add `assert(new_r != 0)` and
  Grumpkin point-on-curve checks at each ECIES use site.
- **L-01** (KDF domain separation in keystream). Lower priority.

All three are tractable in the same redeploy as this cutover; they
should be bundled to avoid a second cutover.
