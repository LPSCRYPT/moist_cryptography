# Incremental Feature Reveal Plan

## Goal

Replace solve-time reveal with an incremental per-slot reveal model.

A ShadowNFT owner can reveal any currently hidden occupied feature slot at any time. After reveal, that slot is public, full-color, immutable, and permanently locked into its current slot. Hidden/BW shadow generation ignores revealed slots, and renderers overlay revealed full-color slots above all hidden BW content.

## What Changes From The Current Working Tree

The current working tree contains a just-added session-style feature reveal solve:

```solidity
startFeatureRevealSolve(uint256 shadowId)
revealFeatureSlots(uint256 shadowId, FeatureRevealArgs[] calldata reveals)
finishFeatureRevealSolve(uint256 shadowId)
```

and per-shadow state:

```solidity
bool solving;
uint16 solveRequired;
uint16 solveRevealed;
```

That model should be removed. It still treats reveal as a global solve process. The new design treats reveal as a normal per-slot state transition that can happen gradually over the NFT lifetime.

## Intended User Semantics

For a hidden occupied slot:

1. Owner reveals the slot.
2. Contract verifies the revealed plaintext/palette against the current committed hidden state.
3. Contract changes the slot from hidden `OCCUPIED` to public `REVEALED`.
4. The slot can never again be mutated, extracted, transferred as a carrier, removed, replaced, or re-encrypted.
5. Future hidden-shadow generation excludes this slot.
6. SVG/full renderer overlays this revealed feature in full color above all hidden BW elements.
7. Other revealed features can later overlay it depending on revealed-feature ordering.

## Contract Data Model

### Slot state

Change `SlotKind` from:

```solidity
enum SlotKind {
    EMPTY,
    OCCUPIED
}
```

to:

```solidity
enum SlotKind {
    EMPTY,
    OCCUPIED,  // hidden/encrypted/mutable
    REVEALED   // public/immutable/locked
}
```

`ManifestEntry` can keep `featureId`, `liveStateHash`, `mutationCount`, and `chainTip` for audit/history. For revealed slots, those fields become historical: they describe the hidden state that was opened.

Add revealed ordering metadata. Minimal option:

```solidity
mapping(uint256 => uint8[16]) private _revealedRanks;
```

A rank of `0` can be ambiguous with a valid rank, so either:

- store rank only for `SlotKind.REVEALED`, or
- store rank plus a bitmap.

Recommended: derive presence from `SlotKind.REVEALED`; store `uint8 rank` directly.

### Remove solve-session state

Remove from `Shadow`:

```solidity
bool solving;
uint16 solveRequired;
uint16 solveRevealed;
```

Remove errors/events used only for solve sessions:

```solidity
SolveActive()
ShadowFeatureRevealStarted
ShadowFeatureRevealFinished
```

Keep `bool solved` only if the project still needs a global “fully public/bridgeable/finalized” state. If global solved is no longer meaningful, replace it with derived view logic:

```solidity
function isFullyRevealed(uint256 shadowId) public view returns (bool)
```

Recommended conservative cutover: keep `solved` for now but define it as “all non-empty slots are revealed,” settable automatically after a reveal if no hidden occupied slots remain. This avoids breaking bridge/tests that currently gate on `solved`.

## New API

Replace session solve with per-slot reveal:

```solidity
struct RevealSlotArgs {
    uint8 slotIdx;
    bytes proof;
    bytes plaintext;          // 39 field elements: pose, dimensions, palette indices
    bytes32[10] palette;      // canonical 10-color named palette as field elements
    bytes32 paletteSalt;
    uint8 revealedRank;       // public ordering among revealed slots
    bytes32[2] newT10;        // updated BW shadow commitment after excluding this slot
    bytes proofT10;           // atomic T10 refresh proof
}

function revealSlot(uint256 shadowId, RevealSlotArgs calldata args) external whenNotPaused;
function revealSlots(uint256 shadowId, RevealSlotArgs[] calldata args) external whenNotPaused;
```

`revealSlots` is optional batching. It must be equivalent to calling `revealSlot` repeatedly, except it should refresh the hidden BW/T10 once at the end if that is how the T10 circuit is structured.

## Proof Binding

The reveal proof should prove one current hidden slot opens to the emitted plaintext.

Proposed public inputs:

```text
PI[0] shadowId
PI[1] slotIdx
PI[2] featureId
PI[3] oldLiveStateHash
PI[4] stateCommit = sponge_39(plaintext)
PI[5] paletteCommit
PI[6] ownerPkX
PI[7] ownerPkY
PI[8] revealedRank
```

Contract-provided values:

- `shadowId` from calldata.
- `slotIdx` from calldata.
- `featureId` and `oldLiveStateHash` from `ManifestEntry`.
- `stateCommit` recomputed from `plaintext` via `sponge_39`.
- `paletteCommit` from `FeatureNFT.paletteCommitOf(featureId)`.
- owner pubkey from shadow header.
- `revealedRank` from calldata, range-checked by contract and/or circuit.

Circuit responsibilities:

- Prove owner knowledge of the current decryption key for the slot.
- Prove the plaintext encrypts/commits to the current ciphertext commitment embedded in `oldLiveStateHash`.
- Reconstruct `oldLiveStateHash` from:
  - `stateCommit`,
  - `ctCommit`,
  - `c1.x`,
  - `c1.y`,
  - `mutationCount`,
  - `chainTip`.
- Ensure `sponge_39(plaintext) == stateCommit`.
- Ensure public inputs match the slot being revealed.

Contract responsibilities:

- Reject non-owner.
- Reject `slotIdx >= 16`.
- Reject `EMPTY` and `REVEALED` slots.
- Verify reveal proof.
- Verify/open palette by calling FeatureNFT reveal hook.
- Set slot kind to `REVEALED`.
- Store revealed rank.
- Refresh hidden BW/T10 state atomically.
- Emit a `ShadowSlotRevealed` event.

## FeatureNFT Hook Rename

Current hook name:

```solidity
revealPaletteAtSolve(...)
```

This is now misleading. Rename it to:

```solidity
revealInsertedFeature(
    uint256 featureId,
    uint256 shadowId,
    uint8 slotIdx,
    bytes32[16] calldata palette,
    bytes32 salt,
    bytes calldata plaintext
)
```

It should still:

- require caller is `ShadowToken`,
- reject double reveal,
- recompute `sponge_palette_salt(palette, salt) == paletteCommit`,
- emit `FeaturePaletteRevealed`,
- emit `FeatureSlotRevealed`,
- mark `paletteRevealed = true`.

Add/keep a ShadowToken-level event:

```solidity
event ShadowSlotRevealed(
    uint256 indexed shadowId,
    uint8 indexed slotIdx,
    uint256 indexed featureId,
    uint8 revealedRank
);
```

## Mutation / Transfer / Insert / Extract Rules

### mutateSlot

Reject if slot is not hidden `OCCUPIED`:

```solidity
if (m.kind != SlotKind.OCCUPIED) revert SlotNotMutable(slotIdx);
```

### mutateBatch

Reject if any targeted slot is `REVEALED`. Batch semantics must remain atomic.

### extractSlot

Reject `REVEALED`. A revealed feature is permanently bound to its slot.

### insertFeature

Only `EMPTY` is insertable. `REVEALED` is not empty.

### transferShadow

Only hidden `OCCUPIED` slots need new ciphertext/c1/liveStateHash. `REVEALED` slots are public and immutable, so transfer should skip re-encryption for them.

Important: the transfer proof/T10 circuit must be updated so revealed slots contribute as public revealed slots, not hidden ciphertext slots.

### setZIndexCommit

Hidden z-index changes must not move revealed slots underneath hidden BW content. Recommended rule:

- `zIndexCommit` governs hidden `OCCUPIED` slots only.
- revealed slots use public `revealedRank` and always render above hidden BW.
- once a slot is revealed, its `revealedRank` is immutable.

If users need to choose revealed ordering, they choose `revealedRank` at reveal time.

## BW Shadow Generation / T10 Semantics

This is the key invariant:

> Any revealed slot must be ignored for generation of the BW shadow.

Therefore every state-changing operation that affects the public BW downscale must compute it from hidden `OCCUPIED` slots only.

Required changes:

1. Update T10/shadow-generation circuits so `SlotKind.REVEALED` contributes the same as empty/no hidden source for BW generation.
2. Update `ShadowToken._refreshT10Atomically` public inputs or witness expectations if it currently assumes 16 live hidden slots.
3. On reveal, refresh T10 atomically after the slot becomes public/ignored.
4. On mutate/insert/extract/transfer/z-index, hidden BW generation continues to ignore revealed slots.

If the current T10 circuit cannot represent `REVEALED`, it must be changed before contract cutover is considered complete.

## Rendering Semantics

Renderer should use two layers:

1. Hidden BW base:
   - generated from hidden `OCCUPIED` slots only,
   - excludes `EMPTY` and `REVEALED` slots.
2. Revealed full-color overlay:
   - uses emitted plaintext and palette for `REVEALED` slots,
   - sorted by public `revealedRank`,
   - always above BW base.

This means revealed pixels are never hidden by BW pixels. They may be hidden only by later/higher-ranked revealed features if ranks overlap.

## Bridge / Mirror Semantics

Before enabling bridge for partially revealed shadows, L2→L1 payloads must include enough information for L1 to reconstruct visible state:

- slot kind bitmap including `REVEALED`,
- revealed feature IDs,
- revealed ranks,
- revealed plaintext/palette availability via events or mirrored storage commitments.

Conservative option: block bridge while any revealed slots exist until mirror support is added.

Recommended product option: support revealed metadata in bridge payload now, because partial reveal is a first-class state.

## Reverting The Most Recent Changes

Do not use `git reset` because the tree contains many unrelated dirty files. Revert surgically.

Remove/replace the recent session-reveal edits:

1. `contracts/src/ShadowToken.sol`
   - remove `solving`, `solveRequired`, `solveRevealed`, session events, and session APIs;
   - keep the useful per-slot reveal proof binding but move it into `revealSlot(s)`;
   - change `SlotKind` to include `REVEALED`;
   - add slot-level lock behavior.
2. `contracts/src/IFeatureNFT.sol`
   - rename `revealPaletteAtSolve` to `revealInsertedFeature`.
3. `contracts/src/FeatureNFT.sol`
   - rename implementation and comments.
4. `contracts/test/SolveShadow.t.sol`
   - replace session tests with incremental reveal tests.
5. `contracts/test/SolveShadowMaxOccupancy.t.sol`
   - replace solve-session gas tests with revealSlot/revealSlots gas tests.
6. `contracts/test/GasAttribution.t.sol`
   - update labels/path from feature solve to incremental reveal.
7. `contracts/test/Testable.sol`
   - remove test-only solve-session field resets.
8. `contracts/script/SolveOnSepolia.s.sol`
   - replace with a reveal-slot broadcaster or remove if no longer useful.
9. `contracts/test/fixtures/zk_surface_manifest.json`
   - replace `solveFeatureReveal` with `incrementalFeatureReveal`.
10. `roadmap/reveal_canvas_fix_handoff.md`
   - supersede with this plan; do not treat it as the target architecture.

The already-deleted canvas-only prototype files should remain deleted unless needed for reference:

- `circuits/solve_canvas/src/main.nr`
- `circuits/solve_canvas/Nargo.toml`
- `tools/build_solve_canvas_fixture.py`

## Test Plan

### Contract unit tests

Add/modify tests for:

- owner can reveal one hidden occupied slot;
- non-owner cannot reveal;
- cannot reveal empty slot;
- cannot reveal already revealed slot;
- reveal emits plaintext and palette events;
- reveal sets slot kind to `REVEALED`;
- reveal stores immutable public rank;
- mutate revealed slot reverts;
- mutateBatch containing revealed slot reverts atomically;
- extract revealed slot reverts;
- insert into revealed slot reverts;
- transferShadow skips revealed slots and does not require ciphertext for them;
- z-index update cannot demote revealed slots under BW;
- T10/BW update ignores revealed slots;
- all-hidden existing behavior still works;
- all-revealed shadow behavior is well-defined.

### Real proof tests

After circuit update, add real-verifier tests:

- successful reveal of one slot against a generated fixture;
- tampered plaintext fails;
- tampered palette fails;
- wrong slot index fails;
- wrong featureId fails;
- wrong owner key fails;
- stale liveStateHash fails after mutation;
- reveal after transfer uses current owner key, not old owner key.

### Gas tests

Measure:

- one-slot reveal;
- 4-slot batch reveal;
- 16-slot progressive reveal total;
- transferShadow with 0/8/16 revealed slots;
- mutateBatch with mixed hidden/revealed rejection path.

## Open Questions / Assumptions

I can implement with the following assumptions unless you want a different product rule:

1. Revealed slot rank is chosen and frozen at reveal time.
2. Hidden `zIndexCommit` affects hidden BW slots only after this change.
3. `solved` remains as a compatibility flag meaning “all non-empty slots are revealed,” not a separate user-triggered solve.
4. Bridge support should be updated for partially revealed state rather than blocked.
5. Revealed features remain inserted/custody-locked forever and cannot become standalone FeatureNFTs again.

## Recommended Implementation Order

1. Cut contract state/API to `SlotKind.REVEALED` and `revealSlot(s)`.
2. Update FeatureNFT hook naming and events.
3. Enforce revealed-slot lockouts across mutate/extract/insert/transfer/z-index.
4. Update T10/BW circuit interface to ignore revealed slots.
5. Update tests to pin every state transition.
6. Update scripts/manifests/docs.
7. Generate real reveal proof/verifier and fixtures.
8. Run focused Forge tests, real proof tests, manifest checks, gas tests, and EIP-170 checks.
