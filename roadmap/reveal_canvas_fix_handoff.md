# Feature-by-Feature Reveal Solve Handoff

Branch observed during this continuation: `secondary`.

## Decision

Canvas-only solve was abandoned for now because the real canvas-render Noir circuit OOMed locally even after reducing it to a selected-layer proof. The chosen solve design is now feature-by-feature reveal. Privacy doxxing of individual features is accepted.

## Current Implementation

`ShadowToken` solve is now a chunkable feature reveal state machine:

```solidity
startFeatureRevealSolve(uint256 shadowId)
revealFeatureSlots(uint256 shadowId, FeatureRevealArgs[] calldata reveals)
finishFeatureRevealSolve(uint256 shadowId)
```

Per shadow state:

```solidity
bool solved;
bool solving;
uint16 solveRequired; // occupied-slot bitmap snapshotted at solve start
uint16 solveRevealed; // slots revealed during this solve session
bytes32 zIndexCommit;
```

Behavior:

1. `startFeatureRevealSolve` may only be called by the shadow owner on an unsolved, inactive shadow.
2. Starting snapshots the occupied-slot bitmap and sets `solving = true`.
3. While `solving == true`, existing mutation/state-change surfaces still revert with `SolveActive()`:
   - `mutateSlot`
   - `mutateBatch`
   - `extractSlot`
   - `insertFeature`
   - `transferShadow`
   - `setZIndexCommit`
4. `revealFeatureSlots` can submit one slot, several slots, or all slots in a transaction.
5. Each reveal must be for a slot occupied at solve start, and each slot can be revealed only once.
6. `finishFeatureRevealSolve` succeeds only when `solveRevealed == solveRequired`.
7. Empty slots are skipped. A fully empty shadow can start and immediately finish.
8. The final artwork is reconstructed by indexers from the emitted per-feature plaintext/palette events plus the z-index commitment/order opening used by the proof tooling.

## Per-Feature Reveal Public Inputs

`SOLVE_FEATURE_PI_LEN = 9`:

```text
PI[0] shadowId
PI[1] slotIdx
PI[2] featureId
PI[3] liveStateHash
PI[4] stateCommit = sponge_39(plaintext)
PI[5] paletteCommit
PI[6] zIndexCommit
PI[7] ownerPkX
PI[8] ownerPkY
```

Contract binding:

- `ShadowToken` recomputes `sponge_39(reveal.plaintext)` and requires it to match PI[4] through verifier public inputs.
- `ShadowToken` pulls the current manifest `liveStateHash`, `featureId`, owner key, and `zIndexCommit` from storage.
- `ShadowToken` pulls `paletteCommit` from `FeatureNFT.paletteCommitOf(featureId)`.
- After proof verification, `ShadowToken` calls `FeatureNFT.revealPaletteAtSolve`, which opens the palette commitment and emits:
  - `FeaturePaletteRevealed`
  - `FeatureSlotRevealed`
- The feature remains inserted/locked; solve does not extract carriers.

## Files Changed

- `contracts/src/ShadowToken.sol`
  - Removed deferred canvas solve API.
  - Added feature reveal solve API/state/events.
  - Removed obsolete canvas palette-root helper.
- `contracts/src/IFeatureNFT.sol`
  - Updated reveal hook docs from legacy/canvas-only to active feature solve.
- `contracts/script/SolveOnSepolia.s.sol`
  - Updated to broadcast feature solve start/finalize session boundaries.
- `contracts/test/SolveShadow.t.sol`
  - Rewritten around feature reveal solve state machine.
- `contracts/test/SolveShadowMaxOccupancy.t.sol`
  - Rewritten for max-occupancy feature reveal; asserts chunked transaction gas, not impossible all-in-one gas.
- `contracts/test/GasAttribution.t.sol`
  - Updated gas attribution labels and solve measurement path.
- `contracts/test/Testable.sol`
  - Updated test-only solved state setter for `solveRequired/solveRevealed`.
- `contracts/test/fixtures/zk_surface_manifest.json`
  - Replaced `solveCanvasLayer` surface with `solveFeatureReveal`.
- Removed obsolete untracked canvas-only prototype:
  - `circuits/solve_canvas/src/main.nr`
  - `circuits/solve_canvas/Nargo.toml`
  - `tools/build_solve_canvas_fixture.py`

## Verification Completed

From `contracts/`:

```text
forge test --match-contract SolveFeatureRevealTest -vv
  11 passed, 0 failed, 0 skipped

forge test --match-contract SolveShadowMaxOccupancyTest -vv
  2 passed, 0 failed, 0 skipped
  feature reveal solve 16 occ total mocked gas: 23,940,070
  feature reveal solve 4-slot max mocked tx gas: 5,979,001

forge test --match-contract GasAttributionTest --match-test 'test_featureReveal' -vv
  2 passed, 0 failed, 0 skipped
  feature reveal solve empty slots, mocked verifier: 235,924
  feature reveal solve 16 occ, mocked verifier: 23,800,451
```

## Important Outstanding Work

1. Real proof cutover is not complete yet.
   - Current contract tests use mock verifiers for the new 9-PI per-feature surface.
   - The existing `circuits/solve_shadow_v2` proves a 16-slot all-at-once reveal with a 7-field PI, so it does not match the new chunkable 9-PI API.
2. Next proof task:
   - Replace or add a per-feature Noir circuit that proves one occupied slot reveal against the 9 public inputs above.
   - Generate/update `contracts/src/SolveShadowVerifier.sol` for that circuit.
   - Generate real proof fixtures.
   - Add real-verifier positive and negative tests for `revealFeatureSlots`.
3. Gas numbers above isolate contract overhead with a mock verifier. Real verifier gas must be measured after verifier regeneration.
4. The total 16-feature solve remains about 24M gas in one logical sequence, but it is intended to be split. A 4-feature chunk measured below 6M mocked gas.
