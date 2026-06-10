# Canvas-Only Solve Plan

## Goal

Replace the current per-feature solve reveal with a canvas-only reveal:

```text
prove hidden slots + z-order compose to this final 48x48 canvas
emit only the final canvas
```

This preserves the ability to publicly render a solved ShadowNFT while avoiding per-feature doxxing. The chain should reveal the finished artwork, not each component feature's plaintext, palette, pose, or z-order contribution.

## Current implementation

Current `ShadowToken.solve()` reveals feature internals slot-by-slot:

1. Verifies `solve_shadow_v2` against current slot state commitments.
2. For each occupied slot:
   - verifies `sponge_39(plaintext) == stateCommit`,
   - calls `FeatureNFT.revealPaletteAtSolve`,
   - emits `FeaturePaletteRevealed`,
   - emits `FeatureSlotRevealed` with full 39-field plaintext.
3. Marks the shadow solved.
4. Auto-extracts every occupied carrier.

This exposes:

- individual feature plaintexts,
- feature-local palette tables,
- per-slot feature payloads,
- enough data for indexers to reconstruct individual components.

At max occupancy this is also expensive: current `solve` with 16 occupied slots is about 24.7M gas.

## Intended implementation

Introduce a canvas-only solve path that verifies and reveals only the final composited image.

High-level flow:

```text
owner decrypts/knows all hidden slot states off-chain
owner computes final rendered 48x48 canvas
owner generates solve_canvas proof
owner submits proof + compact canvas bytes
contract verifies proof against current storage roots
contract marks shadow solved
contract emits final canvas only
```

The proof proves:

1. The prover knows the plaintext/palette data for every occupied slot.
2. Each private slot state matches the current on-chain `liveStateHash`.
3. Each private palette opens the corresponding stored `paletteCommit`.
4. The private z-order opens the stored `zIndexCommit`.
5. Rendering all occupied slots with canonical scale/rotation/translation/z-order produces the submitted final canvas.
6. The submitted canvas commitment equals the public `canvasCommit`.

The contract never emits per-feature plaintext or per-feature palette data.

## Privacy property

Canvas-only solve reveals:

- the final public artwork.

Canvas-only solve does not reveal:

- per-feature sprites,
- per-feature palette tables,
- per-feature local plaintexts,
- per-feature poses,
- per-feature dimensions beyond what can be visually inferred,
- slot-to-pixel attribution,
- z-order as a standalone value.

This does not make the solved artwork private. It only prevents the solve process from decomposing the artwork into individual reusable feature components.

## Proposed public data format

Prefer a compact globally indexed canvas:

```text
canvasPalette: 16 RGB colors = 48 bytes
canvasIndices: 48 * 48 4-bit indices = 1152 bytes
canvasBytes: canvasPalette || canvasIndices = 1200 bytes
```

Benefits:

- much smaller than full RGB (`6912` bytes),
- much smaller than current 16-slot plaintext reveal (`16 * 1248 = 19968` bytes),
- directly renderable by indexers,
- aligns with the project's existing palette-indexed representation.

If exact RGB output is required and global 16-color quantization is unacceptable, use full RGB instead:

```text
48 * 48 * 3 = 6912 bytes
```

That is still smaller than current max-occupancy per-feature reveal, but the global-palette format should be the default target.

## New circuit: `solve_canvas`

Add a new Noir circuit:

```text
circuits/solve_canvas/
```

### Public inputs

Suggested PI layout:

```text
PI[0]  shadow_id
PI[1]  manifest_root or lsh_root over current liveStateHash[16]
PI[2]  z_index_commit
PI[3]  canvas_commit
PI[4]  owner_pk_x
PI[5]  owner_pk_y
```

If the contract keeps using `sponge_16(liveStateHash[16])`, then `PI[1]` should be that root.

### Private witnesses

The witness should include:

```text
owner_sk
slot plaintexts[16][39]
slot palettes[16][16]
palette salts[16]
slot occupancy flags[16]
slot liveStateHash components[16]
z permutation
canvas palette
canvas packed indices
```

The circuit should derive all public commitments internally.

### Constraints

For each slot:

1. If occupied:
   - decode plaintext into pose, dimensions, and palette indices,
   - validate geometry using the same invariant as mint/mutate,
   - recompute `stateCommit`,
   - recompute `ctCommit` if required by the current `liveStateHash` layout,
   - reconstruct `liveStateHash`,
   - assert it matches the corresponding current slot hash.
2. If empty:
   - assert the corresponding live state hash is zero.
3. Recompute/open palette commitment:
   - `sponge_palette_salt(palette, salt) == paletteCommit`.
4. Open z-order:
   - recompute `zIndexCommit` from witnessed z permutation.
5. Render occupied slots into a 48x48 canvas using canonical renderer semantics:
   - nearest-neighbor scale,
   - quarter-turn rotation only,
   - x/y translation,
   - containment inside 48x48,
   - z-order compositing.
6. Quantize or assert the rendered canvas equals the submitted canvas encoding.
7. Recompute `canvasCommit` from `canvasBytes`.

The circuit must use the same rendering semantics as:

```text
tools/render_shadow.py
```

and the simulator must remain downstream of that canonical implementation.

## Contract changes

### Add storage

Add solved canvas metadata to `ShadowToken`:

```solidity
mapping(uint256 => bytes32) public solvedCanvasCommit;
mapping(uint256 => bytes32) public solvedCanvasDataHash;
```

`solvedCanvasCommit` should be the proof-bound Poseidon commitment used by the circuit.
`solvedCanvasDataHash` can be `keccak256(canvasBytes)` for cheap event/data integrity checks by indexers.

### Add event

```solidity
event ShadowCanvasSolved(
    uint256 indexed shadowId,
    bytes32 canvasCommit,
    bytes32 canvasDataHash,
    bytes canvas
);
```

If full canvas bytes are too large for one tx, use chunked events described below.

### Add verifier slot

Add a verifier slot for `SolveCanvasVerifier`:

```solidity
uint8 public constant SLOT_SOLVE_CANVAS = ...;
IVerifier internal solveCanvasVerifier;
```

This may require bytecode-budget review. If `ShadowToken.sol` is near EIP-170, replace or retire the old `solveShadowVerifier` instead of adding another permanent verifier slot.

### Add entry point

```solidity
struct SolveCanvasArgs {
    uint256 shadowId;
    bytes proof;
    bytes canvas;
    bytes32 canvasCommit;
    bytes32 zPermPacked;
}

function solveCanvas(SolveCanvasArgs calldata args) external whenNotPaused;
```

Contract behavior:

1. Require caller owns the shadow.
2. Require shadow is not already solved.
3. Build public inputs from storage:
   - `shadowId`,
   - current manifest liveStateHash root,
   - current `zIndexCommit`,
   - supplied `canvasCommit`,
   - current owner public key.
4. Verify `solve_canvas` proof.
5. Compute `canvasDataHash = keccak256(args.canvas)`.
6. Optionally verify `canvasCommit` on-chain from `args.canvas` if the same hash is available cheaply. If not, rely on the proof and store both hashes.
7. Mark shadow solved.
8. Set `zIndexRevealedSet = false` or leave z-index unrevealed; do not expose raw z-order if the privacy goal is canvas-only reveal.
9. Store canvas commitment/hash.
10. Emit `ShadowCanvasSolved`.

### What to do with carriers

Do not auto-extract carriers inside `solveCanvas` initially.

Recommended first behavior:

```text
solveCanvas freezes the shadow and leaves inserted carriers locked in the solved shadow.
```

Reason:

- auto-extracting all carriers is expensive,
- extraction is per-feature state mutation,
- extraction can reveal or emphasize individual features,
- solve's primary product goal is final artwork reveal.

If carrier recovery is required, add a later explicit path:

```solidity
claimSolvedSlot(uint256 shadowId, uint8 slotIdx)
```

That path should release custody without revealing feature plaintext. It can be chunked one slot at a time.

## Single-tx vs chunked canvas publication

### Preferred: single transaction

For global 16-color canvas encoding, `canvas` is about 1200 bytes. This should be feasible in one tx if the verifier remains within normal UltraHonk verifier cost.

Single-tx solve is best because the final image appears atomically.

### Fallback: chunked canvas publication

If full canvas publication plus verifier still exceeds the target gas envelope, chunk the canvas spatially or by byte range, not by feature.

State machine:

```text
Active -> CanvasSolvePending -> Solved
```

Entry points:

```solidity
beginCanvasSolve(shadowId, proof, canvasCommit, canvasDataHash, totalLength)
publishCanvasChunk(shadowId, chunkIndex, bytes chunk)
finishCanvasSolve(shadowId)
```

Rules:

- `beginCanvasSolve` verifies the proof and freezes the shadow.
- `publishCanvasChunk` stores or emits byte chunks of the final canvas only.
- `finishCanvasSolve` checks all chunks were published and `keccak256(joinedChunks) == canvasDataHash`.
- No chunk is feature-specific.

This progressively reveals the final image, but it does not dox individual features.

## State machine changes

Current solved state is a boolean:

```solidity
bool solved;
```

If chunking is needed, replace or extend this with:

```solidity
enum SolveState {
    Active,
    CanvasSolvePending,
    Solved
}
```

During `CanvasSolvePending`, block:

- `mutateSlot`,
- `mutateBatch`,
- `extractSlot`,
- `insertFeature`,
- `transferShadow`,
- `setZIndexCommit`,
- `bridgeShadow`,
- plain ERC721 transfer if it would create ambiguous ownership.

Only chunk publication/finalization should be allowed.

If single-tx `solveCanvas` is sufficient, keep the existing boolean and avoid this complexity.

## Renderer/tooling changes

Update or add:

```text
tools/build_solve_canvas_fixture.py
tools/render_canvas_solve.py
tools/test_solve_canvas_semantics.py
```

The builder should:

1. Load current slot state fixtures.
2. Render the final 48x48 canvas using canonical off-chain renderer.
3. Encode the canvas into the selected compact format.
4. Generate `solve_canvas` proof.
5. Emit contract fixture files.

The renderer should prefer `ShadowCanvasSolved` over per-feature reveal events when present.

## Tests

### Circuit tests

Add tests that prove/reject:

- valid current hidden state renders to submitted canvas,
- tampered canvas fails,
- tampered z-order fails,
- tampered slot plaintext fails,
- tampered palette fails,
- empty slots do not contribute pixels,
- out-of-frame pose fails,
- non-quarter-turn rotation fails,
- invalid scale/translation fails.

### Contract tests

Add Forge tests:

- `solveCanvas` succeeds with real proof,
- non-owner cannot solve,
- already solved shadow cannot solve again,
- wrong canvas bytes/proof fails,
- wrong current manifest state fails,
- post-solve mutation/extract/insert/transferShadow fail,
- event emits only final canvas, not per-feature plaintext/palette,
- gas under target at max occupancy.

### Privacy regression tests

Assert `solveCanvas` does not emit:

- `FeaturePaletteRevealed`,
- `FeatureSlotRevealed`,
- per-slot plaintext payloads,
- raw z permutation unless explicitly chosen.

## Migration / cutover

This should be a full cutover, not a parallel long-term solve mode.

Recommended path:

1. Build and test `solve_canvas` circuit.
2. Add `SolveCanvasVerifier`.
3. Replace `solve()` semantics or rename the existing per-feature solve to test-only/deprecated and remove it before deploy.
4. Update docs to define solve as canvas-only reveal.
5. Update render/indexer tools to consume `ShadowCanvasSolved`.
6. Remove per-feature reveal-at-solve dependencies if no longer used.

Avoid shipping both per-feature solve and canvas-only solve as public production paths unless there is a deliberate product reason. Two solve representations create ambiguity about what a solved ShadowNFT is.

## Open decisions

1. **Canvas encoding**
   - Recommended: global 16-color palette + 4-bit indices.
   - Alternative: full RGB bytes.

2. **Carrier lifecycle after solve**
   - Recommended first version: carriers remain locked in solved shadow.
   - Alternative: claimable solved slots.
   - Avoid auto-extract in the solve tx.

3. **Single tx or chunked publication**
   - Recommended first attempt: single tx.
   - Add chunking only if gas measurement requires it.

4. **Retire old solve or keep both temporarily**
   - Recommended: full cutover before production deploy.

## Acceptance criteria

The feature is complete when:

1. `solveCanvas` reveals a renderable final 48x48 canvas.
2. The proof binds that canvas to the current hidden slot state and z-order commitment.
3. No per-feature plaintext or palette events are emitted during solve.
4. Max-occupancy solve fits under the target gas envelope, or uses canvas chunks without feature-level reveal.
5. Existing mutation/transfer/insert/extract semantics remain unchanged before solve.
6. After solve, no hidden-state mutation path remains reachable.
7. Renderer/indexer tooling can reconstruct the solved NFT image from canvas-only events.
