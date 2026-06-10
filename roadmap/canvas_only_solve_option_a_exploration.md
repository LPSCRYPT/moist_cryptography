# Canvas-Only Solve Option A Exploration

Branch observed: `secondary`.

Goal: reveal only the final 48x48 canvas, without revealing per-feature plaintext, palettes, slot attribution, z-order, or partial canvas regions before the final reveal.

## Current Implementation State

`ShadowToken.solveCanvas` is contract-side canvas-only:

- verifies caller owns the shadow;
- rejects already-solved shadows;
- requires canonical canvas bytes length: `39 * 32 = 1248`;
- checks `Poseidon2Sponge39(canvas) == canvasCommit` before verifier call;
- builds 7 public inputs:
  1. `shadowId`
  2. current manifest live-state root
  3. current occupied-slot palette-commit root
  4. current `zIndexCommit`
  5. `canvasCommit`
  6. owner public key X
  7. owner public key Y
- marks the shadow solved;
- emits only `ShadowCanvasSolved(shadowId, canvasCommit, canvas)`.

The real `solve_canvas` verifier/fixture is not completed. A first-pass monolithic Noir circuit exists, but local `nargo execute` was killed after about 20 minutes, before `bb prove`. That means the current blocker is witness/ACIR scale, not Solidity wiring.

## Why the Monolithic Circuit Is Too Large

The naive circuit privately renders the full canvas by testing every canvas pixel against every slot:

```text
48 * 48 * 16 = 36,864 slot/pixel interactions
```

Each interaction includes private transform math, bounds checks, rotation handling, scaled coordinate mapping, palette lookup, z-order application, and final color comparison. The circuit also binds/decrypts all live slots and opens all palette commitments. Existing successful proofs mostly prove state transitions or small visual hashes; this one moves a full renderer into the circuit.

## Non-Goals

These options must not:

- reveal individual feature plaintext;
- reveal individual feature palettes;
- reveal z-order or slot attribution;
- emit partial tile/row pixels before final solve;
- allow mutation/insert/extract/transfer after a solve session has begun;
- accept a final canvas not bound to all subproofs.

## Option A1: Hidden Row-Band Proofs, Final Full Reveal

Split the 48 rows into row bands, for example:

- 8 proofs of 6 rows each;
- 6 proofs of 8 rows each;
- 12 proofs of 4 rows each.

Each row-band proof privately renders only its assigned rows. The public output is a commitment to the band pixels, not the band bytes themselves.

### Flow

1. `startCanvasSolve(shadowId, canvasCommit, expectedBandRoot)`
   - freezes the shadow against further mutation/insert/extract/transfer;
   - stores current roots/owner key/z-commit snapshot;
   - initializes a submitted-band bitmap.
2. `submitCanvasBand(shadowId, bandIndex, bandCommit, proof)`
   - verifies a band proof against the frozen snapshot;
   - records `bandCommit`;
   - marks the band completed.
3. `finishCanvasSolve(shadowId, canvas)`
   - requires all bands complete;
   - requires `canvas.length == 1248`;
   - requires `sponge_39(canvas) == canvasCommit`;
   - recomputes each band commitment from the submitted full canvas;
   - checks recomputed commitments match stored `bandCommit`s;
   - marks solved and emits the full canvas.

### Privacy

Intermediate transactions reveal only band indexes and commitments. They do not reveal band pixels. Final transaction reveals the entire current canvas at once.

### Advantages

- Minimal product semantic change.
- Row-major canvas packing makes final recomputation simpler than arbitrary tiles.
- Smaller circuits than full 48x48 rendering.
- No per-feature doxxing.

### Costs/Risks

- Multiple verifier calls across multiple transactions.
- Extra storage for session state and commitments.
- Need careful session invalidation/freezing.
- The per-band proof still needs all feature witnesses because any feature can overlap any row band.

## Option A2: Hidden Tiles, Final Full Reveal

Split the canvas into tiles, for example:

- 4x4 grid of 12x12 tiles = 16 proofs;
- 6x6 grid of 8x8 tiles = 36 proofs;
- 4x6 grid of 12x8 tiles = 24 proofs.

Each proof renders one tile privately and emits only `tileCommit`.

### Advantages

- Smaller per-proof pixel count than row bands.
- Better chance of fitting local/prover RAM.
- Possible to tune tile size after real benchmarking.

### Costs/Risks

- More proofs and more transaction overhead.
- Final canvas-to-tile commitment recomputation is more complex because canonical canvas encoding is packed row-major.
- More submitted-item bitmap/root bookkeeping.

## Option A3: Private Winner Witness Per Pixel

For each rendered pixel, witness the winning slot/order/source coordinate/palette index privately, then prove:

1. the winning slot actually covers that pixel and yields the claimed color;
2. no higher-z occupied slot covers that pixel;
3. the claimed color matches the final canvas color.

This does not reveal winners because the witness is private.

### Use

This is best used inside a row-band or tile proof, not as a standalone full-canvas proof.

### Advantages

- May reduce repeated color accumulation logic.
- Encodes renderer semantics more directly: final pixel equals topmost covering occupied slot, else background.

### Costs/Risks

- The exclusion proof still has to check later z slots, so worst-case it remains roughly `pixels * slots`.
- Needs careful handling of empty/background pixels.
- Does not by itself solve full-canvas scale.

## Option A4: Slot-Accumulator Per Band/Tile

Instead of per-pixel winner witnesses, process slots in z-order and update a small band/tile accumulator. This keeps the imperative renderer model but restricts the canvas accumulator to a small region.

### Advantages

- Closest to current monolithic circuit semantics.
- Natural cut from existing `assert_canvas_render`.
- Easier to reason about correctness than coverage-mask shortcuts.

### Costs/Risks

- Still loops over all slots for every pixel in the band/tile.
- Needs enough duplication or parameterization to support multiple band/tile sizes.

## Option A5: Recursive/Aggregated Proofs

Noir documentation says recursive proof verification is supported through Barretenberg recursive aggregation, via the `bb_proof_verification` library and the `recursive_aggregation` foreign call. However, this project is pinned to `nargo 1.0.0-beta.19` and `bb 5.0.0-nightly.20260419`, and there is no existing recursive verifier pattern in the repo.

### Verdict

Treat recursion as research, not the immediate implementation path. It may eventually allow many row/tile proofs to aggregate into one final proof, but it adds another high-risk toolchain surface. Contract-side multi-proof sessions are more practical first.

## Option A6: Semantic Reduction

Reveal a smaller canonical visual artifact, such as the T10/16x16 grayscale downscale, instead of the full 48x48 palette-indexed canvas.

### Verdict

Technically easier, but it changes the product promise. It is not a drop-in fix if the desired solved state is the full current canvas.

## Recommended Path

Build Option A1 first: hidden row-band proofs with final full-canvas reveal.

Reasoning:

- It preserves the privacy requirement.
- It keeps final reveal atomic from the user's perspective: no partial pixels are public before finish.
- It is simpler than arbitrary tiles because the canvas is row-major packed.
- It can be tuned by band height: start with 6-row bands, then adjust after proof benchmarks.
- It avoids relying on immature recursion support.

If row-band proofs still exceed RAM, move to Option A2 with smaller tiles.

## Contract Changes Needed

Add solve-session state, likely:

```solidity
struct CanvasSolveSession {
    bool active;
    bytes32 canvasCommit;
    bytes32 lshRoot;
    bytes32 paletteCommitRoot;
    bytes32 zIndexCommit;
    bytes32 ownerPkX;
    bytes32 ownerPkY;
    uint256 completedBitmap;
    bytes32 bandRootOrRollingCommit;
}
```

The contract must reject mutation, insertion, extraction, transfer, and z-index changes while `CanvasSolveSession.active == true`.

Prefer a rolling commitment or fixed-size band commitment array depending on gas/bytecode budget:

- fixed array: easier final checking, more storage;
- rolling commitment/root: less storage, more careful ordering constraints.

## Circuit Changes Needed

Create a parameterized row-band circuit with public inputs:

1. `shadowId`
2. frozen `lshRoot`
3. frozen `paletteCommitRoot`
4. frozen `zIndexCommit`
5. `canvasCommit`
6. owner public key X
7. owner public key Y
8. `bandIndex`
9. `bandCommit`

Private witness includes the same encrypted slot state/palettes/z-permutation as the monolithic proof plus only the band's canvas cells.

The band circuit proves:

- owner key derives owner public key;
- occupied slot plaintexts decrypt and bind to frozen `lshRoot`;
- palettes open to frozen `paletteCommitRoot`;
- z permutation opens to frozen `zIndexCommit`;
- rendered pixels for `bandIndex` equal the private band pixels;
- `bandCommit` commits to the private band pixels and their position;
- optionally, `canvasCommit` is included only as a session binding, not recomputed in every band proof.

## Verification Strategy

1. Keep existing contract tests for `solveCanvas` canonical length and privacy events.
2. Add session tests:
   - cannot start twice;
   - cannot mutate/insert/extract/transfer during active solve;
   - cannot submit duplicate band;
   - cannot finish before all bands complete;
   - cannot finish with canvas whose recomputed band commitments mismatch;
   - successful finish emits only full canvas.
3. Add real-proof tests once the band verifier exists:
   - one positive proof fixture;
   - corrupted public input fails;
   - corrupted band commit fails;
   - corrupted final canvas fails at finish.
4. Benchmark:
   - `nargo execute` RSS/time per band size;
   - `bb prove` RSS/time per band size;
   - Solidity verifier gas per band;
   - total gas across all session transactions;
   - final finish gas.

## Immediate Next Steps

1. Wait for the server benchmark of the monolithic proof to determine if it is merely local-RAM-bound or structurally too large.
2. In parallel, prototype a 6-row band circuit by extracting `assert_canvas_render_band` from `assert_canvas_render`.
3. Benchmark 6-row, 4-row, and 8-row band sizes.
4. If verifier gas per band plus contract overhead is too high, test tile sizes and consider a rolling root to reduce storage.
5. Only revisit recursion after a non-recursive band proof is working and measured.


## Revised Direction: Deferred Sequential Private Compositing

> Decision update: prefer z-layer transition proofs over row-band proofs.

The intended solve protocol is not row-band rendering. The preferred design is a solve-time, step-by-step private compositing session in ascending committed z-index order.

Each step proves one hidden z-layer transition:

```text
C_i -> C_{i+1}
```

where `C_i` is the current hidden canvas commitment. The proof does not reveal the feature, slot, palette, z-order entry, or intermediate canvas pixels.

### Default Transaction Model

Each layer transition can be submitted as its own transaction by default. This keeps each proof/gas unit small and lets the user progress through solve even when a full 16-step solve would exceed gas limits.

The contract should also expose a batching path so users can submit multiple consecutive layer proofs in one transaction when gas permits:

```text
submitSolveLayer(shadowId, proof, newCanvasCommit)
submitSolveLayers(shadowId, proofs[], newCanvasCommits[])
```

Batching must be purely an efficiency option. The canonical state machine is still one ordered cursor advancing from layer `0` through layer `15`. The batched function just repeats the same transition verification internally until gas or user preference says stop.

### Solve Lock Invariant

Once a solve session is initiated, the ShadowNFT and its inserted/extracted feature state are locked into solve-only mode.

Allowed while active:

```text
submit the next solve layer proof
submit a batch of consecutive solve layer proofs
finish solve by revealing the final canvas after all 16 layers are complete
cancel solve only if an explicit protocol escape hatch is intentionally added
```

Disallowed while active:

```text
mutate slot
batch mutate
insert feature
extract feature
transfer shadow
transfer or modify inserted features through this shadow path
set z-index commit
start another solve session
bridge state that would bypass the frozen snapshot
```

This lock is necessary because every layer proof binds to the frozen snapshot roots:

```text
liveStateRoot
paletteCommitRoot
zIndexCommit
ownerPk
```

If any of those can change mid-session, the rolling canvas commitment no longer represents a single coherent shadow state.

### Implemented Contract State

The contract now stores the solve cursor and rolling canvas commitment directly on `Shadow` to stay under EIP-170:

```solidity
struct Shadow {
    bytes32 ecdhPubX;
    bytes32 ecdhPubY;
    bool solved;
    bool solving;
    uint8 solveCursor;
    bytes32 rollingCanvasCommit;
    bytes32 zIndexCommit;
    uint64 mintIdx;
    uint64 mintedAt;
}
```

`startCanvasSolve(shadowId)` initializes:

```text
solveCursor = 0
rollingCanvasCommit = 0  // circuit convention: layer 0 treats this as blank canvas
solving = true
```

The contract does not store a user-supplied final canvas commitment. The 16th layer proof produces the final rolling commitment; `finishCanvasSolve` then reveals the full canvas and checks that the emitted bytes hash to that final rolling commitment.

Each successful transition requires:

```text
public layerIndex == cursor
public oldCanvasCommit == rollingCanvasCommit
proof verifies against frozen session roots
```

Then updates:

```text
rollingCanvasCommit = newCanvasCommit
cursor += 1
```

`finishCanvasSolve` requires:

```text
solveCursor == 16
sponge_39(finalCanvasBytes) == rollingCanvasCommit
```

Then it marks the shadow solved and emits only the full final canvas.

### Privacy Properties

Before the final reveal, observers see only:

```text
solve session started
cursor advanced
old/new canvas commitments
proof bytes
```

They do not learn:

```text
which slot is at a z-layer
which feature was painted
feature plaintext
palette
intermediate pixels
partial canvas regions
```

Use fixed 16 logical steps. Empty/unoccupied/private no-op layers still produce proofs, so the public protocol does not need to reveal a variable number of visible layers.

### Circuit Shape

Replace the monolithic `solve_canvas` relation with a `solve_canvas_layer` relation.

Public inputs:

```text
shadowId
frozenLiveStateRoot
frozenPaletteCommitRoot
frozenZIndexCommit
ownerPkX
ownerPkY
layerIndex
oldCanvasCommit
newCanvasCommit
```

Private witness:

```text
oldCanvas
newCanvas
zPerm
selectedSlot = zPerm[layerIndex]
selected slot plaintext
selected slot palette
selected palette salt
selected slot encrypted-state/opening data
owner secret/decryption witness
selected slot occupancy
```

The proof establishes:

```text
oldCanvas hashes to oldCanvasCommit
newCanvas hashes to newCanvasCommit
zPerm opens frozenZIndexCommit
selectedSlot is zPerm[layerIndex]
selected slot state binds into frozenLiveStateRoot
selected palette binds into frozenPaletteCommitRoot
if selected slot is occupied:
    newCanvas is oldCanvas with exactly that hidden feature composited over it
else:
    newCanvas == oldCanvas
```

### Implementation Priority

This supersedes the row-band recommendation as the primary Option A path.

Current implementation status:

```text
1. Contract solve-session state machine with mocked layer verifier: done.
2. Tests for locking, cursor ordering, batching equivalence, final reveal, canonical canvas length, and EIP-170: done.
3. Noir `solve_canvas_layer` prototype using full old/new canvas witnesses: still outstanding.
4. Benchmark one real layer proof: still outstanding; requires real circuit/verifier/proof generation.
5. If full old/new canvas hashing dominates, move canvasCommit from sponge_39 to a chunked/rooted canvas commitment.
```