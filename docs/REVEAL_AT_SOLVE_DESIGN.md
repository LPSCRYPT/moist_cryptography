# Reveal at solve — full canonical-image design

**Branch:** `reveal-update`. **Status:** in progress, supersedes
`STAGING_REFACTOR/2026-04-27_palette_reveal_working.md`.

## Spec

`solve` is the single canonical reveal moment. One tx that simultaneously:

1. opens the per-carrier `paletteCommit` (16 RGB colors + salt → public)
2. opens the per-slot `liveStateHash`'s `stateCommit` (39-field plaintext
   → public; gives pose, w, h, palette indices)
3. opens the `zIndexCommit` (16-element z-permutation; this already
   happens in current `solve`)
4. freezes the shadow (`solved = true`, no further mutations)
5. auto-extracts every inserted carrier (already happens)
6. unlocks `bridgeShadow` (already gated on `solved == true`)

Post-solve the chain stores everything needed to render the canonical
NFT image with no off-chain decrypt: anyone can compose 16 sprites
from event-emitted plaintexts at their poses with their event-emitted
palettes in the event-emitted z-order.

## What's bound by what (3 commitments)

| Commitment | Storage | Hides | Mutability | Opened by |
|---|---|---|---|---|
| `paletteCommit` | `FeatureNFT._features[fid]` | 16 RGB colors + salt | immutable from mint | new on-chain `sponge_palette_salt` check at solve |
| `liveStateHash` (lsh) | `ShadowToken._manifests[shadowId][slot]` | 39-field plaintext (pose, w, h, palette indices) via `stateCommit`, plus ECIES envelope (`ctCommit`, `c1.x`, `c1.y`), plus `count`, plus `chainTip` | updated every mutate / extract / insert / transferFeature | proof binds `stateCommit` via PI[1] root; new on-chain `sponge_39(plaintext) == stateCommit` check binds the calldata plaintext to what the proof actually witnessed |
| `zIndexCommit` | `ShadowToken._shadows[shadowId]` | z-permutation + salt | immutable from `setZIndexCommit` | proof binds `zPermPacked` via PI[2] vs `zIndexCommit` (existing) |

## Why no ZK proof for palette/plaintext reveal

The `paletteCommit` and `stateCommit` are stored on chain (directly or
folded into `liveStateHash` which the proof binds). Soundness comes
from the chain-side hash check; a separate ZK proof of
"I know `(palette, salt)` opening `paletteCommit`" duplicates the
collision-resistance argument the contract can verify directly via
Poseidon2 in a few hundred microseconds of EVM.

This is the key cost-saving observation: the original
`palette_reveal_v2` design with one ZK proof per carrier (3.5M gas
per slot × 16 slots = 56M, breaks 16M cap) is replaced by 16 native
Poseidon2 sponges (~70k each = ~1.1M total).

## Calldata shape

```solidity
struct SolveArgs {
    uint256 shadowId;
    bytes   proof;                   // solve_shadow_v2 proof (unchanged)
    bytes[16]            plaintexts; // per-slot 39 fields = 1248 B; empty for EMPTY slots
    bytes32[16][16]      palettes;   // [slot][color]: 16 RGB-as-Field per slot; zero rows for EMPTY
    bytes32[16]          paletteSalts; // per-slot salt; 0 for EMPTY
    bytes32              zPermPacked;
    uint8[16]            zPerm;
}
```

Removed from current SolveArgs: `bytes32[16] stateCommits` — contract
now derives it on chain via `sponge_39(plaintexts[i])`.

## Solve flow

```
1. _ownerOf(shadowId) == msg.sender                                (existing)
2. !s.solved                                                       (existing)
3. lengths/empty-slot consistency checks                           (existing-ish)
4. For each slot i:
     if OCCUPIED:
         stateCommit[i] = sponge_39(plaintexts[i])                 (NEW on-chain)
     else:
         stateCommit[i] = 0                                        (NEW)
5. piS[1] = sponge_16(stateCommit array)                           (was: caller-supplied stateCommits, now derived)
   Other PI fields unchanged.
6. solveShadowVerifier.verify(proof, piS)                          (existing)
7. s.solved = true; s.zIndexRevealed = uint64(zPermPacked); s.zIndexRevealedSet = true;  (existing)
8. For each OCCUPIED slot i:
     featureId = manifest[i].featureId
     featureNFT.revealPaletteAtSolve(featureId, palettes[i], paletteSalts[i])  (NEW)
       which on FeatureNFT:
         - asserts sponge_palette_salt(palette, salt) == f.paletteCommit  (NEW Yul)
         - asserts !f.paletteRevealed                              (NEW)
         - f.paletteRevealed = true                                (NEW)
         - emits FeaturePaletteRevealed(featureId, paletteCommit, rgb_48b)
     emit FeatureSlotRevealed(featureId, shadowId, slotIdx, plaintexts[i])    (NEW)
9. _autoExtractAllSlots                                            (existing)
10. emit ShadowSolved                                              (existing)
```

## New / changed events

```solidity
// New on FeatureNFT (privileged: ShadowToken-only at solve):
event FeatureSlotRevealed(
    uint256 indexed featureId,
    uint256 indexed shadowId,
    uint8   indexed slotIdx,
    bytes   plaintext  // 39 fields = 1248 B
);

// Existing on FeatureNFT, kept:
event FeaturePaletteRevealed(uint256 indexed featureId, bytes32 paletteCommit, bytes paletteRGB);

// Existing on ShadowToken, kept:
event ShadowSolved(uint256 indexed shadowId, address indexed solver, uint64 zIndexRevealed);
```

## Removed surface

| Removed | Reason |
|---|---|
| `FeatureNFT.revealPalette(featureId, proof, pi)` | Reveal happens in solve only |
| `FeatureNFT.paletteRevealVerifier` slot + `setPaletteRevealVerifier` | No verifier needed |
| `FeatureNFT.PaletteAlreadyRevealed` error | One-shot enforced via `paletteRevealed` flag at `revealPaletteAtSolve` |
| `FeatureNFT.PALETTE_REVEAL_PI_LEN` | n/a |
| `FeatureNFT.SLOT_PALETTE_REVEAL` | n/a |
| `circuits/palette_reveal_v2/` | Soundness via on-chain sponge |
| `contracts/src/PaletteRevealV2Verifier.sol` | n/a |
| `contracts/script/RevealPaletteOnSepolia.s.sol` | Standalone reveal path gone |
| `tools/build_palette_reveal_fixture.py` | n/a |

## Held-carrier semantics

A carrier extracted (via `extractSlot`) BEFORE the host shadow's
`solve` is held by an EOA with `paletteCommit` still committed. There
is no standalone reveal path under this design. The carrier can only
have its palette revealed by being **re-inserted** into another
shadow which subsequently solves. If never re-inserted, its palette
stays committed forever.

This is by design: the spec ties reveal to solve; the reveal moment
is per-shadow, not per-carrier.

## On-chain Poseidon2 helpers needed

| Helper | Existing? | Used by |
|---|---|---|
| `Poseidon2YulSponge.sponge_39` | yes | new on-chain plaintext binding |
| `Poseidon2YulSponge16.sponge_8_pad16` | yes | existing PI[1] root |
| `Poseidon2YulSpongePaletteSalt` (new, sponge_17) | NEW | per-slot palette commitment check |

The sponge_17 contract: 5 full rate-3 absorbs over `palette[0..14]`
(15 elements) + 1 partial absorb of `(palette[15], salt)` + sentinel
pad. 7 permutations, byte-equivalent to
`circuits/palette_reveal_v2/src/main.nr::sponge_palette_salt` — which
becomes the spec for the Yul implementation, then is deleted.

## Gas budget

| Component | Per-slot | 16 slots |
|---|---|---|
| sponge_39 over plaintext (Yul, 14 perms) | ~120-150k | ~2.0-2.4M |
| sponge_palette_salt (Yul, 7 perms) | ~60-80k | ~1.0-1.3M |
| paletteRevealed flag SSTORE | ~5k | ~80k |
| FeaturePaletteRevealed emit (48 B + 2 topics) | ~7k | ~112k |
| FeatureSlotRevealed emit (1248 B + 3 topics) | ~25k | ~400k |
| Calldata overhead per slot (palette 512 B + salt 32 B + plaintext 1248 B) | ~28k | ~448k |
| **Per-slot reveal overhead** | **~245-290k** | |
| **16-slot reveal overhead** | | **~3.9-4.7M** |

Solve total estimate (16 occupancy):
- existing solve: ~3.7-5.0M (varies w/ occupancy + auto-extract count)
- + reveal overhead: ~4.7M
- **= ~9.7M total, well under the 16M cap.**

For 8 occupancy: ~6.5M.

## Migration path

Pipeline #4 is now **superseded-by-#5-pending**. Once the redesign is
implemented and tested:

1. Pipeline #5 deploy on Base Sepolia.
2. Lifecycle re-broadcast on #5: registerImage → mintShadow → mutate
   → setZIndex → solve-with-full-reveal.
3. Verify post-solve: `paletteRevealed` flag flipped on all carriers,
   `FeaturePaletteRevealed` and `FeatureSlotRevealed` events emitted,
   visualizer renders directly from chain (no sk needed).
4. Pipeline #4 demoted to "Historical (palette-reveal-via-separate-fn,
   superseded by full-reveal-at-solve)".

## Implementation order

1. `Poseidon2YulSpongePaletteSalt` Yul contract + integration test.
2. FeatureNFT: drop standalone revealPalette surface.
3. FeatureNFT: add `revealPaletteAtSolve` ShadowToken-only.
4. FeatureNFT: add `FeatureSlotRevealed` event.
5. ShadowToken.solve: extend SolveArgs, add per-slot reveal logic,
   derive stateCommits internally.
6. Update SolveShadow tests.
7. Delete palette_reveal_v2 circuit + verifier + standalone broadcast script.
8. Delete build_palette_reveal_fixture.py.
9. Update build_solve_*_fixture.py to emit palette + plaintext args.
10. Update render_onchain_shadow.py to read FeatureSlotRevealed events.
11. Update DeployShadowPipeline (drop palette verifier; add Yul sponge17).
12. forge test all green; pipeline #5 deploy + lifecycle.

## Open questions resolved

- **Held carriers:** by design, only revealed via re-insertion + future solve.
- **Bound vs advisory plaintext at solve:** now BOUND on chain via sponge_39 check. (Closes a real soundness gap in the current advisory-plaintext design.)
- **stateCommits in calldata:** removed; derived on chain.
