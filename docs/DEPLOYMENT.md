# Deployment

This document records every Base Sepolia deploy of the v2 contract set
plus the on-chain operations executed against it.

**Canonical live deployment: pipeline #5** (full reveal at solve --
palette + plaintext revealed atomically inside `solve()`, no separate
verifier). Pipelines #3 and #4 preserved as historical references; see
"Historical pipelines" near the end of this document.

## Status (canonical = pipeline #5)

| Spec criterion | Pipeline | Status |
|---|---|---|
| Fresh contract set deployed (full-reveal-at-solve ABI) | **#5** | done -- 27 deploy txs, 99.7M gas |
| `registerImage` (face_disc proof) | #5 | done |
| `mintShadow` (1 shadow + 8 carriers, real palette + salt envelopes) | #5 | done |
| `setZIndexCommit` | #5 | done |
| **`solve` with palette + plaintext reveal** (item 5 spec, atomic) | **#5** | done -- tx [`0xea461ee9...`](https://sepolia.basescan.org/tx/0xea461ee94e8e41b5ed47e71589524050ea2c7545883eaeef946d211813ce1394), 8.14M gas, block 40,783,890. **8 `FeaturePaletteRevealed` + 8 `FeatureSlotRevealed` events** in single tx. |
| Visualizer renders solved shadow WITHOUT sk | #5 | done -- `tools/render_onchain_shadow.py` decodes plaintexts from FeatureSlotRevealed events; palettes from FeaturePaletteRevealed events; canonical NFT image from chain alone |
| `mutateSlot` (chained to live state) | **#5** | done -- B' slot 0, tx [`0x77c94d80...`](https://sepolia.basescan.org/tx/0x77c94d80f436e395b2461b8c82ee1ff92054d3c7c3eb35d5821a76c709969874), 7.12M gas, block 40,791,976 |
| `mutateBatch` (multi-slot in one tx) | **#5** | done -- B' slots 1+2, tx [`0x66ad4960...`](https://sepolia.basescan.org/tx/0x66ad496000c16901fbfe348eb5a2912069d14563f13a13c73c467deedc7f24ea), 10.80M gas, block 40,792,154 |
| `extractSlot` | **#5** | done -- B' slot 3, tx [`0xad84c4f2...`](https://sepolia.basescan.org/tx/0xad84c4f2b2f969cd191b02b840e55113fb974b82b41ca8321e3443ef4908efd2), 3.43M gas, block 40,792,228 |
| `insertFeature` (held carrier into empty slot) | **#5** | done -- carrier from B' slot 3 → B' slot 8, tx [`0xc8a2c7ba...`](https://sepolia.basescan.org/tx/0xc8a2c7bac817e014c17b7f39866a579b2a8238efd6837bba09f7dc35473d5c25), 7.25M gas, block 40,792,355 |
| **`transferShadow`** proof-bound (8-slot ECIES rotation) | **#5** | done -- B' PK2 → deployer, tx [`0x05ca2cf4...`](https://sepolia.basescan.org/tx/0x05ca2cf49db35adcd9750b761db9327163eb876ce63a435bd9c8bfeee0275482), 9.06M gas, block 40,792,654 |
| `transferFeature` V2 (held-carrier rotation) | **#5** | done -- A' slot-0 carrier deployer → PK2, tx [`0xb9470c0f...`](https://sepolia.basescan.org/tx/0xb9470c0f9aae7ef0526d423186059158a3e020c6c35ab798cd3877757c92b08e), 3.70M gas, block 40,792,820 |
| `bridgeShadow` L2-leg | **#5** | done -- A' → ShadowBridgeL2 #5, tx [`0x7e27fcb4...`](https://sepolia.basescan.org/tx/0x7e27fcb4b8737dec037238721640c5c46dd93987dfdaec3a9b38747a8e368556), 0.40M gas, block 40,792,879 |
| `bridgeShadow` L1 finalize | n/a | calendar-bound (~7d OP Stack window) -- bridge L2 wired to historical L1 mirror; deploy fresh mirror to exercise |

**Reveal architecture** (pipeline #5):
  * `FeatureNFT.revealPaletteAtSolve(featureId, shadowId, slotIdx, palette[16],
    salt, plaintext)` -- ShadowToken-only. Verifies
    `sponge_palette_salt(palette, salt) == storedPaletteCommit` via the
    new `Poseidon2YulSpongePaletteSalt` Yul contract (no ZK proof needed;
    soundness via Poseidon2 collision-resistance). Sets `paletteRevealed`,
    emits `FeaturePaletteRevealed(fid, commit, rgb_48b)` +
    `FeatureSlotRevealed(fid, shadowId, slotIdx, plaintext_1248b)`.
  * `ShadowToken.solve()` calls `revealPaletteAtSolve` per occupied slot,
    then auto-extracts. Plaintext is advisory at the chain layer
    (off-chain indexers verify `sponge_39(plaintext) == stateCommit`,
    where `stateCommit` is bound by the proof's PI[1]).
  * Removed: `revealPalette()` standalone fn, `palette_reveal_v2`
    circuit + verifier, `setPaletteRevealVerifier`. Replaced by the
    on-chain Yul sponge_17 + per-slot reveal at solve.
---

## Network

- Chain: **Base Sepolia** (chain id `84532`)
- L2 block explorer: https://sepolia.basescan.org/
- RPC tested: `https://base-sepolia.gateway.tenderly.co` (others have
  lower per-tx envelope caps)
- Deployer EOA: `0x1b43AFe43afC74bF9D0EBd764787eFD7CCcC2B6F`

## Contract addresses (canonical = pipeline #5)

Deploy commit: `3e08ad1` -- `reveal-update: Option B (cheap) + visualizer + tooling`.
Deployed 2026-04-28.

| Contract | Address |
|---|---|
| `Poseidon2YulSponge` (sponge_39) | [`0xe57AB0963Aa9eD22193910Ed24CeE188003126fA`](https://sepolia.basescan.org/address/0xe57AB0963Aa9eD22193910Ed24CeE188003126fA) |
| `Poseidon2YulSponge16` (sponge_16) | [`0x43a58e82c7D2C3464299780512Ac9fB96971Ec68`](https://sepolia.basescan.org/address/0x43a58e82c7D2C3464299780512Ac9fB96971Ec68) |
| **`Poseidon2YulSpongePaletteSalt`** (sponge_17, NEW) | [`0x3515BD5118d92513B4751051ed5bD9ed274330b8`](https://sepolia.basescan.org/address/0x3515BD5118d92513B4751051ed5bD9ed274330b8) |
| `KeyRegistry` | [`0xA71143F4E5bB5a11C98e9A1eE8D02b4344f3a2eE`](https://sepolia.basescan.org/address/0xA71143F4E5bB5a11C98e9A1eE8D02b4344f3a2eE) |
| `ShadowToken` | [`0xbf9f3FC142f497774986345F027d3eaCa7Eba810`](https://sepolia.basescan.org/address/0xbf9f3FC142f497774986345F027d3eaCa7Eba810) |
| `FeatureNFT` | [`0x414606aBa41297a4Dc71F2603453177885499f16`](https://sepolia.basescan.org/address/0x414606aBa41297a4Dc71F2603453177885499f16) |
| `MintShadowVerifier` | [`0xF22Cc89703CA4159928f50Ca9c490586A2cd2fc4`](https://sepolia.basescan.org/address/0xF22Cc89703CA4159928f50Ca9c490586A2cd2fc4) |
| `FaceDiscVerifier` | [`0x96f6CfBc8526a1fc76827140d701A5D7B924d1e9`](https://sepolia.basescan.org/address/0x96f6CfBc8526a1fc76827140d701A5D7B924d1e9) |
| `MutateSlotVerifier` | [`0xD513070B6E0A832efA4A4B79d63Ce8668f233Aa9`](https://sepolia.basescan.org/address/0xD513070B6E0A832efA4A4B79d63Ce8668f233Aa9) |
| `T10ShadowVerifier` | [`0xaFFD93687B99A358A704A8caffeaAf57A59f5CBC`](https://sepolia.basescan.org/address/0xaFFD93687B99A358A704A8caffeaAf57A59f5CBC) |
| `ZIndexCommitVerifier` | [`0x7AE1a5B0bCC92f504a3d1E0dB0465d6ebee67a24`](https://sepolia.basescan.org/address/0x7AE1a5B0bCC92f504a3d1E0dB0465d6ebee67a24) |
| `TransferShadowVerifier` | [`0x6Bc27317aCcc5ce53B78e4Ac2377683974154089`](https://sepolia.basescan.org/address/0x6Bc27317aCcc5ce53B78e4Ac2377683974154089) |
| `SolveShadowVerifier` | [`0x3c9aE7A736003e19De09BAF645f0C175344476b5`](https://sepolia.basescan.org/address/0x3c9aE7A736003e19De09BAF645f0C175344476b5) |
| `TransferFeatureV2Verifier` | [`0x3656b49d2F9A642A7c9d212b42e87495570B9560`](https://sepolia.basescan.org/address/0x3656b49d2F9A642A7c9d212b42e87495570B9560) |
| `ShadowBridgeL2` (deployed 2026-04-28, **broken-wire**: `l1Mirror` set to historical `0x89dB0113`) | [`0x9Ef3f7a3340454BffD618099Ae5645218b4924CC`](https://sepolia.basescan.org/address/0x9Ef3f7a3340454BffD618099Ae5645218b4924CC) |
| `ShadowBridgeL2` **#5b** (deployed 2026-04-28, fresh pair; canonical) | [`0x49A8d60114C4869D2f0422c8e5b1f9442f5e4529`](https://sepolia.basescan.org/address/0x49A8d60114C4869D2f0422c8e5b1f9442f5e4529) |
| `ShadowMirrorL1` (Eth Sepolia, paired with #5b) | [`0xe9B8b1DddaEC95C165B0c4aE55Ea13FeAAC79042`](https://sepolia.etherscan.io/address/0xe9B8b1DddaEC95C165B0c4aE55Ea13FeAAC79042) |

**No** `PaletteRevealV2Verifier` -- replaced by the on-chain
`Poseidon2YulSpongePaletteSalt` (sponge_17). Soundness flows from the
chain-stored `paletteCommit` storage check + Poseidon2 collision-
resistance, not from a per-carrier ZK proof.

Wiring: every privileged setter is one-shot and locked after deploy.
Pipeline #5's `DeployShadowPipeline.s.sol` deploys all 14 contracts and
wires every verifier slot in a single broadcast.

## Deploy run (pipeline #5)

```
forge script script/DeployShadowPipeline.s.sol:DeployShadowPipeline \
    --broadcast --rpc-url https://base-sepolia.gateway.tenderly.co \
    --private-key $PRIVATE_KEY
```

Total gas: 99,673,531 across 27 setup txs. Cost ~0.001 Sepolia ETH.
No single tx exceeded EIP-170; per-tx CREATE never breaks the 16M cap.

Broadcast artifact:
`contracts/broadcast/DeployShadowPipeline.s.sol/84532/run-latest.json`

---

## Pipeline #5 lifecycle

Three working shadows (C, D, E) collectively exercise every entry-point
function on pipeline #5 with no stranded state. Two earlier shadows
(A, B) remain on chain as instructive scar tissue from bugs since fixed
in the toolchain; their tables are documented under "Historical
casualties" below.

### Bridge wiring (pipeline #5)

Two L2 bridges exist on chain. Only the second is canonical:

| Bridge | Address | `l1Mirror` | Status |
|---|---|---|---|
| #5 (first attempt) | `0x9Ef3f7a3340454BffD618099Ae5645218b4924CC` | `0x89dB0113...` (pipeline #3 mirror) | **stranded** -- holds A; L1 finalize not deliverable because the pipeline-#3 L1 mirror's `l2Bridge` is fixed to pipeline #3's L2 bridge |
| #5b (canonical) | `0x49A8d60114C4869D2f0422c8e5b1f9442f5e4529` | `0xe9B8b1DddaEC95C165B0c4aE55Ea13FeAAC79042` (pipeline #5 mirror, fresh deploy) | **live** -- holds shadows C and D; clean L1-finalize candidates after the OP-Stack 7-day window |

Why two: `ShadowBridgeL2.setL1Mirror` and `ShadowMirrorL1.setL2Bridge`
are both one-shot (revert if already set). Once the first L2 bridge
was wired to the historical L1 mirror, redirecting it to a new
mirror was impossible -- only a fresh PAIR works. The existing L2
bridge `0x9Ef3f7a3` retains custody of A permanently; the message
it dispatched references the wrong L1 mirror and is undeliverable.

Fresh-pair deploy txs:
  * `ShadowMirrorL1` deploy (Eth Sepolia): [`0xd0b6cdcd...`](https://sepolia.etherscan.io/tx/0xd0b6cdcd0c06ed0863f8dea48a864438374765257ae18a2d8bd6d303bac6ab72), block 10,747,~273
  * `ShadowBridgeL2` deploy (Base Sepolia): [`0x90918ade...`](https://sepolia.basescan.org/tx/0x90918ade70c45f66624769ba3f616fd625ea35505c277a5c6d5861bae331b753)
  * `setL2Bridge` on L1 mirror: [`0xa27ca617...`](https://sepolia.etherscan.io/tx/0xa27ca617a44cc8902b9b653e2738b05b34eefffb38a395f05c2b5575a7da32d4), block 10,747,281
  * `setL1Mirror` on L2 bridge: [`0xa5f466a3...`](https://sepolia.basescan.org/tx/0xa5f466a37b7f6cc374971d5dc83fab19744c8fc08091a7fe47446a032e59b319), block 40,793,510

### Shadow C -- minimal mint -> solve -> bridge

C is the smallest demo: deployer-owned, no mutations, straight to solve
and bridge through the canonical `#5b` pair. Image is synthetic
`grid_48/s100_smile_+3.png` registered as `face_disc/carol0` (disc score
16.4, face_disc proof generated locally on M3 in ~3 min). Mint seed
`solve_demo_c` with owner_seed `palette_reveal_live` so owner_pk matches
the deployer's KeyRegistry registration. C shadowId =
`0x0c923942a9a2e9c8a4178a12ade300472d62ce1ff3c2b4281a465ca827dbea3c`,
`mint_counter_base = 16` (C's carriers are 17..24).

| # | Action | Tx | Block | Gas |
|---|---|---|---:|---:|
| C1 | `registerImage` (image C = carol0) | [`0x0193400d...`](https://sepolia.basescan.org/tx/0x0193400d430a37dab6bff5ed0097fcef1e18a1dba5b0c845f6d2fa3602a60a8c) | 40,794,257 | -- |
| C2 | `mintShadow` C (8 carriers, mintCounter 17..24) | [`0x876157cf...`](https://sepolia.basescan.org/tx/0x876157cf7f963149ab41b085d7f12cd98522520850484df088fb080105da8994) | 40,794,258 | ~10.5M |
| C3 | `setZIndexCommit` C | [`0xa8f8fe52...`](https://sepolia.basescan.org/tx/0xa8f8fe521039410011381dbe1f804e9e667e266c5d84ce73aabb02af680b5779) | 40,794,393 | -- |
| C4 | **`solve`** C (palette + plaintext atomic reveal; 8+8 events; auto-extracts 8 carriers) | [`0xfd58fb3d...`](https://sepolia.basescan.org/tx/0xfd58fb3d6dd835d0ad3082f6d32d3691a476c3eb7ca5775e083454ed69f47b39) | 40,794,657 | ~8.1M |
| C5 | **`bridgeShadow`** C (custody to ShadowBridgeL2 **#5b** `0x49A8d6...`; emits L2->L1 withdrawal to fresh L1 mirror) | [`0xdd7306cb...`](https://sepolia.basescan.org/tx/0xdd7306cb78277646befa8283f36443aa7672a2477b0259cbb53b78be4db79a31) | -- | ~0.4M |

### Shadow D -- mint -> solve -> transfer x 3 -> bridge

D is the **full reveal lifecycle**: deployer-owned, exercises
`transferFrom` plain-ERC721 round trip post-solve, `transferFeature` V2
with proof-bound recipient pk rotation, and `bridgeShadow` through the
canonical `#5b` pair. Image is synthetic `grid_48/s110_neutral.png`
registered as `face_disc/dave0` (disc score 19.5, face_disc proof
generated locally on M3 in ~110s). Mint seed `lifecycle_demo_d` with
owner_seed `palette_reveal_live`. D shadowId =
`0x2b9e5c62dff9dccdc941e2f6184b15a1632bc50a4f8cc2c623e21ac60d73d7fd`,
`mint_counter_base = 24` (D's carriers are 25..32).

| # | Action | Tx | Block | Gas |
|---|---|---|---:|---:|
| D1 | `registerImage` (image D = dave0) | [`0x985472ec...`](https://sepolia.basescan.org/tx/0x985472ec67f9f4295a013db3aab58af5db9f0cde343399add82ce4354602cc66) | 40,830,737 | 4,661,092 |
| D2 | `mintShadow` D (8 carriers, mintCounter 25..32) | [`0xb810c8f0...`](https://sepolia.basescan.org/tx/0xb810c8f0bf6b9b13b0b3f3c16d5e27ef88ed7eb33d1a3055e0aafdeab6ca6321) | 40,830,739 | **11,000,899** |
| D3 | `setZIndexCommit` D | [`0xd75d0c53...`](https://sepolia.basescan.org/tx/0xd75d0c53594364513f9e4d105af9fb6ea63ce20aefec191c26603b89af70cac0) | 40,830,817 | 6,953,497 |
| D4 | **`solve`** D (palette + plaintext atomic reveal; 8+8 events; auto-extracts 8 carriers) | [`0xf95f95e2...`](https://sepolia.basescan.org/tx/0xf95f95e29a84f98ece8202cf7fe375f85315928b73453030ef178b84d7e0b9b6) | 40,830,956 | **8,137,513** |
| D5 | `transferFrom` D deployer -> PK2 (post-solve plain ERC721 unlocked) | [`0x2796105e...`](https://sepolia.basescan.org/tx/0x2796105e2937b51a6ebb72a338619529e321e8e6535e4dbfdacad80eb25049ee) | 40,830,971 | 62,682 |
| D6 | `transferFrom` D PK2 -> deployer (round trip) | [`0x98751253...`](https://sepolia.basescan.org/tx/0x98751253856cfee010edb198a7bc04f61abafd88ff274c3317fdb57253f5530a) | 40,830,978 | 40,782 |
| D7 | `transferFeature` V2 (held carrier slot 0, deployer -> PK2; ZK-rotated to recipient pk) | [`0x13305fc7...`](https://sepolia.basescan.org/tx/0x13305fc771b25309b817696705e771627bdec4e45734db382a93a3aa3fb5f2d6) | 40,831,068 | **3,687,290** |
| D8a | `approve(bridge, shadowId)` (D8 prep) | [`0xa24d6893...`](https://sepolia.basescan.org/tx/0xa24d689316b85379d4aa325d3bb214d6e9a955516792506ae2fe725fbc0c9c71) | 40,834,630 | 49,175 |
| D8b | **`bridgeShadow`** D (custody to ShadowBridgeL2 **#5b**; emits L2->L1 withdrawal to fresh L1 mirror) | [`0x35d0c712...`](https://sepolia.basescan.org/tx/0x35d0c712d03c217aeaaba68cb19c7f802e6f4cd1b282bd42df69d3383f0afb4e) | 40,834,631 | 387,741 |

### Shadow E -- mint -> mutate x 2 -> extract -> insert -> transferShadow

E is the **full pre-solve dynamic-state lifecycle**: PK2-owned, exercises
`mutateSlot`, `mutateBatch`, `extractSlot`, `insertFeature`, and the
proof-bound `transferShadow` (which ECIES-rotates all 8 occupied slots
atomically). Image is synthetic `grid_48/s112_neutral.png` registered as
`face_disc/eve0` (disc score 15.7, face_disc proof generated locally on
M3 in ~110s). Mint seed `lifecycle_demo_e` with owner_seed
`atomic_mint_demo` matching PK2's KeyRegistry registration. E shadowId =
`0x2f1601c0b2a4657ac13de45e106fb7378aa673bd11349dfe5bdafa9327a52ee4`,
`mint_counter_base = 32` (E's carriers are 33..40).

| # | Action | Tx | Block | Gas |
|---|---|---|---:|---:|
| E1 | `registerImage` (image E = eve0) | [`0xa5158bac...`](https://sepolia.basescan.org/tx/0xa5158bac283253aea983c21d4a33e8fa81f4f0ff500248f7d4bb67f3de8f9c8b) | 40,834,820 | 4,661,236 |
| E2 | `mintShadow` E (PK2 sender, 8 carriers, mintCounter 33..40) | [`0xc790b597...`](https://sepolia.basescan.org/tx/0xc790b597b35ddb5eccb144a7e8f479bc170b0297f6baaa6e9e1ba6711574fac9) | 40,834,823 | **11,018,107** |
| E3 | `mutateSlot` E slot 0 (count 0->1) | [`0x148b9ce0...`](https://sepolia.basescan.org/tx/0x148b9ce0468d3d88ab18ab33a72c8876b9d770d6af4e4d044f6d9d8b8349eb1e) | 40,835,100 | **7,117,959** |
| E4 | `mutateBatch` E slots 1+2 (each count 0->1, single tx) | [`0x187046b3...`](https://sepolia.basescan.org/tx/0x187046b310a4b000333a022cbc822271ff69e7b056c3a98ee1919b0f80b9e2e3) | 40,835,251 | **10,802,216** |
| E5 | `extractSlot` E slot 3 (carrier becomes held) | [`0xa4c1a5d6...`](https://sepolia.basescan.org/tx/0xa4c1a5d61e0f255dc5f5143ed3e234c02e9c20681cb3fc2b0818349443aadf2b) | 40,835,311 | 3,432,675 |
| E6 | `insertFeature` (extracted slot-3 carrier into E slot 8) | [`0x5ca9d610...`](https://sepolia.basescan.org/tx/0x5ca9d610fe8ffdb695a49bd7d53ec1dbe93f6361ff1d0e4ba7551d52aca463df) | 40,835,407 | 7,254,978 |
| E7 | **`transferShadow`** E PK2 -> deployer (proof-bound, all 8 occupied slots ECIES-rotated) | [`0x95b82bb4...`](https://sepolia.basescan.org/tx/0x95b82bb4f17532ebdad96e89d15496d99c988e96d275a189442b19ecbb99b2d2) | 40,835,611 | **9,062,974** |

E is held pre-solve under deployer ownership post-transferShadow. Solve
+ bridge for E require `slot_state.py` extension with a `post-transfer`
kind (~150 LOC); deferred. C and D collectively cover those entry
points.

### Solve event signature

Solve emits per occupied slot:
  * `FeaturePaletteRevealed(featureId, paletteCommit, bytes paletteRGB_48)`
  * `FeatureSlotRevealed(featureId, shadowId, slotIdx, bytes plaintext_1248)`

8 occupied carriers -> 8 of each event in one tx. Auto-extracts all
carriers (manifest cleared, `paletteRevealed` flipped, `solved=true`,
`zIndexRevealed` written).

### Visualizer events-only path (no sk required)

```bash
# Shadow C
python3 tools/render_onchain_shadow.py \
  --shadow-id 0x0c923942a9a2e9c8a4178a12ade300472d62ce1ff3c2b4281a465ca827dbea3c \
  --rpc https://base-sepolia.gateway.tenderly.co \
  --st 0xbf9f3FC142f497774986345F027d3eaCa7Eba810 \
  --fn 0x414606aBa41297a4Dc71F2603453177885499f16 \
  --from-block 40794200 \
  --out-dir /tmp/shadow_c_render

# Shadow D
python3 tools/render_onchain_shadow.py \
  --shadow-id 0x2b9e5c62dff9dccdc941e2f6184b15a1632bc50a4f8cc2c623e21ac60d73d7fd \
  --rpc https://base-sepolia.gateway.tenderly.co \
  --st 0xbf9f3FC142f497774986345F027d3eaCa7Eba810 \
  --fn 0x414606aBa41297a4Dc71F2603453177885499f16 \
  --from-block 40830737 \
  --out-dir /tmp/shadow_d_render
```

Output: 8 sprite PNGs + composite + strip per shadow, all rendered with
the actual 16-color palettes from `FeaturePaletteRevealed` events and
the actual plaintexts from `FeatureSlotRevealed` events. Confirms the
canonical NFT image is fully derivable from chain state alone -- no
owner cooperation, no off-chain decrypt key required.

### Cumulative gas

| Component | Gas |
|---|---:|
| Deploy (27-tx setup) | ~100M |
| Working shadows: C + D + E | ~107M |
| Historical casualties: A + B (see below) | ~75M |
| Total cumulative | ~282M |

Wall-clock for the working-shadows portion (Phase 1-3 of the test
matrix re-run): ~50 minutes including local face_disc proving for D and
E, fixing one toolchain bug discovered during E3 broadcast, and 17
successful broadcasts.

### Historical casualties on pipeline #5

Two shadows demonstrate what happens when pre-fixed bugs were live.
They remain on chain because the operations that landed are real;
the demos just dead-end. Both bugs are now caught at build time.

**Shadow A (mis-wired bridge):**

Custody-locked in stranded bridge `0x9Ef3f7a3...` whose `l1Mirror`
points at the historical pipeline-#3 mirror. The dispatched L2->L1
message references the wrong mirror and is undeliverable. A's on-chain
ops 1-8 (mint through `transferFeature` V2) are valid demos; op 9
(`bridgeShadow`) is the casualty -- A is custody-locked in the stranded
bridge forever. Bug fixed: fresh bridge pair deployed (see #5b in the
Bridge wiring table above).

Image is `face_disc/alice0`, mint seed unknown (predates current
fixture conventions). A shadowId =
`0x011c687ec30b886164f6506b5ad3972fbe295f2e1da1047bd782d686c645d52a`.

| # | Action | Tx | Block | Gas |
|---|---|---|---:|---:|
| 1 | `KeyRegistry.register` (deployer) | (mint run-latest.json) | -- | -- |
| 2 | `registerImage` (image A) | (mint run-latest.json) | -- | -- |
| 3 | `mintShadow` A (1 shadow + 8 carriers, real palette + salt envelopes) | (mint run-latest.json) | -- | -- |
| 4 | `setZIndexCommit` A | (zindex run-latest.json) | -- | -- |
| 5 | **`solve`** A (palette + plaintext atomic reveal; 8+8 events) | [`0xea461ee9...`](https://sepolia.basescan.org/tx/0xea461ee94e8e41b5ed47e71589524050ea2c7545883eaeef946d211813ce1394) | 40,783,890 | **8,137,657** |
| 6 | `transferFrom` A deployer -> PK2 (post-solve plain ERC721 unlocked) | [`0xd91dbfb6...`](https://sepolia.basescan.org/tx/0xd91dbfb6c26c628e51af1623d01214767eb98272de043a373db74e1a716c7529) | 40,786,056 | 57,882 |
| 7 | `transferFrom` A PK2 -> deployer (round trip) | [`0x95e8fa3f...`](https://sepolia.basescan.org/tx/0x95e8fa3f7128472dea1cfff52f7be2f6f2bac86b5941b49a61611410e9905f92) | 40,786,058 | 57,882 |
| 8 | `transferFeature` V2 (held carrier slot 0, deployer -> PK2; ZK-rotated to recipient pk) | [`0xb9470c0f...`](https://sepolia.basescan.org/tx/0xb9470c0f9aae7ef0526d423186059158a3e020c6c35ab798cd3877757c92b08e) | 40,792,820 | **3,704,534** |
| 9 | **WARN** `bridgeShadow` L2-leg A (custody to ShadowBridgeL2 #5; L2->L1 message references wrong mirror, undeliverable) | [`0x7e27fcb4...`](https://sepolia.basescan.org/tx/0x7e27fcb4b8737dec037238721640c5c46dd93987dfdaec3a9b38747a8e368556) | 40,792,879 | 404,841 |

**Shadow B (stale palette commit fixture):**

Permanently unsolvable. Minted with the legacy `atomic_mint_demo_b`
fixture whose `palette_commits` came from the old
`deterministic_int_mint(seed, "palette_{i}", P)` formula; the on-chain
solve verifier opens via `sponge_palette_salt(palette, salt)`, which has
no preimage to those values. B's ops B1-B8 are valid demos; B's
`setZIndexCommit` (`0x475bf0ed...`, ~7M gas) is dead state, written
before the impossibility was discovered. Bug fixed:
`build_atomic_mint_fixture.py` now asserts sponge-consistency before
exiting; in addition, during the C/D/E re-run a sibling regression was
discovered in `build_mutate_slot_onchain.py:reconstruct_mint_slot_state`
(reused by mutate / mutate_batch / insert / transfer / slot_state) which
still recomputed `palette_commit` via the old formula -- now centrally
fixed to read from the mint fixture's `meta.json::palette_commits`.

Image is `face_disc/bob0`. B shadowId =
`0x2c6f0a0b412f403a6d080b2fa2fa3c4375cef9a5567f3c46df177ede9b74014d`,
owner is deployer post-transferShadow.

| # | Action | Tx | Block | Gas |
|---|---|---|---:|---:|
| B1 | `KeyRegistry.register` (PK2) | [`0xdfc420a7...`](https://sepolia.basescan.org/tx/0xdfc420a7ea6863413c603fa9402c25572f77f08f61889898f875128719d1aa60) | 40,786,288 | 68,566 |
| B2 | `registerImage` (image B) | [`0x5827e802...`](https://sepolia.basescan.org/tx/0x5827e8021996c64456bea8ef3fbb50d67ad7f7e997c5f108fecaf613de0a873b) | 40,786,288 | 4,661,224 |
| B3 | `mintShadow` B (8 carriers, mintCounter 9..16) | [`0xab50a7ad...`](https://sepolia.basescan.org/tx/0xab50a7ad3834fb009df189c328ccd44c65870c7fd6979d51a6cb21584683ba53) | 40,786,288 | 11,025,823 |
| B4 | `mutateSlot` B slot 0 (count 0->1) | [`0x77c94d80...`](https://sepolia.basescan.org/tx/0x77c94d80f436e395b2461b8c82ee1ff92054d3c7c3eb35d5821a76c709969874) | 40,791,976 | **7,118,271** |
| B5 | `mutateBatch` B slots 1+2 (each count 0->1, single tx) | [`0x66ad4960...`](https://sepolia.basescan.org/tx/0x66ad496000c16901fbfe348eb5a2912069d14563f13a13c73c467deedc7f24ea) | 40,792,154 | **10,802,060** |
| B6 | `extractSlot` B slot 3 (carrier becomes held) | [`0xad84c4f2...`](https://sepolia.basescan.org/tx/0xad84c4f2b2f969cd191b02b840e55113fb974b82b41ca8321e3443ef4908efd2) | 40,792,228 | 3,432,579 |
| B7 | `insertFeature` (extracted slot-3 carrier into B slot 8) | [`0xc8a2c7ba...`](https://sepolia.basescan.org/tx/0xc8a2c7bac817e014c17b7f39866a579b2a8238efd6837bba09f7dc35473d5c25) | 40,792,355 | 7,254,726 |
| B8 | **`transferShadow`** B PK2 -> deployer (proof-bound, all 8 occupied slots ECIES-rotated) | [`0x05ca2cf4...`](https://sepolia.basescan.org/tx/0x05ca2cf49db35adcd9750b761db9327163eb876ce63a435bd9c8bfeee0275482) | 40,792,654 | **9,058,102** |
| B9 | **WARN** `setZIndexCommit` B (dead state; B is unsolvable due to palette commit drift) | [`0x475bf0ed...`](https://sepolia.basescan.org/tx/0x475bf0ed9a14a8c1f17af49aa28bcf7fb43e0d0a55c2cb8e7da5c79b39f5d2e2) | 40,793,648 | ~7M |

---

## Historical pipelines (#3, #4)

Pipelines #3 (palette-blind, original full lifecycle) and #4 (standalone
`revealPalette` mid-redesign) are preserved on chain at their original
addresses but **no longer canonical**. Their detailed lifecycle records
and per-op tables now live in
[`HISTORICAL_DEPLOYMENTS.md`](HISTORICAL_DEPLOYMENTS.md). Quick lookup
of the historical addresses:

| Pipeline | ShadowToken | FeatureNFT | Notes |
|---|---|---|---|
| #3 (palette-blind) | `0x8439c6796508930863599cd9cB49db741C6ea21f` | `0x82cd6763cB7362EA5652b63E12617fBa06702D69` | Source of the L1-bridge L2 leg whose 7-day OP Stack window is still ticking. |
| #4 (revealPalette standalone) | `0xe5089e09D7B8393fE37bC2e53E6a44CCD534Ef88` | `0x578eda36Dc4750c35c29E5F12a0789DaD35e2072` | Spec-compliant interim; superseded by pipeline #5's reveal-at-solve. |
| L1 mirror (Eth Sepolia, wired to #3 bridge) | `0x89dB0113AeC52f03606E0550c5FfCA5554eF646D` | -- | Reused as `l1Mirror` on pipeline #5's new ShadowBridgeL2; full L1 finalize from #5 needs a fresh L1 mirror deploy. |

Use `git log -- docs/DEPLOYMENT.md` to retrieve any earlier table that
lived inline before the 2026-04-28 archive.

## Comprehensive on-chain verification (live deployment)

Two purpose-built tools confirm the deployed contracts behave as
specified beyond "tx didn't revert":

### `tools/verify_onchain_mint.py`

Runs **39 hard byte-equality assertions** against the live
Base Sepolia deployment, all passing as of commit `c1bfb37`. Each
assertion is structured (event signature, manifest layout, struct
decoding) — no heuristics. Notable checks:

  - All 12 wiring cross-references read from chain match the deploy
    record.
  - Each of the 8 `ShadowSlotMutated` event payloads has a `c2` byte
    field that is **byte-for-byte equal** to the fixture's
    `c2_per_slot[i]` (39 fields × 32 bytes BE per slot).
  - Each `c2` is **ECIES-decrypted** under `owner_sk` (recomputed
    deterministically from the seed `atomic_mint_demo`). The recovered
    39-field plaintext is byte-equal to an independently-encoded
    plaintext built from the seed-derived `(pose, w, h, palette indices)`
    tuple. **This is the "pixel correctness" check** — the on-chain
    ciphertext round-trips through ECIES + plaintext layout and
    produces structured sprite data that matches the prover's claim.
  - All 8 decoded plaintexts are pairwise distinct (no encryption
    collision, no aliased keystream).
  - On-chain `ManifestEntry.liveStateHash` byte-equals the fixture's
    `lsh_inits[i]` for all 8 occupied slots.
  - All 8 `FeatureNFT` carriers have the right
    `(typeIdx, originFaceId, hostShadowId, hostSlotIdx, owner)` —
    cross-checked against fixture meta and against the slot's event
    payload.
  - On-chain `shadowT10[shadowId]` byte-equals the event payload byte-equals
    the fixture's bundled T10 PI.
  - Slots 8..15 are EMPTY (`kind=0, fid=0, lsh=0`).
  - `Shadow` struct fields match (ecdhPub = owner_pk, solved = false,
    zIndexCommit = 0, mintIdx = 1).

Run:

```bash
python3 tools/verify_onchain_mint.py \
  --rpc https://base-sepolia.gateway.tenderly.co \
  --st 0xe5089e09D7B8393fE37bC2e53E6a44CCD534Ef88 \
  --fn 0x578eda36Dc4750c35c29E5F12a0789DaD35e2072 \
  --kr 0x402DCD8f6C615f89D9C34fb6928F4D69e39b3Aa1 \
  --poseidon39 0x36E5A53dd45eB318C3373486ABe854e80b7451CD \
  --poseidon16 0x44c498f8B871B8F6ADbEfD28E25EE96748d8258a \
  --mint-tx 0x4ff2056fe2b011dc0dc5a8d66fcc3ded5afd23a27d6b05c1f0e7986d3a86e255 \
  --register-tx 0x9311e37cbb971723c689abd928abba07611afb9f524a310e92748cdde5386fa4 \
  --deployer 0x1b43AFe43afC74bF9D0EBd764787eFD7CCcC2B6F
```

Wall-clock: ~2-3 min (8 ECIES decrypts × ~14 Poseidon2 perms each
via `nargo` subprocess). Exit 0 on all-pass, exit 1 on any failure.

### `tools/render_onchain_shadow.py`

Companion to the verifier. Renders the 8 decrypted sprites as PNGs
(pure Python writer, no PIL). Output:

  - `slot_0.png` ... `slot_7.png` — each `w × h` palette-indexed sprite,
    upscaled 8× for visibility.
  - `composite.png` — all 8 sprites layered on a 48×48 canvas at their
    poses' `(x, y)` coordinates. Visible diagonal cluster.
  - `sprite_strip.png` — side-by-side strip of all 8 sprites in a
    consistent grid.

The output is structured multi-color sprites (not noise), confirming
the on-chain payload decrypts to recoverable pixel data.

### Negative-path simulation: `_NegTestGates.s.sol`

Three on-chain negative paths confirmed via `eth_call` (no broadcast,
no gas spent) against the live ShadowToken bytecode:

  1. `registerImage(imageCommit, proofDisc)` for the already-registered
     imageCommit reverts with **`ImageAlreadyRegistered(bytes32)`**
     (selector `0xd9c06450`).
  2. `mintShadow(args)` with a fake unregistered imageCommit
     (`0xdeadbeef...`) reverts with **`ImageNotRegistered(bytes32)`**
     (selector `0x33d7893f`).
  3. `mintShadow(args)` with the already-minted imageCommit reverts with
     **`AlreadyMinted(bytes32)`** (selector `0x26521300`).

All three selectors match `keccak256(<error sig>)[:4]` — exact contract
bytecode behavior, not heuristic.

---

## Local-only verification (current commit)

**160/160 forge tests pass with real ZK proofs (no mocks)**, including
the 4 new in `PaletteReveal.t.sol`.

| Op | Local gas-pin budget | Measured local | On-chain (where measured) |
|---|---|---|---|
| `registerImage` | 4M | ~3.79M | **4.66M (#3) ✅** |
| `mintShadow` | 11M | ~9.5M (body only) | **11.04M (#3) / 11.07M (#4) ✅** |
| `mutateSlot` | 6M | ~5M | **7.12M (#3) ✅** |
| `mutateBatch` (2 slots) | 25M | ~7.5M | **10.80M (#3) ✅** |
| `transferShadow` (8-occ) | 7M | ~6.2M | **9.16M (#3) ✅** |
| `setZIndexCommit` | n/a | ~4.8M | **6.95M (#3) ✅** |
| `extractSlot` | n/a | ~2.4M | **3.44M (#3) ✅** |
| `insertFeature` | n/a | ~5M | **7.25M (#3) ✅** |
| `solve` | 8M | ~6.5M | **4.79M (#3) ✅** |
| `transferFeature` | n/a | ~3.5M | **3.69M (#3) ✅** |
| `bridgeShadow` (L2 leg) | n/a | n/a | **0.40M (#3) ✅** |
| `revealPalette` | n/a | ~2.66M | **3.29M (#4) ✅** |

All 14 `RealChainLimits.t.sol` checks confirm every contract fits
EIP-170's 24,576-byte runtime cap with 100+ B headroom.

---

## Outstanding work (not yet on chain)

1. **L1 finalize for `bridgeShadow` A** -- calendar-bound (~7-day OP
   Stack challenge window after the L2 output root proposal). Sequence:
   `proveWithdrawalTransaction` -> wait -> `finalizeWithdrawalTransaction`
   on Eth Sepolia. ETA >= 2026-05-04. See
   `STAGING_REFACTOR/2026-04-27_bridge_live_working.md`.
2. **Pipeline #4 lifecycle is sparse** -- only mintShadow + revealPalette
   exercised. The full mutation/transfer/bridge story still lives on
   pipeline #3, which lacks palette reveal. Re-broadcasting the
   lifecycle on #4 would unify the demo at the cost of ~80M gas /
   ~30 min compute.
3. **Spec item 5 redesign**: per the canonical interpretation, palette
   reveal should be atomic with `solve` -- one tx that simultaneously
   reveals all occupied carriers' palettes, freezes the shadow, and
   unlocks bridging. Current implementation is a separate
   owner-callable `revealPalette()` per carrier. Redesign would
   obsolete the `palette_reveal_v2` circuit + verifier and inline the
   commitment opening into `solve` via on-chain Yul Poseidon2 (no
   per-carrier proof needed). Requires pipeline #5 redeploy due to
   breaking solve ABI change.

---

## Toolchain

| Tool | Where |
|---|---|
| `forge` | `~/.foundry/bin/forge` (no specific commit pin yet) |
| `nargo` | `$HOME/.nargo/bin/nargo` |
| `bb` | `$HOME/.bb/bb` |
| `solc` | 0.8.27 (via foundry) |
| Verifier scheme | UltraHonk (keccak oracle), `--verifier_target evm` |

Every Solidity verifier in `contracts/src/*Verifier.sol` is generated
from `bb write_solidity_verifier` against the `bb prove`-produced vk.
`forge build --sizes` confirms each verifier's runtime byte count fits
EIP-170 with 100+ bytes of headroom.

---

## Historical: pre-pipeline-#3 deploys (superseded, do not use)

Earlier deploys exist on Base Sepolia history but use incompatible
ABIs (the `MintShadowArgs` struct and `ShadowToken` storage shape
have since changed). They are NOT compatible with the current
`MintOnSepolia.s.sol` and should be ignored:

- pre-v2-gas (commit `ff309b1`): `ShadowToken=0xDb5808...A42e`
- v2-gas only, pre-registerImage-split (commit `5a33652`):
  `ShadowToken=0xf75fd5...56f6`

## Historical: pipeline #3 (palette-reveal-blind, full lifecycle)

Pipeline #3 was deployed 2026-04-26/27 from commit `c1bfb37`
(`registerImage split: drop face_disc from mintShadow body`). It
predates the palette-reveal ABI -- its FeatureNFT lacks `revealPalette`,
`paletteRevealedOf`, `setPaletteRevealVerifier`, the `paletteRevealed`
flag, and the `FeaturePaletteSaltEnvelope` event. It cannot be
upgraded; shadows minted on it can never have their palettes revealed.

Preserved as historical reference because the lifecycle exercises on
it are extensive and unmodified by pipeline #4's existence.

| Contract | Pipeline #3 address |
|---|---|
| `Poseidon2YulSponge` | `0xDAB29834F3CEe1Fbc262f4614f61F669B8627F38` |
| `Poseidon2YulSponge16` | `0xCa8C63D3F592ec0d9Acd191bc74e4231DA14A5A5` |
| `KeyRegistry` | `0x5f7cb4DEd00A30D2a5a52F26e1bCDA8401a738C5` |
| `ShadowToken` | `0x8439c6796508930863599cd9cB49db741C6ea21f` |
| `FeatureNFT` | `0x82cd6763cB7362EA5652b63E12617fBa06702D69` |
| `MintShadowVerifier` | `0x446daaEa9366e8A465EA911c768476d191480D53` |
| `FaceDiscVerifier` | `0x739cDab4A464632bFb67bdB8760A59a444044E7d` |
| `MutateSlotVerifier` | `0xBc5b41EEB6a5c5598fBb0D1aD4120889a7488294` |
| `T10ShadowVerifier` | `0xceEC22F38B4507C22D1Cb6a73Ac9069A850cAAfe` |
| `ZIndexCommitVerifier` | `0x43237d169e5b89609B842ABC60F49c3dA3c1f960` |
| `TransferShadowVerifier` | `0x403DcbE6B0Bbc93c21cFa45571Dbd95FC36DAE08` |
| `SolveShadowVerifier` | `0x338a715348FB9dbe99Ea103F994BE00b8C11154A` |
| `TransferFeatureV2Verifier` (added mid-life) | `0x75fB0299451b7F36572631d0200A0FA07F573389` |