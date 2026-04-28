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
| `mutateSlot` (chained to live state) | #3 | done -- block 40,764,607 (legacy demo) |
| `mutateBatch` (recipient-side multi-slot) | #3 | done -- block 40,769,858 (legacy) |
| `extractSlot` | #3 | done -- block 40,764,834 (legacy) |
| `insertFeature` (cross-shadow) | #3 | done -- block 40,766,987 (legacy) |
| `transferShadow` to fresh recipient | #3 | done -- block 40,767,400 (legacy) |
| Recipient lifecycle on B (extract / setZIndex / solve from new owner) | #3 | done (legacy) |
| `transferFeature` (held-carrier rotation) | #3 | done -- block 40,772,596 (legacy) |
| `bridgeShadow` L2 leg | #3 | done -- block 40,772,843 (legacy) |
| `bridgeShadow` L1 finalize | n/a | calendar-bound (~7d OP Stack window) |

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

## Pipeline #5 lifecycle (canonical demo)

Shadow A' on pipeline #5 has `shadowId =
`0x011c687ec30b886164f6506b5ad3972fbe295f2e1da1047bd782d686c645d52a` 
(deterministic from the `face_disc/alice0` fixture; collides with #3
and #4's shadow A by design -- different deployments, same math).

| # | Action | Tx | Block | Gas |
|---|---|---|---:|---:|
| 1 | `KeyRegistry.register` (deployer) | (run-latest.json) | -- | -- |
| 2 | `registerImage` | (run-latest.json) | -- | -- |
| 3 | `mintShadow` (1 shadow + 8 carriers, real palette + salt envelopes) | (run-latest.json) | -- | -- |
| 4 | `setZIndexCommit` | (run-latest.json) | -- | -- |
| 5 | **`solve`** (palette + plaintext atomic reveal) | [`0xea461ee9...`](https://sepolia.basescan.org/tx/0xea461ee94e8e41b5ed47e71589524050ea2c7545883eaeef946d211813ce1394) | 40,783,890 | **8,137,657** |

Solve emits per occupied slot:
  * `FeaturePaletteRevealed(featureId, paletteCommit, bytes paletteRGB_48)`
  * `FeatureSlotRevealed(featureId, shadowId, slotIdx, bytes plaintext_1248)`

8 occupied carriers → 8 of each event in one tx. Auto-extracts all
carriers (manifest cleared, `paletteRevealed` flipped, `solved=true`,
`zIndexRevealed` written).

**Visualizer events-only path (no sk required):**

```bash
python3 tools/render_onchain_shadow.py \
  --shadow-id 0x011c687ec30b886164f6506b5ad3972fbe295f2e1da1047bd782d686c645d52a \
  --rpc https://base-sepolia.gateway.tenderly.co \
  --st 0xbf9f3FC142f497774986345F027d3eaCa7Eba810 \
  --fn 0x414606aBa41297a4Dc71F2603453177885499f16 \
  --from-block 40780000 \
  --out-dir /tmp/shadow_p5_render
```

Output: 8 sprite PNGs + composite + strip, all rendered with the actual
16-color palettes from `FeaturePaletteRevealed` events and the actual
plaintexts from `FeatureSlotRevealed` events. Confirms the canonical NFT
image is fully derivable from chain state alone -- no owner cooperation,
no off-chain decrypt key required.

---

## On-chain lifecycle (preserved on pipeline #3, palette reveal on pipeline #4)

Pipeline #3's ShadowToken (`0x8439c679...6ea21f`) carries the rich
behavioural lifecycle: 16 entry-point txs over shadows A and B from
two separate EOAs (deployer + recipient), including transferShadow,
transferFeature, and bridgeShadow's L2 leg. Pipeline #4's deployment
carries the palette reveal demonstration (mint with real envelopes +
first revealPalette tx). The ShadowId math is identical because both
deploys consume the same `face_disc/alice0` fixture, but the two
deployments live at different addresses and are independent.

### Pipeline #3 lifecycle

## On-chain mint flow

Shadow A's `imageCommit` and `shadowId` are both:

```
0x011c687ec30b886164f6506b5ad3972fbe295f2e1da1047bd782d686c645d52a
```

(Mint sets `shadowId = imageCommit % FR_MOD` deterministically; for
this fixture both lie in-field so they coincide.)

| Step | Tx | Block | Gas used | Status |
|---|---|---|---|---|
| `KeyRegistry.register` | [`0x87f6cfb5...43f`](https://sepolia.basescan.org/tx/0x87f6cfb5c3e0bc7e2d0a326d0299af455964098549409c2e68aede58fbbd543f) | (early) | 68,566 | ✅ |
| `ShadowToken.registerImage` | [`0x775b2918...63c`](https://sepolia.basescan.org/tx/0x775b291815f34ed36c66a88c10831a24afad5cb3c1d23a05d28e88ac6f02a63c) | 40,761,804 | **4,661,236** | ✅ |
| `ShadowToken.mintShadow` | [`0xe273562a...198`](https://sepolia.basescan.org/tx/0xe273562ab241f52fd7f142fa02794aeee0b3a0453bdd88c67b538fbc1ba5d198) | 40,761,922 | **11,038,478** | ✅ |

`mintShadow` consumes **11.04M gas on chain**, comfortably under the
16M public-RPC anti-DoS envelope cap. Compared to the pre-split
attempt (14.67M, reverted with T10 verifier OOG inside the
staticcall), the registerImage split removes face_disc's ~3.6M from
`mintShadow` body and lets the bundled T10 refresh complete with
healthy gas headroom.

### State verified on chain after mintShadow

```
ShadowToken.registeredImages(imageCommit)  =  true
ShadowToken.mintedOrigins(imageCommit)     =  true
ShadowToken.ownerOf(shadowId)              =  0x1b43AFe43afC74bF9D0EBd764787eFD7CCcC2B6F
ShadowToken.shadowT10(shadowId, 0)         =  0x...276f487a23783fe1fada8df1a2102270  (hi)
ShadowToken.shadowT10(shadowId, 1)         =  0x...2e1b800e9a7a00c65adfeb5a5e302b46  (lo)
ShadowToken.mintCounter                    =  1
ShadowToken.slotOf(shadowId, 0..7).kind    =  OCCUPIED  (each)
                              .featureId   =  matches fixture origin_face_id derivation
                              .liveStateHash = matches fixture lsh_inits[i]
ShadowToken.slotOf(shadowId, 8..15).kind   =  EMPTY     (each)
```

### Gas-multiplier note

Forge's local `eth_estimateGas` simulation under-estimates Base
Sepolia's true gas cost by **~28-30 %** for ZK-verifier-heavy txs.
With the default `--gas-estimate-multiplier 130`, forge sets the tx
envelope at `1.30 × local_estimate`, which on Sepolia is `~1.015 ×
real_cost` — too tight, txs revert with sub-staticcall OOG before
exhausting the envelope.

Empirical fix: `--gas-estimate-multiplier 150`. That gives:

  - registerImage envelope ≈ 5.4 M (vs ~4.66 M actual cost)
  - mintShadow envelope ≈ 15 M (vs ~11.0 M actual cost; under 16 M cap)

Higher multipliers (e.g. `200`) push mintShadow's envelope above
the public RPC's per-tx envelope ceiling and the RPC rejects with
`gas limit too high`. So **150 is the sweet spot for this contract
set.**

---

### Pipeline #3 full per-op lifecycle
### Per-op gas + size + timing

Tx hashes link to BaseScan; gas is `cast receipt`'s `gasUsed`; block
timestamps are the L2 block's `timestamp`; proof / PI sizes are the
raw `*.bin` lengths in the fixture dir; build wall-clock is the
`tools/build_*_onchain.py` end-to-end run on M3 (nargo execute + bb
write_vk + bb prove + bb verify, single-process).

| # | Op | Tx | Block | Block ts (UTC) | Gas used | Headroom <16M | Proof size | PI size | Build wall-clock |
|---|---|---|---:|---|---:|---:|---:|---:|---:|
| 1 | `KeyRegistry.register`  | [`0x87f6cfb5...`](https://sepolia.basescan.org/tx/0x87f6cfb5c3e0bc7e2d0a326d0299af455964098549409c2e68aede58fbbd543f) | 40,761,515 | 2026-04-27 12:01:58 |     68,566 | 15.93M | n/a       | n/a    | n/a   |
| 2 | `registerImage`         | [`0x775b2918...`](https://sepolia.basescan.org/tx/0x775b291815f34ed36c66a88c10831a24afad5cb3c1d23a05d28e88ac6f02a63c) | 40,761,804 | 2026-04-27 12:11:36 |  4,661,236 | 11.34M | (face_disc fixture) | (face_disc) | reused |
| 3 | `mintShadow`            | [`0xe273562a...`](https://sepolia.basescan.org/tx/0xe273562ab241f52fd7f142fa02794aeee0b3a0453bdd88c67b538fbc1ba5d198) | 40,761,922 | 2026-04-27 12:15:32 | 11,038,478 |  4.96M | mint 8.77K + T10 6.85K | 224 + 640 B | ~5 min (landmark_regions_v2 dominates) |
| 4 | `mutateSlot`            | [`0xa713ae31...`](https://sepolia.basescan.org/tx/0xa713ae312ac700e0900d573dd2e7d17531a55f13e1646853ffb8c6a3bdaa8e8c) | 40,764,607 | 2026-04-27 13:45:02 |  7,118,065 |  8.88M | mut 8.00K + T10 6.85K | 512 + 640 B | ~3 s |
| 5 | `setZIndexCommit`       | [`0x3333e5de...`](https://sepolia.basescan.org/tx/0x3333e5de2c58d847bcae29b557650fdf36bf3f9c604daf21ae532dd2919ec4fc) | 40,764,748 | 2026-04-27 13:49:44 |  6,953,315 |  9.05M | z 7.62K + T10 6.85K |  64 + 640 B | ~2 s |
| 6 | `extractSlot`           | [`0x07e7e044...`](https://sepolia.basescan.org/tx/0x07e7e0440bf528af6d8d95633974c903cdb8ebe1ba472e2e954d482c99999a3a) | 40,764,834 | 2026-04-27 13:52:36 |  3,437,387 | 12.56M | T10 only 6.85K       | 640 B   | ~0.5 s |
| 7 | `solve`                 | [`0x94ee6403...`](https://sepolia.basescan.org/tx/0x94ee6403fa5d8e66887b86bcd29de30eba3ad5e1dca6b9a034f7f2440eca5cb5) | 40,765,120 | 2026-04-27 14:02:08 |  4,794,531 | 11.21M | solve 8.77K          | 224 B   | ~3 s |
| 8 | `registerImage` (B)     | [`0xe29ef015...`](https://sepolia.basescan.org/tx/0xe29ef015fc4670fc1b8198593a37cb250cea0cec86ce46cb18d499fa08bbd828) | 40,766,752 | 2026-04-27 14:56:32 |  4,661,224 | 11.34M | (face_disc bob0)     | 32 B    | ~85 s vast (s114\_neutral.png face) |
| 9 | `mintShadow` (B)        | [`0x19ba0d91...`](https://sepolia.basescan.org/tx/0x19ba0d91f9922ca012486d23bf2cd56eca7a55de6bbada912ef39ef812d6374c) | 40,766,754 | 2026-04-27 14:56:36 | 10,969,742 |  5.03M | mint 8.77K + T10 6.85K | 224 + 640 B | ~60 s |
| 10 | `KeyRegistry.register` (recipient) | [`0x1f6d878c...`](https://sepolia.basescan.org/tx/0x1f6d878c405e241046766b1f0831b715af100cf146aacb102d67b80970d746e9) | 40,767,131 | 2026-04-27 15:09:10 |     68,578 | 15.93M | n/a | n/a | n/a |
| 11 | `insertFeature`        | [`0x054dad4e...`](https://sepolia.basescan.org/tx/0x054dad4e3df64c81f1f433c80dc3b035a8a7cb8686e907022fd8653d794d9767) | 40,766,987 | 2026-04-27 15:04:22 |  7,254,742 |  8.75M | ins 8.00K + T10 6.85K | 512 + 640 B | ~17 s |
| 12 | `transferShadow`       | [`0xc3231bec...`](https://sepolia.basescan.org/tx/0xc3231bec05d18285d422221acc196fae5c0478f5319d38bd8bcafea3e052c711) | 40,767,400 | 2026-04-27 15:18:08 |  9,163,063 |  6.84M | xfer 9.15K + T10 6.85K | 256 + 640 B | ~4 min (transfer\_shadow\_v2 dominates) |
| 13 | `mutateBatch` (recipient on B[0,1]) | [`0xc367fa25...`](https://sepolia.basescan.org/tx/0xc367fa25ca6b56193078ac302639556ef00a5df82693b811571fd2cdfb2a8cc6) | 40,769,858 | 2026-04-27 16:32:30 | 10,801,616 |  5.20M | 2x mut 8.00K + T10 6.85K | 2x 512 + 640 B | ~5 min |
| 14 | `extractSlot` (recipient on B[2]) | [`0x577a2a60...`](https://sepolia.basescan.org/tx/0x577a2a60be8d85f801b2da21bd49b17d0f16dcc7a696197f716104e7a687f2e1) | 40,769,968 | 2026-04-27 16:36:10 |  3,435,423 | 12.56M | T10 only 6.85K | 640 B | ~0.5 s |
| 15 | `setZIndexCommit` (recipient on B) | [`0xe2ea5fce...`](https://sepolia.basescan.org/tx/0xe2ea5fcefc41436242c059f72f9a41e339a9b8be85397da98422374c7f2bbc96) | 40,770,095 | 2026-04-27 16:40:24 |  6,953,399 |  9.05M | z 7.62K + T10 6.85K | 64 + 640 B | ~2 s |
| 16 | `solve` (recipient on B) | [`0x2df9e58f...`](https://sepolia.basescan.org/tx/0x2df9e58f6c734545c17509c669f63ed97bcc61c70edcd5023f9b095655fe4b03) | 40,770,295 | 2026-04-27 16:47:04 |  4,831,280 | 11.17M | solve 8.77K | 224 B | ~5 s |
| 17 | `setTransferFeatureVerifier` deploy + wire | [`0xe345c9a7...`](https://sepolia.basescan.org/tx/0xe345c9a7a577d64bc4f65e18f829eac4b9229ac4b71527514f1071a589d9c2c4) + [`0x3a6c086f...`](https://sepolia.basescan.org/tx/0x3a6c086f27e833a1a87072bbb6127f39c6e60e7b5edf25dc005b2f4ac0f23dfd) | 40,772,221 | 2026-04-27 17:48:?? |  6,742,016 | n/a | TransferFeatureV2Verifier `0x75fB0299...` | n/a | n/a |
| 18 | `transferFeature` (A's slot-0 carrier `0x0c15f2ea...` to recipient) | [`0x8bd6889d...`](https://sepolia.basescan.org/tx/0x8bd6889d92cbc0b8e7a215e5d926c09e4dae9cc79ec4312d8958d780b1158f80) | 40,772,596 | 2026-04-27 17:54:?? |  3,687,517 | 12.31M | transfer_feature_v2 8.00K | 256 B | ~3 s |
| 19 | `bridgeShadow` (A from L2 to L1) | [`0xc6bebd45...`](https://sepolia.basescan.org/tx/0xc6bebd455248255c549e363a036c74e5a8bf0a7030c68c5efafa7d843daee617) | 40,772,843 | 2026-04-27 17:59:?? |    399,678 | 15.60M | revealedPi 224 B | n/a | ~1 s |

Aggregate gas across all 19 entry-point txs against the live deployment:
**107,040,854 gas** on Base Sepolia. At ~0.011 gwei observed at
broadcast time, total cost ≈ **0.00118 Sepolia ETH** for the entire
lifecycle including: A's full lifecycle, B's mint + insert + transfer,
the recipient's full lifecycle on B (mutateBatch + extract + setZIndex +
solve), the v2 transferFeature deploy + first held-carrier rotation, and
the L2 leg of bridgeShadow on A.

Plus on Ethereum Sepolia: ShadowMirrorL1 deploy `0x4222e80d...` (1.80M gas)
+ setL2Bridge `0x333512c9...` (45K gas) at L1 mirror `0x89dB0113AeC52f03606E0550c5FfCA5554eF646D`,
block 10,744,157 / 10,744,166. Cost ≈ 0.00056 L1 Sepolia ETH at 0.24 gwei.

Bridge L1 finalization is calendar-bound: ~1hr for output root proposal +
proveWithdrawalTransaction + 7-day OP Stack challenge window +
finalizeWithdrawalTransaction. Sequenced in `STAGING_REFACTOR/2026-04-27_bridge_live_working.md`.

Every entry point clears the 16M sequencer cap with healthy headroom.
Tightest margins:
  * `mintShadow` 4.96-5.03M (still > 4M headroom even with 8 ECIES bundles + T10)
  * `mutateBatch` 5.20M (2 mutate proofs + T10 in one tx, recipient-side)
  * `transferShadow` 6.84M (16-slot rotation + 9 carrier ERC-721 rotations + T10)
  * `solve` 11.17–11.21M (4.79–4.83M used)

### Pipeline #4 (palette-reveal-enabled, fresh on 2026-04-28)

The `revealPalette` ABI required a fresh pipeline cutover (the existing
FeatureNFT at `0x82cd...` predates the new ABI). Pipeline #4 is the
first deployment that exercises end-to-end palette reveal:

| Contract | Address |
|---|---|
| ShadowToken              | `0xe5089e09D7B8393fE37bC2e53E6a44CCD534Ef88` |
| FeatureNFT               | `0x578eda36Dc4750c35c29E5F12a0789DaD35e2072` |
| KeyRegistry              | `0x402DCD8f6C615f89D9C34fb6928F4D69e39b3Aa1` |
| Poseidon2YulSponge       | `0x36E5A53dd45eB318C3373486ABe854e80b7451CD` |
| Poseidon2YulSponge16     | `0x44c498f8B871B8F6ADbEfD28E25EE96748d8258a` |
| MintShadowVerifier       | `0x983831dFB2bF827c8689aD2e3bEa202Bc26Fd969` |
| FaceDiscVerifier         | `0xd00E4a5e45A770EA54A295b4748e40F9D5539965` |
| MutateSlotVerifier       | `0x9C879431001Fa90CaD81d0342d61c12D298C0aD8` |
| T10ShadowVerifier        | `0x1f559689D500b91e07a05432318F1eBBF0637112` |
| ZIndexCommitVerifier     | `0x47E1ACF2131De8c68d2940773ceC946d1F707f10` |
| TransferShadowVerifier   | `0x3240377E7C2947E7A3a1b6f62f0575cea111157e` |
| SolveShadowVerifier      | `0x87371A7C174fDB97215778CF0EFAcd27CA0812F6` |
| TransferFeatureV2Verifier| `0xa85eCAcD44D6A6a0659DdcA9d9f3901a2BB4C291` |
| **PaletteRevealV2Verifier**  | **`0x4ef46EFa1484d4981498Fa99e3eE1a580f4EF3D8`** |

Pipeline #4 deploy: 27 txs in blocks 40,780,061 - 40,780,064, total gas
**68,022,941** (~0.000748 Sepolia ETH at 0.011 gwei).

Live palette-reveal demo on pipeline #4:

| # | Action | tx | block | gas | budget |
|---|---|---|---|---|---|
| 1 | `mintShadow` (fresh shadow A' with real palette envelopes) | [`0x4ff2056f...`](https://sepolia.basescan.org/tx/0x4ff2056fe2b011dc0dc5a8d66fcc3ded5afd23a27d6b05c1f0e7986d3a86e255) | 40,780,219 | 11,069,551 | 4.93M |
| 2 | `revealPalette` (slot-0 carrier `0x0c15f2ea...`) | [`0x36d3ab8f...`](https://sepolia.basescan.org/tx/0x36d3ab8fd358c0dfcaeae651d51a32b54f45f4758cab0bb404d83e3d61f90f8b) | 40,780,277 | 3,294,874 | 12.71M |

**End-to-end ZK-bound palette reveal verified live**:

1. mint commits `paletteCommit_i = sponge_palette_salt(palette_i, salt_i)`
   per slot and emits `FeaturePaletteSaltEnvelope(featureId, saltCt, c1.x, c1.y)`
   for the owner to ECIES-decrypt off-chain.
2. owner decrypts the envelope under `KeyRegistry.pkOf(owner)`'s sk to
   recover `palette_salt`.
3. owner calls `revealPalette(featureId, proof, pi)`. Proof binds:
   - `sponge_palette_salt(palette, salt) == paletteCommit (PI[1])` -> chain checks vs storage,
   - `palette_packed[i] == palette[2i] + palette[2i+1] * 2^24`.
4. `FeaturePaletteRevealed(featureId, paletteCommit, bytes paletteRGB)` emits
   the 48 raw RGB bytes; `f.paletteRevealed = true` (anti-replay).
5. `tools/render_onchain_shadow.py --fn 0x578eda36...` reads the event and
   renders the slot with the actual color table; off-chain palette colors
   match on-chain RGB byte-for-byte.

Verifier sizes (real-chain confirmed):
  * PaletteRevealV2Verifier: **24,337 B** runtime (239 B under EIP-170).


### Chained-fixture builders (`tools/build_*_onchain.py`)

These produce per-op fixtures whose ZK witnesses are bound to the
live chain state, not to synthetic local state. They reconstruct the
necessary per-slot crypto material deterministically from the
atomic_mint seed (`atomic_mint_demo`) plus chain-derived featureIds
(via `keccak256(DOMAIN_FEATURE, chainId, shadowId, slotIdx, mintCounter)
% FR_MOD`). No JSON-RPC reads are required for fixture building —
all live state matches the seed-derived reconstruction byte-for-byte
(asserted at builder start).

  - `tools/build_mutate_slot_onchain.py` — mutateSlot + T10 against
    the post-mutate manifest where the OTHER 7 slots' lsh values come
    from chain (not zeroed as in the standalone synthetic builder).
  - `tools/build_zindex_onchain.py` — setZIndexCommit + T10 against
    the FULL live LSH array, with z_commit = sponge_16(perm).
  - `tools/build_extract_onchain.py` — T10 only (extractSlot is
    proofless at the per-slot level), bound to the post-extract
    manifest with the target slot zeroed.
  - `tools/build_solve_onchain.py` — solve_shadow_v2 proof for the
    full 16-slot reveal, with state_commits and lsh_root computed
    over the post-extract manifest (slot 0 EMPTY since it was
    extracted, slots 1–7 OCCUPIED at mint state, slots 8–15 EMPTY).
    z_perm must match what was used at setZIndexCommit time so PI[3]
    z_index_commit equals the chain.
  - `tools/build_insert_onchain.py` — insertFeature (mutate_slot circuit
    shape, carrier-checkpoint as old_lsh) + T10 against host shadow B's
    post-insert manifest. Reconstructs the carrier's pre-insert state
    from the source shadow A's mint seed (slots 1–7 of A are
    never-mutated and thus reconstructible). Asserts the reconstructed
    lsh equals `liveStateHashCheckpointOf(featureId)` on chain via
    `--carrier-checkpoint`.
  - `tools/build_transfer_onchain.py` — transfer_shadow_v2 proof
    rotating all occupied slots' encryption to a recipient pk + T10
    against host shadow B's post-transfer manifest. Reconstructs B's
    full per-slot state including the post-insert slot 8 (count=1)
    and B's mint slots 0–7 (count=0). Recipient Grumpkin sk is
    deterministic from `--recipient-seed`; the recipient's ETH address
    must register their Grumpkin pk in KeyRegistry before broadcast.

### Broadcast scripts (`contracts/script/*OnSepolia.s.sol`)

Each entry point has a dedicated broadcast script with idempotency
guards (skip-if-already-applied):

  - `MintOnSepolia.s.sol` — register + mint
  - `MutateOnSepolia.s.sol` — skip if slot's lsh != fixture old_lsh
  - `SetZIndexOnSepolia.s.sol` — skip if zIndexCommit already equals fixture's
  - `ExtractOnSepolia.s.sol` — skip if slot already EMPTY
  - `SolveOnSepolia.s.sol` — skip if shadow already solved
  - `InsertOnSepolia.s.sol` — skip if `isInserted(featureId)`; pre-checks
    `liveStateHashCheckpointOf(featureId) == fixture.old_lsh` for a clear
    error if the carrier moved between fixture build and broadcast.
  - `TransferOnSepolia.s.sol` — skip if `ownerOf(shadowId) ==` recipient;
    requires recipient already registered in KeyRegistry.

All scripts use `--gas-estimate-multiplier 150`.

### Final state of shadow A (post-solve)

  - `shadow.solved = true`
  - `shadow.zIndexCommit = 0x1a0bc94892a6fb54e515b07d1be241001d294a2ffb3f5c0a6c81b9494dd67dc3`
  - `shadow.zIndexRevealed = 0xbc8a6ed342f09715` (lower 64 bits of z_perm_packed)
  - `shadow.zIndexRevealedSet = true`
  - All 16 slots: EMPTY (slot 0 explicit-extracted, slots 1–7 auto-extracted
    by solve, slots 8–15 always were)
  - All 8 FeatureNFT carriers: `isInserted = false`, owner = deployer
    (deployer can now transfer them as plain ERC-721s)

The z-permutation `[5, 1, 7, 9, 0, 15, 2, 4, 3, 13, 14, 6, 10, 8, 12, 11]`
is now publicly revealed on chain via `s.zIndexRevealed`. This is the
irreversible "reveal everything" final state — no further mutations,
transfers, or extracts on shadow A are possible.

### Final state of shadow B (post-transfer)

  - `shadowId = 0x2c6f0a0b412f403a6d080b2fa2fa3c4375cef9a5567f3c46df177ede9b74014d`
    (faceCommit = derived from `examples/faces/synthetic/grid_48/s114_neutral.png`,
    fixture seed `bob0`).
  - `ownerOf(shadowId) = 0xFD90Bd22EDA6f54EBA3587E6a3642AB3B5236Ca2`
    (rotated from the deployer at transferShadow).
  - `shadow.ecdhPub` rotated to recipient's Grumpkin pk
    (`0x2ba2a91c82b29722...`, `0x18308955...`); recipient's Grumpkin sk
    is the only key that can decrypt B's slots' c2 ciphertexts now.
  - `shadow.solved = false`. Slots 0–7 (B's own carriers) and slot 8
    (the carrier inherited from shadow A's slot 1 via `insertFeature`)
    are OCCUPIED with post-rotation LSH; slots 9–15 are EMPTY.
  - All 9 inserted FeatureNFT carriers (B's 8 + the A-derived one in
    slot 8): `isInserted = true`, `hostShadowId = B`, ERC-721 owner =
    recipient (`rotateInsertedOwner` was called per-slot at transfer time).
  - shadow B remains live (not solved), so the recipient can still
    mutate / extract / setZIndex / solve. Demonstrating those ops from
    the recipient is left as future work; the contract path has full
    coverage in unit tests and shadow A.

Cryptographic correctness was verified end-to-end via
`tools/verify_onchain_transfer.py`:
  - on-chain owner == recipient,
  - on-chain `shadow.ecdhPub` == recipient_pk,
  - all 16 per-slot LSHs match the fixture's `post_transfer_lsh_array`,
  - all 9 occupied slots' new c2 (from event-emitted calldata) decrypts
    under recipient_sk to the byte-equivalent pre-rotation plaintext.

---

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