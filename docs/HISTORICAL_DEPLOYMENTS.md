# Historical deployments (pipelines #3, #4)

**Status:** archive — superseded by pipeline #5 (see docs/DEPLOYMENT.md).
Moved here 2026-04-28 once pipeline #5's full lifecycle was complete on chain.

Pipelines #3 and #4 are preserved unchanged at their original addresses;
the contracts continue to function on Base Sepolia, but no new operations
are run against them. They are kept for replay-against-history and for the
OP-Stack 7-day bridge L1 finalize that originated on pipeline #3.

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

