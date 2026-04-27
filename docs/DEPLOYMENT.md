# Deployment

This document records every Base Sepolia deploy of the v2 contract set
plus the on-chain operations executed against it.

## Status

| Spec criterion #5 step | Status |
|---|---|
| Fresh contract set deployed | ✅ done (12 contracts, 22 setup txs) |
| One real `registerImage` (face_disc proof) | ✅ done — block 40,761,804 |
| One real `mintShadow` (1 shadow + 8 carriers) | ✅ done — block 40,761,922 |
| One real `mutateSlot` (chained to A's on-chain state) | ⏳ next session — needs on-chain-bound fixture builder |
| One real `setZIndexCommit` | ⏳ next session — same |
| One real `extractSlot` → `insertFeature` into a different shadow | ⏳ next session — same |
| One real `solve` | ⏳ next session — same |

The mint half of the lifecycle is fully on-chain. The 5 downstream
ops (mutate / setZIndex / extract / insert / solve) all share a common
blocker: they need a "chained on-chain fixture" — proofs whose
witnesses are derived from shadow A's actual current state on chain,
not from synthetic state local to a Python builder. See "Next session
work" below.

---

## Network

- Chain: **Base Sepolia** (chain id `84532`)
- L2 block explorer: https://sepolia.basescan.org/
- RPC tested: `https://base-sepolia.gateway.tenderly.co` (others have
  lower per-tx envelope caps)
- Deployer EOA: `0x1b43AFe43afC74bF9D0EBd764787eFD7CCcC2B6F`

## Contract addresses (current — v2-gas + registerImage split)

Deploy commit: `c1bfb37` — `registerImage split: drop face_disc from mintShadow body (152 -> 156)`.

| Contract | Address |
|---|---|
| `Poseidon2YulSponge` (sponge_39) | [`0xDAB29834F3CEe1Fbc262f4614f61F669B8627F38`](https://sepolia.basescan.org/address/0xDAB29834F3CEe1Fbc262f4614f61F669B8627F38) |
| `Poseidon2YulSponge16` (sponge_16) | [`0xCa8C63D3F592ec0d9Acd191bc74e4231DA14A5A5`](https://sepolia.basescan.org/address/0xCa8C63D3F592ec0d9Acd191bc74e4231DA14A5A5) |
| `KeyRegistry` | [`0x5f7cb4DEd00A30D2a5a52F26e1bCDA8401a738C5`](https://sepolia.basescan.org/address/0x5f7cb4DEd00A30D2a5a52F26e1bCDA8401a738C5) |
| `ShadowToken` | [`0x8439c6796508930863599cd9cB49db741C6ea21f`](https://sepolia.basescan.org/address/0x8439c6796508930863599cd9cB49db741C6ea21f) |
| `FeatureNFT` | [`0x82cd6763cB7362EA5652b63E12617fBa06702D69`](https://sepolia.basescan.org/address/0x82cd6763cB7362EA5652b63E12617fBa06702D69) |
| `MintShadowVerifier` | [`0x446daaEa9366e8A465EA911c768476d191480D53`](https://sepolia.basescan.org/address/0x446daaEa9366e8A465EA911c768476d191480D53) |
| `FaceDiscVerifier` | [`0x739cDab4A464632bFb67bdB8760A59a444044E7d`](https://sepolia.basescan.org/address/0x739cDab4A464632bFb67bdB8760A59a444044E7d) |
| `MutateSlotVerifier` | [`0xBc5b41EEB6a5c5598fBb0D1aD4120889a7488294`](https://sepolia.basescan.org/address/0xBc5b41EEB6a5c5598fBb0D1aD4120889a7488294) |
| `T10ShadowVerifier` | [`0xceEC22F38B4507C22D1Cb6a73Ac9069A850cAAfe`](https://sepolia.basescan.org/address/0xceEC22F38B4507C22D1Cb6a73Ac9069A850cAAfe) |
| `ZIndexCommitVerifier` | [`0x43237d169e5b89609B842ABC60F49c3dA3c1f960`](https://sepolia.basescan.org/address/0x43237d169e5b89609B842ABC60F49c3dA3c1f960) |
| `TransferShadowVerifier` | [`0x403DcbE6B0Bbc93c21cFa45571Dbd95FC36DAE08`](https://sepolia.basescan.org/address/0x403DcbE6B0Bbc93c21cFa45571Dbd95FC36DAE08) |
| `SolveShadowVerifier` | [`0x338a715348FB9dbe99Ea103F994BE00b8C11154A`](https://sepolia.basescan.org/address/0x338a715348FB9dbe99Ea103F994BE00b8C11154A) |

The wiring (cross-references between contracts and the verifier-slot
assignments inside `ShadowToken`) is set in a single deploy script run.
Every privileged setter is one-shot and locked after the deploy.

## Deploy run

```
forge script script/DeployShadowPipeline.s.sol:DeployShadowPipeline \
    --broadcast --rpc-url https://base-sepolia.gateway.tenderly.co \
    --private-key $PRIVATE_KEY --slow
```

Total gas estimate: ~72M (split across 22 txs). No single tx exceeded
the per-tx gas cap because deploys are bytecode CREATE which charges
0.4 gas/byte (cold), well below the 16M ceiling.

Broadcast artifact:
`contracts/broadcast/DeployShadowPipeline.s.sol/84532/run-latest.json`

---

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
  --st 0x8439c6796508930863599cd9cB49db741C6ea21f \
  --fn 0x82cd6763cB7362EA5652b63E12617fBa06702D69 \
  --kr 0x5f7cb4DEd00A30D2a5a52F26e1bCDA8401a738C5 \
  --poseidon39 0xDAB29834F3CEe1Fbc262f4614f61F669B8627F38 \
  --poseidon16 0xCa8C63D3F592ec0d9Acd191bc74e4231DA14A5A5 \
  --mint-tx 0xe273562ab241f52fd7f142fa02794aeee0b3a0453bdd88c67b538fbc1ba5d198 \
  --register-tx 0x775b291815f34ed36c66a88c10831a24afad5cb3c1d23a05d28e88ac6f02a63c \
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

156/156 forge tests pass with real ZK proofs (no mocks).

| Op | Local gas-pin budget | Measured local | On-chain (where measured) |
|---|---|---|---|
| `registerImage` | 4M | ~3.79M | **4.66M ✅** |
| `mintShadow` | 11M | ~9.5M (body only) | **11.04M ✅** |
| `mutateSlot` | 6M | ~5M | not yet on chain |
| `mutateBatch` (2 slots) | 25M | ~7.5M | not yet on chain |
| `transferShadow` (4-occ) | 7M | ~6.2M | not yet on chain |
| `transferShadow` (16-occ) | 11M | ~9.4M | not yet on chain |
| `setZIndexCommit` | n/a | ~4.8M | not yet on chain |
| `extractSlot` | n/a | ~2.4M | not yet on chain |
| `insertFeature` | n/a | ~5M | not yet on chain |
| `solve` (4-occ) | 8M | ~6.5M | not yet on chain |
| `solve` (16-occ) | 7M | ~3.7M | not yet on chain |

All 14 `RealChainLimits.t.sol` checks confirm every contract fits
EIP-170's 24,576-byte runtime cap with 100+ B headroom.

---

## Next session work

The remaining 5 lifecycle ops — `mutateSlot`, `setZIndexCommit`,
`extractSlot`, `insertFeature`, `solve` — each need a fresh ZK proof
whose witness is bound to **shadow A's current on-chain state**, not
to synthetic state generated locally. Existing
`tools/build_*_fixture.py` scripts produce fixtures keyed off
self-bootstrapped state (their own random seeds); those proofs would
fail on-chain because their pre-state hashes (chain_tips, lsh values,
mutation counts) don't match shadow A's slots.

What's needed:

1. A read-only on-chain state extractor (`tools/read_shadow_state.py`):
   given a `ShadowToken` address and `shadowId`, returns the per-slot
   `(originFaceId, mutationCount, chainTip, lsh, c1, ctCommit)` tuple.
   This already exists implicitly in the contract storage layout —
   each slot's manifest entry is readable via `ShadowToken.slotOf` and
   the per-slot chain state is reconstructable from event logs
   (`ShadowSlotMutated`).
2. Modified fixture builders (`tools/build_*_onchain.py` variants):
   accept `--from-state state.json` and use that as the prover witness's
   `old_*` inputs, so the resulting proof binds to chain state.
3. A driver script (`tools/run_lifecycle_on_sepolia.py`) that chains:
   `extract on-chain state → build proof → broadcast → re-extract →
   build next proof → broadcast → ...` for all 5 ops, capturing tx hashes.

Each proof is ~minutes of `nargo execute` + `bb prove` wall-clock; the
full lifecycle would take ~30–60 min of compute plus broadcast time.
Worth its own focused session because the tooling generalises to any
on-chain proof generation pipeline (post-mint UX, indexer
back-reconciliation, debugging stuck states).

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

## Historical: pre-split deploys (superseded)

Two earlier deploys exist on Base Sepolia history but use
incompatible ABIs (the `MintShadowArgs` struct and `ShadowToken`
storage shape have since changed). They are NOT compatible with the
current `MintOnSepolia.s.sol` and should be ignored:

- pre-v2-gas (commit `ff309b1`): `ShadowToken=0xDb5808...A42e`
- v2-gas only, pre-registerImage-split (commit `5a33652`):
  `ShadowToken=0xf75fd5...56f6`
