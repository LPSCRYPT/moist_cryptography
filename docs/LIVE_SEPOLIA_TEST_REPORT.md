# Live Sepolia test report

Last updated: 2026-06-08

## Deployment under test

Base Sepolia deployment of the ciphertext-envelope cutover contracts. This deployment predates the source change that disables `transferShadow` for bounded shadows.

| Contract | Address |
|---|---|
| `ShadowToken` | `0x15f8D237Cc15377a7C140617E2cfEEe39F49a91C` |
| `FeatureNFT` | `0x31ADA4c1E9837b336e7540B57F174417e04F42bA` |
| `KeyRegistry` | `0xffDb68f22Db0f9E63F739Cdf865541E3bA8bDE18` |
| `ShadowMintController` | `0x0fBCeb82555190011e5e0BA10D2265a852C2ED7c` |
| `Poseidon2YulSponge` | `0x9A68796Bd6c80bdC0106D175b19c88FC36A774d9` |
| `Poseidon2YulSponge16` | `0xF89A93BEf837Ea874A6DcBAdd9F38f1e7A399992` |
| `Poseidon2YulHash2` | `0x87feb57DF99716E114B033adce6639998804B9c3` |
| `MintShadowVerifier` | `0x89b7aac5dc255111b627D48279E2e72B1f8Ae750` |
| `FaceDiscVerifier` | `0x85Cf651da336b937eBAAfB2e03B535aec5C3F044` |
| `MutateSlotVerifier` | `0x27b4785548352054A7FEdc300386Af598F129988` |
| `T10ShadowVerifier` | `0x86C751c4DdFfDf1BE7C7D45feb922fFD5536C461` |
| `ZIndexCommitVerifier` | `0xa3C4A965ef00c052787387101F58e9a25658636a` |
| `TransferShadowVerifier` | `0x3CD751E9F8DF56C96D4f4dDc3DB92541A2Aee08d` |
| `SolveShadowVerifier` | `0x79b86342B732e88BA3455211814FCb9B8488b874` |
| `TransferFeatureV2Verifier` | `0xF0474B877d8D7d9dd4836c42563b4cC2dFe12840` |
| `Poseidon2YulSpongePaletteSalt` | `0xD776Aba3B4ad2257EC0ad98190734053BBD2556B` |

Deployment artifact: `contracts/broadcast/DeployShadowPipeline.s.sol/84532/run-latest.json`.
First deployment block: `42673299`.

## Local preflight before redeploy

Run from `contracts/`:

```text
python3 ../tools/test_chain_decryptability.py && forge test -vv
```

Observed result:

```text
255 tests passed, 0 failed, 0 skipped
```

The Python decryptability regression also completed successfully before Forge ran.

## Live transactions and verification

### Deploy latest pipeline

`DeployShadowPipeline.s.sol` completed successfully on Base Sepolia.

| Item | Tx | Gas used |
|---|---|---:|
| deploy/wire pipeline, first tx | `0xac8e257814c3d6de6a92c882aa3e7f63fa255ef9f9782c282441a3649ece3df0` | 1,382,391 |
| deploy/wire pipeline, final tx | `0x5f137356b7d06707c5d6dcef61ccddfd418a00e1f60a78d89615c08ade70700c` | 45,306 |
| total across deployment broadcast | see broadcast artifact | 76,333,335 |

### Modular phased mint

Fixture: `contracts/test/fixtures/atomic_mint/atomic_mint_demo`.
Shadow id: `0x011c687ec30b886164f6506b5ad3972fbe295f2e1da1047bd782d686c645d52a`.

| Step | Tx | Gas used |
|---|---|---:|
| `KeyRegistry.register` deployer key | `0x3d904f356aa00efc1221a697db78c165035abff9205bea7fee06e29cc5c53b53` | 68,609 |
| register image + begin mint | `0x4295268d66ffeb11be092d78eae690dcce78537022bd62aeab8101f7e89ee092` | 12,754,556 |
| submit ciphertext | `0xcf7091b74b66b0a5cf94ae24e9fee8022be6c4af053ccb1894b2191b4d966b26` | 818,256 |
| submit ciphertext | `0x229ba8f5e57a2e2187f1a846ad217cbaba438364f401ff442e2025c555f3844e` | 818,196 |
| submit ciphertext | `0xa4ac37e4b84f4ce65dc2592575bd51be21ee9eea9ce32da6de7b30c57b546bb8` | 818,184 |
| submit ciphertext | `0x57829cad4a4346883f78fa34324b1b4a0be48f02c94688a6a94e9d073d65a40a` | 818,244 |
| submit ciphertext | `0xc6bd56509db36c7f18dfa42a48ef54cd590265cc402efad4d1f4b49ee904aa93` | 818,232 |
| submit ciphertext | `0xcf2caef082d4aaefceaf4017e0979cd1a823241c8cdf4c4473e7bcb7c9da4a1b` | 818,256 |
| submit ciphertext | `0xc287363962967529144e7bf11c61c7e7a9db1ecad590a0c9f2db5b604a4f60fc` | 818,232 |
| submit ciphertext + finalize | `0xc97b2c28af4092503da8328a631766e1600cdef4a416c0965bf510227caae834` | 7,327,886 |

Verification command used `tools/verify_onchain_mint.py` against the addresses above.
Observed result:

```text
45 passed, 0 failed
```

Checked live postconditions include contract wiring, `KeyRegistry.pkOf(deployer)`, all tx receipt statuses, one `ShadowMinted`, eight `ShadowSlotMutated`, eight `MintCiphertextSubmitted`, one `ShadowT10Updated`, eight `ShadowSlotEnvelope` events, event/storage T10 equality, byte-equal ciphertext payloads, owner-key decryption for all eight mint ciphertexts, per-slot `liveStateHash` equality, carrier metadata, empty slots 8..15, registered/minted origin flags, owner, ECDH pubkey, unsolved state, and zero z-index commit.

### `mutateSlot`

Fixture: `contracts/test/fixtures/onchain_mutate/live_latest_slot0`.

| Step | Tx | Gas used |
|---|---|---:|
| mutate slot 0 | `0xa0d04486c62c10b23d2d1e443578e7f98b026c4836c15049b6d29ac43276cbbf` | 7,908,520 |

The broadcast script checked the current slot was `OCCUPIED` and that on-chain `liveStateHash` matched the fixture's proof-bound `old_lsh` before sending. The receipt succeeded and emitted the expected mutation/T10/envelope log surface.

### `mutateBatch`

Fixture: `contracts/test/fixtures/onchain_mutate_batch/live_latest_batch`.

| Step | Tx | Gas used |
|---|---|---:|
| mutate slots 1 and 2 | `0xa00a076eb7503332537bfc41d87e2b1634cc12a11f1b06fe4e0c4729f0962c36` | 12,361,711 |

The fixture included the prior slot-0 mutation in its T10 manifest. The broadcast script checked both target slots' current `liveStateHash` values against the fixture before sending. The receipt succeeded and emitted the expected two mutation entries plus T10/envelope log surface.

### Historical `transferShadow` blocker before disablement

A real transfer fixture was generated for the post-mint/post-mutation shadow and a fresh recipient was funded and registered in `KeyRegistry`.

Preparation transactions:

| Step | Tx |
|---|---|
| fund fresh recipient EOA | `0xf58770a27c7e17e235151b8ffabd5c5bf0175944b52e4f924e11ab96bafd281c` |
| recipient `KeyRegistry.register` | `0xb10c45ce4921d0659960c7bcef97f50048767bb1dbff7c8e8107b807d664ccbf` |

Attempted command:

```text
forge script script/TransferOnSepolia.s.sol:TransferOnSepolia \
  --rpc-url https://base-sepolia.gateway.tenderly.co \
  --broadcast --gas-estimate-multiplier 150
```

Observed failure:

```text
Estimated total gas used for script: 22376806
Error: Failed to send transaction after 4 attempts Err(server returned an error response: error code -32099: gas limit too high)
```

No `transferShadow` live transaction was included. The generated fixture and simulation were real, but the network rejected the gas limit before inclusion. The current source resolves this by disabling full Shadow NFT transfer while any feature is bound; only featureless shadows may transfer via normal ERC-721 transfer.

## Current live coverage status

| Flow | Live status |
|---|---|
| deploy latest contracts | passed |
| phased mint with real proofs | passed |
| chain-only mint ciphertext decryptability | passed via `verify_onchain_mint.py` (`c2` + emitted `ShadowSlotEnvelope` `c1`) |
| `mutateSlot` real proof | passed |
| `mutateBatch` real proofs | passed |
| `transferShadow` real proof | disabled in current source; prior live attempt rejected at 22.38M estimated gas |
| `transferFeatureV2` | not rerun in this pass |
| extract / insert | not rerun in this pass |
| reveal / solve | not rerun in this pass |
| bridge | not rerun in this pass |
| browser dashboard live-load | dashboard defaults now point at this deployment; manual browser verification still outstanding |

Do not claim full end-to-end live coverage until the remaining feature-transfer/extract/insert/reveal/bridge paths are rerun against a deployment that includes the non-transferable Shadow NFT policy.
