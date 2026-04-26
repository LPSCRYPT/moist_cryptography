# Verification

Reference runs from a real Base Sepolia / Eth Sepolia execution. These are
the tx hashes you can plug into [Basescan](https://sepolia.basescan.org/)
or [Etherscan](https://sepolia.etherscan.io/) to verify our work.

> **Note.** This file mixes two Sepolia generations: the canonical alice0
> `face_disc` mint (the **current** topology, with the disc gate live and
> 11 deployed contracts) and the prior 5-verifier run (preserved as
> historical reference). The deploy + mint with `face_disc` are real
> Sepolia tx hashes below; the per-op extract/transfer/solve numbers are
> from the prior run because the new fixtures still bind to chain 31337
> shadow-state and weren't regenerated for chain 84532. The disc gate
> itself is verified on chain by the new mint tx.
>
> A noise-rejection negative test lives in `tools/test_noise_mint.py`.


## Solve scenario (38 / 38 checks pass)

Deployer EOA: `0x1b43AFe43afC74bF9D0EBd764787eFD7CCcC2B6F`

Deployed contracts (Base Sepolia, current `face_disc` topology):

| Contract                | Address |
|-------------------------|---------|
| Poseidon2YulSponge      | [`0x5490E40e319f482a7F9241dDBaF3e1F61374F7AA`](https://sepolia.basescan.org/address/0x5490E40e319f482a7F9241dDBaF3e1F61374F7AA) |
| KeyRegistry             | [`0x7D0eC7b232d95D7bd46C21dB68268db50e177596`](https://sepolia.basescan.org/address/0x7D0eC7b232d95D7bd46C21dB68268db50e177596) |
| ShadowToken             | [`0x0887012dC44009085BC3a21Dc23aD0829F055fFc`](https://sepolia.basescan.org/address/0x0887012dC44009085BC3a21Dc23aD0829F055fFc) |
| FeatureNFT              | [`0xD14B21380a8B4b2990f92b39609Caa08CdAC3419`](https://sepolia.basescan.org/address/0xD14B21380a8B4b2990f92b39609Caa08CdAC3419) |
| FaceDiscVerifier        | [`0x498650e3fC853366E48c7F1c1D48420B5653D169`](https://sepolia.basescan.org/address/0x498650e3fC853366E48c7F1c1D48420B5653D169) |
| MintShadowVerifier      | [`0xa71ab2BfB5a3A0b6475B3E9CDe28DE2a94C83a0d`](https://sepolia.basescan.org/address/0xa71ab2BfB5a3A0b6475B3E9CDe28DE2a94C83a0d) |
| TransferShadowVerifier  | [`0x0301EB7283FAf11F9A7710f6731E087B79e859E7`](https://sepolia.basescan.org/address/0x0301EB7283FAf11F9A7710f6731E087B79e859E7) |
| ExtractSlotVerifier     | [`0x3E9ad25D44343BA976Ca5544A256A3bBCEC1a9F3`](https://sepolia.basescan.org/address/0x3E9ad25D44343BA976Ca5544A256A3bBCEC1a9F3) |
| TransferFeatureVerifier | [`0x6C3B0a156e368c7FF3e903c743c41fa559c074C2`](https://sepolia.basescan.org/address/0x6C3B0a156e368c7FF3e903c743c41fa559c074C2) |
| SolveShadowVerifier     | [`0x450D626F76acdf42C3E5CF5d8A7fDC2E1ebbaC83`](https://sepolia.basescan.org/address/0x450D626F76acdf42C3E5CF5d8A7fDC2E1ebbaC83) |
| T10ShadowVerifier       | [`0x5573955396aB4968AfF0D0312c06177064886e0f`](https://sepolia.basescan.org/address/0x5573955396aB4968AfF0D0312c06177064886e0f) |

Verifier deployed sizes (post-`face_disc` build, EIP-170 limit 24,576):

| Verifier                | Bytes  | Headroom |
|-------------------------|-------:|---------:|
| FaceDiscVerifier        | 24,341 |      235 |
| MintShadowVerifier      | 24,340 |      236 |
| TransferShadowVerifier  | 24,337 |      239 |
| ExtractSlotVerifier     | 24,340 |      236 |
| TransferFeatureVerifier | 24,337 |      239 |
| SolveShadowVerifier     | 24,342 |      234 |
| T10ShadowVerifier       | (separate slot, larger than EIP-170)         ||

Per-op transactions:

| Op | Gas | Tx |
|----|----:|-----|
| mintShadow (face_disc + landmark, 4-arg) | **14,548,201** | [`0x9d3c178e…`](https://sepolia.basescan.org/tx/0x9d3c178ebcc0966621e84a7489ae26cfc70aee3163130fe6ed17961710661915) (block 40,722,872, status 1) |
| mutateSlot × 7          | ~44k each | (in same run) |
| extractSlot (slot 3)    | 4,890,133 | [`0xfc866aec…`](https://sepolia.basescan.org/tx/0xfc866aec672a3a191da30e081662cd65f228ce91c4355f83dac36d90b3802916) |
| transferFeature (carol → dave) | 4,524,301 | [`0xd39533b5…`](https://sepolia.basescan.org/tx/0xd39533b55ed69d59c71c1c4f68eb3712202a61c8e8f4efe17379bbdac101198e) |
| solve                   | 4,404,739 | [`0xbd0753c7…`](https://sepolia.basescan.org/tx/0xbd0753c730b59cca947a559b7a618354bcdf7ef072f7c7a77022585e8dc24d16) |
| transferFrom (post-solve, alice → bob) | 57,699 | [`0xa07f820a…`](https://sepolia.basescan.org/tx/0xa07f820af8c35eb4f8fe2b786dfaac2528e357a4319007bfbaa4b791e9f537c9) |

All under the 16,777,216-gas Base Sepolia per-tx cap.

The shadow id derived for this run:

```
faceOriginId = 0x... (alice0 mint PI[8])
chainid       = 84532 (Base Sepolia)
shadowId      = keccak256(abi.encode(DOMAIN_SHADOW, 84532, faceOriginId)) % FR_MOD
              = 0x0f2ecd8f902b3a1b4560eeec85f2034ea7420fad09f315359537e0dd7f8550c1
```

## Cross-chain bridge (L2 leg)

Deployed contracts:

| Side | Contract       | Address |
|------|----------------|---------|
| L1 (Eth Sepolia)  | `ShadowMirrorL1` | [`0x710559A34F5702460bEf0ca0a3b3181510aB4aA6`](https://sepolia.etherscan.io/address/0x710559A34F5702460bEf0ca0a3b3181510aB4aA6) |
| L2 (Base Sepolia) | `ShadowBridgeL2` | [`0x04d79cf8E6a2A7B20823b298Ac59657b07981112`](https://sepolia.basescan.org/address/0x04d79cf8E6a2A7B20823b298Ac59657b07981112) |

`bridgeShadow` tx (L2):

```
hash       0x2dd6e98effda9a7427635f7ccbf893d073607f385a63967423a62f240506ddac
gas        721,109   (4.3% of 16.78M cap)
state      bridged[sid] = OWNED_ON_L1
locked     ownerOf(sid) = ShadowBridgeL2
```

Basescan: [`0x2dd6e98e…`](https://sepolia.basescan.org/tx/0x2dd6e98effda9a7427635f7ccbf893d073607f385a63967423a62f240506ddac)

The L1 mint completes when `OptimismPortal.proveWithdrawalTransaction`
+ `finalizeWithdrawalTransaction` are submitted (anyone can do this) after
the standard OP withdrawal challenge period has elapsed.

## T10 public-shadow scenario (8 / 8 setShadowT10 txs land)

Separate Sepolia deploy that exercises the T10 stack: mint + 7 mutateSlot
+ 8 setShadowT10. Reproducible with `tools/anvil_t10_e2e.py --rpc <sepolia>`.

Deployed contracts (Base Sepolia):

| Contract            | Address |
|---------------------|---------|
| Poseidon2YulSponge  | [`0xeb078Cc13Daa55Ed3760fBa03081F3CC8f38BD8A`](https://sepolia.basescan.org/address/0xeb078Cc13Daa55Ed3760fBa03081F3CC8f38BD8A) |
| ShadowToken         | [`0x07DD0635b1a84763Cb72B44258a2b292896d2F7f`](https://sepolia.basescan.org/address/0x07DD0635b1a84763Cb72B44258a2b292896d2F7f) |
| FeatureNFT          | [`0xbFA6Dcf5BAc03aaB4E7Aa97725cEb63f955DD6F2`](https://sepolia.basescan.org/address/0xbFA6Dcf5BAc03aaB4E7Aa97725cEb63f955DD6F2) |
| MintShadowVerifier  | [`0x0F9f1AC4edAd72ebC8f156B6B844cCb25F6b8c9D`](https://sepolia.basescan.org/address/0x0F9f1AC4edAd72ebC8f156B6B844cCb25F6b8c9D) |
| T10ShadowVerifier   | [`0x6920E335D863474ee20e205b4BaB5d63aDBbEEFc`](https://sepolia.basescan.org/address/0x6920E335D863474ee20e205b4BaB5d63aDBbEEFc) |

Per-op transactions (representative):

| Op | Gas | Tx |
|----|----:|-----|
| mintShadow                     | 9,934,057 | [`0xce73cfa0…`](https://sepolia.basescan.org/tx/0xce73cfa01d2ece622d5ba56c8686b49eab095c6294bfb9314d89fd2eee5be062) |
| mutateSlot (step 1, eye L +3)  |    64,292 | [`0x5bcec561…`](https://sepolia.basescan.org/tx/0x5bcec5612aecc2de68a4473e79cce0c0eae9bcfff36523d31f80441a8849c3e6) |
| setShadowT10 (step 1)          | 5,072,373 | [`0x4682b8fa…`](https://sepolia.basescan.org/tx/0x4682b8fabf3101d3601d9c0c34ca4bda100d91835aedcbb44e8f5c3aea6aee2a) |

Visual output: [`examples/demo_t10_sepolia.png`](demo_t10_sepolia.png) —
8-step strip with public T10 silhouettes (top row, decoded from on-chain
`shadowT10[hi, lo]`) above private composites (bottom row, owner-decrypted).

See [`docs/T10.md`](../docs/T10.md) for the algorithm, public-input layout,
and reproduction recipe.

## Reproducing locally

You don't need ETH to verify — `forge test` runs against the bundled
fixtures and proves byte-equality to the same proofs that landed on
Sepolia:

```sh
cd contracts && forge test         # 111/111 pass
cd ../tools  && python3 validate_pixels.py
```

Both run in under a minute on a laptop and require zero on-chain calls.

## Visualizing on-chain state

The artistic claim of this project is that visual outputs are
chain-derived. `tools/visualize_shadow.py` makes that auditable end to
end: read RAW bytes from chain, ECIES-decrypt with the owner's sk,
render the result.

Two modes:

```sh
# Snapshot one shadow's CURRENT state from a live RPC
# (needs cast + the owner's Grumpkin sk + the ECIES c1 ephemeral pk)
python3 tools/visualize_shadow.py snapshot \
    --rpc https://sepolia.base.org \
    --shadow-token 0x0887012dC44009085BC3a21Dc23aD0829F055fFc \
    --shadow-id 0x1039d4890975c7b307ec39da0d6e3480182ab4583cf16481d7db1fa5d385a601 \
    --owner-sk-hex 0x... \
    --c1-x-hex 0x... --c1-y-hex 0x... \
    --from-block 40722872 \
    --out runs/snapshot.png

# Offline snapshot from a saved fixture (no RPC needed)
python3 tools/visualize_shadow.py snapshot \
    --from-fixture contracts/test/fixtures/mint_shadow/alice0 \
    --out runs/snapshot.png

# Replay every state transition for a shadow (multi-row montage)
python3 tools/visualize_shadow.py history \
    --from-run-dir runs/anvil_disc_<ts> \
    --from-fixture contracts/test/fixtures/mint_shadow/alice0 \
    --out runs/history.png
```

The pipeline:
1. Read `boxesPackedOf(shadowId)` for region geometry (immutable from mint)
2. Read `manifestOf(shadowId)` for current poses (mutated by `mutateSlot`)
3. Read `shadowT10(shadowId, 0)` and `(shadowId, 1)` for the 16x16 silhouette
4. Walk `ShadowCiphertext` event logs for the latest c2 ciphertext
5. ECIES-decrypt c2 with the owner's sk + the ECIES c1 ephemeral pk
6. Split decrypted plaintext into 8 region byte arrays (constant after mint)
7. Composite under the chain-stored poses to recover the 48x48 RGB face
8. Decode shadowT10 hi/lo into the public 16x16 silhouette

Both RGB face and T10 silhouette are produced from chain bytes.
Anyone with `cast`, the owner's sk, and the c1 ephemeral pk can run the
tool and reproduce identical pixels.
