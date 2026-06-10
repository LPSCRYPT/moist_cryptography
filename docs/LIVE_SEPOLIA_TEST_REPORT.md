# Live Sepolia test report

Last updated: 2026-06-08

## Deployment under test

Base Sepolia modular phased-mint deployment:

| Contract | Address |
|---|---|
| `ShadowToken` | `0x73a2bb3411B1a5D6f9df5a06d3b4bFBA95970e3d` |
| `FeatureNFT` | `0x6CfAD30a588a57946b306136D4094ca0c07f51aC` |
| `KeyRegistry` | `0x8c00dD1B1AA71099C9055942F22dB63Dc4361F9D` |
| `ShadowMintController` | `0x68f777E5B1b8E6b1099F3d8D6153a7C5c9d19A9b` |
| `Poseidon2YulSponge` | `0xbB664d9Ff720Dc8b381AdBc0422E4fe64c088E03` |
| `Poseidon2YulSponge16` | `0xD81E987464B3c40CFF033C01aeC99C7eB7956080` |

## Completed live verification

### Modular phased mint

Command executed from repo root:

```bash
python3 tools/verify_onchain_mint.py \
  --rpc "$RPC" \
  --st 0x73a2bb3411B1a5D6f9df5a06d3b4bFBA95970e3d \
  --fn 0x6CfAD30a588a57946b306136D4094ca0c07f51aC \
  --kr 0x8c00dD1B1AA71099C9055942F22dB63Dc4361F9D \
  --mc 0x68f777E5B1b8E6b1099F3d8D6153a7C5c9d19A9b \
  --poseidon39 0xbB664d9Ff720Dc8b381AdBc0422E4fe64c088E03 \
  --poseidon16 0xD81E987464B3c40CFF033C01aeC99C7eB7956080 \
  --register-tx 0xbe542296be09dbd9485a0241b4a8906fd32f39daf47e45d60ed37bf43853d238 \
  --mint-tx 0x99fbc0da74aa89f4eb525320083d52c3272d4f8aeb464a17bbfc818d5f361d39 \
  --submit-tx 0x769307da37b3a4196c0855ff45787304001185f9a3c2501805114725d944bab5 \
  --submit-tx 0x7098a5bf73b8234d5836c395842095515d3bda324e6b7044df93812b64528527 \
  --submit-tx 0x08ea762c377ab11be572ed8dd0391284b9e4221b559bdc9b06c4d11afac79047 \
  --submit-tx 0x10b8de83280c785b58cf3c9737548c8a343b49286e9279028f1c739e7f747a53 \
  --submit-tx 0xdd000d2a44826041bc757cfda1337a078133a494dc6c7a7a57738a3eb47dd894 \
  --submit-tx 0x763537dc78c56d8293e46575642f4d1bcc7a57bfbf674e3e6207968cdfea6a23 \
  --submit-tx 0x3cb9806c6e2cf01147a76a89f8a485a298bfa4c1b41233ed8dbdb7e6985971ec \
  --submit-tx 0x99fbc0da74aa89f4eb525320083d52c3272d4f8aeb464a17bbfc818d5f361d39 \
  --deployer "$DEPLOYER_ADDRESS" \
  --fixture contracts/test/fixtures/atomic_mint/latest_testnet_incremental \
  --seed latest_testnet_incremental
```

Result:

```text
44 passed, 0 failed
```

Observed tx gas:

| Step | Tx | Gas |
|---|---|---:|
| register + begin | `0xbe542296be09dbd9485a0241b4a8906fd32f39daf47e45d60ed37bf43853d238` | 11,654,925 |
| submit slot 0 | `0x769307da37b3a4196c0855ff45787304001185f9a3c2501805114725d944bab5` | 816,222 |
| submit slot 1 | `0x7098a5bf73b8234d5836c395842095515d3bda324e6b7044df93812b64528527` | 816,174 |
| submit slot 2 | `0x08ea762c377ab11be572ed8dd0391284b9e4221b559bdc9b06c4d11afac79047` | 816,186 |
| submit slot 3 | `0x10b8de83280c785b58cf3c9737548c8a343b49286e9279028f1c739e7f747a53` | 816,162 |
| submit slot 4 | `0xdd000d2a44826041bc757cfda1337a078133a494dc6c7a7a57738a3eb47dd894` | 816,222 |
| submit slot 5 | `0x763537dc78c56d8293e46575642f4d1bcc7a57bfbf674e3e6207968cdfea6a23` | 816,162 |
| submit slot 6 | `0x3cb9806c6e2cf01147a76a89f8a485a298bfa4c1b41233ed8dbdb7e6985971ec` | 816,198 |
| submit slot 7 + finalize | `0x99fbc0da74aa89f4eb525320083d52c3272d4f8aeb464a17bbfc818d5f361d39` | 7,300,874 |

Checked live postconditions:

- contract wiring;
- `KeyRegistry.pkOf(deployer)` equals fixture owner pubkey;
- all tx receipts `status=0x1`;
- exactly one `ShadowMinted`;
- exactly eight `ShadowSlotMutated` finalization events;
- exactly eight `MintCiphertextSubmitted` events;
- exactly one `ShadowT10Updated`;
- event and storage T10 equal fixture PI;
- all eight submitted `c2` payloads byte-equal fixture ciphertext;
- all eight ciphertexts decrypt under fixture owner secret key and decode to expected pose/dim/palette-index plaintext;
- on-chain per-slot `liveStateHash` equals fixture `lsh_inits[i]`;
- all eight carriers match expected type/origin/host/owner metadata;
- slots 8..15 are empty;
- `registeredImages[imageCommit] == true`;
- `mintedOrigins[imageCommit] == true`;
- `ownerOf(shadowId) == deployer`;
- `Shadow.ecdhPub` matches fixture owner pubkey;
- `Shadow.solved == false`;
- `Shadow.zIndexCommit == 0`.

## Testing-audit finding: browser decryption data availability

This report was recorded against the pre-cutover live deployment. That deployment emitted mint `c2` but did not emit per-slot mint `c1X/c1Y`, so chain-only browser decryption of hidden mint slots was not possible there.

The current local contracts have since been patched so every hidden-slot ciphertext path publishes proof-bound `c1`:

| Operation | Chain emits `c2` | Chain emits proof-bound `c1` | Browser chain-only decryption on patched deployments |
|---|---:|---:|---:|
| phased mint | yes | yes, `ShadowSlotEnvelope` at finalization | possible |
| `mutateSlot` / `mutateBatch` | yes | yes, `ShadowSlotEnvelope` | possible |
| `insertFeature` | yes | yes, `ShadowSlotEnvelope` | possible |
| `transferShadow` | yes | yes, `ShadowSlotEnvelope` | possible |
| `transferFeature` | yes | yes, `FeatureTransferred.newC1X/newC1Y` | possible |
| `revealSlots` | plaintext public | not needed | public |

A new live report must be generated after redeploying the patched verifier/contracts; the old deployment remains historical evidence only. The dashboard refuses to fake decryption from fixtures or server helpers.

## Still outstanding for exhaustive live coverage

The following live Base Sepolia operations still need to be run and recorded against the latest deployment or a redeployed patched deployment:

1. `mutateSlot` real proof tx and postcondition verification.
2. `mutateBatch` real proof tx and postcondition verification.
3. `revealSlots` real proof tx and postcondition verification.
4. `transferShadow` real proof tx and recipient decryption verification.
5. `transferFeatureV2` real proof tx and recipient decryption verification.
6. `extractSlot` / `insertFeature` live txs if still supported in the latest branch state.
7. `setZIndexCommit` live tx if still supported in the latest branch state.
8. Bridge L2 leg and, if in scope, OP finalization after the challenge window.
9. Browser dashboard live-load test over the latest deployment after serving from HTTP.

Do not claim full end-to-end live coverage until every item above has tx hashes, gas, and RPC-checked postconditions.
