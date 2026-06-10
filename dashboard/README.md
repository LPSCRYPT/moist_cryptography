# Sepolia dashboard

Static browser dashboard for the current Base Sepolia ShadowNFT deployment.

## Run

From the repository root:

```bash
python3 -m http.server 8080 --directory dashboard
```

Open `http://127.0.0.1:8080`.

The dashboard is intentionally static. It uses:

- Base Sepolia JSON-RPC via the URL entered in the UI;
- `viem` from a browser ESM CDN for ABI encoding/decoding;
- `@zkpassport/poseidon2` from a browser ESM CDN for BN254 Poseidon2;
- local BigInt Grumpkin arithmetic for ECIES shared-secret derivation.

## Privacy boundary

Private keys are used only in the browser. The dashboard never sends private keys, ECDH shared secrets, decrypted fields, or plaintext pixels to RPC. RPC calls are limited to public chain reads and event-log queries.

## Data-availability truth table

Browser decryption from chain-only data requires both:

1. ciphertext `c2`, and
2. the corresponding ECIES ephemeral public point `c1 = (c1X, c1Y)`.

Current contract support after the c1 data-availability cutover:

| Path | `c2` on chain | proof-bound `c1` on chain | Browser can decrypt from chain-only data? |
|---|---:|---:|---:|
| phased mint ciphertext submissions | yes | yes, `ShadowSlotEnvelope` at finalization | yes |
| `mutateSlot` / `mutateBatch` | yes | yes, `ShadowSlotEnvelope` | yes |
| `insertFeature` | yes | yes, `ShadowSlotEnvelope` | yes |
| `transferShadow` | yes | yes, `ShadowSlotEnvelope` | yes |
| `transferFeature` | yes | yes, `FeatureTransferred.newC1X/newC1Y` | yes |
| incremental reveal | plaintext public | not needed | public |

For historical deployments that predate this cutover, the dashboard still labels hidden slots as `ciphertext present, c1 missing from chain events`. That is a deployed-protocol data-availability limitation, not a dashboard bug.

## Subgraph decision

No subgraph is required for the present live testnet volume. The dashboard chunks `eth_getLogs` by block range and caches user settings in `localStorage`. If event volume or public-RPC range limits become a problem, the same event schema can be moved behind a subgraph or a small indexer without changing the browser decryption boundary.
