# Chain dashboard

Static browser dashboard for the current Base Sepolia deployment and localhost Anvil test runs.

## Base Sepolia run

From the repository root:

```bash
python3 -m http.server 8080 --directory dashboard
```

Open `http://127.0.0.1:8080` and click **Load chain data**.

## Full localhost run

From the repository root:

```bash
python3 tools/start_local_dashboard.py
```

The launcher starts Anvil, deploys the latest contracts, runs the committed atomic mint fixture with real proofs unless `--skip-mint` is passed, writes `dashboard/local.json`, and serves the repository root so the dashboard can display `examples/` face images. Open `http://127.0.0.1:8080/dashboard/`. Stop it with:

```bash
python3 tools/start_local_dashboard.py --stop
```

The generated `dashboard/local.json` is ignored by git because it contains local test EVM private keys. Those are public Anvil keys and must never be reused outside localhost.

The dashboard is intentionally static. It uses:

- Base Sepolia JSON-RPC via the URL entered in the UI;
- `viem` from a browser ESM CDN for ABI encoding/decoding;
- `@zkpassport/poseidon2` from a browser ESM CDN for BN254 Poseidon2;
- local BigInt Grumpkin arithmetic for ECIES shared-secret derivation.

## Privacy boundary

Private keys are used only in the browser. The dashboard never sends private keys, ECDH shared secrets, decrypted fields, or plaintext pixels to RPC. RPC calls are limited to public chain reads and event-log queries.


## Function caller

The localhost dashboard includes a generic ABI caller. Pick any configured profile, target a known or custom contract, paste a single ABI function item, provide JSON args, and choose read/simulate or send transaction. EVM private keys stay in browser memory/localStorage and are intended for localhost/test keys only.

## T10 replay and local visual reconstruction

For each selected Shadow NFT, the dashboard filters `ShadowDownscaleUpdated` by
`shadowId` and orders by the event's per-shadow `revision`. In current v2, the
`(hi, lo)` pair is an opaque T10 state hash, not a raster image, so the dashboard
shows it as commitment history rather than fake BW pixels.

When the active viewer can decrypt slot plaintext and the real palette RGB is
available from a reveal event or the localhost fixture metadata, the dashboard
also renders a viewer-local feature composite and a derived 16x16 BW preview.
Those previews are local reconstructions, not the on-chain T10 hash.


## Local minter fixture gallery

When `dashboard/local.json` is present, the dashboard renders the configured full 48x48 face images used for local mint testing before any mint function call is made. This is a visibility/debugging feature only; the actual face-discriminator and mint proofs are generated in the committed fixture and exercised by the Forge mint script during the localhost run.

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
| `transferShadow` | n/a | n/a | disabled for bounded shadows |
| `transferFeature` | yes | yes, `FeatureTransferred.newC1X/newC1Y` | yes |
| incremental reveal | plaintext public | not needed | public |

For historical deployments that predate this cutover, the dashboard still labels hidden slots as `ciphertext present, c1 missing from chain events`. That is a deployed-protocol data-availability limitation, not a dashboard bug.

## Subgraph decision

No subgraph is required for the present live testnet volume. The dashboard chunks `eth_getLogs` by block range and caches user settings in `localStorage`. If event volume or public-RPC range limits become a problem, the same event schema can be moved behind a subgraph or a small indexer without changing the browser decryption boundary.


The localhost atomic mint fixture now uses the canonical 23 named palettes from `tools/landmark/palette_quantizer.py`. The dashboard labels each rendered feature by the exact named palette; any non-matching revealed palette is flagged as non-canonical.