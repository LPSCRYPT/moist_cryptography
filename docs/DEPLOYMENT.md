> **v1 historical document.** Lists deployment addresses and procedures
> for the v1 contract set on Base Sepolia. The `staging` branch v2
> contracts have not yet been deployed (Phase 11 pending). See
> [`V2_STATUS.md`](V2_STATUS.md) for the v2 surface.

---

# Deployment

Step-by-step on Base Sepolia (L2) and Ethereum Sepolia (L1).

## Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation) (forge, cast, anvil)
- Python 3.11+
- An EOA funded with Base Sepolia ETH (and Eth Sepolia ETH for the bridge)
- A `.env` file at the repo root containing:

  ```
  PRIVATE_KEY=0x...
  ```

For fixture rebuilds (optional — pre-built fixtures ship with the repo):

- [Nargo](https://github.com/noir-lang/noir) 1.0.0-beta.19
- [bb](https://github.com/AztecProtocol/aztec-packages) 1.4.0

For mint-side proof generation against an arbitrary face you also need
sufficient compute (the `landmark_regions` circuit takes ~90 s of `nargo
execute` on M1, longer for `bb prove`); the harness assumes a remote prover
host by default — see `tools/build_landmark_mint_fixture.py`.

## Local (Anvil)

```sh
cd contracts

# Start anvil in another terminal: anvil --port 8545

# Deploy + run a baseline e2e (mint -> mutate -> transferShadow)
cd ../tools
python3 run_phase2.py
```

Outputs to `runs/anvil_phase2/`. Asserts:

- 10 contracts deploy (the 9 prior + `FaceDiscVerifier`)
- mint succeeds (~11.6M gas; Anvil run at `runs/anvil_disc_1777212932/`
  recorded mintShadow at 11,584,099 gas)
- mutate succeeds (~44k gas)
- transferShadow succeeds (~7.2M gas)
- on-chain owner rotates
- noise images are rejected by `face_disc` at proof generation
  (`tools/test_noise_mint.py`)

## Base Sepolia

The Python harness in `tools/sepolia_e2e.py` does deploy + scenarioed e2e
in one shot.

### Scenario A — `transfer`

`mint -> mutate × 7 -> extract_slot -> transferShadow alice -> bob`

```sh
cd tools
python3 gen_test_keys.py            # mints fresh bob/carol/dave keypairs
python3 sepolia_e2e.py --scenario transfer
```

34 checks. Outputs to `runs/sepolia_<ts>/manifest.json` (gas, tx hashes,
addresses, all per-check pass/fail).

### Scenario B — `solve`

`mint -> mutate × 7 -> extract_slot -> transferFeature -> solve -> transferFrom`

```sh
python3 sepolia_e2e.py --scenario solve
```

38 checks. Exercises every verifier: mint, transfer_shadow, extract_slot,
transfer_feature, solve. Includes a post-solve `transferFrom alice -> bob`
to demonstrate the gate-lift, and a `re-solve` revert to confirm the
`AlreadySolved` guard.

### Re-using a deploy

```sh
python3 sepolia_e2e.py --scenario solve \
        --skip-deploy \
        --out-dir runs/sepolia_<ts>
```

Reads `addresses.json` from the run directory and skips the deploy phase.

## T10 public-shadow

Independent of the secret-passing scenarios above. Deploys + walks the
8-step PROGRAMME (mint + 7 mutations) and refreshes the on-chain T10
silhouette after each. Same harness drives Anvil and Base Sepolia.

```sh
cd tools

# Anvil (foreground anvil in another terminal: anvil --port 8545)
python3 anvil_t10_e2e.py

# Base Sepolia
python3 anvil_t10_e2e.py \
    --rpc https://sepolia.base.org \
    --chain-id 84532 \
    --private-key "$(grep '^PRIVATE_KEY=' ../.env | cut -d= -f2)" \
    --fixture-root ../contracts/test/fixtures/shadow_t10_sepolia \
    --label sepolia
```

Outputs to `runs/<label>_t10_<ts>/`:

- 8 `step_NN_public.png` (decoded from on-chain `shadowT10[hi, lo]`)
- 8 `step_NN_secret.png` (owner-decrypted face under chain poses)
- 1 `<label>_t10_strip.png` (3072x808 montage)
- per-tx receipts + `addresses.json`

Reproduces byte-equality between the chain T10 grid and the Python
reference at every step. See [`T10.md`](T10.md) for the algorithm and
circuit details.

## Cross-chain bridge

Requires a successful `solve` scenario (so the L2 has a solved shadow you
own) and ETH on Eth Sepolia.

```sh
cd tools
python3 run_bridge.py
```

Steps:

1. **Connectivity check** (deployer balance on both chains)
2. **Deploy `ShadowMirrorL1`** on Eth Sepolia
3. **Deploy `ShadowBridgeL2`** on Base Sepolia (constructor takes the
   existing `ShadowToken` address)
4. **Wire** `bridge.setL1Mirror` + `mirror.setL2Bridge`
5. **Fund** the L2 shadow owner if it's not the deployer (small amount
   for one bridge tx)
6. **Approve** the bridge for the shadowId, then call `bridgeShadow`
7. **Verify** L2 lock state (`bridged[sid] == OWNED_ON_L1`,
   `ownerOf(sid) == bridge`)

Outputs to `runs/bridge_<ts>/manifest.json`. The L2 leg completes in
under a minute. The L1 mint requires waiting out the OP withdrawal
challenge period (~7 days), then calling
`OptimismPortal.proveWithdrawalTransaction` and
`OptimismPortal.finalizeWithdrawalTransaction`.

## Rebuilding fixtures

The pre-built proof fixtures in `contracts/test/fixtures/` are signed by
specific test keys. To rebuild them (e.g. after changing the chainId
binding to a new target chain):

```sh
cd tools
python3 gen_test_keys.py
BOB=$(python3 -c "import json; print(json.load(open('test_keys.json'))['roles']['bob']['grumpkin_sk'])")
CAROL=$(python3 -c "import json; print(json.load(open('test_keys.json'))['roles']['carol']['grumpkin_sk'])")
DAVE=$(python3 -c "import json; print(json.load(open('test_keys.json'))['roles']['dave']['grumpkin_sk'])")

# 31337 = anvil/forge default; 84532 = Base Sepolia
CHAIN=31337
python3 build_transfer_shadow_fixture.py  --chain-id $CHAIN --recipient-sk $BOB
python3 build_extract_slot_fixture.py     --chain-id $CHAIN --recipient-sk $CAROL --slot 3
python3 build_transfer_feature_fixture.py --chain-id $CHAIN --recipient-sk $DAVE
python3 build_solve_fixture.py
```

Each builder writes:
- `contracts/test/fixtures/<flow>/<seed>/proof` (binary)
- `contracts/test/fixtures/<flow>/<seed>/public_inputs` (binary)
- `contracts/test/fixtures/<flow>/<seed>/fixture.json` (JSON metadata)
- `contracts/src/<Flow>Verifier.sol` (regenerated from the rebuilt vk)

Afterwards `forge test` regression-checks against the new fixtures.

## Verifier addresses on Base Sepolia (current `face_disc` deploy)

Deployed 2026-04-26 from this machine; broadcast log under
`contracts/broadcast/DeployShadowPipeline.s.sol/84532/run-1777214026997.json`.
Run sheet at `runs/sepolia_disc_1777213944/`. The deploy includes the new
`FaceDiscVerifier`, regenerated `MintShadowVerifier` (18-field PI), and
`ShadowToken` with the disc verifier wired in.

| Contract | Address |
|----------|---------|
| Poseidon2YulSponge      | `0x5490E40e319f482a7F9241dDBaF3e1F61374F7AA` |
| KeyRegistry             | `0x7D0eC7b232d95D7bd46C21dB68268db50e177596` |
| ShadowToken             | `0x0887012dC44009085BC3a21Dc23aD0829F055fFc` |
| FeatureNFT              | `0xD14B21380a8B4b2990f92b39609Caa08CdAC3419` |
| FaceDiscVerifier        | `0x498650e3fC853366E48c7F1c1D48420B5653D169` |
| MintShadowVerifier      | `0xa71ab2BfB5a3A0b6475B3E9CDe28DE2a94C83a0d` |
| TransferShadowVerifier  | `0x0301EB7283FAf11F9A7710f6731E087B79e859E7` |
| ExtractSlotVerifier     | `0x3E9ad25D44343BA976Ca5544A256A3bBCEC1a9F3` |
| TransferFeatureVerifier | `0x6C3B0a156e368c7FF3e903c743c41fa559c074C2` |
| SolveShadowVerifier     | `0x450D626F76acdf42C3E5CF5d8A7fDC2E1ebbaC83` |
| T10ShadowVerifier       | `0x5573955396aB4968AfF0D0312c06177064886e0f` |

Canonical alice0 mint on Base Sepolia (chain id 84532):

| Field | Value |
|-------|-------|
| Tx hash | `0x9d3c178ebcc0966621e84a7489ae26cfc70aee3163130fe6ed17961710661915` |
| Block | 40,722,872 |
| Status | 1 (success) |
| Gas used | 14,548,201 (under 16,777,216 = 2^24 per-tx cap) |
| shadowId | `0x1039d4890975c7b307ec39da0d6e3480182ab4583cf16481d7db1fa5d385a601` |
| faceOriginId | `0x1963ff7e82d1cc71f46b7e2e6af3db8910dccc3a9759282bfff00670eefbe57c` |
| Both proofs | mint (landmark+envelope, 18 PI) AND face_disc (1 PI) verified atomically; chain asserted `mint.PI[17] == disc.PI[0]` (image_commit binding) |

Pre-`face_disc` Sepolia addresses (5-verifier topology) are preserved
in `examples/verification.md` for tx-history archaeology only.
