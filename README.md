> **v2 refactor in progress.** The `staging` branch ships a hard-fork v2
> design where pose, dimensions, scale, rotation, and pixel content all
> become **owner-private** (in-c2 plaintext as 4-bit palette indices), and
> every state-changing operation **atomically refreshes** the public T10
> hash. See [`docs/V2_STATUS.md`](docs/V2_STATUS.md) for the as-built v2
> surface and the working note in `STAGING_REFACTOR/` for the full design.
> The text below describes the **v1** architecture currently deployed on
> Base Sepolia.

---

<p align="center"><img src="docs/img/a_var_blush.png" alt="a_var_blush" width="480"></p>

# Moist Cryptography, The Protocol

Selectively-revealable face-bound NFTs.

Deployed on Base L2 with a cross-chain mirror to Ethereum Sepolia. 

A 48×48 RGB image is encrypted under the owner's key and
bound, via a zero-knowledge proof, to eight landmark commitments. Owners can
re-pose, eject (extract), insert (assemble), transfer, and ultimately *solve*
the shadow — revealing its plaintext, freezing its dynamic operations, and
optionally bridging it to L1 mainnet.

```
   ┌──────────────── shadow ────────────────┐
   │  origPose[8]   immutable               │   ← the face's eight true landmark
   │  manifest[16]  mutable, public         │     positions; recorded forever
   │  c2 (ECIES)    encrypted plaintext     │
   │  solved        boolean reveal flag     │
   └────────────────────────────────────────┘
       mutateSlot     pose-only, ~50k gas
       extractSlot    landmark → standalone FeatureNFT, ~4.9M gas
       insertFeature  bind a FeatureNFT into an EMPTY slot
       removeFeature  unbind without burning
       transferShadow ECIES re-encryption to a new owner, ~8.4M gas
       solve          reveal + freeze, ~4.4M gas
       setShadowT10   refresh the public 16x16 grayscale silhouette, ~3.6M gas
       bridgeShadow   L2 lock → L1 mirror via OP messenger, ~720k gas
```

## What's in this repo

| Path | Contents |
|------|----------|
| `contracts/`   | Solidity sources (~12 contracts incl. T10 verifier), Forge tests (111 unit tests), deploy scripts, pre-built proof fixtures |
| `circuits/`    | Seven Noir circuits — `face_disc` (mint gate), `landmark_regions` (mint), `transfer_shadow`, `extract_slot`, `transfer_feature`, `solve_shadow`, `shadow_t10` — plus helpers |
| `tools/`       | Python harness: pixel validator, fixture builders, end-to-end runners (Anvil + Sepolia + cross-chain bridge), keypair generator, vendored landmark CNN + palette quantizer |
| `examples/`    | Canonical test face (`alice0.png`), 45-image curated synthetic test corpus (`faces/synthetic/`), rendered demo strips (`demo_t10_*.png`), verification manifest |
| `lib/`         | Two upstream submodules: `forge-std@v1.15.0`, `openzeppelin-contracts@v5.4.0` (see [`lib/VERSIONS.md`](lib/VERSIONS.md)) |
| `docs/`        | Architecture, circuit specs, bridge design, T10 public shadow, deployment + security notes |

Total: ~12 contracts, ~1.9k lines Solidity, ~1.2k lines Noir, ~2.5k lines Python.

## Quick start

```sh
# Clone with submodules (or run `git submodule update --init --recursive` after a plain clone)
git clone --recurse-submodules <url> moist_cryptography
cd moist_cryptography

# 1. Solidity — 111/111 unit tests
cd contracts
forge test

# 2. Cryptographic round-trip — pixel byte-equality vs Python simulation
cd ../tools
python3 -m pip install -r requirements.txt
python3 validate_pixels.py
```

The first verifies every entry point of every contract against pre-built proof
fixtures (no nargo / bb required). The second decrypts the on-chain ciphertext
fixtures with the recipient secret keys and asserts byte-by-byte equality with
a deterministic Python re-implementation of the mint pipeline; renders are
written to `runs/validation_renders/`.

## Real-network verification

Both end-to-end scenarios passed on Base Sepolia. Tx hashes for one canonical
run (38/38 checks) are recorded in [`examples/verification.md`](examples/verification.md).

To run your own:

```sh
cd tools
python3 gen_test_keys.py                      # mints fresh Grumpkin + secp256k1 keypairs
python3 sepolia_e2e.py --scenario transfer    # 34 checks: mint, mutate, extract, transferShadow
python3 sepolia_e2e.py --scenario solve       # 38 checks: + solve + transferFeature + post-solve
python3 run_bridge.py                         # L2 → L1 cross-chain bridge (lock-on-L2 leg)
```

Requires `PRIVATE_KEY` in a top-level `.env` and a funded Base Sepolia EOA
(deploys cost ~0.001 ETH per scenario).

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — the 16-slot manifest, the
  immutable-origin / mutable-manifest split, what's public vs encrypted
- [`docs/CIRCUITS.md`](docs/CIRCUITS.md) — what each of the seven proofs
  attests, public-input layouts, and how the proofs compose
- [`docs/T10.md`](docs/T10.md) — the public 16x16 grayscale shadow: how
  it's derived, refreshed, and bound to chain state
- [`docs/BRIDGE.md`](docs/BRIDGE.md) — L2 → L1 bridge design via OP-Stack
  CrossDomainMessenger, finality, round-trip path
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — step-by-step deploy + e2e on
  Base Sepolia + Ethereum Sepolia
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model, chainId binding,
  audit-fix status, known limitations

## License

[Apache-2.0](LICENSE).
