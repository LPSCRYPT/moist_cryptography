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

## System functionality

Where the proofs come from, where they get verified, and how a solved
shadow eventually mints a mirror NFT on L1.

```
  ┌────────────────────────────────────────────────────────────────────────┐
  │ EOAs    deployer 0x1b43AFe4···   ·   PK2 0xFD90Bd22···                 │
  └────────────────────────────────────────────────────────────────────────┘
       │ A. signs txs carrying ZK proofs
       ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │ Off-chain prover toolchain                                             │
  │   Python builders (build_*_onchain.py) + slot_state.py                 │
  │     → Prover.toml                                                      │
  │   Noir circuits (nargo) → bb UltraHonk(keccak), verifier_target=evm    │
  │     → proof.bin + public_inputs.bin                                    │
  │                                                                        │
  │   face_disc · landmark_regions_v2 · mutate_slot / mutate_batch         │
  │   extract_slot · insert_feature · transfer_shadow / transfer_feature_v2│
  │   zindex_commit · shadow_t10 · solve_shadow_v2                         │
  └────────────────────────────────────────────────────────────────────────┘
       │ B. forge script broadcast (proof bytes + caller PI fields)
       ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │ Base Sepolia (L2) — pipeline #5                                        │
  │                                                                        │
  │   KeyRegistry           ShadowToken            FeatureNFT              │
  │    pkOf(EOA)      ───►   shadows[id]     ───►   ERC721 carriers        │
  │    Grumpkin owner_pk     manifest[16]           paletteCommit          │
  │    binds proof PI        isSolved               liveStateHash          │
  │                          zCommit, T10                                  │
  │                                │                    │                  │
  │                                ▼                    ▼                  │
  │                       8 Honk verifiers        Yul Poseidon2            │
  │                       Mint, Mutate(+Batch),    sponge_16               │
  │                       T10, ZIdx, Solve,        sponge_palette_salt(17) │
  │                       TransferShadow,          (palette opens at solve │
  │                       FaceDisc,                 via on-chain Poseidon2;│
  │                       TransferFeatureV2          no ZK proof needed)   │
  │                                │                                       │
  │                                ▼                                       │
  │                       ShadowBridgeL2 #5b                               │
  │                        0x49A8d60114C4869D2f0422c8e5b1f9442f5e4529      │
  │                        bridgeShadow(id, revealedPi):                   │
  │                          custody-lock ERC721 +                         │
  │                          L2 CDM sendMessage(L1Mirror, payload)         │
  │                                                                        │
  │   D. solve emits 8 × FeaturePaletteRevealed (palette + salt)           │
  │               + 8 × FeatureSlotRevealed   (39-field plaintext)         │
  └────────────────────────────────────────────────────────────────────────┘
       │ C. OP-Stack L2→L1 message
       │   output proposal (~1 h)
       │   7-day challenge window
       │   proveWithdrawal + finalizeWithdrawal
       ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │ Eth Sepolia (L1)                                                       │
  │                                                                        │
  │   ShadowMirrorL1   0xe9B8b1DddaEC95C165B0c4aE55Ea13FeAAC79042          │
  │     mintFromBridge(payload):                                           │
  │       ERC721 mirror NFT to recipient                                   │
  │       + per-slot lineage (typeIdx, originFaceId, paletteCommit)        │
  │       + revealedPi blob (full solve PI; off-chain renders read this)   │
  └────────────────────────────────────────────────────────────────────────┘

  Off-chain consumers — anyone, no key required post-solve:

  ┌────────────────────────────────────────────────────────────────────────┐
  │ Visualizer / indexer     tools/render_onchain_shadow.py                │
  │   D. events → palette[16] + plaintext[39] per occupied slot            │
  │   → 8 sprite PNGs + 48×48 composite     ──► E. EOA reads sprites       │
  │                                                                        │
  │   pre-solve:  needs owner --sk to decrypt ECIES envelope               │
  │   post-solve: events alone are sufficient                              │
  └────────────────────────────────────────────────────────────────────────┘
```

**Flow:**
  - **A.** Owner builds a fixture (witness + proof) off-chain. Each
    builder takes a slot-spec describing the shadow's per-slot state
    (`mint`, `post-mutate-single/batch`, `post-insert`).
  - **B.** A `forge script` broadcasts a single tx carrying the proof
    bytes + caller-supplied PI fields (lsh array, palette + salt at
    solve time, etc.).
  - **C.** Solved shadows can `bridgeShadow` to L2 bridge #5b, which
    custody-locks the ERC721 and fires an OP-Stack L2→L1 message.
    After the 7-day challenge window, anyone can finalize on L1 to
    mint the mirror NFT.
  - **D.** Solve emits 8 `FeaturePaletteRevealed` + 8
    `FeatureSlotRevealed` events in one tx. Together they carry the
    full 16-color palette + 39-field plaintext per slot — enough for
    an indexer to render the canonical 48×48 sprite with no owner
    cooperation.
  - **E.** Pre-solve, the owner uses their Grumpkin sk to decrypt the
    chain-stored ECIES envelope; post-solve, the events are sufficient.

## What's in this repo

| Path | Contents |
|------|----------|
| `contracts/`   | Solidity sources (~22 contracts: ShadowToken, FeatureNFT, KeyRegistry, ShadowBridgeL2, ShadowMirrorL1, 2 Yul Poseidon2 sponges, 8 Honk verifiers), Forge tests (176 unit tests), deploy scripts, pre-built proof fixtures |
| `circuits/`    | Noir circuits compiled with bb UltraHonk(keccak): `face_disc` (mint gate), `landmark_regions_v2` (mint), `mutate_slot`, `mutate_batch`, `extract_slot`, `insert_feature`, `transfer_shadow`, `transfer_feature_v2`, `zindex_commit`, `shadow_t10`, `solve_shadow_v2` |
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

# 1. Solidity — 176/176 unit tests
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
