> **v2 status.** The v1 tooling listed below is preserved as historical
> reference; each v1 script carries an explicit `**STALE**` banner at
> the top. The active v2 toolchain is:
>
> | Script | Role |
> |---|---|
> | `v2_circuit_helpers.py` | Canonical Python primitives (sponge_39/16/6/18, keystream_39, ECIES, plaintext encode/decode) |
> | `build_mutate_slot_fixture.py` | mutate_slot proof + verifier |
> | `build_zindex_commit_fixture.py` | zindex_commit proof + verifier |
> | `build_shadow_t10_fixture.py` | shadow_t10 v2 proof + verifier |
> | `build_atomic_mutate_fixture.py` | linked (mutate, T10) pair |
> | `build_atomic_extract_fixture.py` | linked (T10 only — extract is proofless) |
> | `build_atomic_zindex_fixture.py` | linked (zindex, T10) pair |
>
> Pending: visualizer rewrite, mint/transfer/solve fixture builders.
> See [`../docs/V2_STATUS.md`](../docs/V2_STATUS.md) and
> `STAGING_REFACTOR/PROGRESS.md`.

---

# Tools

Python harness: pixel validator, fixture builders, Sepolia / Anvil / bridge
runners, keypair generator, and vendored landmark + palette dependencies.

```
tools/
├── README.md                        (this file)
├── requirements.txt
├── chain_ids.py                     # central shadowId / featureNftId derivation (chain-aware)
├── secret_inbox.py                  # ECIES, Poseidon2 (via helper circuits), Grumpkin curve ops
├── relay_geom.py                    # canonical pack/unpack of region bytes -> Field arrays
├── mint_pipeline.py                 # CNN landmarks + region recolor + 249-Field pack
├── mint_decrypt.py                  # decrypt a 249-Field shadow ciphertext
├── render_shadow.py                 # render a recovered 48x48 face to PNG
├── t10.py                           # Python reference for the T10 composite + quantize
├── validate_pixels.py               # the headline byte-equality validator
├── gen_test_keys.py                 # mint fresh Grumpkin + secp256k1 test keypairs
├── build_landmark_mint_fixture.py   # mint proof + fixture
├── build_transfer_shadow_fixture.py # transfer_shadow proof + fixture
├── build_extract_slot_fixture.py    # extract_slot proof + fixture
├── build_transfer_feature_fixture.py# transfer_feature proof + fixture
├── build_solve_fixture.py           # solve proof + fixture
├── build_shadow_t10_fixture.py      # T10 fixture builder (mint state + 7 mutation steps)
├── run_phase2.py                    # Anvil end-to-end driver (Phase 2 secret-passing)
├── sepolia_e2e.py                   # Base Sepolia end-to-end (--scenario transfer|solve)
├── anvil_t10_e2e.py                 # T10 e2e: mint + 7 mutate + 8 setShadowT10 + chain-derived strip
├── demo_ten_turns.py                # 10-step PROGRAMME demo (composite preview)
├── run_bridge.py                    # cross-chain bridge L2 -> L1
├── test_noise_mint.py               # robustness check: mint pipeline on random noise
└── landmark/                        # vendored CNN landmark detector + palette quantizer
    ├── fixed_point_infer.py
    ├── v5_geometry.py
    ├── palette_quantizer.py
    └── weights/landmark_v3_5point.json
```

## Install

```sh
pip3 install -r requirements.txt
```

That's all that's required for the headline checks. For fixture rebuilds
or anything that produces a new SNARK proof you also need:

- [Nargo](https://github.com/noir-lang/noir) 1.0.0-beta.19 — `nargo execute`
  / `nargo compile`
- [bb](https://github.com/AztecProtocol/aztec-packages) 5.0.0-nightly.20260419 — `bb prove`
  / `bb write_solidity_verifier`

The repo-standard local install paths are `$HOME/.nargo/bin/nargo` and
`$HOME/.bb/bb`. If `which nargo` or `which bb` fails, do not conclude the
toolchain is unavailable until checking those paths and prepending them:

```sh
export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"
which nargo && nargo --version
which bb && bb --version
ls -la "$HOME/.nargo/bin/nargo" "$HOME/.bb/bb"
```

Fixture builders resolve both tools from `PATH`, falling back to
`~/.nargo/bin/nargo` and `~/.bb/bb`. Override with `NARGO_PATH` /
`BB_PATH` env vars when running in a different sandbox or CI image.

## Headline check: pixel byte-equality

```sh
python3 validate_pixels.py
```

Runs the deterministic Python pipeline over the alice0 fixture and asserts
byte-equality with the chain-bound c2 ciphertexts at every stage:

1. Mint: `compute_face_state` -> 8 recolored region byte-arrays -> packed
   249 Fields -> ECIES under alice's pk -> chain c2. Decrypt with alice's
   sk and compare.
2. transferShadow: bob decrypts the new c2 with his sk; should reproduce
   alice's plaintext byte-for-byte.
3. extractSlot: carol's feature_c2 decrypts to the canonical
   `packed_padded[slot=3]`.
4. transferFeature: dave decrypts; should match carol's feature payload.

Renders are written to `runs/validation_renders/` for visual inspection.

## End-to-end runners

| Script | What it does | Default RPC |
|--------|--------------|-------------|
| `run_phase2.py`            | Anvil baseline (mint -> mutate -> transferShadow) | `http://localhost:8545` |
| `sepolia_e2e.py`           | Base Sepolia 34 (transfer scenario) or 38 (solve scenario) checks | `https://sepolia.base.org` |
| `run_bridge.py`            | Deploy + run L2 -> L1 bridge leg                   | both Base + Eth Sepolia |
| `anvil_t10_e2e.py`         | Deploy + mint + 7 mutate + 8 setShadowT10, build chain-derived strip | configurable via `--rpc` |

All four write per-run manifests + renders to `runs/<kind>_<ts>/`.
Sepolia + bridge require `PRIVATE_KEY` in a top-level `.env`.

## Test keys

`gen_test_keys.py` writes `tools/test_keys.json` with three random
keypairs (bob, carol, dave). Each entry has both a Grumpkin sk (for
ECIES decryption) and a secp256k1 sk (for EVM tx signing). The
addresses are fresh by construction — never broadcast under any
EIP-7702 authorization. The file is gitignored.

> ⚠️ **The keys in `test_keys.json` are for testing only. They are derived
> from `secrets.token_bytes` at generation time but live unencrypted on
> your filesystem. Never use them on mainnet or with non-test ETH.**

## Vendored deps (`landmark/`)

The mint pipeline uses three modules + a CNN weights file that originally
lived in a sibling repo. They're vendored here so the repo is
self-contained:

- `fixed_point_infer.py` — bit-exact integer-fixed-point landmark
  detector. Mirrors the Noir circuit's arithmetic exactly so the proof
  and the Python sim agree byte-for-byte.
- `v5_geometry.py` — proportional region boxes derived from the 5-point
  landmark output. Pure integer arithmetic; deterministic.
- `palette_quantizer.py` — 23 fixed 10-color palettes + the rarity-frozen
  rank order used by `color` PI.
- `weights/landmark_v3_5point.json` — CNN weights (~40KB).
