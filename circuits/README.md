# Circuits

Six Noir 1.0.0-beta.19 circuits + two helper circuits used by the Python
ECIES harness.

| Directory | What it proves |
|-----------|----------------|
| `landmark_regions/`         | mint: 8 region commitments + ECIES envelope |
| `transfer_shadow/`          | re-encrypt 249-Field shadow plaintext to new owner |
| `extract_slot/`             | extract slot's bytes into a 42-Field FeatureNFT (byte-equality enforced) |
| `transfer_feature/`         | re-encrypt 42-Field feature payload to new owner |
| `solve_shadow/`             | re-attest mint witness + reveal recolored bytes |
| `shadow_t10/`               | T10 public 16x16 grayscale silhouette (composite + quantize, sponge_18 protocol) |
| `_poseidon2_state_helper/`  | helper used by `tools/secret_inbox.py` to compute `Poseidon2(a, b)` deterministically |
| `_ecies_keystream_helper/`  | helper used by `tools/secret_inbox.py` to derive the ECIES keystream from a seed |

See [`../docs/CIRCUITS.md`](../docs/CIRCUITS.md) for what each proof
attests, the public-input layouts, and how the proofs compose.

## Building

Toolchain: [Nargo](https://github.com/noir-lang/noir) 1.0.0-beta.19 +
[bb](https://github.com/AztecProtocol/aztec-packages) 5.0.0-nightly.20260419.
Pinned paths and hashes are machine-checked by `../tools/check_toolchain.py`.

```sh
cd circuits/<name>
nargo compile

# Generate Solidity verifier (UltraHonk-Keccak):
bb write_solidity_verifier \
  -k target/<name>.json \
  -o ../../contracts/src/<Name>Verifier.sol \
  --verifier_target evm
```

Note: the four phase-2 circuits (`transfer_shadow`, `extract_slot`,
`transfer_feature`, `solve_shadow`) compile in under a second on M1 and
fit under EIP-170 with 234-239 bytes of headroom on the verifier. The
mint circuit (`landmark_regions`) is the heaviest — `nargo execute` takes
~90 s on M1 and `bb prove` requires significant memory. For routine
fixture generation point `tools/build_landmark_mint_fixture.py` at a
remote prover host (defaults baked in; modify `VAST_HOST` etc. for your
own).

## Helper circuits and `target/`

The `_poseidon2_state_helper` and `_ecies_keystream_helper` circuits exist
*only* to let the Python harness compute Poseidon2 hashes that match
in-circuit semantics bit-exactly. They are invoked from
`tools/secret_inbox.py` via `nargo execute` at fixture-build time.

`target/` is gitignored. Running `nargo compile` (or `nargo execute`)
populates it from the `src/` source. None of the runtime guarantees
depend on `target/` artifacts being present; if you only want to run the
contract tests + Python validator, you don't need nargo at all.
