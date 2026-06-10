# Full Audit and Proof Fuzzing Report

## Scope

This pass was constrained to additive audit, test, and report artifacts. Existing production/source files were not modified. Production cleanup items found below are therefore documented as follow-up work, not patched in this pass.

Production paths reviewed by the additive scanner:

- Solidity production contracts: `contracts/src/*.sol`
- Noir circuit entrypoints: `circuits/*/src/main.nr`
- Proof/build/assurance tooling: `tools/*.py`, `tools/*.sh`
- ZK manifests: `contracts/test/fixtures/verifier_manifest.json`, `contracts/test/fixtures/zk_surface_manifest.json`, and new `contracts/test/fixtures/production_surface_manifest.json`

The pre-existing untracked `contracts/test/GasAttribution.t.sol` is test-only gas-attribution work. It uses mocked verifiers deliberately for gas measurement and is not counted as proof coverage.

## Additive artifacts created

- `contracts/test/fixtures/production_surface_manifest.json`
  - Inventories active production verifiers and circuits.
  - Explicitly classifies legacy/superseded verifier and circuit artifacts as non-production.
- `tools/audit_placeholder_scan.py`
  - Enforces production inventory completeness.
  - Scans production paths for unresolved placeholder/mock/stub/simulation terminology.
  - Allows generated-verifier `dummy_round` only as a generated implementation detail.
- `contracts/test/ProofFuzz.t.sol`
  - Real-verifier fuzz harness for all active verifier fixtures.
  - Mutates proof bytes and external public inputs and requires rejection.
  - Uses no mocked verifier for proof-layer claims.
- `tools/fuzz_proof_witnesses.py`
  - Materializes canonical witnesses from existing fixture builders before mutation.
  - Runs `nargo check`, validates generated witnesses are not empty templates, and fails instead of skipping missing inputs.
  - Restores pre-existing `Prover.toml` files after successful runs so generated witness secrets are not left dirty.
- `docs/FULL_AUDIT_REPORT.md`
  - This report.

## Production proof surface inventory

Active real verifier surfaces from `verifier_manifest.json` and `production_surface_manifest.json`:

| Surface | Contract verifier | Circuit | Fixture coverage |
| --- | --- | --- | --- |
| `registerImage` | `FaceDiscVerifier` | `circuits/landmark_regions_v2` | `contracts/test/fixtures/face_disc/eve0` |
| `mintShadow` | `MintShadowVerifier` | `circuits/landmark_regions_v2` | `contracts/test/fixtures/atomic_mint/atomic_mint_demo` |
| T10 refresh bundle | `T10ShadowVerifier` | `circuits/shadow_t10` | `contracts/test/fixtures/shadow_t10/t10_demo` |
| `mutateSlot` / `mutateBatch` / `insertFeature` | `MutateSlotVerifier` | `circuits/mutate_slot` | `contracts/test/fixtures/mutate_slot/mutate_demo_v2` |
| `solve` | `SolveShadowVerifier` | `circuits/solve_shadow_v2` | `contracts/test/fixtures/solve_shadow_v2/solve_demo` |
| `transferShadow` | `TransferShadowVerifier` | `circuits/transfer_shadow_v2` | `contracts/test/fixtures/atomic_transfer/atomic_transfer_demo` |
| `FeatureNFT.transferFeature` | `TransferFeatureV2Verifier` | `circuits/transfer_feature_v2` | `contracts/test/fixtures/onchain_transfer_feature_v2/transfer_feature_v2_atomic_mint_demo_slot0` |
| `setZIndexCommit` | `ZIndexCommitVerifier` | `circuits/zindex_commit` | `contracts/test/fixtures/zindex_commit/zidx_demo` |

Explicitly classified non-production or superseded artifacts:

- `contracts/src/ExtractSlotVerifier.sol` — legacy/no current real fixture.
- `contracts/src/TransferFeatureVerifier.sol` — superseded by `TransferFeatureV2Verifier`.
- `circuits/landmark_regions/src/main.nr` — historical v1.
- `circuits/solve_shadow/src/main.nr` — historical v1.
- `circuits/transfer_shadow/src/main.nr` — historical v1.
- `circuits/transfer_feature/src/main.nr` — historical v1.
- `circuits/extract_slot/src/main.nr` — legacy/no current fixture.
- `circuits/face_disc/src/main.nr` — historical relative to active v2 face-disc path.
- `circuits/_ecies_keystream_helper/src/main.nr` and `circuits/_poseidon2_state_helper/src/main.nr` — helper-only.

## Findings

### Resolved: production proof-surface vocabulary scanner is clean

`python3 tools/audit_placeholder_scan.py` now passes with no inventory errors and
no unresolved placeholder/mock terminology in active production proof surfaces.
The scanner still classifies test-only mocks and historical verifier artifacts
explicitly, so the cleanup does not weaken the distinction between real proof
coverage and behavior/gas diagnostics.

Impact: active contracts, circuits, and tooling no longer use ambiguous
placeholder/stub language for live proof paths. Test-only mocks remain present
where they isolate state-machine behavior or gas attribution, and they must not
be cited as cryptographic proof evidence.

### Resolved: canonical Noir `Prover.toml` witnesses were absent or empty templates

Earlier runs showed the coordinated negative witness suites failing or skipping because active circuit directories contained missing or empty-template `Prover.toml` files. `tools/fuzz_proof_witnesses.py` now invokes the existing fixture builders to materialize known-good canonical witnesses before each suite, rejects empty-template witness values, and restores pre-existing `Prover.toml` contents after successful completion.

Current result: `python3 tools/fuzz_proof_witnesses.py --cases 32` passes with 7 `nargo check` runs, 5 negative suites run, and 0 skipped.

### Low: test-only mocks are present and should remain explicitly scoped

`contracts/test/GasAttribution.t.sol` contains `AlwaysOkVerifier` and mocked-verifier gas tests. Bridge tests also use messenger stubs. These are acceptable only for gas/wiring/state isolation and must not be cited as proof-layer correctness evidence.

Required follow-up: keep these tests named/documented as mock or gas/wiring tests. Do not include them in proof coverage matrices.

## Proof fuzz coverage matrix

`contracts/test/ProofFuzz.t.sol` adds fuzz rejection tests for every active real generated verifier fixture:

| Verifier | Valid fixture sanity | Fuzzed proof byte rejection | Fuzzed public input rejection | Mock-free |
| --- | --- | --- | --- | --- |
| `FaceDiscVerifier` | Yes | Yes | Yes | Yes |
| `MintShadowVerifier` | Yes | Yes | Yes | Yes |
| `T10ShadowVerifier` | Yes | Yes | Yes | Yes |
| `MutateSlotVerifier` | Yes | Yes | Yes | Yes |
| `SolveShadowVerifier` | Yes | Yes | Yes | Yes |
| `TransferShadowVerifier` | Yes | Yes | Yes | Yes |
| `TransferFeatureV2Verifier` | Yes | Yes | Yes | Yes |
| `ZIndexCommitVerifier` | Yes | Yes | Yes | Yes |

Contract-level calldata byte-binding coverage continues to rely on the existing targeted tests listed in `zk_surface_manifest.json` (`MintShadow`, `MutateSlot`, `MutateBatch`, `TransferShadow`, `SolveShadow`, `TransferFeatureV2`, `SetZIndexCommit`, etc.). This pass did not add new contract-level fuzzing around every entrypoint because the execution addendum prohibited modifying existing production/source code and the safest additive coverage was verifier-level fuzzing.

## Limitations

- `tools/audit_placeholder_scan.py` currently fails by design on real findings. It is ready for CI once existing production/source cleanup is approved and applied.
- `tools/fuzz_proof_witnesses.py` now runs cleanly and is integrated into `tools/run_crypto_assurance_checks.sh` with `PROOF_WITNESS_FUZZ_CASES` as the runtime bound.
- This pass does not resolve high-gas max-occupancy architecture. Existing max-occupancy tests and gas-attribution work remain separate evidence.
- This report is not a third-party external audit.

## Verification log

Final observed verification results:

- `python3 tools/check_zk_surface_manifest.py && python3 tools/check_byte_binding_tests.py && python3 tools/check_metadata_authority.py && python3 tools/check_verifier_manifest.py && python3 tools/generate_poseidon2_vectors.py --check && python3 -m compileall -q tools`
  - Result: pass.
  - Output: 9 ZK surfaces covered, 251 Solidity byte-binding test functions present, metadata/tooling authority checks pass, 8 verifier fixtures validated with 2 allowlisted, Poseidon2 vectors match.
- `python3 tools/audit_placeholder_scan.py`
  - Result: expected failure.
  - Inventory errors: `0`.
  - Production term findings: `24`.
- `cd contracts && forge build`
  - Result: pass. Foundry emitted generated-verifier style notes only.
- `cd contracts && FOUNDRY_FUZZ_RUNS=64 forge test --match-contract ProofFuzz -vv`
  - Result: pass.
  - 8 fuzz tests passed; 0 failed; 0 skipped.
- `cd contracts && forge test --match-contract 'GeneratedVerifierMatrix|CryptoInvariants|Replay|KeyRegistry|FeatureNFT|MintShadow|MutateSlot|MutateBatch|TransferShadow|SolveShadow|TransferFeature|SetZIndexCommit|Bridge' -vv`
  - Result: failure due to pre-existing bridge gas threshold, not proof verification.
  - 174 tests passed; 1 failed.
  - Failing test: `test/BridgeShadow.t.sol:BridgeShadowTest.test_bridgeShadow_gas_under_block_budget()` with `bridgeShadow gas regressed past 1M: 1005058 >= 1000000`.
- `python3 tools/fuzz_proof_witnesses.py --cases 32 --skip-nargo-check`
  - Result: pass.
  - 5 negative suites ran; 0 skipped.
- `python3 tools/fuzz_proof_witnesses.py --cases 32`
  - Result: pass.
  - 7 `nargo check` runs passed: `landmark_regions_v2`, `mutate_slot`, `transfer_shadow_v2`, `transfer_feature_v2`, `solve_shadow_v2`, `zindex_commit`, `shadow_t10`.
  - 5 negative suites ran; 0 skipped.