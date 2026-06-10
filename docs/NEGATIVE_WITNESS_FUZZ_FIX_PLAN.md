# Negative Witness Fuzz Fix Plan

## Goal

Make this command pass without missing or malformed witness-input failures:

```sh
python3 tools/fuzz_proof_witnesses.py --cases 32
```

The negative witness suites must mutate known-good canonical circuit witnesses, not missing files or empty `Prover.toml` templates.

---

## Phase 1: Inventory current witness expectations

### 1. Map each negative suite to its required circuit inputs

Audit these scripts:

- `tools/test_mutation_no_rotation_semantics.py`
- `tools/test_m06_negative.py`
- `tools/test_h04_negative.py`
- `tools/test_m05_negative.py`
- `tools/test_noise_mint.py`

For each, record:

- circuit directory used
- expected `Prover.toml` path
- required field names
- whether it runs a baseline `nargo execute`
- tamper file name it writes
- whether it cleans up after success

Expected output: internal mapping like:

| Suite | Circuit(s) | Required canonical witness | Baseline required |
| --- | --- | --- | --- |
| `mutate_slot_single_class` | `mutate_slot` | `circuits/mutate_slot/Prover.toml` | yes |
| `ecies_well_formedness` | multiple v2 circuits | each circuit `Prover.toml` | yes |
| `mint_geometry` | `landmark_regions_v2` | `circuits/landmark_regions_v2/Prover.toml` | yes |
| `mint_noise` | `landmark_regions_v2` | `circuits/landmark_regions_v2/Prover.toml` | yes |
| `h05_metadata` | script-specific | script-specific | yes |

### 2. Identify existing builder scripts that can produce those witnesses

Inspect existing builders and determine which ones actually write valid `Prover.toml` files for the target circuit:

| Circuit | Candidate builder |
| --- | --- |
| `landmark_regions_v2` | `tools/build_atomic_mint_fixture.py`, `tools/build_landmark_mint_fixture.py` |
| `mutate_slot` | `tools/build_mutate_slot_fixture.py`, `tools/build_mutate_slot_onchain.py` |
| `transfer_shadow_v2` | `tools/build_transfer_shadow_v2_fixture.py`, `tools/build_atomic_transfer_fixture.py` |
| `transfer_feature_v2` | `tools/build_transfer_feature_v2_fixture.py` |
| `solve_shadow_v2` | `tools/build_solve_shadow_v2_fixture.py` |
| `zindex_commit` | `tools/build_zindex_commit_fixture.py` |
| `shadow_t10` | `tools/build_shadow_t10_fixture.py` |

Do not assume the name is enough. Verify each builder’s outputs.

Acceptance for Phase 1:

- Every negative suite has a known setup command or is explicitly marked needing a new fixture-generation path.
- No suite relies on a committed empty-template `Prover.toml`.

---

## Phase 2: Add witness materialization to `fuzz_proof_witnesses.py`

### 1. Replace tuple-based suite config with structured config

Change from:

```python
SUITES = [
    ("mutate_slot_single_class", [sys.executable, "tools/test_mutation_no_rotation_semantics.py"]),
]
```

to something like:

```python
SUITES = [
    {
        "name": "mutate_slot_single_class",
        "setup": [
            [sys.executable, "tools/build_mutate_slot_fixture.py"],
        ],
        "test": [sys.executable, "tools/test_mutation_no_rotation_semantics.py"],
        "required": [
            "circuits/mutate_slot/Prover.toml",
        ],
    },
]
```

Each suite should declare:

- `name`
- `setup` commands
- `test` command
- `required` canonical witness files
- optionally `baseline` commands if the suite itself does not baseline

### 2. Add setup execution

Before running a negative suite:

1. Run its setup commands.
2. Confirm required files exist.
3. Confirm required files are not templates.
4. Then run the negative suite.

Pseudo-flow:

```python
for suite in selected_suites:
    run_setup(suite)
    validate_required_witnesses(suite)
    run_negative_suite(suite)
```

### 3. Add anti-template validation

Add a TOML-level or text-level guard that catches empty values.

Minimum acceptable guard:

```python
def assert_no_empty_witness_values(path: Path) -> None:
    text = path.read_text()
    if '""' in text:
        raise RuntimeError(f"{path} contains empty witness values")
```

Better guard:

- parse TOML if Python version supports `tomllib`
- recursively reject:
  - empty strings
  - empty arrays where the circuit expects fixed arrays
  - missing required keys

Start with the simple guard unless existing fixture formatting requires more nuance.

### 4. Do not silently skip required suites

Current behavior can skip when inputs are missing. After setup is added, missing required inputs should be a failure, not a skip.

Skips are only acceptable when:

- toolchain is absent and the caller did not require Noir checks, or
- suite is explicitly disabled by CLI flag.

Acceptance for Phase 2:

- `fuzz_proof_witnesses.py` tries to generate canonical witnesses before testing.
- Missing or empty required witnesses fail loudly.
- No negative suite passes merely because it skipped.

---

## Phase 3: Fix stale negative suite parsers

### 1. Fix `test_h04_negative.py`

Current failure:

```text
RuntimeError: plaintexts slot[0].field[0] not found
```

This means the script expects a witness shape like:

```toml
plaintexts = [
  ["0x...", ...]
]
```

but the current `landmark_regions_v2/Prover.toml` schema differs.

Preferred fix:

- Use a real TOML parser.
- Read the current key structure emitted by the builder.
- If the current key is not `plaintexts`, update the script to use the actual builder output.

Example:

```python
import tomllib

data = tomllib.loads(text)
plaintexts = data["plaintexts"]
field0 = int(plaintexts[0][0], 16)
```

Avoid piling more regex onto stale schema assumptions.

### 2. Fix `test_mutation_no_rotation_semantics.py`

Current failure includes:

```text
c2_field_count invalid: cannot parse integer from empty string
```

This is probably caused by an empty template `Prover.toml`, not necessarily a parser bug.

After setup generation, verify:

- `circuits/mutate_slot/Prover.toml` contains populated values.
- canonical baseline `nargo execute` passes.

If it still fails:

- update the builder or script to emit the required current `c2_field_count`.
- ensure `c2_field_count` is numeric, not `""`.

### 3. Fix `test_m06_negative.py`

Current failure:

```text
chain_tips_root invalid: cannot parse integer from empty string
```

Same likely root cause: empty or stale canonical witness.

After setup generation:

- ensure `landmark_regions_v2/Prover.toml` has `chain_tips_root` populated.
- ensure baseline `nargo execute` passes before tampering.

### 4. Fix `test_m05_negative.py`

Current failure also comes from invalid canonical `mutate_slot/Prover.toml`.

After setup generation:

- rerun.
- if still failing, update field names to current schema.

Acceptance for Phase 3:

- Every negative script can run a clean baseline against the generated canonical witness.
- Every mutation failure is due to a circuit constraint rejection, not malformed or missing inputs.

---

## Phase 4: Make baseline execution mandatory

Every negative suite must prove:

1. Canonical witness succeeds.
2. Mutated witness fails.

The invariant is:

```text
valid witness passes; invalid witness fails
```

If the baseline fails, the negative test is invalid.

Recommended split:

- `fuzz_proof_witnesses.py` ensures setup and required files exist.
- each negative script validates baseline for the circuit(s) it mutates.

Acceptance:

- No negative test reports success unless it first observed a valid canonical witness pass.

---

## Phase 5: Cleanup temporary witness artifacts safely

Negative scripts should write tampered files under deterministic temporary names, for example:

```text
ProverTamperH04.toml
ProverTamperM06.toml
ProverNoopMutation.toml
ProverCombinedMutation.toml
ProverPayloadMutation.toml
```

Rules:

- Do not overwrite canonical `Prover.toml`.
- Delete tamper files on success.
- Leave tamper files on failure for debugging.
- Do not commit generated `Prover.toml` unless explicitly chosen as repo policy.

If setup builders generate `Prover.toml`, decide whether to:

- leave generated canonical witnesses untracked after test runs, or
- delete them after completion.

Recommended:

- delete generated canonical witnesses if they were not present before the run.
- preserve pre-existing files.

Acceptance:

- Running the harness does not leave dirty generated witness files on success.

---

## Phase 6: Run and verify incrementally

### 1. Tool compile check

```sh
python3 -m compileall -q tools
```

### 2. Single-suite checks

Run one suite at a time while fixing:

```sh
python3 tools/fuzz_proof_witnesses.py --cases 1
```

Then expand:

```sh
python3 tools/fuzz_proof_witnesses.py --cases 2
python3 tools/fuzz_proof_witnesses.py --cases 3
python3 tools/fuzz_proof_witnesses.py --cases 32
```

### 3. Direct negative scripts

For failures, run the underlying script directly:

```sh
python3 tools/test_mutation_no_rotation_semantics.py
python3 tools/test_m06_negative.py
python3 tools/test_h04_negative.py
python3 tools/test_m05_negative.py
python3 tools/test_noise_mint.py
```

### 4. Noir checks

```sh
$HOME/.nargo/bin/nargo check
```

or per active circuit:

```sh
cd circuits/mutate_slot && $HOME/.nargo/bin/nargo check
```

### 5. Final required command

```sh
python3 tools/fuzz_proof_witnesses.py --cases 32
```

Acceptance:

- command exits `0`
- no missing witness skips
- no empty-template failures
- all baseline witnesses pass
- all negative mutations fail as expected

---

## Phase 7: Integrate into assurance script

Only after Phase 6 passes, update:

```sh
tools/run_crypto_assurance_checks.sh
```

Add:

```sh
python3 tools/fuzz_proof_witnesses.py --cases "${PROOF_WITNESS_FUZZ_CASES:-32}"
```

Optionally support a CI override:

```sh
PROOF_WITNESS_FUZZ_CASES=8 tools/run_crypto_assurance_checks.sh
```

Acceptance:

- `tools/run_crypto_assurance_checks.sh` runs witness fuzzing.
- CI can bound runtime without disabling the check.

---

## Phase 8: Update audit report

Update `docs/FULL_AUDIT_REPORT.md`:

- Move the witness-suite issue from active finding to resolved finding.
- Document which builders materialize canonical witnesses.
- Record final successful command output.
- Note any remaining limitations.

Acceptance:

- Report accurately distinguishes:
  - real proof fuzz coverage
  - circuit negative witness coverage
  - test-only mock/gas coverage

---

## Final acceptance criteria

The fix is complete when all are true:

1. `python3 tools/fuzz_proof_witnesses.py --cases 32` passes.
2. No suite is skipped because canonical witnesses are missing.
3. No suite uses empty-template `Prover.toml` values.
4. Every negative suite validates a clean baseline before mutation.
5. Every mutation failure is a circuit constraint failure, not a TOML parse/schema error.
6. Successful harness runs leave no unintended dirty generated witness files.
7. `python3 -m compileall -q tools` passes.
8. `tools/run_crypto_assurance_checks.sh` includes the witness fuzz harness only after it is green.
