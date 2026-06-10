# Smart Contract Repo Cleanup Audit

Date: 2026-06-08
Branch observed: `secondary`
Scope: smart-contract code, contract scripts, contract tests, proof fixtures, and contract-adjacent docs/tools.

This is a cleanup checklist only. It does not propose changing product behavior unless explicitly called out as a bug/risk.

## Current verified baseline

Recent observed verification before this audit:

- Local `forge build`: passing.
- Local `forge test --match-contract MintShadowE2ETest -vv`: 25 passed, 0 failed.
- Local `forge test --match-contract RealChainLimitsTest -vv`: 15 passed, 0 failed.
- Local full `forge test`: 254 passed, 0 failed.
- Base Sepolia modular mint verified by `tools/verify_onchain_mint.py`: 43 passed, 0 failed.

Latest successful modular mint stack used during verification:

| Contract | Address |
|---|---|
| `ShadowToken` | `0x73a2bb3411B1a5D6f9df5a06d3b4bFBA95970e3d` |
| `FeatureNFT` | `0x6CfAD30a588a57946b306136D4094ca0c07f51aC` |
| `KeyRegistry` | `0x8c00dD1B1AA71099C9055942F22dB63Dc4361F9D` |
| `ShadowMintController` | `0x68f777E5B1b8E6b1099F3d8D6153a7C5c9d19A9b` |

Important caveat: this repo is not clean. There are many modified files and several untracked files, including production Solidity, tests, fixtures, docs, and tools.

## High-priority cleanup before considering the branch clean

### 1. Decide the canonical mint architecture and remove old mental models

Current implementation has moved from one-shot `mintShadow` to phased/modular minting through `ShadowMintController`:

- `beginMintShadow(args, recipient)`
- `submitMintCiphertexts(shadowId, slots, c2s)`
- `finalizeMintShadow(shadowId, proofT10)`
- `executeMintBatch(MintBatch)` as a gas-planning wrapper that executes register -> begin -> submit -> finalize in fixed order.

Cleanup needed:

- Make `ShadowMintController.sol` tracked if this is the intended architecture.
- Remove or update any docs/scripts/tests still describing `ShadowToken.mintShadow` as the active mint entry point.
- Make explicit that final mint install emits empty `ShadowSlotMutated.c2`; authoritative mint ciphertext bytes are emitted by `ShadowMintController.MintCiphertextSubmitted`.
- Ensure `IShadowToken.sol` and any external integration docs expose only the current intended surfaces.
- Audit downstream tools/indexers for the new event source:
  - old: `ShadowSlotMutated(..., c2)` during mint finalization
  - new: `MintCiphertextSubmitted(..., c2)` during submit phase

### 2. Fix stale deployment documentation

`docs/DEPLOYMENT.md` is currently internally inconsistent:

- It says canonical live deployment is pipeline #5.
- It also has a newer "Latest phased-mint testnet deployment" section.
- That section still shows older phased-mint addresses (`0x887C...`, `0x1B70...`) rather than the latest verified stack above (`0x73a2...`, `0x68f7...`).
- The gas table in that section is for the earlier primitive flow, not the latest modular chunk flow.

Cleanup needed:

- Pick one canonical section for the current branch.
- Move older pipeline #5 / prior phased-mint deployments under historical references.
- Add the latest modular mint addresses and tx hashes.
- Add the latest observed modular mint gas table:

| Step | Gas used |
|---|---:|
| register + begin | 11,654,925 |
| submit slot 0 | 816,222 |
| submit slot 1 | 816,174 |
| submit slot 2 | 816,186 |
| submit slot 3 | 816,162 |
| submit slot 4 | 816,222 |
| submit slot 5 | 816,162 |
| submit slot 6 | 816,198 |
| submit slot 7 + finalize | 7,300,874 |

- Document why the default script uses conservative chunking despite `executeMintBatch` allowing larger batches: Base Sepolia tx gas / calldata fee behavior caused larger simulated batches to fail on-chain.

### 3. Clarify `registerImage` vs `beginMintShadow` batching semantics

`executeMintBatch` can run `registerImage` and `beginMintShadow` together, but `MintOnSepolia.s.sol` now defaults to:

- `BEGIN_SUBMIT_COUNT=0`
- `SUBMIT_CHUNK_SIZE=1`

Cleanup needed:

- Document this as a gas-safe default, not a protocol limitation.
- Make script logs precise: the first batch may be `register/begin` only, not necessarily `register/begin/prefix` if `BEGIN_SUBMIT_COUNT=0`.
- Consider splitting scripts into clearer entry points:
  - `RegisterAndBeginMintOnSepolia.s.sol`
  - `SubmitMintCiphertextsOnSepolia.s.sol`
  - `FinalizeMintOnSepolia.s.sol`
  - or keep one script, but make env-var driven modes explicit in docs.

### 4. Patch remaining script/tool drift from private getter removals

For bytecode-size reasons, `ShadowToken` no longer exposes several getters used by older tools:

- `yulSponge16()`
- `keyRegistry()`
- `featureNFT()`
- `mintCounter()`

`tools/verify_onchain_mint.py` has been patched to avoid these and verify reachable behavior instead. Other scripts/tools may still assume old getters.

Cleanup needed:

- Search all tools/scripts/docs for private getter calls.
- Either remove those assumptions or route through public authoritative sources:
  - `FeatureNFT.shadowToken()` for back-reference.
  - `KeyRegistry.pkOf(address)` for registered key state.
  - `ShadowToken.shadowHeaderOf(shadowId)` for shadow header.
  - `ShadowToken.slotOf(shadowId, slotIdx)` for manifest.
  - `ShadowMintController` public immutables for mint-controller wiring.
- `verify_onchain_mint.py` still accepts `--poseidon16`; either use it to check `ShadowMintController.yulSponge16()` or remove the required argument.

### 5. Remove stale `STUB` section labels in production contracts

`contracts/src/ShadowToken.sol` still has section comments like:

- `mutateSlot (STUB)`
- `extractSlot (STUB)`
- `insertFeature (STUB)`
- `transferShadow (STUB)`
- `setZIndexCommit (STUB)`

These sections are implemented. Leaving `STUB` in production code is misleading.

Cleanup needed:

- Rename section headers to the actual implemented feature names.
- Do not change behavior.

### 6. Decide what to do with mock-based gas attribution tests

Untracked `contracts/test/GasAttribution.t.sol` contains explicitly mock-verifier gas attribution tests. Mock-based tests are useful for isolating storage/event overhead, but they should not be confused with assurance tests.

Cleanup options:

1. Track them under a clearly named diagnostics target, e.g. `GasAttribution.t.sol`, and document that they are not correctness/security evidence.
2. Move them to a separate non-default diagnostics directory or make them opt-in.
3. Drop them if they duplicate real gas benchmarks and create confusion.

Recommendation: keep only if labeled as diagnostics and excluded from any "real proof assurance" claims.

### 7. Resolve untracked smart-contract files and fixtures intentionally

Current untracked files relevant to contracts:

- `contracts/src/ShadowMintController.sol`
- `contracts/test/GasAttribution.t.sol`
- `contracts/test/ProofFuzz.t.sol`
- `contracts/test/SolveShadowRealProof.t.sol`
- `contracts/test/fixtures/atomic_mint/latest_testnet_incremental/`
- `contracts/test/fixtures/production_surface_manifest.json`
- `contracts/test/fixtures/solve_shadow_v2/incremental_reveal_contract/`
- `docs/FULL_AUDIT_REPORT.md`
- `docs/NEGATIVE_WITNESS_FUZZ_FIX_PLAN.md`
- `tools/audit_placeholder_scan.py`
- `tools/fuzz_proof_witnesses.py`

Cleanup needed:

- Track `ShadowMintController.sol` if phased mint is canonical.
- Track tests only if they are intended CI/assurance surface.
- Decide whether large generated fixtures belong in git. If yes, add them with naming and provenance. If no, add generation commands and ignore rules.
- Do not leave proof fixtures untracked if tests depend on them.
- Do not leave audit/fuzz tools untracked if they are part of the branch's evidence.

### 8. Reconcile solve/reveal architecture docs and implementation

Current repo includes both:

- incremental reveal work (`revealSlots`, `FeatureNFT.revealInsertedFeature`, docs and tests), and
- modified `solve_shadow_v2` circuit/tooling/fixtures.

Cleanup needed:

- State which solve architecture is canonical now:
  - incremental feature reveal during ownership lifetime, or
  - final solve/reveal flow, or
  - both with distinct purposes.
- If the old canvas-only solve plan is superseded, mark roadmap docs historical.
- If `solve_shadow_v2` remains active, ensure:
  - `SolveShadowVerifier.sol` was regenerated from the current circuit.
  - `contracts/test/fixtures/zk_surface_manifest.json` includes the current verifier hash/surface.
  - `contracts/test/fixtures/production_surface_manifest.json` is either tracked and used, or deleted.
  - `SolveShadowRealProof.t.sol` is tracked if it is now the persistent real-proof test.

### 9. Keep `ShadowToken` bytecode budget decisions explicit

The refactor moved pending mint session logic to `ShadowMintController` because adding it directly to `ShadowToken` exceeded EIP-170.

Cleanup needed:

- Document the design boundary in code/docs:
  - `ShadowToken` owns final installed shadow state.
  - `ShadowMintController` owns pending mint sessions and ciphertext submission.
  - `ShadowToken.finalizeMintFromController` is the only installation hook.
- Keep EIP-170 tests for both contracts:
  - `ShadowToken`
  - `ShadowMintController`
- Avoid reintroducing getters or helper wrappers into `ShadowToken` unless size-tested.

### 10. Tighten `ShadowMintController.executeMintBatch` documentation

The batch API is correct in broad shape, but its edge semantics should be documented for integrators:

- Fixed canonical order regardless of struct field order.
- If `doBeginMint == true`, derived `shadowId` is used for later submit/finalize steps.
- If `batch.shadowId != 0`, it must match the derived ID.
- If `doBeginMint == false`, caller must provide `batch.shadowId`.
- If `doRegisterImage == true && doBeginMint == true`, `batch.imageCommit` must match `batch.mintArgs.imageCommit`.
- `submitSlots` and `submitC2s` must both be empty or same nonzero length.

Potential patch to consider:

- Add an explicit error for `doBeginMint == false && shadowId == 0 && (submit/finalize requested)` if zero is not a valid practical shadow ID. Currently it will fall through to `PendingMintNotFound(0)`, which is technically fine but less communicative.

### 11. Align interfaces with production contracts

Modified interface files:

- `contracts/src/IShadowToken.sol`
- `contracts/src/IFeatureNFT.sol`

Cleanup needed:

- Confirm interfaces expose all events/errors/functions that off-chain/indexer/contracts need after modular mint and incremental reveal.
- Remove obsolete one-shot mint function signatures if present.
- Add `finalizeMintFromController` only if another contract/interface consumer needs it; otherwise keep it out of external user-facing interfaces.
- Ensure interface comments describe `OCCUPIED` vs `REVEALED` correctly.

### 12. Re-run and record current generated verifier provenance

Generated verifier files changed:

- `contracts/src/SolveShadowVerifier.sol`

Circuit/tooling changed:

- `circuits/solve_shadow_v2/src/main.nr`
- `tools/build_solve_shadow_v2_fixture.py`

Cleanup needed:

- Record exact `nargo` and `bb` versions used.
- Rebuild verifier from circuit and compare output to committed `SolveShadowVerifier.sol`.
- If byte-exact matching is not stable due generator formatting, record verifier hash and public input ABI.
- Update `GeneratedVerifierMatrix.t.sol` and manifests accordingly.

### 13. Fix docs that still overstate "no mocks" or confuse test categories

`docs/SECURITY.md` says Forge surface is covered by real proofs and no mocks, but the repo contains mock-verifier tests for behavior/gas isolation.

Cleanup needed:

- Distinguish:
  - real-proof tests,
  - generated-verifier rejection/fuzz tests,
  - mock-based contract behavior tests,
  - mock-based gas attribution tests.
- Avoid statements like "no mocks" unless restricted to a specific test suite.

### 14. Update negative-gate scripts for controller errors

`script/_NegTestGates.s.sol` now checks controller selectors:

- `ShadowMintController.ImageNotRegistered.selector`
- `ShadowMintController.AlreadyMinted.selector`

Cleanup needed:

- Confirm docs mention these errors are controller-level during phased mint.
- If external clients previously watched for `ShadowToken.ImageNotRegistered`, update client docs.
- Consider error-name duplication across `ShadowToken` and `ShadowMintController`; it is okay ABI-wise but should be documented so tooling does not assume one contract owns the selector.

### 15. Reconcile bridge docs and code changes

Modified files include:

- `contracts/src/ShadowBridgeL2.sol`
- `contracts/src/ShadowMirrorL1.sol`
- bridge scripts/tests.

Cleanup needed:

- Confirm bridge still targets current `ShadowToken` ABI after incremental reveal and phased mint.
- Ensure bridge does not allow bypassing reveal/mint lock invariants.
- Update `docs/DEPLOYMENT.md` bridge status if current canonical deployment is no longer pipeline #5.
- Keep OP 7-day finality listed as known limitation.

### 16. Update README and top-level docs to current branch reality

Modified:

- `README.md`
- `docs/AUTHENTICATED_METADATA.md`
- `docs/REVEAL_AT_SOLVE_DESIGN.md`
- `docs/SEPOLIA_TEST_MATRIX.md`

Cleanup needed:

- Remove references to superseded canvas-only solve if no longer intended.
- Describe incremental feature reveal and modular mint in the project overview.
- Add command snippets for the current testnet flow:
  - deploy stack
  - register/begin
  - submit ciphertext chunks
  - finalize
  - run `verify_onchain_mint.py`

## Medium-priority cleanup

### 17. Improve test naming around real vs mocked proof paths

Files to review:

- `MintShadow.t.sol` uses real generated verifiers for mint/face/t10.
- `SolveShadowRealProof.t.sol` appears intended as real proof coverage but is untracked.
- `SolveShadowMaxOccupancy.t.sol` uses mocked verifier for max-occupancy gas overhead.
- `GasAttribution.t.sol` uses mock verifiers by design.

Cleanup needed:

- Rename or comment test contracts so the test output makes the proof mode obvious.
- Keep real-proof fixture tests persistent if they are part of release assurance.
- Put mock-only gas attribution in a separate section of docs.

### 18. Normalize fixture naming

Current fixture names mix concepts:

- `atomic_mint_demo`
- `latest_testnet_incremental`
- `incremental_reveal_contract`
- `production_surface_manifest.json`
- `zk_surface_manifest.json`

Cleanup needed:

- Define naming convention:
  - `atomic_mint_demo`: deterministic local CI fixture.
  - `latest_testnet_incremental`: latest Base Sepolia proof bundle.
  - `solve_shadow_v2/incremental_reveal_contract`: solve/reveal real proof fixture.
- Include provenance file for each tracked fixture:
  - tool command,
  - circuit commit/hash,
  - verifier hash,
  - generated date,
  - intended test.

### 19. Audit comments for stale pipeline numbers

`docs/SECURITY.md` references "pipeline #6" while `docs/DEPLOYMENT.md` still says canonical is pipeline #5.

Cleanup needed:

- Stop using pipeline numbers as current-truth labels unless absolutely necessary.
- Prefer dates + git commits + contract addresses.
- If pipeline labels remain, define exactly what each pipeline means.

### 20. Check all scripts for address env requirements

Current scripts now vary by required env vars:

- `ST_ADDRESS`
- `KR_ADDRESS`
- `MC_ADDRESS`
- `FIX`
- `BEGIN_SUBMIT_COUNT`
- `SUBMIT_CHUNK_SIZE`

Cleanup needed:

- Add explicit `Usage:` blocks to scripts.
- Fail early with clear messages for missing env vars.
- Keep address output from deploy script machine-readable enough for copy/paste or tooling.

## Low-priority cleanup

### 21. Remove duplicated `.gitignore` entries

`.gitignore` repeats `circuits/*/target/` twice. Harmless but noisy.

Cleanup needed:

- Deduplicate ignore entries during a hygiene pass.

### 22. Consider formatting long Solidity lines

Some new constructor and verifier/controller calls are long. If the project has a formatter convention, run it as a separate formatting-only commit.

Do not mix formatting churn with behavior changes.

### 23. Decide whether audit docs are repo docs or local-only artifacts

Untracked:

- `docs/FULL_AUDIT_REPORT.md`
- `docs/NEGATIVE_WITNESS_FUZZ_FIX_PLAN.md`

Cleanup needed:

- If these are intended project docs, track them.
- If they are local working notes, move them under ignored `/audit/` or `STAGING_REFACTOR/`.

## Execution decisions from cleanup pass

The following untracked smart-contract-adjacent files are intentional branch
artifacts and should be committed with the modular mint / incremental reveal
cutover if verification remains green:

- `contracts/src/ShadowMintController.sol` — production controller for pending
  mint sessions and ciphertext chunk submission.
- `contracts/test/SolveShadowRealProof.t.sol` plus
  `contracts/test/fixtures/solve_shadow_v2/incremental_reveal_contract/` —
  persistent real-proof incremental reveal regression.
- `contracts/test/ProofFuzz.t.sol` — real generated-verifier rejection fuzz
  harness; use bounded fuzz counts in CI.
- `contracts/test/GasAttribution.t.sol` — mock-verifier diagnostic gas
  attribution. Keep documented as diagnostics only, not proof/security evidence.
- `contracts/test/fixtures/atomic_mint/latest_testnet_incremental/` — latest
  Base Sepolia modular-mint proof bundle used by `verify_onchain_mint.py`.
- `contracts/test/fixtures/production_surface_manifest.json` — production
  verifier/proof surface manifest if `check_zk_surface_manifest.py` consumes it.
- `tools/audit_placeholder_scan.py` and `tools/fuzz_proof_witnesses.py` — audit
  evidence tooling if they are part of the branch's assurance process.

The following look like planning/audit documents rather than contract runtime
inputs. Keep them if the repo is meant to retain full audit history; otherwise
move them under ignored `/audit/` or `STAGING_REFACTOR/` in a separate cleanup
commit after user approval:

- `docs/FULL_AUDIT_REPORT.md`
- `docs/NEGATIVE_WITNESS_FUZZ_FIX_PLAN.md`
- `roadmap/canvas_only_solve_option_a_exploration.md`
- `roadmap/canvas_only_solve_plan.md`
- `roadmap/incremental_feature_reveal_plan.md`
- `roadmap/reveal_canvas_fix_handoff.md`
- `roadmap/smart_contract_repo_cleanup_audit.md`

No untracked file above is untracked because of `.gitignore`; `.gitignore` only
covers build/runtime/local-secret artifacts and local planning workspaces.

## Suggested cleanup order

1. **Classify untracked files**: track, delete, or ignore each one intentionally.
2. **Commit canonical production architecture**: include `ShadowMintController.sol`, updated `ShadowToken.sol`, interfaces, deployment script, mint script, and mint tests together.
3. **Patch stale docs**: deployment addresses/gas, security test taxonomy, phased mint flow, private getter changes.
4. **Fix misleading comments**: remove `STUB`; update event-source comments.
5. **Reconcile real-proof fixtures**: decide which fixtures are committed and update manifests.
6. **Run verification again**:
   - `forge build`
   - `forge test --match-contract MintShadowE2ETest -vv`
   - `forge test --match-contract RealChainLimitsTest -vv`
   - `forge test`
   - `python3 tools/verify_onchain_mint.py ...` against latest Base Sepolia stack.
7. **Only then commit** with a message that makes the design cutover explicit: phased modular mint + incremental reveal + verifier/tooling cleanup.

## Do not do accidentally

- Do not keep both one-shot mint and phased mint as parallel public concepts.
- Do not document mock gas tests as proof/security tests.
- Do not leave `ShadowMintController.sol` untracked if contracts/scripts/tests depend on it.
- Do not commit generated proof fixtures without provenance.
- Do not add compatibility shims for removed getters just to satisfy stale scripts; update scripts instead unless a real external contract needs the getter.
- Do not mix formatting-only churn with semantic cleanup.
