# Sepolia test matrix

A catalogue of edge cases that **only** show up when running against a
real chain (Base Sepolia for L2 ops, Eth Sepolia for L1 mirror ops) and
that the forge unit/integration suite cannot cover.

Forge tests are deterministic, fast, and cover all the in-process state
transitions. They are **necessary but not sufficient.** What they cannot
exercise:

  - Real bb UltraHonk(keccak) proof verification on the on-chain Yul
    verifier (the deployed verifier is a Solidity stub generated from the
    bb verification key; the in-process verifier is the same artifact,
    but a chain receipt is the only proof it actually mounts under L2
    gas pricing).
  - EIP-170 24KB code-size cap for every deployed verifier.
  - Block gas limit 30M (effective 16M public-RPC ceiling).
  - Cross-domain messenger interop with Base's L1CrossDomainMessenger
    proxy and the OP-Stack output proposal cadence.
  - State that persists across multiple txs from different EOAs.
  - Indexer-side render of solve events.

## Status legend

  - **DONE** -- a tx hash is on chain confirming this case
  - **FORGE** -- covered by the in-process forge suite, not run on chain
  - **OPEN** -- worth running but not yet executed
  - **N/A** -- not applicable to current pipeline

Tx hashes link `https://sepolia.basescan.org/tx/<hash>` (Base Sepolia)
unless prefixed with `eth-` (`https://sepolia.etherscan.io/tx/<hash>`).

---

## 1. Mint flow

| # | Case | Status | Tx / Note |
|---|---|---|---|
| 1.1 | mint from a fresh image (alice0) | DONE | A' (pipeline #5 deploy) |
| 1.2 | mint a second shadow under a fresh image with a fresh OWNER (PK2) | DONE | B' `0xab50a7ad...` |
| 1.3 | mint a third shadow under existing OWNER, fresh image (carol0) | DONE | C' `0x876157cf...`, mintCounter 17..24 |
| 1.4 | mint with --owner-seed != --seed (split key/fixture seeds) | DONE | C' (owner=palette_reveal_live, seed=solve_demo_c) |
| 1.5 | replay the same imageCommit | FORGE | `MintShadow.t.sol::test_mintShadow_reverts_when_already_minted` |
| 1.6 | mint without registerImage first | FORGE | `test_mintShadow_reverts_when_image_not_registered` |
| 1.7 | mint with tampered face_disc proof | FORGE | `test_registerImage_reverts_when_proof_tampered` |
| 1.8 | mint with tampered ct_commits / c2 | FORGE | `MintShadow.t.sol` (3 cases) |
| 1.9 | gas under 16M ceiling at full 8-carrier mint | DONE | C' mint ~10.5M gas |
| 1.10 | palette_commit consistency: every fixture's stored commit opens via sponge_palette_salt | DONE | enforced in build_atomic_mint_fixture.py + tools/test_slot_state.py |

## 2. Mutate flow

| # | Case | Status | Tx / Note |
|---|---|---|---|
| 2.1 | mutateSlot on slot in middle of mint state | DONE | B' slot 0 `0x77c94d80...` |
| 2.2 | mutateSlot on already-mutated slot (count 1 -> 2) | OPEN | exercise `prev_mutation_count` increment |
| 2.3 | mutateBatch of 2 adjacent slots | DONE | B' slots 1+2 `0x66ad4960...` |
| 2.4 | mutateBatch of 3+ slots in one tx | OPEN | gas test up to N=8 in single tx |
| 2.5 | mutateBatch with duplicated slot | FORGE | `test_mutateBatch_reverts_when_slot_referenced_twice` |
| 2.6 | mutateBatch with empty entries | FORGE | `test_mutateBatch_reverts_on_empty_entries` |
| 2.7 | mutate after solve | FORGE | `test_mutateSlot_reverts_when_solved` |
| 2.8 | mutate by non-owner | FORGE | `test_mutateSlot_reverts_when_caller_not_owner` |
| 2.9 | tampered c2 length | FORGE | `test_mutateSlot_reverts_when_c2_length_wrong` |
| 2.10 | mutate gas under block budget | FORGE + DONE | forge cap test + on-chain `0x77c94d80...` 7.12M, batch 10.8M |

## 3. Extract / Insert

| # | Case | Status | Tx / Note |
|---|---|---|---|
| 3.1 | extractSlot on mint-state carrier | DONE (legacy on #3) | extract+insert lifecycle |
| 3.2 | extractSlot on POST-MUTATE carrier | DONE | B' slot 3 `0xad84c4f2...` (slot was post-mutate) |
| 3.3 | extractSlot of already-empty slot | FORGE | `ExtractSlot.t.sol::test_extractSlot_reverts_when_slot_empty` |
| 3.4 | insertFeature into mint-state host | OPEN | (#3 lifecycle covered this) |
| 3.5 | insertFeature into POST-MUTATE host | DONE | B' slot 8 `0xc8a2c7ba...` (host slot 8 was empty mint state) |
| 3.6 | insertFeature where carrier already inserted | FORGE | `test_insertFeature_reverts_when_carrier_already_inserted` |
| 3.7 | insertFeature into occupied slot | FORGE | `test_insertFeature_reverts_when_slot_occupied` |
| 3.8 | extract+insert preserves immutables | FORGE | `ExtractInsertPreservation.t.sol` |
| 3.9 | extract by non-owner | FORGE | `test_extractSlot_reverts_when_not_owner` |
| 3.10 | transferFrom while inserted (custody-locked carrier) | FORGE | `test_transferFrom_revertsWhileInserted_custodyLock` |

## 4. Transfer (shadow + feature)

| # | Case | Status | Tx / Note |
|---|---|---|---|
| 4.1 | proof-bound transferShadow PK -> deployer (8 occupied slots, all rotate) | DONE | B' `0x05ca2cf4...` 9.06M gas |
| 4.2 | transferShadow with mixed-kind slots (post-mutate-single, post-mutate-batch, mint, post-insert) | DONE | B' slot-spec was `b_p5_post_insert.json` |
| 4.3 | transferShadow with wrong recipient_pk (not in KeyRegistry) | OPEN | should revert at PI[1..2] check; currently only failed-locally |
| 4.4 | transferShadow tampered LSH | FORGE | `test_transferShadow_reverts_when_lsh_tampered` |
| 4.5 | transferShadow replay after rotation | FORGE | `ReplayTransferShadowTest` (2 cases) |
| 4.6 | transferShadow at MAX 16 occupied slots | FORGE | `TransferShadowMaxOccupancy.t.sol` |
| 4.7 | transferFeature V2 on POST-MUTATE held carrier | DONE | A' slot 0 `0xb9470c0f...` |
| 4.8 | transferFeature V2 on MINT-STATE solve auto-extracted carrier | OPEN | (similar path; A's case was post-mutate) |
| 4.9 | transferFeature V2 to recipient not in KeyRegistry | OPEN | reverts at check |
| 4.10 | transferFeature V2 while still inserted in shadow | FORGE | `test_transferFeature_revertsWhileInserted` |

## 5. Solve flow

| # | Case | Status | Tx / Note |
|---|---|---|---|
| 5.1 | solve mint-state shadow (8 occupied) | DONE | A' `0xea461ee9...`, C' `0xfd58fb3d...` |
| 5.2 | solve POST-MUTATE/POST-INSERT mixed-kind shadow | OPEN (blocked) | B' has stale palette commits (see below); future shadow needed |
| 5.3 | solve max-occupancy 16 carriers | FORGE | `SolveShadowMaxOccupancy.t.sol` |
| 5.4 | solve without setZIndexCommit | FORGE | `test_solve_reverts_when_zIndexCommit_unset` |
| 5.5 | solve with mismatched zIndexCommit | FORGE | `test_solve_reverts_when_zIndexCommit_mismatched` |
| 5.6 | solve with tampered palette | FORGE | `test_solve_reverts_when_palette_tampered` |
| 5.7 | solve with tampered salt | FORGE | `test_solve_reverts_when_salt_tampered` |
| 5.8 | solve when already solved | FORGE | `test_solve_reverts_when_already_solved` |
| 5.9 | solve with stale palette_commit (not openable via sponge) | DONE-lesson | B' broadcasted setZIndex `0x475bf0ed...` but solve impossible; hard-stop at FeatureNFT.revealPaletteAtSolve |
| 5.10 | event-only render: 8 palette + 8 plaintext events drive a complete sprite render with NO --sk and NO --c1-sidecar | DONE | A' + C' both verified via `tools/render_onchain_shadow.py`; C' rendered 2026-04-28 with --rpc base-sepolia.gateway.tenderly.co (public RPC rate-limits getLogs) -- 8 sprite PNGs + composite + strip emitted under `/tmp/shadow_c_render` |

## 6. Bridge flow (L2-leg)

| # | Case | Status | Tx / Note |
|---|---|---|---|
| 6.1 | bridgeShadow a SOLVED shadow through paired L2 bridge | DONE | C' `0xdd7306cb...` -> bridge #5b |
| 6.2 | bridgeShadow before solve | FORGE | `test_bridgeShadow_reverts_when_unsolved` |
| 6.3 | bridgeShadow when l1Mirror unset | FORGE | `BridgeShadowTest::reverts_when_l1_mirror_unset` |
| 6.4 | bridgeShadow with bad PI length (not multiple of 32) | FORGE | `test_bridgeShadow_reverts_on_bad_revealed_pi_length` |
| 6.5 | bridgeShadow with empty PI | FORGE | `test_bridgeShadow_reverts_on_zero_length_revealed_pi` |
| 6.6 | bridgeShadow as non-owner | FORGE | `test_bridgeShadow_reverts_when_not_owner` |
| 6.7 | bridgeShadow against an L2 bridge wired to a STRANDED L1 mirror (this case actually shipped) | DONE-lesson | A' `0x7e27fcb4...` to old bridge `0x9Ef3f7a3` -> message undeliverable |

## 7. Bridge wiring (setters)

| # | Case | Status | Tx / Note |
|---|---|---|---|
| 7.1 | L2.setL1Mirror happy path | DONE | `0xa5f466a3...` (bridge #5b) |
| 7.2 | L1.setL2Bridge happy path | DONE | eth-`0xa27ca617...` |
| 7.3 | L2.setL1Mirror called twice (one-shot revert) | FORGE | `BridgeWiring.t.sol::test_setL1Mirror_one_shot_reverts_on_re_point` |
| 7.4 | L1.setL2Bridge called twice | FORGE | `test_setL2Bridge_one_shot_reverts_on_re_point` |
| 7.5 | setters by non-deployer | FORGE | `test_setL1Mirror_only_deployer_reverts` (+ symmetric) |
| 7.6 | setters with zero address | FORGE | `test_setL1Mirror_zero_address_reverts` (+ symmetric) |

## 8. Bridge L1 finalize (Eth Sepolia)

| # | Case | Status | Tx / Note |
|---|---|---|---|
| 8.1 | L1 mirror minted via cross-domain message after challenge window | OPEN | calendar-bound; C' candidate (bridged 2026-04-28, finalize ~2026-05-05) |
| 8.2 | proveWithdrawalTransaction against new L1 mirror | OPEN | first OP-Stack output proposal lands ~1hr after L2-leg |
| 8.3 | finalizeWithdrawalTransaction after 7-day window | OPEN | calendar-bound |
| 8.4 | mintFromBridge with non-messenger caller | FORGE | `BridgeWiring.t.sol::test_mintFromBridge_reverts_when_caller_not_messenger` |
| 8.5 | mintFromBridge with xsender != paired L2 bridge | FORGE | `test_mintFromBridge_reverts_when_xsender_not_l2_bridge` |
| 8.6 | mintFromBridge replay (same shadowId) | FORGE | `test_mintFromBridge_reverts_on_replay` |
| 8.7 | burnAndUnbridge by non-mirror-owner | FORGE | `test_burnAndUnbridge_reverts_when_not_owner` |
| 8.8 | full L1 -> L2 round trip (mint then burn back) | OPEN | calendar-bound |

## 9. KeyRegistry

| # | Case | Status | Tx / Note |
|---|---|---|---|
| 9.1 | register a new EOA | DONE | PK2 `0xdfc420a7...` + deployer (during pipeline #5 deploy) |
| 9.2 | register twice (different pk) | FORGE | `test_Register_RevertsOnDoubleRegister` |
| 9.3 | pkOf for unregistered EOA | FORGE | `test_PkOf_Reverts_WhenNotRegistered` |
| 9.4 | two EOAs maintain independent bindings | FORGE | `test_TwoActorsHaveIndependentBindings` |

## 10. Cross-cutting / infrastructure

| # | Case | Status | Tx / Note |
|---|---|---|---|
| 10.1 | Every verifier under EIP-170 24KB | FORGE | `RealChainLimits.t.sol` (14 tests) |
| 10.2 | sponge_16 / sponge_39 cryptographic invariants | FORGE | `CryptoInvariants.t.sol` (12 tests) |
| 10.3 | Yul Poseidon2 sponges produce same output as Python | FORGE | `Poseidon2YulSponge16Test`, `Poseidon2YulSpongePaletteSaltTest` |
| 10.4 | Replay protection for every state-mutating entry point | FORGE | `ReplayProtection.t.sol` |
| 10.5 | Round-trip: every per-slot rebuilder == its corresponding builder | TEST | `tools/test_slot_state.py` (30 assertions, sponge-consistency check fires on drift) |
| 10.6 | atomic_mint sponge_palette_salt consistency: every emitted palette_commit MUST open via the published palette+salt | TEST + ASSERT | enforced inside the builder; tests in test_slot_state.py |

---

## Future-shadow work

The chain currently has three shadows on pipeline #5; capturing future
broadcasts is cheaper than paying for redundant ones. The matrix entries
below are the ones that genuinely add coverage (i.e., expose a code path
that's not already on chain or in forge).

### High value (worth a real broadcast)

  - **5.2** -- solve a POST-MUTATE/POST-INSERT mixed-kind shadow.
    Requires a fresh shadow whose meta.json palette_commits are
    consistent (post-fix builder), then mutate + extract + insert + solve.
    Validates that solve correctly threads palettes when slot 8 holds a
    foreign-origin carrier (palette commit derives from origin slot, not
    host slot).
  - **2.2** -- mutate slot count 1 -> 2. The mutate circuit's
    `prev_mutation_count` arithmetic is exercised in forge but not on
    chain.
  - **4.3** -- transferShadow to a recipient whose pk isn't in
    KeyRegistry. Should revert; on-chain confirmation of the failure
    mode.
  - **8.1 / 8.2 / 8.3** -- L1 finalize for shadow C through the new
    bridge. Calendar-bound; nothing to do until ~2026-05-05.

### Medium value

  - **2.4** -- mutateBatch of 5+ slots in one tx. Useful for gas curve.
  - **3.4** -- insertFeature into mint-state host (rather than empty
    slot). Distinct from B's case which inserted into an empty slot.

### Low value (already covered)

Everything FORGE-covered above. Sepolia broadcasts here would be
redundant with the in-process tests.

---

## Tooling for replay

To rebuild any matrix entry's fixture from scratch, follow the canonical
script chain. **Order matters:** each builder's fixture meta.json may
reference the previous one.

```
build_face_disc_fixture.py        # one-time per image
build_atomic_mint_fixture.py      # one-time per shadow (writes meta.json
                                  # with palette_commit consistency
                                  # asserted before exit)

build_mutate_slot_onchain.py      # mutate one slot
build_mutate_batch_onchain.py     # mutate two slots
build_extract_onchain.py          # extract a (possibly mutated) slot
build_insert_onchain.py           # insert a held carrier into any slot

build_transfer_onchain.py         # rotate ALL occupied slots ECIES via slot-spec
build_transfer_feature_v2_fixture.py # rotate ONE held carrier ECIES

build_zindex_onchain.py           # commit z-perm against current LSH array
build_solve_onchain.py            # freeze + reveal everything

# Bridge has no proof; just the call.
script/BridgeShadowOnSepolia.s.sol
```

Each builder takes `--owner-seed` + `--mint-counter-base` where
applicable. The slot-spec format in
`contracts/test/fixtures/slot_specs/<name>.json` drives transfer +
solve builders for non-trivial pre-states; new specs should be added per
shadow as it crosses kind boundaries.
