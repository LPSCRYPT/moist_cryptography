# Live Sepolia testing + dashboard execution plan

## Goal

Run the current smart-contract system against live Base Sepolia with real proofs, audit the testing surface itself, and add a browser dashboard that shows exactly what public on-chain data exists and what a user can decrypt locally from that data.

## Critical finding and cutover status

Initial audit finding: browser-side decryption from chain-only data required both hidden slot ciphertext bytes (`c2`) and the ECIES ephemeral public point `c1 = (c1X, c1Y)`. Transfer paths already exposed proof-bound `c1`, but phased mint, `mutateSlot`, `mutateBatch`, and `insertFeature` did not.

Cutover implemented locally:

- phased mint now emits `ShadowSlotEnvelope` for each finalized minted slot, with c1 roots bound by the mint circuit public inputs;
- `mutateSlot`, every `mutateBatch` entry, and `insertFeature` now expose `newC1X/newC1Y` as mutate-circuit public inputs and emit `ShadowSlotEnvelope`;
- dashboard decryption remains browser-only and refuses to synthesize missing c1 for historical deployments.

Impact: on patched deployments, a dashboard can decrypt current hidden slots from chain-only data plus the user's private key. Historical deployments that predate this cutover still lack mint/mutate/insert c1 events and remain non-decryptable from chain-only data.

## Phase 1 — local testing audit additions

1. Local tests now assert ciphertext-envelope availability:
   - Mint finalization emits `ShadowSlotEnvelope` for each minted slot.
   - `mutateSlot`, every checked `mutateBatch` entry, and `insertFeature` emit proof-bound `ShadowSlotEnvelope` values matching the new encrypted payload.
2. Documentation now distinguishes:
   - public/revealed data available to everyone;
   - historical deployments where hidden ciphertext is present but c1 is missing;
   - patched deployments where hidden ciphertext is decryptable with only browser key material because c1 is available.

## Phase 2 — dashboard v1

Because the repo currently has no frontend package, add a dependency-light static dashboard under `dashboard/`:

- `dashboard/index.html`
- `dashboard/styles.css`
- `dashboard/app.js`
- `dashboard/crypto.js`
- `dashboard/README.md`

Architecture:

- RPC-first, no subgraph initially. Current event volume is small enough for `eth_getLogs` by contract address and topic. If RPC range limits appear, the dashboard will chunk block ranges and cache in IndexedDB/localStorage.
- Users configure:
  - RPC URL;
  - Base Sepolia deployment addresses;
  - from-block;
  - one or more local user profiles: label, EVM address, optional Grumpkin secret key.
- Views:
  1. Public chain overview: deployment addresses, latest block, discovered shadows, events, gas/tx links.
  2. Shadow detail: header, slots, feature ids, T10, event timeline, reveal state.
  3. User view: for each configured user, ownership and decryptability status per slot/feature.
  4. Browser decryption panel: performs ECIES locally only when both `c2` and corresponding `c1` are available in events. Private keys never leave browser memory/local storage.

Security boundary:

- The dashboard must never send private keys, shared secrets, or decrypted plaintext to RPC.
- Decryption must refuse to run when c1 is absent instead of guessing or using fixture files.
- It must label missing c1 as a protocol/data-availability gap, not a user error.

## Phase 3 — live Sepolia testing harness

Add a live test report harness that records observed tx hashes and checks:

1. Current latest phased mint stack:
   - `registerImage` / `beginMintShadow` / `submitMintCiphertexts` / `finalizeMintShadow` already has a verifier; rerun it and persist a report.
2. Post-mint state-changing flows on latest deployment:
   - `mutateSlot` real proof tx;
   - `mutateBatch` real proof tx;
   - `revealSlots` real proof tx;
   - `transferShadow` real proof tx;
   - `transferFeatureV2` real proof tx;
   - `extractSlot` / `insertFeature` if still supported by current state;
   - `setZIndexCommit` if still supported by current state;
   - bridge L2 leg if a solved shadow is available and bridge is in scope.
3. Each live operation report must include:
   - tx hash;
   - gas used;
   - chain postconditions checked by RPC reads/events;
   - whether ciphertext is decryptable from chain-only data in the dashboard.

## Phase 4 — protocol patch if required for dashboard decryption

If browser decryption from chain-only data is a hard requirement, patch the protocol before claiming end-to-end coverage:

1. `landmark_regions_v2`:
   - Add public roots for per-slot mint `c1X[8]` and `c1Y[8]`.
   - Update `MintShadowVerifier` PI length and generated verifier.
   - Store `c1` roots in `ShadowMintController.PendingMint` or verify per-slot c1 submissions against roots.
   - Emit per-slot `ShadowSlotEnvelope` during final mint install.
2. `mutate_slot`:
   - Add `new_c1_x` and `new_c1_y` public inputs.
   - Assert they equal the internally computed `new_c1.x/y`.
   - Update `MutateSlotVerifier` PI length and all builders/scripts/tests.
   - Emit `ShadowSlotEnvelope` from `mutateSlot`, `mutateBatch`, and `insertFeature` after verifying c1.
3. Regenerate proofs/verifiers and re-run local and live Sepolia tests.

## Initial implementation decision

Proceed with Phase 1–3 now. The dashboard will be truthful: it will decrypt only paths that expose c1 and will explicitly mark mint/mutate/insert hidden slots as not decryptable from chain-only data until Phase 4 is implemented. Do not fake decryption with fixture sidecars or server helpers.
