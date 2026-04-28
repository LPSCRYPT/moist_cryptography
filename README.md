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
  ┌──────────────────────────────────────────────────────────────────────────────┐
  │ 1.  Actors                                                                   │
  ├──────────────────────────────────────────────────────────────────────────────┤
  │ deployer  0x1b43AFe43afC74bF9D0EBd764787eFD7CCcC2B6F   (Base + Eth Sepolia)  │
  │ PK2       0xFD90Bd22EDA6f54EBA3587E6a3642AB3B5236Ca2                         │
  │                                                                              │
  │ Each EOA registers its Grumpkin pk in KeyRegistry once.                      │
  │ After that, every state-mutating tx for that EOA carries a proof whose       │
  │ PI[owner_pk_x, owner_pk_y] must equal pkOf(msg.sender).                      │
  └──────────────────────────────────────────────────────────────────────────────┘
         │  A. owner builds a fixture (witness + proof) off-chain
         ▼
  ┌──────────────────────────────────────────────────────────────────────────────┐
  │ 2.  Off-chain prover stack    (Python + Noir + bb UltraHonk)                 │
  ├──────────────────────────────────────────────────────────────────────────────┤
  │ Inputs                                                                       │
  │   · 48×48 RGB face image           alice0, bob0, carol0, …                   │
  │   · slot-spec JSON                 per-slot pre-state of the shadow          │
  │   · seeds                          Grumpkin sk; ECIES nonces; palette        │
  │                                                                              │
  │ Pipeline                                                                     │
  │   tools/slot_state.py        rebuilds per-slot state by kind                 │
  │                              { mint, post-mutate-single,                     │
  │                                post-mutate-batch, post-insert }              │
  │   tools/build_*_onchain.py   emits Prover.toml for the right circuit         │
  │   nargo execute              solves the witness                              │
  │   bb prove                   emits proof.bin + public_inputs.bin             │
  │                              (UltraHonk, oracle_hash=keccak,                 │
  │                               verifier_target=evm)                           │
  │                                                                              │
  │ Eleven circuits, eight on-chain Honk verifiers                               │
  │ (mutate_slot reused by mutate_batch; landmark_regions_v2 + face_disc         │
  │ both verify at mintShadow + registerImage; rest are 1-to-1)                  │
  │                                                                              │
  │   face_disc                  → registerImage gate                            │
  │   landmark_regions_v2        → mintShadow witness                            │
  │   mutate_slot                → mutateSlot   (single)                         │
  │                              → mutateBatch (called twice in same tx)         │
  │   extract_slot               → extractSlot                                   │
  │   insert_feature             → insertFeature                                 │
  │   transfer_shadow            → transferShadow  (rotates all 16 slots)        │
  │   transfer_feature_v2        → transferFeature (held-carrier rotation)       │
  │   zindex_commit              → setZIndexCommit                               │
  │   shadow_t10                 → bundled with mutate / setZIndex / solve       │
  │   solve_shadow_v2            → solve  (PI + chain palette open + freeze)     │
  └──────────────────────────────────────────────────────────────────────────────┘
         │  B. forge script broadcasts tx; verifier reads PI from proof bytes
         ▼
  ┌──────────────────────────────────────────────────────────────────────────────┐
  │ 3.  Base Sepolia (L2)  —  pipeline #5  canonical                             │
  ├──────────────────────────────────────────────────────────────────────────────┤
  │ KeyRegistry            0xA71143F4E5bB5a11C98e9A1eE8D02b4344f3a2eE            │
  │   pkOf(EOA) → (Grumpkin pk_x, pk_y);  one-shot register per EOA.             │
  │   Every proof-bound entry point reads pkOf(msg.sender) and asserts           │
  │   it matches the proof's owner_pk PI fields.                                 │
  ├──────────────────────────────────────────────────────────────────────────────┤
  │ ShadowToken    0xbf9f3FC142f497774986345F027d3eaCa7Eba810   ERC721           │
  ├──────────────────────────────────────────────────────────────────────────────┤
  │ shadows[id]    { ecdhPubX/Y, t10Hi/Lo, zIndexCommit, zIndexRevealed,         │
  │                  solved }                                                    │
  │ manifest[id][16]    ManifestEntry { kind, featureId, liveStateHash }         │
  │ registeredImages[imageCommit]   set by registerImage (1-shot)                │
  │ mintedOrigins[imageCommit]      set by mintShadow    (1-shot)                │
  │                                                                              │
  │ Entry points and the verifier each invokes:                                  │
  │   registerImage       → FaceDiscVerifier                                     │
  │   mintShadow          → MintShadowVerifier  + ShadowT10Verifier              │
  │   mutateSlot          → MutateSlotVerifier  + ShadowT10Verifier              │
  │   mutateBatch         → MutateSlotVerifier ×2  + ShadowT10Verifier           │
  │   extractSlot         → ShadowT10Verifier   (FeatureNFT.mint side)           │
  │   insertFeature       → ShadowT10Verifier   (lsh checkpoint check)           │
  │   setZIndexCommit     → ZIndexCommitVerifier + ShadowT10Verifier             │
  │   transferShadow      → TransferShadowVerifier + ShadowT10Verifier           │
  │   solve               → SolveShadowVerifier + per-slot palette open          │
  │   bridgeShadow        → no ZK (requires isSolved + ownership)                │
  ├──────────────────────────────────────────────────────────────────────────────┤
  │ FeatureNFT    0x414606aBa41297a4Dc71F2603453177885499f16   ERC721            │
  ├──────────────────────────────────────────────────────────────────────────────┤
  │ features[id]   { typeIdx, originFaceId, paletteCommit,                       │
  │                  liveStateHashCheckpoint, paletteRevealed,                   │
  │                  hostShadowId or 0  (custody-locked while inserted) }        │
  │                                                                              │
  │ paletteCommit  immutable, set at mint via mintAtShadowMint(...)              │
  │                opened at solve via revealPaletteAtSolve(...)  which          │
  │                recomputes sponge_palette_salt(palette,salt) on chain         │
  │                and asserts == features[id].paletteCommit.                    │
  │ ERC721 transferFrom is GATED — reverts while a carrier is inserted           │
  │                in a shadow OR the host has not yet been solved.              │
  │ transferFeature(id, args)  →  TransferFeatureV2Verifier  (ZK, rotates        │
  │                ECIES of a held carrier to a fresh recipient pk).             │
  ├──────────────────────────────────────────────────────────────────────────────┤
  │ Yul Poseidon2 sponges    (Solidity-Yul, no ZK)                               │
  ├──────────────────────────────────────────────────────────────────────────────┤
  │ Poseidon2YulSponge16              sponge_16(field[16])                       │
  │                                     → manifest LSH root                      │
  │                                     → zIndexCommit (perm of [0..15])         │
  │ Poseidon2YulSpongePaletteSalt     sponge_palette_salt(palette[16], salt)     │
  │                                     → 17-input opener for paletteCommit      │
  ├──────────────────────────────────────────────────────────────────────────────┤
  │ ShadowBridgeL2 #5b    0x49A8d60114C4869D2f0422c8e5b1f9442f5e4529             │
  ├──────────────────────────────────────────────────────────────────────────────┤
  │ bridgeShadow(id, revealedPi):                                                │
  │   require(isSolved(id) && ownerOf(id) == msg.sender)                         │
  │   shadowToken.transferFrom(owner, bridge, id)        ── custody lock         │
  │   L2CrossDomainMessenger(0x4200000…0007).sendMessage(                        │
  │       l1Mirror = 0xe9B8b1Dd…,                                                │
  │       abi.encode(mintFromBridge.selector, payload),                          │
  │       DEFAULT_L1_GAS_LIMIT)                                                  │
  │                                                                              │
  │ payload = { shadowId, recipient, ecdhPub, t10, zIndex,                       │
  │             manifest[16], typeIdxs[16], originFaceIds[16],                   │
  │             paletteCommits[16], revealedPi (raw solve PI bytes) }            │
  │                                                                              │
  │ unbridgeShadow(id, l2Recipient)   incoming round-trip from L1                │
  │   require(msg.sender == L2_MESSENGER &&                                      │
  │           xDomainMessageSender() == l1Mirror)                                │
  │   require(bridged[id] == OWNED_ON_L1)                                        │
  │   shadowToken.transferFrom(bridge, l2Recipient, id)                          │
  ├──────────────────────────────────────────────────────────────────────────────┤
  │ Events emitted by the lifecycle (the indexer surface)                        │
  ├──────────────────────────────────────────────────────────────────────────────┤
  │ ImageRegistered(imageCommit)                                                 │
  │ ShadowMinted(shadowId, owner, ecdhPub, t10)                                  │
  │ ShadowSlotMutated(shadowId, slotIdx, ctCommit, c1, lsh, count)               │
  │ SlotExtracted(shadowId, slotIdx, featureId, finalLsh)                        │
  │ SlotInserted(shadowId, slotIdx, featureId, newLsh, newCount)                 │
  │ ZIndexCommitSet(shadowId, newCommit)                                         │
  │ ShadowTransferred(shadowId, fromOwner, toOwner, newEcdhPub, newT10)          │
  │ ShadowSolved(shadowId, owner, zIndexRevealed)                                │
  │ FeaturePaletteRevealed(featureId, paletteCommit, palette, salt)   × 8        │
  │ FeatureSlotRevealed   (featureId, shadowId, slotIdx, plaintext)   × 8        │
  │ ShadowBridged(shadowId, sender, messageHash)                                 │
  └──────────────────────────────────────────────────────────────────────────────┘
         │  C. solve emits 16 events per shadow (8 palette + 8 slot);
         │     bridgeShadow custody-locks the ERC721 + dispatches an L2→L1 msg.
         ▼
  ┌──────────────────────────────────────────────────────────────────────────────┐
  │ 4.  OP-Stack L2→L1 withdrawal path                                           │
  ├──────────────────────────────────────────────────────────────────────────────┤
  │ L2 tx included in a Base Sepolia block                                       │
  │         │                                                                    │
  │         │  ~1 h     L2OutputOracle proposes L2 output root on L1             │
  │         ▼                                                                    │
  │ Withdrawal entered into the L1 OptimismPortal                                │
  │         │                                                                    │
  │         │  anyone   proveWithdrawalTransaction(...)                          │
  │         ▼                                                                    │
  │ Challenge window  (7 days on Sepolia)                                        │
  │         │                                                                    │
  │         │  anyone   finalizeWithdrawalTransaction(...)                       │
  │         ▼                                                                    │
  │ L1CrossDomainMessenger relays → ShadowMirrorL1.mintFromBridge                │
  └──────────────────────────────────────────────────────────────────────────────┘
         │  finalize delivers the bridge payload to L1
         ▼
  ┌──────────────────────────────────────────────────────────────────────────────┐
  │ 5.  Eth Sepolia (L1)                                                         │
  ├──────────────────────────────────────────────────────────────────────────────┤
  │ ShadowMirrorL1   0xe9B8b1DddaEC95C165B0c4aE55Ea13FeAAC79042   ERC721         │
  │                                                                              │
  │ mintFromBridge(payload):                                                     │
  │   require(msg.sender == l1Messenger)                                         │
  │   require(xDomainMessageSender() == l2Bridge)   // 0x49A8d6…                 │
  │   require(!mintedFromBridge[shadowId])          // anti-replay               │
  │   _mirrors[id] = MirrorState from payload                                    │
  │   _revealedPi[id] = payload.revealedPi                                       │
  │   _mint(payload.recipient, shadowId)            // ERC721 mirror NFT         │
  │   emit ShadowMirrored(shadowId, recipient, t10Hi, t10Lo)                     │
  │                                                                              │
  │ burnAndUnbridge(id, l2Recipient):                                            │
  │   require(ownerOf(id) == msg.sender)                                         │
  │   _burn(id); delete state                                                    │
  │   L1CrossDomainMessenger.sendMessage(l2Bridge,                               │
  │       abi.encode("unbridgeShadow(uint256,address)", id, l2Recipient))        │
  └──────────────────────────────────────────────────────────────────────────────┘

  ───────────  off-chain consumers (parallel to the chain)  ───────────

  ┌──────────────────────────────────────────────────────────────────────────────┐
  │ 6.  Visualizer / indexer    tools/render_onchain_shadow.py                   │
  ├──────────────────────────────────────────────────────────────────────────────┤
  │ Two render modes, distinguished by what events the chain has emitted:        │
  │                                                                              │
  │ POST-SOLVE  (canonical, anyone can render)                                   │
  │   eth_getLogs → 8× FeaturePaletteRevealed   palette + salt                   │
  │               + 8× FeatureSlotRevealed     39-field plaintext                │
  │   → palette[16] + plaintext per occupied slot, no decryption needed          │
  │                                                                              │
  │ PRE-SOLVE   (owner-only)                                                     │
  │   eth_getLogs → ShadowSlotMutated*          per-slot ECIES c2 history        │
  │   + owner --sk + per-slot c1 sidecar from build_*_onchain meta               │
  │   → ECDH(sk, c1) → AES key → decrypt c2 → plaintext                          │
  │                                                                              │
  │ Both modes pipe through decode_plaintext_v2 to render                        │
  │   · 8 sprite PNGs  · 48×48 composite  · sprite strip                         │
  └──────────────────────────────────────────────────────────────────────────────┘
         │  D. anyone (post-solve) or the owner (pre-solve) reads the rendered art
         ▼
```


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
