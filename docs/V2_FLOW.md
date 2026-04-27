# v2 system flow — mermaid diagrams

Companion to `docs/ARCHITECTURE.md` and `docs/CIRCUITS.md`. This file
captures the v2 protocol in five focused diagrams, current as of
`staging` tip `ac19af2`.

---

## 1. System overview — actors, contracts, circuits

```mermaid
graph TB
    subgraph "Actors"
        A[Alice<br/>shadow owner]
        B[Bob<br/>recipient]
        I[Indexer / Visualizer]
        L1[L1 Mirror<br/>ShadowMirrorL1]
    end

    subgraph "Off-chain"
        IMG[48x48 RGB face image]
        PROVER[bb prove<br/>UltraHonk + keccak]
    end

    subgraph "On-chain - L2"
        ST[ShadowToken<br/>ERC-721 shadows<br/>16 manifest slots each]
        FN[FeatureNFT<br/>ERC-721 carriers]
        KR[KeyRegistry<br/>owner pk lookup]
        BL[ShadowBridgeL2]
    end

    subgraph "Verifiers - 7 Honk + 2 sponges"
        V_DISC[FaceDiscVerifier]
        V_MINT[MintShadowVerifier]
        V_MUT[MutateSlotVerifier]
        V_T10[T10ShadowVerifier]
        V_Z[ZIndexCommitVerifier]
        V_TR[TransferShadowVerifier]
        V_SOL[SolveShadowVerifier]
        SP[Poseidon2YulSponge<br/>sponge_39]
        SP16[Poseidon2YulSponge16<br/>sponge_16]
    end

    A --> IMG --> PROVER
    PROVER -->|proofs + PI| ST
    A -->|mintShadow / mutateSlot /<br/>mutateBatch / extractSlot /<br/>insertFeature / setZIndexCommit /<br/>transferShadow / solve| ST
    B -->|kr.register| KR
    A -->|kr.register| KR
    ST --> V_DISC & V_MINT & V_MUT & V_T10 & V_Z & V_TR & V_SOL
    ST --> SP & SP16
    ST <-->|carrier ownership +<br/>insertion state| FN
    ST -->|read owner pk| KR
    A -->|approve + bridgeShadow<br/>post-solve| BL
    BL -->|sendMessage| L1
    ST -.->|ShadowMinted /<br/>ShadowSlotMutated /<br/>ShadowT10Updated /<br/>ShadowTransferred /<br/>ShadowSolved /<br/>SlotExtracted| I
    FN -.->|FeatureMinted /<br/>FeatureExtracted /<br/>FeatureInserted| I

    classDef actor fill:#fff3cd,stroke:#856404
    classDef onchain fill:#d4edda,stroke:#155724
    classDef verifier fill:#d1ecf1,stroke:#0c5460
    classDef offchain fill:#e2e3e5,stroke:#383d41
    class A,B,I,L1 actor
    class ST,FN,KR,BL onchain
    class V_DISC,V_MINT,V_MUT,V_T10,V_Z,V_TR,V_SOL,SP,SP16 verifier
    class IMG,PROVER offchain
```

---

## 2. Full lifecycle — one shadow, mint to solve

```mermaid
sequenceDiagram
    actor Alice
    participant Off as Off-chain prover<br/>(nargo + bb)
    participant ST as ShadowToken
    participant FN as FeatureNFT

    Note over Alice,FN: ---------- MINT ----------
    Alice->>Off: face_disc.prove(image)
    Alice->>Off: landmark_regions_v2.prove(image, owner_pk)
    Alice->>Off: shadow_t10.prove(post-mint manifest)
    Alice->>ST: mintShadow(proofMint, proofDisc, proofT10, c2s[8], ...)
    ST->>ST: verify all 3 proofs<br/>(image_commit equality across mint+disc)
    ST->>ST: check mintedOrigins[imageCommit] == false
    ST->>FN: mint 8 carriers, isInserted=true
    ST->>ST: write Shadow + 8 OCCUPIED slots<br/>+ shadowT10
    ST-->>Alice: ShadowMinted + 8x ShadowSlotMutated<br/>+ ShadowT10Updated

    Note over Alice,FN: ---------- MUTATE one slot ----------
    Alice->>Off: mutate_slot.prove(slot=3,<br/>new_pose, new_dims, new_c2 to self)
    Alice->>Off: shadow_t10.prove(post-mutate manifest)
    Alice->>ST: mutateSlot(args)
    ST->>ST: verify mutate + T10 proofs<br/>(slot's old_lsh == storage)
    ST->>ST: advance slot LSH old -> new<br/>refresh shadowT10
    ST-->>Alice: ShadowSlotMutated + ShadowT10Updated

    Note over Alice,FN: ---------- BATCH MUTATE ----------
    Alice->>Off: 2x mutate_slot.prove(slots A, B)
    Alice->>Off: shadow_t10.prove(post-batch manifest)
    Alice->>ST: mutateBatch([entryA, entryB], newT10, proofT10)
    ST->>ST: per-entry verify + apply (loop)<br/>single T10 refresh at end
    ST-->>Alice: 2x ShadowSlotMutated + ShadowT10Updated

    Note over Alice,FN: ---------- COMMIT z-index ----------
    Alice->>Off: zindex_commit.prove(secret permutation)
    Alice->>Off: shadow_t10.prove(post-z manifest)
    Alice->>ST: setZIndexCommit(args)
    ST->>ST: verify z + T10 proofs
    ST->>ST: write Shadow.zIndexCommit<br/>refresh shadowT10 (now binds zCommit)
    ST-->>Alice: ShadowZIndexCommitSet + ShadowT10Updated

    Note over Alice,FN: ---------- EXTRACT one slot ----------
    Alice->>Off: shadow_t10.prove(post-extract manifest)
    Alice->>ST: extractSlot(slotIdx, newT10, proofT10)
    ST->>ST: slot kind=EMPTY, sync carrier checkpoint
    ST->>FN: extractFromShadow(featureId, ...)<br/>isInserted=false
    ST-->>Alice: SlotExtracted + ShadowT10Updated

    Note over Alice,FN: ---------- SOLVE ----------
    Alice->>Off: solve_shadow_v2.prove(<br/>16 plaintexts + permutation)
    Alice->>ST: solve(args) - no T10, frozen post-solve
    ST->>ST: verify solve proof<br/>(state_commits_root + zCommit + lsh_root)
    ST->>ST: solved=true, zIndexRevealed=packed
    ST->>FN: auto-extractFromShadow for every occupied slot
    ST-->>Alice: ShadowSolved + N x SlotExtracted
```

---

## 3. Slot state machine (per shadow, per slot 0..15)

```mermaid
stateDiagram-v2
    [*] --> EMPTY: fresh slot<br/>(slots 8..15 at mint)
    [*] --> OCCUPIED: mintShadow<br/>(slots 0..7 with origins)
    EMPTY --> OCCUPIED: insertFeature<br/>(carrier reuses mutate_slot proof)
    OCCUPIED --> OCCUPIED: mutateSlot<br/>mutateBatch<br/>transferShadow (LSH advances)
    OCCUPIED --> EMPTY: extractSlot
    OCCUPIED --> Frozen: solve (auto-extract)
    EMPTY --> Frozen: solve
    Frozen --> [*]: shadow solved<br/>(no further state changes)
```

Every transition that mutates the manifest bundles an atomic
`shadow_t10` refresh in the same tx (see diagram 5). `solve` is the
exception: shadow becomes a frozen artifact, no T10 update.

---

## 4. Carrier (FeatureNFT) state machine

```mermaid
stateDiagram-v2
    [*] --> Inserted: mintShadow (mintAtShadowMint)<br/>called only by ShadowToken
    Inserted --> Held: extractSlot<br/>solve (auto-extract)
    Held --> Inserted: insertFeature<br/>(host shadow + slot recorded)
    Held --> Held: ERC-721 transferFrom<br/>(standalone, post-extract)
    Inserted --> Inserted: transferShadow<br/>(carrier ownership rotates with host)

    note right of Inserted
        Standalone transferFrom REVERTS:
        single-host invariant.
        Carrier travels with host shadow.
    end note

    note right of Held
        liveStateHashCheckpoint stores
        the slot's pre-extract LSH.
        Next insertFeature mutate proof
        binds against this checkpoint
        for chain continuity.
    end note
```

---

## 5. Atomic-T10 invariant — every state change in one tx

```mermaid
flowchart TB
    subgraph TX["One transaction"]
        direction TB
        OP[State-changing call<br/>mintShadow / mutateSlot / mutateBatch /<br/>extractSlot / insertFeature /<br/>setZIndexCommit / transferShadow]
        OP_PROOF[Op-specific proof<br/>+ args]
        T10_PROOF[shadow_t10 proof<br/>bound to POST-state manifest]

        OP --> OP_PROOF
        OP --> T10_PROOF

        V_OP{Verify op proof<br/>against contract-built PI}
        V_T10{Verify T10 proof<br/>against post-state PI}

        OP_PROOF --> V_OP
        T10_PROOF --> V_T10

        V_OP -->|pass| APPLY[Apply state change<br/>manifest, ownership, zCommit]
        V_T10 -->|pass| APPLY

        APPLY --> WRITE_T10[Write shadowT10 hi/lo]
        WRITE_T10 --> EVT[Emit op event<br/>+ ShadowT10Updated]

        V_OP -->|fail| REV[revert InvalidProof]
        V_T10 -->|fail| REV
    end

    classDef proof fill:#d1ecf1,stroke:#0c5460
    classDef gate fill:#fff3cd,stroke:#856404
    classDef apply fill:#d4edda,stroke:#155724
    classDef bad fill:#f8d7da,stroke:#721c24
    class OP_PROOF,T10_PROOF proof
    class V_OP,V_T10 gate
    class APPLY,WRITE_T10,EVT apply
    class REV bad
```

**Why this matters.** The public `shadowT10` mapping is the indexer +
bridge + visualizer beacon. By bundling its refresh atomically with
every state-change op, the public composite cannot lag behind storage:
any tx that advances the manifest also advances the public T10, in the
same block, gated on both proofs. `solve` is the single exception —
it freezes the shadow, so T10 stays at its last pre-solve value forever.

---

## 6. Bridge to L1 (post-solve)

```mermaid
sequenceDiagram
    actor Alice
    participant ST as ShadowToken (L2)
    participant BR as ShadowBridgeL2
    participant MSG as L2 Cross-Domain Messenger<br/>(0x4200...0007)
    participant L1 as ShadowMirrorL1

    Note over Alice,L1: shadow MUST be solved=true before bridge

    Alice->>ST: approve(bridge, shadowId)
    Alice->>BR: bridgeShadow(shadowId, revealedPi)
    BR->>ST: read shadowOf, manifestOf,<br/>shadowT10 (post-solve state)
    BR->>ST: transferFrom(alice, bridge, shadowId)<br/>OWNED_ON_L2 -> OWNED_ON_L1
    BR->>BR: encode mintFromBridge(shadowId,<br/>typeIdxs, originFaceIds,<br/>paletteCommits, T10, revealedPi)
    BR->>MSG: sendMessage(l1Mirror, calldata,<br/>DEFAULT_L1_GAS_LIMIT)
    BR-->>Alice: ShadowBridged(shadowId, sender,<br/>messageHash)
    MSG->>L1: relayMessage<br/>(after challenge period)
    L1->>L1: mintFromBridge<br/>(L1 shadow appears)
```

---

## Notes on what's NOT in these diagrams

- **Chain-tip continuity across extract -> insert.** Implicit in the
  carrier state machine (diagram 4): the carrier's
  `liveStateHashCheckpoint` is the bridge between hosts. The next host's
  `mutate_slot` proof PI[6] (`old_lsh`) must equal that checkpoint for
  the proof to verify. End-to-end byte-equal continuity is enforced
  cryptographically.
- **Replay protection.** Each state-change op is replay-resistant. See
  `ReplayProtection.t.sol` for the per-op semantics:
  - `mintShadow` -> `mintedOrigins[imageCommit]` nullifier
  - `solve` -> `Shadow.solved` flag
  - `mutateSlot` / `mutateBatch` / `extractSlot` -> chain-state-bound
    (storage advances, replayed proof's PI mismatches)
  - `transferShadow` -> `NotShadowOwner` after rotation
  - `insertFeature` -> `FeatureAlreadyInserted` single-host guard
  - `setZIndexCommit` -> idempotent-by-design (proof binds only the
    new commit; T10 still passes if manifest unchanged)
- **Mock messenger in tests.** The L2 cross-domain messenger at
  `0x4200...0007` is `vm.etch`'d in `BridgeShadow.t.sol`; production
  uses the OP-Stack predeploy.
