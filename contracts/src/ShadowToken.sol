// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {IVerifier} from "./IVerifier.sol";
import {IFeatureNFT} from "./IFeatureNFT.sol";
import {KeyRegistry} from "./KeyRegistry.sol";
import {PausableMixin} from "./PausableMixin.sol";

/**
 * @title  ShadowToken (v2)
 * @notice Phase-2-v2 composition NFT. A shadow is a 16-slot container
 *         whose contents are atomic FeatureNFTs.
 *
 *         Minting is phased through ShadowMintController:
 *           1. The controller starts a locked pending mint session bound to a
 *              fixed recipient.
 *           2. The controller accepts 8 proof-bound ciphertext payloads in
 *              one or more commitment-checked batches.
 *           3. The controller calls `finalizeMintFromController`, which
 *              creates one shadow, mints 8 FeatureNFTs into slots 0..7, and
 *              refreshes the public T10.
 *
 *         Slot kinds are {EMPTY, OCCUPIED, REVEALED}. OCCUPIED slots are
 *         hidden/encrypted/mutable; REVEALED slots are public, immutable,
 *         and permanently bound to their slot. Public BW generation ignores
 *         REVEALED slots and renderers overlay their full-color plaintext
 *         above hidden BW content.
 *
 *         Mutation surface (v2):
 *           - ShadowMintController begin/submit/finalize phased mint
 *           - mutateSlot             one hidden slot, proof-bound, atomic T10
 *           - mutateBatch            N hidden slots in one tx, atomic T10 at end
 *           - extractSlot            OCCUPIED -> EMPTY, no proof, atomic T10
 *           - insertFeature          EMPTY -> OCCUPIED, proof-bound, atomic T10
 *           - transferShadow         disabled; bounded shadows are non-transferable
 *           - setZIndexCommit        hidden-slot z-order commit, atomic T10
 *           - revealSlots           OCCUPIED -> REVEALED, proof-bound, atomic T10
 *           - bridgeShadow           cross-domain hand-off (unchanged from v1 plan)
 *
 *         No `removeFeature` (collapsed into `extractSlot`).
 *         No `freezeFeature` (custody lock subsumes freezing).
 *         No `c2Commit` / `stateCommitsHash` / `boxesPackedOf` /
 *         `originPose` / per-shadow color (each FeatureNFT carries its
 *         own paletteCommit and originFaceId).
 */
contract ShadowToken is ERC721, PausableMixin {
    // ============== types ==============

    enum SlotKind {
        EMPTY,
        OCCUPIED,
        REVEALED
    }

    /// One manifest entry. `liveStateHash` commits to the encrypted state,
    /// while `mutationCount` and `chainTip` store authoritative event-history
    /// metadata so transfer events do not rely on unbound calldata.
    struct ManifestEntry {
        SlotKind kind;
        uint256 featureId; // 0 when EMPTY; FeatureNFT token id when OCCUPIED
        bytes32 liveStateHash; // poseidon2(stateCommit, ctCommit, c1X, c1Y, count, chainTip)
        uint16 mutationCount; // post-mutation count committed in liveStateHash
        bytes32 chainTip; // latest chain tip committed in liveStateHash
    }

    struct Shadow {
        bytes32 ecdhPubX; // current owner's pk, rotated on transferShadow
        bytes32 ecdhPubY;
        bool solved; // true once every non-empty slot is REVEALED
        bytes32 zIndexCommit; // 0 = identity permutation; governs hidden OCCUPIED slots only
        uint64 mintIdx; // sequential mint counter for indexer ordering
        uint64 mintedAt; // block.number at mint, audit trail
    }


    // ============== constants ==============

    uint256 internal constant N_SLOTS = 16;
    uint256 internal constant N_MINT_ATOMS = 8;

    uint256 internal constant MAX_PLAINTEXT_FIELDS_PER_SLOT = 39;


    /// bn254 Fr field modulus.
    uint256 internal constant FR_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// PI lengths for each verifier (subject to circuit-level finalisation;
    /// kept here as named constants so call sites are self-documenting).
    uint256 internal constant MINT_SHADOW_PI_LEN = 9; // shadowId + imageCommit + pk[2] + lsh/ct/chain/c1 roots
    uint256 internal constant MUTATE_SLOT_PI_LEN = 18;
    uint256 internal constant T10_SHADOW_PI_LEN = 20; // shadowId + newT10[2] + 16x liveStateHash + zIndexCommit
    uint256 internal constant ZINDEX_COMMIT_PI_LEN = 2;
    uint256 internal constant TRANSFER_SHADOW_PI_LEN = 11;
    uint256 internal constant REVEAL_SLOT_PI_LEN = 9;
    uint256 internal constant FACE_DISC_PI_LEN = 1;

    // ============== storage ==============

    address private immutable deployer;
    address public immutable yulSponge;
    address private yulSponge16;
    bool private _yulSponge16Locked;
    address private yulHash2;
    bool private _yulHash2Locked;

    KeyRegistry private keyRegistry;
    bool private _keyRegistryLocked;

    IFeatureNFT private featureNFT;
    bool private _featureNFTLocked;

    address private mintController;
    bool private _mintControllerLocked;

    // Verifier slots. Stored internally; external readers go via
    // `verifierAt(slotId)` (one dispatch entry instead of 7 auto-generated
    // getters; saves ~350 B of runtime bytecode).
    IVerifier internal mintShadowVerifier;
    IVerifier internal faceDiscVerifier;
    IVerifier internal mutateSlotVerifier;
    IVerifier internal t10ShadowVerifier;
    IVerifier internal zIndexCommitVerifier;
    IVerifier internal transferShadowVerifier;
    IVerifier internal solveShadowVerifier;
    /// Bitmap of verifier-slot locks. Bit `slotId` set => slot is
    /// one-shot-locked from setVerifier. Replaces 7 separate booleans
    /// to save runtime bytecode under EIP-170.
    uint8 private _verifierLocks;

    mapping(uint256 => Shadow) private _shadows;
    mapping(uint256 => ManifestEntry[16]) private _manifests;
    mapping(bytes32 => bool) public mintedOrigins;

    /// Public T10 (hi, lo) packed quartets:
    ///   hi = q0 | (q1 << 128); lo = q2 | (q3 << 128).
    /// Refreshed atomically with every state-changing operation per the
    /// "no public lie" rule. Empty for shadows that haven't completed
    /// mint or any subsequent atomic refresh.
    mapping(uint256 => bytes32[2]) public shadowT10;
    /// Monotonic per-shadow BW/downscale history cursor. Incremented exactly
    /// once per successful atomic T10 refresh, so indexers can replay a
    /// shadow's public visual history by filtering ShadowDownscaleUpdated
    /// for the shadowId and ordering by revision.
    mapping(uint256 => uint64) public shadowDownscaleRevision;

    // Feature plaintext/palette bytes are event-published by FeatureNFT during incremental reveal.

    /// Sequential mint counter (audit fix #9): exposed in events for
    /// stable indexer ordering.
    uint64 private mintCounter;

    /// Set of `imageCommit`s that have passed `face_disc` verification
    /// via `registerImage`. `ShadowMintController.beginMintShadow` requires
    /// this before a pending mint session can start.
    mapping(bytes32 => bool) public registeredImages;
    mapping(uint256 => uint8[16]) private _revealedRanks;

    // ============== events ==============

    event ShadowMinted(uint256 indexed shadowId, address indexed minter, uint64 indexed mintIdx, bytes32 imageCommit);
    event ShadowSlotMutated(
        uint256 indexed shadowId,
        uint8 indexed slotIdx,
        bytes32 indexed originFaceId,
        uint256 featureId,
        uint16 mutationCount, // post-bump value
        bytes32 prevChainTip,
        bytes32 newChainTip,
        bytes c2 // per-slot ciphertext (encrypted; hidden content)
    );
    event ShadowSlotEnvelope(uint256 indexed shadowId, uint8 indexed slotIdx, bytes32 c1X, bytes32 c1Y);
    event SlotExtracted(
        uint256 indexed shadowId, uint8 indexed slotIdx, uint256 indexed featureId, bytes32 finalLiveStateHash
    );
    event ShadowFeatureInserted(uint256 indexed shadowId, uint8 indexed slotIdx, uint256 indexed featureId);
    event ShadowTransferred(uint256 indexed shadowId, address indexed to, bytes32 newEcdhPubX, bytes32 newEcdhPubY);
    event ShadowZIndexCommitSet(uint256 indexed shadowId, bytes32 newCommit);
    event ShadowDownscaleUpdated(uint256 indexed shadowId, uint64 indexed revision, bytes32 hi, bytes32 lo);
    event ShadowSlotRevealed(uint256 indexed shadowId, uint8 indexed slotIdx, uint256 indexed featureId, uint8 revealedRank);
    event ImageRegistered(bytes32 indexed imageCommit);


    // ============== errors ==============

    error NotDeployer();
    error NotShadowOwner();
    error AlreadyMinted(bytes32 imageCommit);
    error ImageNotRegistered(bytes32 imageCommit);
    error ImageAlreadyRegistered(bytes32 imageCommit);
    error AlreadySolved();
    error InvalidProof();
    error BadC2Length(uint256 got, uint256 want);
    error BadArrayLen(uint256 got, uint256 want);
    error PkMismatch();
    error MintControllerAlreadySet();

    error VerifierNotSet();
    error VerifierAlreadySet();
    error FeatureNFTAlreadySet();
    error FeatureNFTNotSet();
    error KeyRegistryAlreadySet();

    error SlotOutOfRange(uint8 slotIdx);
    error SlotEmpty(uint8 slotIdx);
    error SlotOccupied(uint8 slotIdx);
    error SlotRevealed(uint8 slotIdx);
    error FeatureNotOwned(uint256 featureId);
    error FeatureAlreadyInserted(uint256 featureId);
    error TransferGated();

    /// Envelope-binding cutover (audit H-01/H-02): emitted when an emitted
    /// byte payload (c2 or solve plaintext) fails to recompute to its
    /// proof-bound digest. Audit H-05 (originFaceId) reuses `InvalidProof`
    /// since the bytecode budget under EIP-170 doesn't allow a third
    /// dedicated error.
    error DigestMismatch();
    error NonCanonicalField();

    // ============== ctor ==============

    constructor(address yulSpongeAddr) ERC721("OMP Shadow", "OMPS") {
        deployer = msg.sender;
        yulSponge = yulSpongeAddr;
        _initPausable(msg.sender);
    }

    // ============== one-shot setters ==============

    function setKeyRegistry(KeyRegistry r) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (_keyRegistryLocked) revert KeyRegistryAlreadySet();
        keyRegistry = r;
        _keyRegistryLocked = true;
    }

    function setFeatureNFT(IFeatureNFT f) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (_featureNFTLocked) revert FeatureNFTAlreadySet();
        featureNFT = f;
        _featureNFTLocked = true;
    }

    function setMintController(address controller) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (_mintControllerLocked) revert MintControllerAlreadySet();
        mintController = controller;
        _mintControllerLocked = true;
    }

    function setYulSponge16(address addr) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (_yulSponge16Locked) revert VerifierAlreadySet();
        yulSponge16 = addr;
        _yulSponge16Locked = true;
    }

    /// One-shot setter for the Poseidon2 hash_2 Yul wrapper. Used to derive
    /// `origin_face_id_i = poseidon2_hash_2(imageCommit, i)` on chain so
    /// phased mint finalization never trusts caller-supplied origin ids alone.
    function setYulHash2(address addr) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (_yulHash2Locked) revert VerifierAlreadySet();
        yulHash2 = addr;
        _yulHash2Locked = true;
    }

    /// One-shot lock + write for any verifier slot. Slot ids match the
    /// `SLOT_*` constants below; lock state is a bitmap on `_verifierLocks`.
    /// Replaces 7 individual `setXVerifier` functions to save runtime
    /// bytecode (each was ~150 B; collapsing all 7 into 1 saves ~1 KB).
    function setVerifier(uint8 slotId, IVerifier v) external {
        if (msg.sender != deployer) revert NotDeployer();
        uint8 mask = uint8(1) << slotId;
        if (_verifierLocks & mask != 0) revert VerifierAlreadySet();
        _verifierLocks |= mask;
        _writeVerifierSlot(slotId, address(v));
    }

    // ============== registerImage ==============

    /// Verify a `face_disc` proof binding `imageCommit` to a valid
    /// face descriptor and mark `imageCommit` as eligible for phased mint.
    /// The mint controller enforces recipient-key ownership and ciphertext
    /// batch binding before calling back into this token to finalize.
    function registerImage(bytes32 imageCommit, bytes calldata proofDisc) external whenNotPaused {
        if (address(faceDiscVerifier) == address(0)) revert VerifierNotSet();
        if (registeredImages[imageCommit]) revert ImageAlreadyRegistered(imageCommit);

        bytes32[] memory piDisc = new bytes32[](FACE_DISC_PI_LEN);
        piDisc[0] = imageCommit;
        _verifyOrRevert(faceDiscVerifier, proofDisc, piDisc);

        registeredImages[imageCommit] = true;
        emit ImageRegistered(imageCommit);
    }

    // ============== phased mint ==============

    /// Fixed-size 8-element arrays let us hash-root via sponge_8_pad16
    /// (16-field buffer fed to Poseidon2YulSponge16 with trailing zeros).
    struct MintShadowArgs {
        bytes proofMint;
        bytes32 imageCommit;
        bytes32[8] ctCommits;
        bytes32[8] liveStateHashInits;
        bytes32[8] chainTips;
        bytes32[8] c1Xs;
        bytes32[8] c1Ys;
        bytes32[8] paletteCommits;
        bytes32[8] paletteSaltCts;
        bytes32[8] saltC1Xs;
        bytes32[8] saltC1Ys;
        bytes32[8] originFaceIds;
        bytes32[2] newT10;
    }
    // Mint domain tag is pinned in circuits/landmark_regions_v2 and CryptoInvariants.t.sol.

    function finalizeMintFromController(
        MintShadowArgs calldata args,
        address recipient,
        bytes32 ownerPkX,
        bytes32 ownerPkY,
        bytes calldata proofT10
    ) external whenNotPaused returns (uint256 shadowId) {
        if (msg.sender != mintController) revert NotDeployer();
        if (address(featureNFT) == address(0)) revert FeatureNFTNotSet();
        if (address(keyRegistry) == address(0)) revert VerifierNotSet();
        if (yulHash2 == address(0)) revert VerifierNotSet();

        bytes32 imageCommit = args.imageCommit;
        if (mintedOrigins[imageCommit]) revert AlreadyMinted(imageCommit);
        if (!registeredImages[imageCommit]) revert ImageNotRegistered(imageCommit);
        shadowId = uint256(imageCommit) % FR_MOD;

        for (uint256 i = 0; i < N_MINT_ATOMS; i++) {
            if (_hash2(imageCommit, bytes32(i)) != args.originFaceIds[i]) revert InvalidProof();
        }

        mintedOrigins[imageCommit] = true;
        uint64 idx = _applyMintState(args, shadowId, recipient, ownerPkX, ownerPkY);
        _refreshT10Atomically(shadowId, args.newT10, proofT10);
        emit ShadowMinted(shadowId, recipient, idx, imageCommit);
    }

    function _applyMintState(
        MintShadowArgs calldata args,
        uint256 shadowId,
        address recipient,
        bytes32 ownerPkX,
        bytes32 ownerPkY
    ) internal returns (uint64 idx) {
        Shadow storage s = _shadows[shadowId];
        s.ecdhPubX = ownerPkX;
        s.ecdhPubY = ownerPkY;
        s.solved = false;
        s.zIndexCommit = bytes32(0);
        idx = ++mintCounter;
        s.mintIdx = idx;
        s.mintedAt = uint64(block.number);

        IFeatureNFT fn = featureNFT;
        ManifestEntry[16] storage manifest = _manifests[shadowId];
        for (uint256 i = 0; i < N_MINT_ATOMS; i++) {
            _mintOneAtom(args, shadowId, recipient, fn, manifest, i);
        }
        _safeMint(recipient, shadowId);
    }

    function _mintOneAtom(
        MintShadowArgs calldata args,
        uint256 shadowId,
        address recipient,
        IFeatureNFT fn,
        ManifestEntry[16] storage manifest,
        uint256 i
    ) internal {
        uint256 featureId = fn.mintAtShadowMint(
            shadowId,
            uint8(i),
            uint8(i),
            args.originFaceIds[i],
            IFeatureNFT.PaletteAtMint({
                commit: args.paletteCommits[i],
                saltCt: args.paletteSaltCts[i],
                saltC1X: args.saltC1Xs[i],
                saltC1Y: args.saltC1Ys[i]
            }),
            args.liveStateHashInits[i],
            recipient
        );
        manifest[i] = ManifestEntry({
            kind: SlotKind.OCCUPIED,
            featureId: featureId,
            liveStateHash: args.liveStateHashInits[i],
            mutationCount: 0,
            chainTip: args.chainTips[i]
        });
        emit ShadowSlotMutated(
            shadowId,
            uint8(i),
            args.originFaceIds[i],
            featureId,
            0,
            bytes32(0),
            args.chainTips[i],
            ""
        );
        _emitSlotEnvelope(shadowId, uint8(i), uint256(args.c1Xs[i]), uint256(args.c1Ys[i]));
    }

    // ============== mutateSlot ==============

    /// One-slot atomic mutation: verify mutate_slot + shadow_t10 proofs,
    /// rewrite slot's liveStateHash, refresh T10.
    /// Calldata struct for mutateSlot. Bundles the per-slot proof,
    /// re-encrypted ciphertext, the new live-state hash, and the
    /// atomic T10 refresh proof.
    struct MutateSlotArgs {
        uint256 shadowId;
        uint8 slotIdx;
        bytes proofMutate;
        uint256 newC1X; // public component of new ECIES ephemeral
        uint256 newC1Y;
        bytes32 newLiveStateHash;
        bytes32 newCtCommit; // = sponge_39(c2); contract sponges c2 to bind
        uint16 c2FieldCount; // == new_c2.length / 32 (constant 39 in v2)
        bytes c2; // emitted via event; sponge-bound to newCtCommit
        bytes32 prevChainTip; // pre-bump chain tip (== old_chain_tip)
        bytes32 newChainTip; // post-bump chain tip
        uint16 prevMutationCount; // pre-bump count (uint16 in chain semantics)
        uint16 newMutationCount; // == prev + 1
        bytes32[2] newT10; // (hi, lo) packed quartets
        bytes proofT10; // bundled atomic T10 refresh
    }

    function mutateSlot(MutateSlotArgs calldata args) external whenNotPaused {
        if (_ownerOf(args.shadowId) != msg.sender) revert NotShadowOwner();
        Shadow storage s = _shadows[args.shadowId];
        if (s.solved) revert AlreadySolved();
        if (args.slotIdx >= N_SLOTS) revert SlotOutOfRange(args.slotIdx);
        if (address(featureNFT) == address(0)) revert FeatureNFTNotSet();

        uint256 expectedC2Bytes = uint256(args.c2FieldCount) * 32;
        if (args.c2.length != expectedC2Bytes) {
            revert BadC2Length(args.c2.length, expectedC2Bytes);
        }

        ManifestEntry storage m = _manifests[args.shadowId][args.slotIdx];
        if (m.kind == SlotKind.EMPTY) revert SlotEmpty(args.slotIdx);
        if (m.kind == SlotKind.REVEALED) revert SlotRevealed(args.slotIdx);

        // ---- 1. mutate_slot proof ----
        bytes32[] memory piMut = _buildSlotPI(
            SlotPIInputs({
                shadowId: args.shadowId,
                slotIdx: args.slotIdx,
                featureId: m.featureId,
                oldLsh: m.liveStateHash,
                newLsh: args.newLiveStateHash,
                newCtCommit: args.newCtCommit,
                newC1X: args.newC1X,
                newC1Y: args.newC1Y,
                c2FieldCount: args.c2FieldCount,
                prevChainTip: args.prevChainTip,
                newChainTip: args.newChainTip,
                prevCount: args.prevMutationCount,
                newCount: args.newMutationCount
            })
        );
        _verifyOrRevert(mutateSlotVerifier, args.proofMutate, piMut);

        // ---- 2. bind emitted c2 to proof-bound newCtCommit (audit H-02) ----
        // The proof binds args.newCtCommit (PI[8]) to the witness c2's
        // sponge_39, but does NOT bind the emitted calldata c2. Pre-fix the
        // chain accepted any c2 in calldata; off-chain consumers had to
        // re-verify out-of-band. Now the contract recomputes sponge_39 over
        // the emitted c2 via the Yul wrapper and asserts equality with
        // newCtCommit before applying state. Tampered c2 reverts before any
        // mutation lands, so every emitted byte is proof-bound at the
        // byte level.
        _assertCtCommitBinding(args.c2, args.newCtCommit);
        _assertCanonicalField(args.newC1X);
        _assertCanonicalField(args.newC1Y);

        // ---- 3. apply state change ----
        bytes32 prevLSH = m.liveStateHash;
        m.liveStateHash = args.newLiveStateHash;
        m.mutationCount = uint16(uint256(piMut[17]));
        m.chainTip = piMut[15];
        // ---- 4. atomic T10 refresh ----
        _refreshT10Atomically(args.shadowId, args.newT10, args.proofT10);

        // ---- 5. event ----
        // The proof binds prev_chain_tip (PI[14]), new_chain_tip (PI[15]),
        // prev_count (PI[16]), and new_count (PI[17]) so an indexer can
        // reconstruct the chain history without trusting the emitter.
        emit ShadowSlotMutated(
            args.shadowId,
            args.slotIdx,
            piMut[4], // origin_face_id from PI
            uint256(piMut[2]), // feature_id from PI
            uint16(uint256(piMut[17])), // post-bump mutation count
            piMut[14], // prev chain tip
            piMut[15], // new chain tip
            args.c2
        );
        _emitSlotEnvelope(args.shadowId, args.slotIdx, args.newC1X, args.newC1Y);
        // Keep the prior hash read explicit for auditability.
        prevLSH;
    }

    /// Build the 18-field PI for mutate_slot from the args + chain state.
    /// Layout matches circuits/mutate_slot/src/main.nr (18 fields):
    ///   PI[0]  shadow_id            (transcript)
    ///   PI[1]  slot_idx
    ///   PI[2]  feature_id           (chain)
    ///   PI[3]  type_idx             (chain)
    ///   PI[4]  origin_face_id       (chain)
    ///   PI[5]  palette_commit       (chain)
    ///   PI[6]  old_live_state_hash  (chain)
    ///   PI[7]  new_live_state_hash  (args)
    ///   PI[8]  new_ct_commit        (args -- bound on-chain via sponge below)
    ///   PI[9]  new_c1_x             (args -- proof-bound and emitted for decryptability)
    ///   PI[10] new_c1_y             (args -- proof-bound and emitted for decryptability)
    ///   PI[11] c2_field_count       (args)
    ///   PI[12] owner_pk_x           (chain)
    ///   PI[13] owner_pk_y           (chain)
    ///   PI[14] prev_chain_tip       (args)
    ///   PI[15] new_chain_tip        (args, derived in proof)
    ///   PI[16] prev_mutation_count  (args)
    ///   PI[17] new_mutation_count   (args, derived in proof)
    /// Inputs to `_buildSlotPI`. Wraps the 11 slot-level fields a
    /// mutate/insert PI build needs so we can pass them by struct and
    /// reuse one builder across the three call sites (mutateSlot,
    /// mutateBatch, insertFeature). Without this consolidation the
    /// three builders were ~80% identical and ate ~600 B of bytecode.
    struct SlotPIInputs {
        uint256 shadowId;
        uint8 slotIdx;
        uint256 featureId;
        bytes32 oldLsh; // m.liveStateHash for mutate; fn.checkpoint for insert
        bytes32 newLsh;
        bytes32 newCtCommit;
        uint256 newC1X;
        uint256 newC1Y;
        uint16 c2FieldCount;
        bytes32 prevChainTip;
        bytes32 newChainTip;
        uint16 prevCount;
        uint16 newCount;
    }

    /// Build the 18-field mutate_slot PI from the canonical slot-level
    /// inputs + chain state. Layout matches
    /// `circuits/mutate_slot/src/main.nr` byte-for-byte.
    function _buildSlotPI(SlotPIInputs memory inp) internal view returns (bytes32[] memory pi) {
        pi = new bytes32[](MUTATE_SLOT_PI_LEN);
        IFeatureNFT fn = featureNFT;
        pi[0] = bytes32(inp.shadowId);
        pi[1] = bytes32(uint256(inp.slotIdx));
        pi[2] = bytes32(inp.featureId);
        pi[3] = bytes32(uint256(fn.typeIdxOf(inp.featureId)));
        pi[4] = fn.originFaceIdOf(inp.featureId);
        pi[5] = fn.paletteCommitOf(inp.featureId);
        pi[6] = inp.oldLsh;
        pi[7] = inp.newLsh;
        pi[8] = inp.newCtCommit;
        pi[9] = bytes32(inp.newC1X);
        pi[10] = bytes32(inp.newC1Y);
        pi[11] = bytes32(uint256(inp.c2FieldCount));
        pi[12] = _shadows[inp.shadowId].ecdhPubX;
        pi[13] = _shadows[inp.shadowId].ecdhPubY;
        pi[14] = inp.prevChainTip;
        pi[15] = inp.newChainTip;
        pi[16] = bytes32(uint256(inp.prevCount));
        pi[17] = bytes32(uint256(inp.newCount));
    }

    /// Verify the bundled shadow_t10 proof and write `shadowT10` atomically.
    /// Builds piT10 from chain state's CURRENT manifest (post-mutate write).
    /// Verify a proof against a verifier slot or revert. Collapses the
    /// `if not set / try verify / not ok / catch` pattern that appears
    /// on every atomic flow (mutate, batch, insert, mint, transfer,
    /// solve, T10, zindex). Saves ~700 B of runtime bytecode by
    /// deduplicating the call shape.
    function _verifyOrRevert(IVerifier v, bytes calldata proof, bytes32[] memory pi) internal view {
        if (address(v) == address(0)) revert VerifierNotSet();
        try v.verify(proof, pi) returns (bool ok) {
            if (!ok) revert InvalidProof();
        } catch {
            revert InvalidProof();
        }
    }
    function _emitSlotEnvelope(uint256 shadowId, uint8 slotIdx, uint256 c1X, uint256 c1Y) internal {
        emit ShadowSlotEnvelope(shadowId, slotIdx, bytes32(c1X), bytes32(c1Y));
    }



    function _refreshT10Atomically(uint256 shadowId, bytes32[2] memory newT10, bytes calldata proofT10) internal {
        bytes32[] memory piT10 = new bytes32[](T10_SHADOW_PI_LEN);
        Shadow storage s = _shadows[shadowId];
        ManifestEntry[16] storage manifest = _manifests[shadowId];
        piT10[0] = bytes32(shadowId);
        piT10[1] = s.zIndexCommit;
        piT10[2] = newT10[0]; // hi
        piT10[3] = newT10[1]; // lo
        for (uint256 i = 0; i < N_SLOTS; i++) {
            // Public BW/T10 tracks hidden OCCUPIED slots only. EMPTY and
            // REVEALED slots contribute zero so revealed full-color features
            // are overlaid by renderers instead of re-entering hidden BW.
            piT10[4 + i] = manifest[i].kind == SlotKind.OCCUPIED ? manifest[i].liveStateHash : bytes32(0);
        }

        _verifyOrRevert(t10ShadowVerifier, proofT10, piT10);

        shadowT10[shadowId][0] = newT10[0];
        shadowT10[shadowId][1] = newT10[1];
        uint64 revision = shadowDownscaleRevision[shadowId] + 1;
        shadowDownscaleRevision[shadowId] = revision;
        emit ShadowDownscaleUpdated(shadowId, revision, newT10[0], newT10[1]);
    }

    /// One per-slot mutation entry inside a `mutateBatch` call. Mirrors
    /// `MutateSlotArgs` minus the `shadowId` (carried once at the batch
    /// level) and minus `newT10`/`proofT10` (one refresh at end of batch).
    /// Spec line 806 listed parallel arrays; we use struct-of-arrays to
    /// dodge stack-too-deep at the entry point and to keep PI building
    /// per-entry self-documenting. Field semantics are byte-for-byte
    /// identical to `MutateSlotArgs`.
    struct MutateSlotEntry {
        uint8 slotIdx;
        bytes proofMutate;
        uint256 newC1X;
        uint256 newC1Y;
        bytes32 newLiveStateHash;
        bytes32 newCtCommit; // == sponge_39(c2); contract sponges c2 to bind
        uint16 c2FieldCount;
        bytes c2; // emitted via event; sponge-bound to newCtCommit
        bytes32 prevChainTip;
        bytes32 newChainTip;
        uint16 prevMutationCount;
        uint16 newMutationCount;
    }

    /// Calldata struct for mutateBatch. One T10 refresh covers the whole
    /// batch -- the spec's gas-amortization rationale for the API. Per
    /// spec line 821, practical batch ceiling is ~2 mutate proofs per tx
    /// within the 16.7M block-gas cap.
    struct MutateBatchArgs {
        uint256 shadowId;
        MutateSlotEntry[] entries; // MUST be non-empty
        bytes32[2] newT10; // post-batch (hi, lo) packed quartets
        bytes proofT10; // bundled atomic T10 against post-batch manifest
    }

    /// Mutate N slots in one transaction with a single T10 refresh at
    /// the end. The atomic-T10 invariant holds because the T10 proof
    /// binds the *post-batch* manifest -- at no point between txs is
    /// `shadowT10` stale.
    /// Reverts on:
    ///   - empty entries array (BadArrayLen)
    ///   - non-owner caller (NotShadowOwner)
    ///   - shadow already solved (AlreadySolved)
    ///   - any per-entry failure (slot OOR, slot EMPTY, proof, c2 length,
    ///     sponge mismatch) -- entire batch aborts atomically
    function mutateBatch(MutateBatchArgs calldata args) external whenNotPaused {
        if (_ownerOf(args.shadowId) != msg.sender) revert NotShadowOwner();
        Shadow storage s = _shadows[args.shadowId];
        if (s.solved) revert AlreadySolved();
        if (address(featureNFT) == address(0)) revert FeatureNFTNotSet();
        uint256 n = args.entries.length;
        if (n == 0) revert BadArrayLen(0, 1);

        // ---- 1..N: verify + apply each entry ----
        for (uint256 i = 0; i < n; i++) {
            _verifyAndApplyOneMutate(args.shadowId, args.entries[i]);
        }

        // ---- N+1: single atomic T10 refresh against post-batch manifest ----
        _refreshT10Atomically(args.shadowId, args.newT10, args.proofT10);
    }

    /// Verify one mutate_slot proof + apply state for a single entry.
    /// Mirrors the inner body of `mutateSlot` minus the T10 refresh
    /// (which the batch caller does once at the end). Extracted as a
    /// helper so the batch loop body stays small enough that Solidity
    /// can compile it without stack-too-deep.
    function _verifyAndApplyOneMutate(uint256 shadowId, MutateSlotEntry calldata e) internal {
        if (e.slotIdx >= N_SLOTS) revert SlotOutOfRange(e.slotIdx);
        uint256 expectedC2Bytes = uint256(e.c2FieldCount) * 32;
        if (e.c2.length != expectedC2Bytes) {
            revert BadC2Length(e.c2.length, expectedC2Bytes);
        }

        ManifestEntry storage m = _manifests[shadowId][e.slotIdx];
        if (m.kind == SlotKind.EMPTY) revert SlotEmpty(e.slotIdx);
        if (m.kind == SlotKind.REVEALED) revert SlotRevealed(e.slotIdx);

        // Build PI for this entry (matches mutate_slot circuit byte-for-byte).
        bytes32[] memory piMut = _buildSlotPI(
            SlotPIInputs({
                shadowId: shadowId,
                slotIdx: e.slotIdx,
                featureId: m.featureId,
                oldLsh: m.liveStateHash,
                newLsh: e.newLiveStateHash,
                newCtCommit: e.newCtCommit,
                newC1X: e.newC1X,
                newC1Y: e.newC1Y,
                c2FieldCount: e.c2FieldCount,
                prevChainTip: e.prevChainTip,
                newChainTip: e.newChainTip,
                prevCount: e.prevMutationCount,
                newCount: e.newMutationCount
            })
        );
        _verifyOrRevert(mutateSlotVerifier, e.proofMutate, piMut);

        // Envelope-binding cutover (audit H-02): bind emitted c2 to
        // proof-bound newCtCommit. Whole batch aborts atomically on the
        // first mismatch (BadC2Length check above already rejected
        // length-tampered c2; this catches content-tampered c2).
        _assertCtCommitBinding(e.c2, e.newCtCommit);
        _assertCanonicalField(e.newC1X);
        _assertCanonicalField(e.newC1Y);

        // Apply state: write new LSH and proof-bound event-history metadata;
        // manifest's kind/featureId are unchanged by mutation.
        m.liveStateHash = e.newLiveStateHash;
        m.mutationCount = uint16(uint256(piMut[17]));
        m.chainTip = piMut[15];
        // Emit per-slot event so indexers can reconstruct chain history.
        emit ShadowSlotMutated(
            shadowId,
            e.slotIdx,
            piMut[4], // origin_face_id from PI
            uint256(piMut[2]), // feature_id from PI
            uint16(uint256(piMut[17])), // post-bump mutation count
            piMut[14], // prev chain tip
            piMut[15], // new chain tip
            e.c2
        );
        _emitSlotEnvelope(shadowId, e.slotIdx, e.newC1X, e.newC1Y);
    }

    // ============== extractSlot ==============

    /// Proofless body + bundled T10 refresh: copy slot.liveStateHash into
    /// the carrier's checkpoint, clear isInserted, zero slot, refresh T10.
    function extractSlot(uint256 shadowId, uint8 slotIdx, bytes32[2] calldata newT10, bytes calldata proofT10)
        external
        whenNotPaused
        returns (uint256 featureId)
    {
        if (_ownerOf(shadowId) != msg.sender) revert NotShadowOwner();
        Shadow storage s = _shadows[shadowId];
        if (s.solved) revert AlreadySolved();
        if (slotIdx >= N_SLOTS) revert SlotOutOfRange(slotIdx);
        if (address(featureNFT) == address(0)) revert FeatureNFTNotSet();

        ManifestEntry storage m = _manifests[shadowId][slotIdx];
        if (m.kind == SlotKind.EMPTY) revert SlotEmpty(slotIdx);
        if (m.kind == SlotKind.REVEALED) revert SlotRevealed(slotIdx);

        // Capture the live state before we clear, then sync into the
        // carrier's checkpoint and release custody.
        featureId = m.featureId;
        bytes32 finalLsh = m.liveStateHash;

        // Clear the slot BEFORE the cross-contract call. If the
        // FeatureNFT misbehaves, our manifest is already in the post-extract
        // state and the contract is reentrancy-safe.
        m.kind = SlotKind.EMPTY;
        m.featureId = 0;
        m.liveStateHash = bytes32(0);
        m.mutationCount = 0;
        m.chainTip = bytes32(0);

        featureNFT.extractFromShadow(featureId, shadowId, slotIdx, finalLsh);

        // Atomic T10 refresh against the post-extract LSH array.
        _refreshT10Atomically(shadowId, newT10, proofT10);

        emit SlotExtracted(shadowId, slotIdx, featureId, finalLsh);
    }

    // ============== insertFeature ==============

    /// EMPTY -> OCCUPIED with proof + atomic T10. Reuses the
    /// `mutate_slot` circuit shape per Open Q2: the FeatureNFT's
    /// liveStateHashCheckpoint is the proof's `old_liveStateHash`.
    struct InsertFeatureArgs {
        uint256 shadowId;
        uint8 slotIdx;
        uint256 featureId;
        bytes proofInsert;
        uint256 newC1X;
        uint256 newC1Y;
        bytes32 newLiveStateHash;
        bytes32 newCtCommit;
        uint16 c2FieldCount;
        bytes c2;
        bytes32 prevChainTip; // == carrier's checkpoint chain tip
        bytes32 newChainTip;
        uint16 prevMutationCount;
        uint16 newMutationCount;
        bytes32[2] newT10;
        bytes proofT10;
    }

    function insertFeature(InsertFeatureArgs calldata args) external whenNotPaused {
        if (_ownerOf(args.shadowId) != msg.sender) revert NotShadowOwner();
        Shadow storage s = _shadows[args.shadowId];
        if (s.solved) revert AlreadySolved();
        if (args.slotIdx >= N_SLOTS) revert SlotOutOfRange(args.slotIdx);
        if (address(featureNFT) == address(0)) revert FeatureNFTNotSet();

        IFeatureNFT fn = featureNFT;
        if (fn.ownerOfFeature(args.featureId) != msg.sender) {
            revert FeatureNotOwned(args.featureId);
        }
        if (fn.isInserted(args.featureId)) {
            revert FeatureAlreadyInserted(args.featureId);
        }

        ManifestEntry storage m = _manifests[args.shadowId][args.slotIdx];
        if (m.kind != SlotKind.EMPTY) revert SlotOccupied(args.slotIdx);

        uint256 expectedC2Bytes = uint256(args.c2FieldCount) * 32;
        if (args.c2.length != expectedC2Bytes) {
            revert BadC2Length(args.c2.length, expectedC2Bytes);
        }

        // ---- 1. verify mutate_slot proof against carrier checkpoint (helper
        // dodges stack-too-deep on the entry point) + return PI for events ----
        bytes32[] memory piMut = _verifyInsertProof(args, fn);

        // Envelope-binding cutover (audit H-02): bind emitted c2 to
        // proof-bound newCtCommit before any state change. Reverts with
        // DigestMismatch if sponge_39(args.c2) != args.newCtCommit.
        _assertCtCommitBinding(args.c2, args.newCtCommit);
        _assertCanonicalField(args.newC1X);
        _assertCanonicalField(args.newC1Y);

        // ---- 3. apply: slot OCCUPIED, carrier inserted ----
        m.kind = SlotKind.OCCUPIED;
        m.featureId = args.featureId;
        m.liveStateHash = args.newLiveStateHash;
        m.mutationCount = args.newMutationCount;
        m.chainTip = args.newChainTip;
        fn.insertIntoShadow(args.featureId, args.shadowId, args.slotIdx);

        // ---- 4. atomic T10 refresh ----
        _refreshT10Atomically(args.shadowId, args.newT10, args.proofT10);

        // ---- 5. events ----
        emit ShadowFeatureInserted(args.shadowId, args.slotIdx, args.featureId);
        emit ShadowSlotMutated(
            args.shadowId,
            args.slotIdx,
            piMut[4], // origin_face_id from PI
            args.featureId,
            args.newMutationCount,
            args.prevChainTip,
            args.newChainTip,
            args.c2
        );
        _emitSlotEnvelope(args.shadowId, args.slotIdx, args.newC1X, args.newC1Y);
    }

    /// Build the insert PI from carrier checkpoint + verify proof.
    /// Extracted from `insertFeature` body to dodge stack-too-deep --
    /// the entry-point body holds many calldata locals + an 18-field PI
    /// array + a SlotPIInputs struct simultaneously, which exceeds the
    /// 16-stack-slot Solidity budget without via-ir.
    function _verifyInsertProof(InsertFeatureArgs calldata args, IFeatureNFT fn)
        internal
        view
        returns (bytes32[] memory piMut)
    {
        piMut = _buildSlotPI(
            SlotPIInputs({
                shadowId: args.shadowId,
                slotIdx: args.slotIdx,
                featureId: args.featureId,
                oldLsh: fn.liveStateHashCheckpointOf(args.featureId),
                newLsh: args.newLiveStateHash,
                newCtCommit: args.newCtCommit,
                newC1X: args.newC1X,
                newC1Y: args.newC1Y,
                c2FieldCount: args.c2FieldCount,
                prevChainTip: args.prevChainTip,
                newChainTip: args.newChainTip,
                prevCount: args.prevMutationCount,
                newCount: args.newMutationCount
            })
        );
        _verifyOrRevert(mutateSlotVerifier, args.proofInsert, piMut);
    }

    // ============== transferShadow ==============

    /// Disabled for bounded shadows: ownership cannot move while any slot is
    /// OCCUPIED or REVEALED. Kept as a reverting entry point so stale callers
    /// fail explicitly instead of silently bypassing the new non-transferable rule.
    /// Calldata struct for transferShadow. All 16 per-slot arrays are
    /// fixed-size to make the contract's hash-root reconstruction
    /// (sponge_16 over each) deterministic and EIP-170-cheap.
    struct TransferShadowArgs {
        uint256 shadowId;
        address to;
        bytes proof; // transfer_shadow_v2 proof
        bytes32[16] newLiveStateHashes; // post-rotation; chain writes these
        bytes32[16] newChainTips; // post-rotation per-slot chain tips (committed in proof)
        uint256[16] newC1Xs; // per-slot fresh ECIES ephemeral c1.x
        uint256[16] newC1Ys; // per-slot fresh ECIES ephemeral c1.y
        bytes32[16] newCtCommits; // per-slot sponge_39(c2) digest; zero for empty slots (envelope binding H-02)
        uint16[16] newMutationCounts; // == prev + 1 for occupied; 0 for empty
        bytes[] c2s; // 16 entries; empty bytes for empty slots
        bytes32[2] newT10; // post-rotation T10 (hi, lo)
        bytes proofT10; // bundled atomic T10 proof
    }

    function transferShadow(TransferShadowArgs calldata args) external whenNotPaused {
        if (_ownerOf(args.shadowId) != msg.sender) revert NotShadowOwner();
        revert TransferGated();
    }

    /// Verify the transfer_shadow_v2 proof. Reconstructs PI from chain
    /// state (prev_lsh_root) and from calldata (newLshRoot, newChainTipsRoot)
    /// via the Yul sponge_16 staticcall.
    function _verifyTransferProof(TransferShadowArgs calldata args, bytes32 recipientPkX, bytes32 recipientPkY)
        internal
        view
    {
        Shadow storage s = _shadows[args.shadowId];
        bytes32[] memory piT = new bytes32[](TRANSFER_SHADOW_PI_LEN);
        piT[0] = bytes32(args.shadowId);
        piT[1] = recipientPkX;
        piT[2] = recipientPkY;
        piT[3] = _sponge16Manifest(_manifests[args.shadowId]);
        piT[4] = _sponge16BytesArr(args.newLiveStateHashes);
        piT[5] = s.ecdhPubX;
        piT[6] = s.ecdhPubY;
        piT[7] = _sponge16BytesArr(args.newChainTips);
        piT[8] = _sponge16BytesArr(args.newCtCommits);
        piT[9] = _sponge16UintArr(args.newC1Xs);
        piT[10] = _sponge16UintArr(args.newC1Ys);
        _verifyOrRevert(transferShadowVerifier, args.proof, piT);
    }

    /// Apply post-transfer state to chain: write new per-slot LSH, rotate
    /// carriers, rotate Shadow.ecdhPub, rotate the shadow's ERC-721 owner.
    function _applyTransferState(TransferShadowArgs calldata args, bytes32 recipientPkX, bytes32 recipientPkY)
        internal
    {
        IFeatureNFT fn = featureNFT;
        ManifestEntry[16] storage manifest = _manifests[args.shadowId];
        for (uint256 i = 0; i < N_SLOTS; i++) {
            ManifestEntry storage m = manifest[i];
            if (m.kind == SlotKind.OCCUPIED) {
                _applyOccupiedTransferSlot(args, i, m, fn);
            } else {
                if (m.kind == SlotKind.REVEALED) {
                    fn.rotateInsertedOwner(m.featureId, args.shadowId, args.to);
                }
                if (args.c2s[i].length != 0) {
                    revert BadC2Length(args.c2s[i].length, 0);
                }
                if (args.newLiveStateHashes[i] != bytes32(0)) revert InvalidProof();
                if (args.newChainTips[i] != bytes32(0)) revert InvalidProof();
                if (args.newCtCommits[i] != bytes32(0)) revert InvalidProof();
                if (args.newC1Xs[i] != 0 || args.newC1Ys[i] != 0) revert InvalidProof();
                if (args.newMutationCounts[i] != 0) revert InvalidProof();
            }
        }
        Shadow storage s = _shadows[args.shadowId];
        s.ecdhPubX = recipientPkX;
        s.ecdhPubY = recipientPkY;
        // ERC-721 ownership of the shadow itself rotates here. _update bypasses
        // the public transferFrom guard; we are the proof-bound path and have
        // already verified the rotation proof.
        _update(args.to, args.shadowId, address(0));
    }

    function _applyOccupiedTransferSlot(
        TransferShadowArgs calldata args,
        uint256 i,
        ManifestEntry storage m,
        IFeatureNFT fn
    ) internal {
        if (m.mutationCount == type(uint16).max) revert InvalidProof();
        uint16 newMutationCount = m.mutationCount + 1;
        bytes32 prevChainTip = m.chainTip;
        uint256 featureId = m.featureId;

        m.liveStateHash = args.newLiveStateHashes[i];
        fn.rotateInsertedOwner(featureId, args.shadowId, args.to);

        // Envelope binding: c2 bytes are canonical and digest-bound; c1
        // coordinates are canonical and root-bound by transfer PI[9..10].
        _assertCanonicalField(args.newC1Xs[i]);
        _assertCanonicalField(args.newC1Ys[i]);
        _assertSlotEnvelope(args.c2s[i], args.newCtCommits[i]);
        if (args.newMutationCounts[i] != newMutationCount) revert InvalidProof();

        m.mutationCount = newMutationCount;
        m.chainTip = args.newChainTips[i];

        emit ShadowSlotMutated(
            args.shadowId,
            uint8(i),
            fn.originFaceIdOf(featureId),
            featureId,
            newMutationCount,
            prevChainTip,
            args.newChainTips[i],
            args.c2s[i]
        );
        _emitSlotEnvelope(args.shadowId, uint8(i), args.newC1Xs[i], args.newC1Ys[i]);
    }

    /// Hash only hidden OCCUPIED slots' liveStateHash values. EMPTY and
    /// REVEALED slots both contribute zero to hidden BW/T10 generation.
    function _sponge16Manifest(ManifestEntry[16] storage manifest) internal view returns (bytes32) {
        bytes memory buf = new bytes(N_SLOTS * 32);
        for (uint256 i = 0; i < N_SLOTS; i++) {
            bytes32 v = manifest[i].kind == SlotKind.OCCUPIED ? manifest[i].liveStateHash : bytes32(0);
            _assertCanonicalField(uint256(v));
            assembly { mstore(add(add(buf, 32), mul(i, 32)), v) }
        }
        return _sponge16(buf);
    }


    /// Hash a fixed-size 16-element bytes32 array via the Yul sponge_16.
    function _sponge16BytesArr(bytes32[16] calldata arr) internal view returns (bytes32) {
        bytes memory buf = new bytes(N_SLOTS * 32);
        for (uint256 i = 0; i < N_SLOTS; i++) {
            bytes32 v = arr[i];
            _assertCanonicalField(uint256(v));
            assembly { mstore(add(add(buf, 32), mul(i, 32)), v) }
        }
        return _sponge16(buf);
    }


    /// Hash a fixed-size 16-element uint256 array via the Yul sponge_16 after
    /// rejecting non-canonical field encodings. This is used for public ECIES
    /// c1 coordinates so verifier-bound roots commit to exact field elements.
    function _sponge16UintArr(uint256[16] calldata arr) internal view returns (bytes32) {
        bytes memory buf = new bytes(N_SLOTS * 32);
        for (uint256 i = 0; i < N_SLOTS; i++) {
            uint256 v = arr[i];
            _assertCanonicalField(v);
            assembly { mstore(add(add(buf, 32), mul(i, 32)), v) }
        }
        return _sponge16(buf);
    }

    /// Memory variant of _sponge16BytesArr. Used by code paths that build
    /// the array locally (e.g. solve verification builds state_commits in
    /// memory by sponging per-slot plaintexts).
    function _sponge16BytesArrMem(bytes32[16] memory arr) internal view returns (bytes32) {
        bytes memory buf = new bytes(N_SLOTS * 32);
        for (uint256 i = 0; i < N_SLOTS; i++) {
            bytes32 v = arr[i];
            _assertCanonicalField(uint256(v));
            assembly { mstore(add(add(buf, 32), mul(i, 32)), v) }
        }
        return _sponge16(buf);
    }

    /// Yul Poseidon2 sponge_16 staticcall over exactly 512 bytes.
    function _sponge16(bytes memory data) internal view returns (bytes32 digest) {
        address y = yulSponge16;
        assembly ("memory-safe") {
            let ok := staticcall(gas(), y, add(data, 32), 512, 0, 32)
            if iszero(ok) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
            digest := mload(0)
        }
    }

    // ============== setZIndexCommit ==============

    /// Per-shadow z-order commit; bundled with T10 refresh because
    /// changing z-order changes what the public composite would render to.
    struct SetZIndexCommitArgs {
        uint256 shadowId;
        bytes32 newCommit;
        bytes proofZ;
        bytes32[2] newT10;
        bytes proofT10;
    }

    function setZIndexCommit(SetZIndexCommitArgs calldata args) external whenNotPaused {
        if (_ownerOf(args.shadowId) != msg.sender) revert NotShadowOwner();
        Shadow storage s = _shadows[args.shadowId];
        if (s.solved) revert AlreadySolved();

        // 1. Verify the zindex_commit proof.
        bytes32[] memory piZ = new bytes32[](ZINDEX_COMMIT_PI_LEN);
        piZ[0] = bytes32(args.shadowId);
        piZ[1] = args.newCommit;
        _verifyOrRevert(zIndexCommitVerifier, args.proofZ, piZ);

        // 2. Apply.
        s.zIndexCommit = args.newCommit;

        // 3. Atomic T10 refresh -- T10 covers zIndexCommit so the public
        //    composite cannot lie about which permutation is committed.
        _refreshT10Atomically(args.shadowId, args.newT10, args.proofT10);

        emit ShadowZIndexCommitSet(args.shadowId, args.newCommit);
    }

    // ============== incremental reveal ==============

    struct RevealSlotArgs {
        uint8 slotIdx;
        bytes proof;
        bytes plaintext; // 39 field elements: pose, dimensions, palette indices
        bytes32[10] palette;
        bytes32 paletteSalt;
        uint8 revealedRank;
        bytes32[2] newT10;
        bytes proofT10;
    }

    /// Reveal one or more hidden occupied features in-place. Revealed slots
    /// become public, immutable, permanently bound to their slots, and ignored
    /// by future hidden BW/T10 generation. A one-element array is the single
    /// feature reveal path; larger arrays batch multiple reveal steps. Each
    /// entry carries its own T10 proof so every intermediate on-chain state
    /// remains honest if a later entry would fail.
    function revealSlots(uint256 shadowId, RevealSlotArgs[] calldata reveals) external whenNotPaused {
        uint256 n = reveals.length;
        if (n == 0) revert BadArrayLen(0, 1);
        if (_ownerOf(shadowId) != msg.sender) revert NotShadowOwner();
        Shadow storage s = _shadows[shadowId];
        if (s.solved) revert AlreadySolved();
        if (address(featureNFT) == address(0)) revert FeatureNFTNotSet();

        for (uint256 i = 0; i < n; i++) {
            _revealSlot(s, shadowId, reveals[i]);
            _refreshT10Atomically(shadowId, reveals[i].newT10, reveals[i].proofT10);
        }
        if (!_hasHiddenOccupiedSlot(shadowId)) s.solved = true;
    }

    function _revealSlot(Shadow storage s, uint256 shadowId, RevealSlotArgs calldata reveal) internal {
        uint8 slotIdx = reveal.slotIdx;
        if (slotIdx >= N_SLOTS) revert SlotOutOfRange(slotIdx);

        ManifestEntry storage m = _manifests[shadowId][slotIdx];
        if (m.kind == SlotKind.EMPTY) revert SlotEmpty(slotIdx);
        if (m.kind == SlotKind.REVEALED) revert SlotRevealed(slotIdx);

        bytes32 stateCommit = bytes32(_sponge(reveal.plaintext));
        _assertSlotEnvelope(reveal.plaintext, stateCommit);
        bytes32 paletteCommit = featureNFT.paletteCommitOf(m.featureId);
        _verifyRevealSlotProof(
            s,
            shadowId,
            slotIdx,
            m.featureId,
            m.liveStateHash,
            stateCommit,
            paletteCommit,
            reveal.revealedRank,
            reveal.proof
        );

        m.kind = SlotKind.REVEALED;
        _revealedRanks[shadowId][slotIdx] = reveal.revealedRank;
        featureNFT.revealInsertedFeature(m.featureId, shadowId, slotIdx, reveal.palette, reveal.paletteSalt, reveal.plaintext);
        emit ShadowSlotRevealed(shadowId, slotIdx, m.featureId, reveal.revealedRank);
    }

    function _verifyRevealSlotProof(
        Shadow storage s,
        uint256 shadowId,
        uint8 slotIdx,
        uint256 featureId,
        bytes32 liveStateHash,
        bytes32 stateCommit,
        bytes32 paletteCommit,
        uint8 revealedRank,
        bytes calldata proof
    ) internal view {
        bytes32[] memory piS = new bytes32[](REVEAL_SLOT_PI_LEN);
        piS[0] = bytes32(shadowId);
        piS[1] = bytes32(uint256(slotIdx));
        piS[2] = bytes32(featureId);
        piS[3] = liveStateHash;
        piS[4] = stateCommit;
        piS[5] = paletteCommit;
        piS[6] = s.ecdhPubX;
        piS[7] = s.ecdhPubY;
        piS[8] = bytes32(uint256(revealedRank));
        _verifyOrRevert(solveShadowVerifier, proof, piS);
    }

    function _hasHiddenOccupiedSlot(uint256 shadowId) internal view returns (bool) {
        ManifestEntry[16] storage manifest = _manifests[shadowId];
        for (uint8 i = 0; i < N_SLOTS; i++) {
            if (manifest[i].kind == SlotKind.OCCUPIED) return true;
        }
        return false;
    }

    function _hasBoundFeature(uint256 shadowId) internal view returns (bool) {
        ManifestEntry[16] storage manifest = _manifests[shadowId];
        for (uint8 i = 0; i < N_SLOTS; i++) {
            if (manifest[i].kind != SlotKind.EMPTY) return true;
        }
        return false;
    }
    // ============== view accessors ==============

    function shadowHeaderOf(uint256 shadowId) external view returns (
        bytes32 ecdhPubX,
        bytes32 ecdhPubY,
        bool solved,
        bytes32 zIndexCommit
    ) {
        Shadow storage s = _shadows[shadowId];
        return (s.ecdhPubX, s.ecdhPubY, s.solved, s.zIndexCommit);
    }


    function slotOf(uint256 shadowId, uint8 slotIdx) external view returns (ManifestEntry memory) {
        if (slotIdx >= N_SLOTS) revert SlotOutOfRange(slotIdx);
        return _manifests[shadowId][slotIdx];
    }






    // ============== ERC-721 transfer lockdown ==============
    //
    // Shadow NFTs are transferable only while they have no bound features.
    // Any OCCUPIED hidden slot or REVEALED public slot permanently binds a
    // feature to the Shadow NFT and makes the Shadow NFT non-transferable.
    // Feature movement must happen by extracting standalone features first;
    // once the shadow manifest is empty, normal ERC-721 transfer is allowed.
    function transferFrom(address from, address to, uint256 tokenId) public override {
        if (_hasBoundFeature(tokenId)) revert TransferGated();
        super.transferFrom(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) public override {
        if (_hasBoundFeature(tokenId)) revert TransferGated();
        super.safeTransferFrom(from, to, tokenId, data);
    }

    // ============== internals ==============

    function _requirePkMatchesCaller(bytes32 px, bytes32 py) internal view {
        _requirePkMatches(msg.sender, px, py);
    }

    function _requirePkMatches(address who, bytes32 px, bytes32 py) internal view {
        KeyRegistry r = keyRegistry;
        if (address(r) == address(0)) return;
        if (!r.isRegistered(who)) return;
        (bytes32 wantX, bytes32 wantY) = r.pkOf(who);
        if (wantX != px) revert PkMismatch();
        if (wantY != py) revert PkMismatch();
    }


    /// Yul Poseidon2 sponge over arbitrary multiple-of-96-byte calldata.
    function _sponge(bytes calldata data) internal view returns (uint256 digest) {
        address y = yulSponge;
        uint256 len = data.length;
        assembly ("memory-safe") {
            let mptr := mload(0x40)
            calldatacopy(mptr, data.offset, len)
            let ok := staticcall(gas(), y, mptr, len, 0, 32)
            if iszero(ok) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
            digest := mload(0)
        }
    }


    /// Yul Poseidon2 `hash_2(a, b)` = `permute([a,b,0,0])[0]`. Used to
    /// bind `args.originFaceIds[i]` to the canonical circuit-side
    /// derivation `poseidon2_hash_2(imageCommit, i)` (audit H-05).
    /// Reverts if `yulHash2` is unset or the staticcall fails.
    function _hash2(bytes32 a, bytes32 b) internal view returns (bytes32 digest) {
        address y = yulHash2;
        assembly ("memory-safe") {
            let mptr := mload(0x40)
            mstore(mptr, a)
            mstore(add(mptr, 32), b)
            let ok := staticcall(gas(), y, mptr, 64, 0, 32)
            if iszero(ok) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
            digest := mload(0)
        }
    }

    /// Bind `c2` calldata to the proof-bound `expected` sponge_39 digest.
    /// Reverts with `DigestMismatch` on disagreement. Factored
    /// out so call sites stay under the EVM stack-depth ceiling (the mint
    /// + insert + batch entry points already carry a lot of locals).
    function _assertCtCommitBinding(bytes calldata c2, bytes32 expected) internal view {
        _assertCanonicalFields(c2);
        bytes32 got = bytes32(_sponge(c2));
        if (got != expected) revert DigestMismatch();
    }

    /// Variant of `_assertCtCommitBinding` for occupied slots that also enforces
    /// the canonical MAX_PLAINTEXT_FIELDS_PER_SLOT * 32 calldata length. Used by
    /// transferShadow and solve where every occupied slot carries exactly 39
    /// fields (no per-call c2FieldCount).
    function _assertSlotEnvelope(bytes calldata c2, bytes32 expected) internal view {
        if (c2.length != MAX_PLAINTEXT_FIELDS_PER_SLOT * 32) {
            revert BadC2Length(c2.length, MAX_PLAINTEXT_FIELDS_PER_SLOT * 32);
        }
        _assertCanonicalFields(c2);
        if (bytes32(_sponge(c2)) != expected) revert DigestMismatch();
    }

    function _assertCanonicalFields(bytes calldata data) internal pure {
        uint256 len = data.length;
        for (uint256 off = 0; off < len; off += 32) {
            uint256 value;
            assembly { value := calldataload(add(data.offset, off)) }
            _assertCanonicalField(value);
        }
    }

    function _assertCanonicalField(uint256 value) internal pure {
        if (value >= FR_MOD) revert NonCanonicalField();
    }

    // ============== verifier rotation slot ids ==============
    uint8 internal constant SLOT_MINT_SHADOW = 0;
    uint8 internal constant SLOT_FACE_DISC = 1;
    uint8 internal constant SLOT_MUTATE_SLOT = 2;
    uint8 internal constant SLOT_T10_SHADOW = 3;
    uint8 internal constant SLOT_ZINDEX_COMMIT = 4;
    uint8 internal constant SLOT_TRANSFER_SHADOW = 5;
    uint8 internal constant SLOT_SOLVE_CANVAS = 6;

    function _writeVerifierSlot(uint8 slot, address newVerifier) internal override {
        if (slot == SLOT_MINT_SHADOW) {
            mintShadowVerifier = IVerifier(newVerifier);
        } else if (slot == SLOT_FACE_DISC) {
            faceDiscVerifier = IVerifier(newVerifier);
        } else if (slot == SLOT_MUTATE_SLOT) {
            mutateSlotVerifier = IVerifier(newVerifier);
        } else if (slot == SLOT_T10_SHADOW) {
            t10ShadowVerifier = IVerifier(newVerifier);
        } else if (slot == SLOT_ZINDEX_COMMIT) {
            zIndexCommitVerifier = IVerifier(newVerifier);
        } else if (slot == SLOT_TRANSFER_SHADOW) {
            transferShadowVerifier = IVerifier(newVerifier);
        } else if (slot == SLOT_SOLVE_CANVAS) {
            solveShadowVerifier = IVerifier(newVerifier);
        } else {
            revert("unknown slot");
        }
    }
}
