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
 *         At mint, the contract atomically:
 *           1. Creates one shadow.
 *           2. Mints 8 FeatureNFTs (one per CNN-detected landmark) and
 *              binds them into slots 0..7 with isInserted=true.
 *           3. Initialises slots 8..15 to EMPTY.
 *           4. Refreshes the public T10 for the 16-slot composition.
 *
 *         Slot kinds collapse to {EMPTY, OCCUPIED}; the slot's pose,
 *         dimensions, scale, rotation, and pixel content are all
 *         private (live in c2 plaintext alongside 4-bit palette indices,
 *         48x48 max canvas). Per-slot mutation history is publicly
 *         queryable via the `liveStateHash` chain plus events.
 *
 *         Mutation surface (v2):
 *           - mintShadow             create shadow + 8 carriers, refresh T10
 *           - mutateSlot             one slot, proof-bound, atomic T10
 *           - mutateBatch            N slots in one tx, atomic T10 at end
 *           - extractSlot            OCCUPIED -> EMPTY, no proof, atomic T10
 *           - insertFeature          EMPTY -> OCCUPIED, proof-bound, atomic T10
 *           - transferShadow         rotates all 16 slots' encryption + carrier ownership
 *           - setZIndexCommit        per-shadow z-order commit, atomic T10
 *           - solve                  reveals current per-slot states + z-perm
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

    enum SlotKind { EMPTY, OCCUPIED }

    /// One manifest entry. Two storage slots per entry; 16 entries per
    /// shadow = 32 storage slots total. `liveStateHash` is the only
    /// on-chain footprint of the slot's encrypted state; the six
    /// sub-fields it commits to are reconstructable from emitted events
    /// plus the bound FeatureNFT's immutable metadata.
    struct ManifestEntry {
        SlotKind kind;
        uint256  featureId;       // 0 when EMPTY; FeatureNFT token id when OCCUPIED
        bytes32  liveStateHash;   // poseidon2(stateCommit, ctCommit, c1X, c1Y, count, chainTip)
    }

    struct Shadow {
        bytes32 ecdhPubX;          // current owner's pk, rotated on transferShadow
        bytes32 ecdhPubY;
        bool    solved;            // set once by solve, irreversible
        bytes32 zIndexCommit;      // 0 = identity permutation; perm of [0..15] hidden pre-solve
        uint64  zIndexRevealed;    // 16 nibbles; valid only after solve
        bool    zIndexRevealedSet;
        uint64  mintIdx;           // sequential mint counter for indexer ordering
        uint64  mintedAt;          // block.number at mint, audit trail
    }

    // ============== constants ==============

    uint256 public constant N_SLOTS = 16;
    uint256 public constant N_MINT_ATOMS = 8;
    uint256 public constant CANVAS_W = 48;
    uint256 public constant CANVAS_H = 48;

    /// Max plaintext bytes per slot:
    ///   pose(8) + w(1) + h(1) + ceil(48*48/2)(1152) = 1162 B
    /// Aligned to 32B boundary = 1184 B = 37 fields of 32B each, or 38
    /// fields if we use 31B per Field per ECIES packing.
    uint256 public constant MAX_PLAINTEXT_BYTES_PER_SLOT = 1184;
    uint256 public constant MAX_PLAINTEXT_FIELDS_PER_SLOT = 39;

    bytes32 public constant DOMAIN_SHADOW = keccak256("OMP_SHADOW_TOKEN_v2");

    /// bn254 Fr field modulus.
    uint256 public constant FR_MOD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// PI lengths for each verifier (subject to circuit-level finalisation;
    /// kept here as named constants so call sites are self-documenting).
    uint256 public constant MINT_SHADOW_PI_LEN     = 15; // packed per-slot tuples + image_commit + pk + featureId-pack
    uint256 public constant MUTATE_SLOT_PI_LEN     = 16;
    uint256 public constant T10_SHADOW_PI_LEN      = 20; // shadowId + newT10[2] + 16x liveStateHash + zIndexCommit
    uint256 public constant ZINDEX_COMMIT_PI_LEN   = 2;
    uint256 public constant TRANSFER_SHADOW_PI_LEN = 0;  // TBD when circuit lands
    uint256 public constant SOLVE_SHADOW_PI_LEN    = 0;  // TBD when circuit lands
    uint256 public constant FACE_DISC_PI_LEN       = 1;

    // ============== storage ==============

    address public immutable deployer;
    address public immutable yulSponge;

    KeyRegistry public keyRegistry;
    bool private _keyRegistryLocked;

    IFeatureNFT public featureNFT;
    bool private _featureNFTLocked;

    IVerifier public mintShadowVerifier;
    IVerifier public faceDiscVerifier;
    IVerifier public mutateSlotVerifier;
    IVerifier public t10ShadowVerifier;
    IVerifier public zIndexCommitVerifier;
    IVerifier public transferShadowVerifier;
    IVerifier public solveShadowVerifier;
    bool private _mintShadowVerifierLocked;
    bool private _faceDiscVerifierLocked;
    bool private _mutateSlotVerifierLocked;
    bool private _t10ShadowVerifierLocked;
    bool private _zIndexCommitVerifierLocked;
    bool private _transferShadowVerifierLocked;
    bool private _solveShadowVerifierLocked;

    mapping(uint256 => Shadow) private _shadows;
    mapping(uint256 => ManifestEntry[16]) private _manifests;
    mapping(bytes32 => bool) public mintedOrigins;

    /// Public T10 (hi, lo) packed quartets:
    ///   hi = q0 | (q1 << 128); lo = q2 | (q3 << 128).
    /// Refreshed atomically with every state-changing operation per the
    /// "no public lie" rule. Empty for shadows that haven't completed
    /// mint or any subsequent atomic refresh.
    mapping(uint256 => bytes32[2]) public shadowT10;

    /// Sequential mint counter (audit fix #9): exposed in events for
    /// stable indexer ordering.
    uint64 public mintCounter;

    // ============== events ==============

    event ShadowMinted(
        uint256 indexed shadowId,
        address indexed minter,
        uint64 indexed mintIdx,
        bytes32 imageCommit
    );
    event ShadowSlotMutated(
        uint256 indexed shadowId,
        uint8   indexed slotIdx,
        bytes32 indexed originFaceId,
        uint256 featureId,
        uint16  mutationCount,        // post-bump value
        bytes32 prevChainTip,
        bytes32 newChainTip,
        bytes   c2                    // per-slot ciphertext (encrypted; hidden content)
    );
    event SlotExtracted(
        uint256 indexed shadowId,
        uint8   indexed slotIdx,
        uint256 indexed featureId,
        bytes32 finalLiveStateHash
    );
    event ShadowFeatureInserted(
        uint256 indexed shadowId,
        uint8   indexed slotIdx,
        uint256 indexed featureId
    );
    event ShadowTransferred(
        uint256 indexed shadowId,
        address indexed to,
        bytes32 newEcdhPubX,
        bytes32 newEcdhPubY
    );
    event ShadowZIndexCommitSet(
        uint256 indexed shadowId,
        bytes32 newCommit
    );
    event ShadowT10Updated(
        uint256 indexed shadowId,
        bytes32 hi,
        bytes32 lo
    );
    event ShadowSolved(
        uint256 indexed shadowId,
        address solver,
        uint64  zIndexRevealed
    );

    event MintShadowVerifierSet(IVerifier v);
    event FaceDiscVerifierSet(IVerifier v);
    event MutateSlotVerifierSet(IVerifier v);
    event T10ShadowVerifierSet(IVerifier v);
    event ZIndexCommitVerifierSet(IVerifier v);
    event TransferShadowVerifierSet(IVerifier v);
    event SolveShadowVerifierSet(IVerifier v);
    event KeyRegistrySet(KeyRegistry r);
    event FeatureNFTSet(IFeatureNFT f);

    // ============== errors ==============

    error NotDeployer();
    error NotShadowOwner();
    error AlreadyMinted(bytes32 imageCommit);
    error AlreadySolved();
    error InvalidProof();
    error BadPILen(uint256 got, uint256 want);
    error BadC2Length(uint256 got, uint256 want);
    error BadArrayLen(uint256 got, uint256 want);
    error CtCommitMismatch(bytes32 fromChain, bytes32 fromProof);
    error LiveStateHashMismatch(bytes32 fromChain, bytes32 fromProof);
    error PkMismatch(bytes32 want, bytes32 got);

    error VerifierNotSet();
    error VerifierAlreadySet();
    error FeatureNFTAlreadySet();
    error FeatureNFTNotSet();
    error KeyRegistryAlreadySet();

    error SlotOutOfRange(uint8 slotIdx);
    error SlotEmpty(uint8 slotIdx);
    error SlotOccupied(uint8 slotIdx);
    error FeatureNotOwned(uint256 featureId);
    error FeatureAlreadyInserted(uint256 featureId);
    error TransferGated();
    error NotImplementedYet();

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
        emit KeyRegistrySet(r);
    }

    function setFeatureNFT(IFeatureNFT f) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (_featureNFTLocked) revert FeatureNFTAlreadySet();
        featureNFT = f;
        _featureNFTLocked = true;
        emit FeatureNFTSet(f);
    }

    function setMintShadowVerifier(IVerifier v) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (_mintShadowVerifierLocked) revert VerifierAlreadySet();
        mintShadowVerifier = v;
        _mintShadowVerifierLocked = true;
        emit MintShadowVerifierSet(v);
    }

    function setFaceDiscVerifier(IVerifier v) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (_faceDiscVerifierLocked) revert VerifierAlreadySet();
        faceDiscVerifier = v;
        _faceDiscVerifierLocked = true;
        emit FaceDiscVerifierSet(v);
    }

    function setMutateSlotVerifier(IVerifier v) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (_mutateSlotVerifierLocked) revert VerifierAlreadySet();
        mutateSlotVerifier = v;
        _mutateSlotVerifierLocked = true;
        emit MutateSlotVerifierSet(v);
    }

    function setT10ShadowVerifier(IVerifier v) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (_t10ShadowVerifierLocked) revert VerifierAlreadySet();
        t10ShadowVerifier = v;
        _t10ShadowVerifierLocked = true;
        emit T10ShadowVerifierSet(v);
    }

    function setZIndexCommitVerifier(IVerifier v) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (_zIndexCommitVerifierLocked) revert VerifierAlreadySet();
        zIndexCommitVerifier = v;
        _zIndexCommitVerifierLocked = true;
        emit ZIndexCommitVerifierSet(v);
    }

    function setTransferShadowVerifier(IVerifier v) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (_transferShadowVerifierLocked) revert VerifierAlreadySet();
        transferShadowVerifier = v;
        _transferShadowVerifierLocked = true;
        emit TransferShadowVerifierSet(v);
    }

    function setSolveShadowVerifier(IVerifier v) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (_solveShadowVerifierLocked) revert VerifierAlreadySet();
        solveShadowVerifier = v;
        _solveShadowVerifierLocked = true;
        emit SolveShadowVerifierSet(v);
    }

    // ============== mintShadow (STUB) ==============

    /// Atomically: verify mint + face_disc proofs, derive 8 originFaceIds
    /// from imageCommit, mint 8 carriers via FeatureNFT.mintAtShadowMint,
    /// install them into slots 0..7, refresh T10.
    /// Full body lands in Phase 3 once landmark_regions is rewritten.
    /// Calldata struct for mintShadow. Bundles all 10 parameters to dodge
    /// stack-too-deep at the entry point.
    struct MintShadowArgs {
        bytes      proofMint;
        bytes32[]  piMint;
        bytes      proofDisc;
        bytes[]    c2s;                  // 8 entries, one per CNN-detected atom
        bytes32[]  liveStateHashInits;   // 8 entries
        bytes32[]  paletteCommits;       // 8 entries
        bytes32    ctCommitsPackHi;      // poseidon2 of (ctCommit[0..3])
        bytes32    ctCommitsPackLo;      // poseidon2 of (ctCommit[4..7])
        bytes32[2] newT10;
        bytes      proofT10;
    }

    function mintShadow(MintShadowArgs calldata /*args*/)
        external
        whenNotPaused
        returns (uint256 /*shadowId*/)
    {
        revert NotImplementedYet();
    }

    // ============== mutateSlot (STUB) ==============

    /// One-slot atomic mutation: verify mutate_slot + shadow_t10 proofs,
    /// rewrite slot's liveStateHash, refresh T10. Body lands in Phase 4.
    /// Calldata struct for mutateSlot. Bundles the per-slot proof,
    /// re-encrypted ciphertext, the new live-state hash, and the
    /// atomic T10 refresh proof.
    struct MutateSlotArgs {
        uint256    shadowId;
        uint8      slotIdx;
        bytes      proofMutate;
        uint256    newC1X;             // public component of new ECIES ephemeral
        uint256    newC1Y;
        bytes32    newLiveStateHash;
        bytes32    newCtCommit;        // = sponge_39(c2); contract sponges c2 to bind
        uint16     c2FieldCount;       // == new_c2.length / 32 (constant 39 in v2)
        bytes      c2;                 // emitted via event; sponge-bound to newCtCommit
        bytes32    prevChainTip;       // pre-bump chain tip (== old_chain_tip)
        bytes32    newChainTip;        // post-bump chain tip
        uint16     prevMutationCount;  // pre-bump count (uint16 in chain semantics)
        uint16     newMutationCount;   // == prev + 1
        bytes32[2] newT10;             // (hi, lo) packed quartets
        bytes      proofT10;           // bundled atomic T10 refresh
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
        if (m.kind != SlotKind.OCCUPIED) revert SlotEmpty(args.slotIdx);

        // ---- 1. mutate_slot proof ----
        bytes32[] memory piMut = _buildMutatePI(args, m);
        IVerifier vMut = mutateSlotVerifier;
        if (address(vMut) == address(0)) revert VerifierNotSet();
        try vMut.verify(args.proofMutate, piMut) returns (bool ok) {
            if (!ok) revert InvalidProof();
        } catch {
            revert InvalidProof();
        }

        // ---- 2. bind c2 calldata via on-chain Yul Poseidon2 sponge_39 ----
        // The proof's PI[8] (new_ct_commit) is sponge_39 of the new c2
        // computed in-circuit. We sponge the calldata locally and require equality.
        bytes32 chainCtCommit = bytes32(_sponge(args.c2));
        if (chainCtCommit != piMut[8]) {
            revert CtCommitMismatch(chainCtCommit, piMut[8]);
        }

        // ---- 3. apply state change ----
        bytes32 prevLSH = m.liveStateHash;
        m.liveStateHash = args.newLiveStateHash;

        // ---- 4. atomic T10 refresh ----
        _refreshT10Atomically(args.shadowId, args.newT10, args.proofT10);

        // ---- 5. event ----
        // The proof binds prev_chain_tip (PI[12]), new_chain_tip (PI[13]),
        // prev_count (PI[14]), and new_count (PI[15]) so an indexer can
        // reconstruct the chain history without trusting the emitter.
        emit ShadowSlotMutated(
            args.shadowId,
            args.slotIdx,
            piMut[4],                              // origin_face_id from PI
            uint256(piMut[2]),                     // feature_id from PI
            uint16(uint256(piMut[15])),            // post-bump mutation count
            piMut[12],                             // prev chain tip
            piMut[13],                             // new chain tip
            args.c2
        );
        // silence unused-prevLSH warning while still asserting the read.
        prevLSH;
    }

    /// Build the 16-field PI for mutate_slot from the args + chain state.
    /// Layout matches circuits/mutate_slot/src/main.nr (16 fields):
    ///   PI[0]  shadow_id            (transcript)
    ///   PI[1]  slot_idx
    ///   PI[2]  feature_id           (chain)
    ///   PI[3]  type_idx             (chain)
    ///   PI[4]  origin_face_id       (chain)
    ///   PI[5]  palette_commit       (chain)
    ///   PI[6]  old_live_state_hash  (chain)
    ///   PI[7]  new_live_state_hash  (args)
    ///   PI[8]  new_ct_commit        (args -- bound on-chain via sponge below)
    ///   PI[9]  c2_field_count       (args)
    ///   PI[10] owner_pk_x           (chain)
    ///   PI[11] owner_pk_y           (chain)
    ///   PI[12] prev_chain_tip       (args)
    ///   PI[13] new_chain_tip        (args, derived in proof)
    ///   PI[14] prev_mutation_count  (args)
    ///   PI[15] new_mutation_count   (args, derived in proof)
    function _buildMutatePI(
        MutateSlotArgs calldata args,
        ManifestEntry storage m
    ) internal view returns (bytes32[] memory pi) {
        pi = new bytes32[](MUTATE_SLOT_PI_LEN);
        IFeatureNFT fn = featureNFT;
        pi[0]  = bytes32(args.shadowId);
        pi[1]  = bytes32(uint256(args.slotIdx));
        pi[2]  = bytes32(m.featureId);
        pi[3]  = bytes32(uint256(fn.typeIdxOf(m.featureId)));
        pi[4]  = fn.originFaceIdOf(m.featureId);
        pi[5]  = fn.paletteCommitOf(m.featureId);
        pi[6]  = m.liveStateHash;
        pi[7]  = args.newLiveStateHash;
        pi[8]  = bytes32(0);  // filled below from extraData
        pi[9]  = bytes32(uint256(args.c2FieldCount));
        pi[10] = _shadows[args.shadowId].ecdhPubX;
        pi[11] = _shadows[args.shadowId].ecdhPubY;
        // PI[12..15] are sourced from args via the auxiliary fields.
        // We thread them through `MutateSlotArgs.aux` to keep the on-chain
        // payload self-describing.
        pi[12] = args.prevChainTip;
        pi[13] = args.newChainTip;
        pi[14] = bytes32(uint256(args.prevMutationCount));
        pi[15] = bytes32(uint256(args.newMutationCount));
        // PI[8] is the proof's claimed new_ct_commit; the contract trusts the
        // proof's witness here -- the calldata c2 binding is enforced *after*
        // proof verification by sponge_39(c2) == PI[8]. We carry it forward
        // from args.newCtCommit so the verifier sees the same value the
        // prover committed to.
        pi[8] = args.newCtCommit;
    }

    /// Verify the bundled shadow_t10 proof and write `shadowT10` atomically.
    /// Builds piT10 from chain state's CURRENT manifest (post-mutate write).
    function _refreshT10Atomically(
        uint256 shadowId,
        bytes32[2] calldata newT10,
        bytes calldata proofT10
    ) internal {
        IVerifier vT10 = t10ShadowVerifier;
        if (address(vT10) == address(0)) revert VerifierNotSet();

        bytes32[] memory piT10 = new bytes32[](T10_SHADOW_PI_LEN);
        Shadow storage s = _shadows[shadowId];
        ManifestEntry[16] storage manifest = _manifests[shadowId];
        piT10[0] = bytes32(shadowId);
        piT10[1] = s.zIndexCommit;
        piT10[2] = newT10[0];   // hi
        piT10[3] = newT10[1];   // lo
        for (uint256 i = 0; i < N_SLOTS; i++) {
            piT10[4 + i] = manifest[i].liveStateHash;
        }

        try vT10.verify(proofT10, piT10) returns (bool ok) {
            if (!ok) revert InvalidProof();
        } catch {
            revert InvalidProof();
        }

        shadowT10[shadowId][0] = newT10[0];
        shadowT10[shadowId][1] = newT10[1];
        emit ShadowT10Updated(shadowId, newT10[0], newT10[1]);
    }


    /// Calldata struct for mutateBatch. Wrapping ten parallel arrays in
    /// a struct dodges Solidity's stack-too-deep at the entry point and
    /// keeps the call site self-documenting.
    struct MutateBatchArgs {
        uint256   shadowId;
        uint8[]   slotIdxs;
        bytes[]   proofMutates;
        uint256[] newC1Xs;
        uint256[] newC1Ys;
        bytes32[] newLiveStateHashes;
        uint16[]  c2FieldCounts;
        bytes[]   c2s;
        bytes32[2] newT10;
        bytes     proofT10;
    }

    function mutateBatch(MutateBatchArgs calldata /*args*/) external whenNotPaused {
        revert NotImplementedYet();
    }

    // ============== extractSlot (STUB) ==============

    /// Proofless body + bundled T10 refresh: copy slot.liveStateHash into
    /// the carrier's checkpoint, clear isInserted, zero slot, refresh T10.
    /// Body lands in Phase 5.
    function extractSlot(
        uint256 shadowId,
        uint8 slotIdx,
        bytes32[2] calldata newT10,
        bytes calldata proofT10
    ) external whenNotPaused returns (uint256 featureId) {
        if (_ownerOf(shadowId) != msg.sender) revert NotShadowOwner();
        Shadow storage s = _shadows[shadowId];
        if (s.solved) revert AlreadySolved();
        if (slotIdx >= N_SLOTS) revert SlotOutOfRange(slotIdx);
        if (address(featureNFT) == address(0)) revert FeatureNFTNotSet();

        ManifestEntry storage m = _manifests[shadowId][slotIdx];
        if (m.kind != SlotKind.OCCUPIED) revert SlotEmpty(slotIdx);

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

        featureNFT.extractFromShadow(featureId, shadowId, slotIdx, finalLsh);

        // Atomic T10 refresh against the post-extract LSH array.
        _refreshT10Atomically(shadowId, newT10, proofT10);

        emit SlotExtracted(shadowId, slotIdx, featureId, finalLsh);
    }

    // ============== insertFeature (STUB) ==============

    /// EMPTY -> OCCUPIED with proof + atomic T10. Reuses the
    /// `mutate_slot` circuit shape per Open Q2: the FeatureNFT's
    /// liveStateHashCheckpoint is the proof's `old_liveStateHash`.
    /// Body lands in Phase 6.
    struct InsertFeatureArgs {
        uint256    shadowId;
        uint8      slotIdx;
        uint256    featureId;
        bytes      proofInsert;
        uint256    newC1X;
        uint256    newC1Y;
        bytes32    newLiveStateHash;
        bytes32    newCtCommit;
        uint16     c2FieldCount;
        bytes      c2;
        bytes32    prevChainTip;       // == carrier's checkpoint chain tip
        bytes32    newChainTip;
        uint16     prevMutationCount;
        uint16     newMutationCount;
        bytes32[2] newT10;
        bytes      proofT10;
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

        // ---- 1. mutate_slot proof (reused for insert per spec Open Q2) ----
        // The proof's old_liveStateHash binds the carrier's checkpoint,
        // not a chain manifest entry. Build PI from chain state + carrier.
        bytes32[] memory piMut = _buildInsertPI(args);
        IVerifier vMut = mutateSlotVerifier;
        if (address(vMut) == address(0)) revert VerifierNotSet();
        try vMut.verify(args.proofInsert, piMut) returns (bool ok) {
            if (!ok) revert InvalidProof();
        } catch {
            revert InvalidProof();
        }

        // ---- 2. bind c2 calldata via on-chain sponge ----
        bytes32 chainCtCommit = bytes32(_sponge(args.c2));
        if (chainCtCommit != piMut[8]) {
            revert CtCommitMismatch(chainCtCommit, piMut[8]);
        }

        // ---- 3. apply: slot OCCUPIED, carrier inserted ----
        m.kind = SlotKind.OCCUPIED;
        m.featureId = args.featureId;
        m.liveStateHash = args.newLiveStateHash;
        fn.insertIntoShadow(args.featureId, args.shadowId, args.slotIdx);

        // ---- 4. atomic T10 refresh ----
        _refreshT10Atomically(args.shadowId, args.newT10, args.proofT10);

        // ---- 5. events ----
        emit ShadowFeatureInserted(args.shadowId, args.slotIdx, args.featureId);
        emit ShadowSlotMutated(
            args.shadowId,
            args.slotIdx,
            piMut[4],                              // origin_face_id from PI
            args.featureId,
            args.newMutationCount,
            args.prevChainTip,
            args.newChainTip,
            args.c2
        );
    }

    /// Build the 16-field PI for mutate_slot reused on the insert path.
    /// Differences from `_buildMutatePI`:
    ///   - PI[2] (feature_id) sourced from args (not from manifest, since
    ///     manifest is EMPTY pre-insert).
    ///   - PI[6] (old_lsh) sourced from the carrier's
    ///     liveStateHashCheckpoint, not chain manifest.
    ///   - PI[3..5] (immutables) read from FeatureNFT's stored values.
    function _buildInsertPI(InsertFeatureArgs calldata args)
        internal view returns (bytes32[] memory pi)
    {
        pi = new bytes32[](MUTATE_SLOT_PI_LEN);
        IFeatureNFT fn = featureNFT;
        pi[0]  = bytes32(args.shadowId);
        pi[1]  = bytes32(uint256(args.slotIdx));
        pi[2]  = bytes32(args.featureId);
        pi[3]  = bytes32(uint256(fn.typeIdxOf(args.featureId)));
        pi[4]  = fn.originFaceIdOf(args.featureId);
        pi[5]  = fn.paletteCommitOf(args.featureId);
        pi[6]  = fn.liveStateHashCheckpointOf(args.featureId);
        pi[7]  = args.newLiveStateHash;
        pi[8]  = args.newCtCommit;
        pi[9]  = bytes32(uint256(args.c2FieldCount));
        pi[10] = _shadows[args.shadowId].ecdhPubX;
        pi[11] = _shadows[args.shadowId].ecdhPubY;
        pi[12] = args.prevChainTip;
        pi[13] = args.newChainTip;
        pi[14] = bytes32(uint256(args.prevMutationCount));
        pi[15] = bytes32(uint256(args.newMutationCount));
    }

    // ============== transferShadow (STUB) ==============

    /// Single proof rotates all 16 slots' encryption to a new owner.
    /// All inserted carriers' ERC-721 ownership is also rotated atomically
    /// (the carriers travel with the shadow per single-host invariant).
    /// Body lands in Phase 7.
    struct TransferShadowArgs {
        uint256   shadowId;
        address   to;
        bytes     proof;
        bytes32[] pi;
        bytes[]   c2s;             // 16 entries, one per slot
        bytes32[] newLiveStateHashes; // 16 entries
        uint256[] newC1Xs;         // 16 entries
        uint256[] newC1Ys;         // 16 entries
    }

    function transferShadow(TransferShadowArgs calldata /*args*/) external whenNotPaused {
        revert NotImplementedYet();
    }

    // ============== setZIndexCommit (STUB) ==============

    /// Per-shadow z-order commit; bundled with T10 refresh because
    /// changing z-order changes what the public composite would render to.
    /// Body lands in Phase 8.
    struct SetZIndexCommitArgs {
        uint256    shadowId;
        bytes32    newCommit;
        bytes      proofZ;
        bytes32[2] newT10;
        bytes      proofT10;
    }

    function setZIndexCommit(SetZIndexCommitArgs calldata args) external whenNotPaused {
        if (_ownerOf(args.shadowId) != msg.sender) revert NotShadowOwner();
        Shadow storage s = _shadows[args.shadowId];
        if (s.solved) revert AlreadySolved();

        // 1. Verify the zindex_commit proof.
        IVerifier vZ = zIndexCommitVerifier;
        if (address(vZ) == address(0)) revert VerifierNotSet();
        bytes32[] memory piZ = new bytes32[](ZINDEX_COMMIT_PI_LEN);
        piZ[0] = bytes32(args.shadowId);
        piZ[1] = args.newCommit;
        try vZ.verify(args.proofZ, piZ) returns (bool ok) {
            if (!ok) revert InvalidProof();
        } catch {
            revert InvalidProof();
        }

        // 2. Apply.
        s.zIndexCommit = args.newCommit;

        // 3. Atomic T10 refresh -- T10 covers zIndexCommit so the public
        //    composite cannot lie about which permutation is committed.
        _refreshT10Atomically(args.shadowId, args.newT10, args.proofT10);

        emit ShadowZIndexCommitSet(args.shadowId, args.newCommit);
    }

    // ============== solve (STUB) ==============

    /// One-way reveal of the per-slot plaintexts + the z-index permutation.
    /// Marks shadow solved. Body lands in Phase 9.
    function solve(
        uint256 /*shadowId*/,
        bytes calldata /*proof*/,
        bytes32[] calldata /*pi*/
    ) external whenNotPaused {
        revert NotImplementedYet();
    }

    // ============== view accessors ==============

    function shadowOf(uint256 shadowId) external view returns (Shadow memory) {
        return _shadows[shadowId];
    }

    function manifestOf(uint256 shadowId) external view returns (ManifestEntry[16] memory) {
        return _manifests[shadowId];
    }

    function slotOf(uint256 shadowId, uint8 slotIdx) external view returns (ManifestEntry memory) {
        if (slotIdx >= N_SLOTS) revert SlotOutOfRange(slotIdx);
        return _manifests[shadowId][slotIdx];
    }

    function shadowIdOf(bytes32 imageCommit) external view returns (uint256) {
        return uint256(keccak256(abi.encode(DOMAIN_SHADOW, block.chainid, imageCommit))) % FR_MOD;
    }

    /// Mint-time convention: originFaceId = poseidon2(imageCommit, slotIdx).
    /// Open Q6 option (b). The pure-keccak fallback is used here only as a
    /// placeholder until the actual Yul Poseidon2 circuit input is wired.
    function originFaceIdOf(bytes32 imageCommit, uint8 slotIdx) public pure returns (bytes32) {
        return keccak256(abi.encode("OMP_ORIGIN_FACE_ID_v2", imageCommit, slotIdx));
    }

    /// Solved? Convenience accessor.
    function isSolved(uint256 shadowId) external view returns (bool) {
        return _shadows[shadowId].solved;
    }

    // ============== ERC-721 transfer lockdown ==============
    //
    // Pre-solve: plain transferFrom is gated. The proof-bound
    // `transferShadow` path is the only authorised ownership rotation
    // because the slots' encryption needs to rotate alongside.
    //
    // Post-solve: plain transferFrom is allowed. The puzzle is public,
    // the per-slot plaintexts are revealed, and the shadow becomes an
    // ordinary collectible. Required by `ShadowBridgeL2`, which lifts
    // solved shadows into custody via plain `transferFrom`.
    function transferFrom(address from, address to, uint256 tokenId)
        public
        override
    {
        if (!_shadows[tokenId].solved) revert TransferGated();
        super.transferFrom(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data)
        public
        override
    {
        if (!_shadows[tokenId].solved) revert TransferGated();
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
        if (wantX != px) revert PkMismatch(wantX, px);
        if (wantY != py) revert PkMismatch(wantY, py);
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

    // ============== verifier rotation slot ids ==============
    uint8 public constant SLOT_MINT_SHADOW       = 0;
    uint8 public constant SLOT_FACE_DISC         = 1;
    uint8 public constant SLOT_MUTATE_SLOT       = 2;
    uint8 public constant SLOT_T10_SHADOW        = 3;
    uint8 public constant SLOT_ZINDEX_COMMIT     = 4;
    uint8 public constant SLOT_TRANSFER_SHADOW   = 5;
    uint8 public constant SLOT_SOLVE_SHADOW      = 6;

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
        } else if (slot == SLOT_SOLVE_SHADOW) {
            solveShadowVerifier = IVerifier(newVerifier);
        } else {
            revert("unknown slot");
        }
    }
}
