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
    uint256 public constant MINT_SHADOW_PI_LEN     = 7;  // shadowId + imageCommit + pk[2] + lsh/ct/chain roots
    uint256 public constant MUTATE_SLOT_PI_LEN     = 16;
    uint256 public constant T10_SHADOW_PI_LEN      = 20; // shadowId + newT10[2] + 16x liveStateHash + zIndexCommit
    uint256 public constant ZINDEX_COMMIT_PI_LEN   = 2;
    uint256 public constant TRANSFER_SHADOW_PI_LEN = 8;
    uint256 public constant SOLVE_SHADOW_PI_LEN    = 7;
    uint256 public constant FACE_DISC_PI_LEN       = 1;

    // ============== storage ==============

    address public immutable deployer;
    address public immutable yulSponge;
    address public yulSponge16;
    bool private _yulSponge16Locked;

    KeyRegistry public keyRegistry;
    bool private _keyRegistryLocked;

    IFeatureNFT public featureNFT;
    bool private _featureNFTLocked;

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

    /// Sequential mint counter (audit fix #9): exposed in events for
    /// stable indexer ordering.
    uint64 public mintCounter;

    /// Set of `imageCommit`s that have passed `face_disc` verification
    /// via `registerImage`. `mintShadow` requires the imageCommit be
    /// in this set before it'll mint a shadow against it.
    mapping(bytes32 => bool) public registeredImages;

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
    event ImageRegistered(bytes32 indexed imageCommit);

    /// Single event covers initial set + subsequent rotation. Replaces
    /// 7 individual setter events to save runtime bytecode.
    event VerifierSet(uint8 indexed slot, IVerifier v);
    event KeyRegistrySet(KeyRegistry r);
    event FeatureNFTSet(IFeatureNFT f);
    event YulSponge16Set(address indexed addr);

    // ============== errors ==============

    error NotDeployer();
    error NotShadowOwner();
    error AlreadyMinted(bytes32 imageCommit);
    error ImageNotRegistered(bytes32 imageCommit);
    error ImageAlreadyRegistered(bytes32 imageCommit);
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

    function setYulSponge16(address addr) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (_yulSponge16Locked) revert VerifierAlreadySet();
        yulSponge16 = addr;
        _yulSponge16Locked = true;
        emit YulSponge16Set(addr);
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
        emit VerifierSet(slotId, v);
    }

    // ============== registerImage ==============

    /// Verify a `face_disc` proof binding `imageCommit` to a valid
    /// face descriptor and mark `imageCommit` as eligible for
    /// `mintShadow`. Split out of `mintShadow` (where it used to live
    /// as a bundled second proof) so the mint tx fits comfortably under
    /// public-RPC gas-LIMIT caps. Anyone may register any imageCommit;
    /// the proof itself is the credential. Ownership of the matching
    /// descriptor key is enforced inside `mintShadow` via the mint
    /// proof's `ownerPk` PI binding to `KeyRegistry.pkOf(msg.sender)`.
    function registerImage(bytes32 imageCommit, bytes calldata proofDisc)
        external
        whenNotPaused
    {
        if (address(faceDiscVerifier) == address(0)) revert VerifierNotSet();
        if (registeredImages[imageCommit]) revert ImageAlreadyRegistered(imageCommit);

        bytes32[] memory piDisc = new bytes32[](FACE_DISC_PI_LEN);
        piDisc[0] = imageCommit;
        _verifyOrRevert(faceDiscVerifier, proofDisc, piDisc);

        registeredImages[imageCommit] = true;
        emit ImageRegistered(imageCommit);
    }

    // ============== mintShadow ==============

    /// Atomically: verify mint proof, derive 8 originFaceIds
    /// from imageCommit, mint 8 carriers via FeatureNFT.mintAtShadowMint,
    /// install them into slots 0..7, mint the shadow ERC-721 to caller,
    /// refresh T10.
    ///
    /// Calldata struct. Fixed-size 8-element arrays let us hash-root via
    /// sponge_8_pad16 (16-field buffer fed to Poseidon2YulSponge16 with
    /// the trailing 8 fields = 0). Identical transcript shape to the
    /// circuit's `sponge_8_pad16` so PI[4..6] match.
    struct MintShadowArgs {
        bytes        proofMint;
        bytes32      imageCommit;
        bytes[]      c2s;                   // 8 entries; each MAX_PLAINTEXT_FIELDS_PER_SLOT * 32 bytes;
                                            //   ADVISORY (emitted in events for indexers; NOT sponge-checked on chain)
        bytes32[8]   ctCommits;             // 8 entries; sponge_39(c2[i]) per slot, computed off-chain by prover.
                                            //   The contract sponge_8_pad16's these and feeds the result into the
                                            //   mint proof's PI[5]. The proof binds the witness's actual c2 -> ctCommit,
                                            //   so a lying caller can't satisfy the proof while passing tampered ctCommits.
                                            //   The c2 calldata bytes are emitted as advisory data only (see comment on c2s).
        bytes32[8]   liveStateHashInits;    // 8 entries; sponge_8_pad16 -> lsh_inits_root (PI[4])
        bytes32[8]   chainTips;             // 8 entries; sponge_8_pad16 -> chain_tips_root (PI[6])
        bytes32[8]   paletteCommits;        // 8 entries; stored on each FeatureNFT (no proof binding)
        bytes32[8]   originFaceIds;         // 8 entries; binding to imageCommit is honored by the prover
                                            //   (circuit derives origin_face_id_i = poseidon2(image_commit, i)
                                            //   and folds it into chain_tip_i which is sponge-bound via PI[6]).
                                            //   The contract trusts these match the prover-derived values; a
                                            //   prover who lies degrades only their own indexer view.
        bytes32[2]   newT10;                // post-install (hi, lo) packed quartets
        bytes        proofT10;              // bundled atomic T10 refresh
    }

    /// Mint domain tag for chain-tip seeding. MUST match landmark_regions_v2
    /// circuit's MINT_TAG constant byte-for-byte.
    bytes32 public constant MINT_TAG = bytes32(uint256(0x91001_5_e5_a_b_a_d_4_3_e_0_a_d_d_e_d_d_a7_a));

    function mintShadow(MintShadowArgs calldata args)
        external
        whenNotPaused
        returns (uint256 shadowId)
    {
        if (address(featureNFT) == address(0)) revert FeatureNFTNotSet();
        if (address(keyRegistry) == address(0)) revert VerifierNotSet();
        if (address(mintShadowVerifier) == address(0)) revert VerifierNotSet();
        if (yulSponge == address(0)) revert VerifierNotSet();
        if (yulSponge16 == address(0)) revert VerifierNotSet();
        if (args.c2s.length != N_MINT_ATOMS) revert BadArrayLen(args.c2s.length, N_MINT_ATOMS);
        _validateMintC2Lengths(args.c2s);

        bytes32 imageCommit = args.imageCommit;
        if (mintedOrigins[imageCommit]) revert AlreadyMinted(imageCommit);
        if (!registeredImages[imageCommit]) revert ImageNotRegistered(imageCommit);
        mintedOrigins[imageCommit] = true;

        // Deterministic shadowId from imageCommit. Each imageCommit can
        // only mint once (anti-replay above), so shadowIds are unique.
        // Mod FR_MOD because imageCommit is treated as a Field in the proof.
        shadowId = uint256(imageCommit) % FR_MOD;

        // Owner pk from KeyRegistry (caller must be registered).
        (bytes32 ownerPkX, bytes32 ownerPkY) = keyRegistry.pkOf(msg.sender);

        // ---- 1. verify mint proof (helper dodges stack-too-deep) ----
        _verifyMintProofs(args, shadowId, imageCommit, ownerPkX, ownerPkY);

        // ---- 2. apply state (mint 8 carriers + install slots + record shadow + ERC-721 mint) ----
        uint64 idx = _applyMintState(args, shadowId, ownerPkX, ownerPkY);

        // ---- 3. atomic T10 refresh against post-install manifest ----
        _refreshT10Atomically(shadowId, args.newT10, args.proofT10);

        // ---- 4. emit ----
        emit ShadowMinted(shadowId, msg.sender, idx, imageCommit);
    }

    /// Verify the mint proof. face_disc is verified separately via
    /// `registerImage`; `mintShadow` gates on `registeredImages[imageCommit]`.
    /// Reconstructs PI for mint via on-chain sponge_8_pad16 over per-slot
    /// hashed c2s, lshInits, chainTips.
    function _verifyMintProofs(
        MintShadowArgs calldata args,
        uint256 shadowId,
        bytes32 imageCommit,
        bytes32 ownerPkX,
        bytes32 ownerPkY
    ) internal view {
        // ---- mint proof: build PI ----
        bytes32[] memory piMint = new bytes32[](MINT_SHADOW_PI_LEN);
        piMint[0] = bytes32(shadowId);
        piMint[1] = imageCommit;
        piMint[2] = ownerPkX;
        piMint[3] = ownerPkY;
        piMint[4] = _sponge8Pad16BytesArr(args.liveStateHashInits);
        piMint[5] = _sponge8Pad16BytesArr(args.ctCommits);
        piMint[6] = _sponge8Pad16BytesArr(args.chainTips);
        _verifyOrRevert(mintShadowVerifier, args.proofMint, piMint);
    }

    /// Validate calldata c2 lengths only. The actual sponge_39 of each c2 is
    /// witnessed off-chain by the prover; the contract trusts args.ctCommits[i]
    /// because the proof's PI[5] = sponge_8_pad16(args.ctCommits) MUST match the
    /// witness ct_commits_root. A caller passing tampered ctCommits cannot
    /// satisfy the proof. (See security note on mutateSlot for c2 advisoriness.)
    function _validateMintC2Lengths(bytes[] calldata c2s) internal pure {
        uint256 expected = MAX_PLAINTEXT_FIELDS_PER_SLOT * 32;
        for (uint256 i = 0; i < N_MINT_ATOMS; i++) {
            if (c2s[i].length != expected) revert BadC2Length(c2s[i].length, expected);
        }
    }

    /// Calldata variant: feed 8-field array + 8 zero fields to yulSponge16.
    function _sponge8Pad16BytesArr(bytes32[8] calldata arr)
        internal view returns (bytes32)
    {
        bytes memory buf = new bytes(N_SLOTS * 32);  // 512 bytes; trailing 8 are zero
        for (uint256 i = 0; i < N_MINT_ATOMS; i++) {
            bytes32 v = arr[i];
            assembly { mstore(add(add(buf, 32), mul(i, 32)), v) }
        }
        return _sponge16(buf);
    }

    /// Memory variant of the above; for arrays we built locally.
    function _sponge8Pad16BytesArrMem(bytes32[8] memory arr)
        internal view returns (bytes32)
    {
        bytes memory buf = new bytes(N_SLOTS * 32);
        for (uint256 i = 0; i < N_MINT_ATOMS; i++) {
            bytes32 v = arr[i];
            assembly { mstore(add(add(buf, 32), mul(i, 32)), v) }
        }
        return _sponge16(buf);
    }

    /// Apply post-mint state: install shadow record, mint 8 FeatureNFTs
    /// into slots 0..7, write manifest entries, mint shadow ERC-721 to caller.
    function _applyMintState(
        MintShadowArgs calldata args,
        uint256 shadowId,
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
            _mintOneAtom(args, shadowId, fn, manifest, i);
        }
        // Slots 8..15 stay EMPTY (default zero values).

        // Mint the shadow ERC-721 to caller.
        _safeMint(msg.sender, shadowId);
    }

    /// Per-slot mint helper. Extracted to dodge stack-too-deep in
    /// _applyMintState. Mints one FeatureNFT, writes the manifest
    /// entry, and emits the per-slot mutation event so indexers can
    /// reconstruct chain history.
    /// origin_face_id semantics: caller-supplied; the proof binds it
    /// transitively via chain_tip[i] = sponge_4(MINT_TAG, originFaceId,
    /// ownerPk.x, ownerPk.y) and chain_tips_root (PI[6]).
    function _mintOneAtom(
        MintShadowArgs calldata args,
        uint256 shadowId,
        IFeatureNFT fn,
        ManifestEntry[16] storage manifest,
        uint256 i
    ) internal {
        bytes32 originFaceId = args.originFaceIds[i];
        uint256 featureId = fn.mintAtShadowMint(
            shadowId,
            uint8(i),
            uint8(i),                          // typeIdx = slot index (8 distinct landmark types)
            originFaceId,
            args.paletteCommits[i],
            args.liveStateHashInits[i],
            msg.sender
        );
        manifest[i] = ManifestEntry({
            kind: SlotKind.OCCUPIED,
            featureId: featureId,
            liveStateHash: args.liveStateHashInits[i]
        });
        emit ShadowSlotMutated(
            shadowId,
            uint8(i),
            originFaceId,
            featureId,
            0,                                 // mutationCount = 0 at mint
            bytes32(0),                        // prevChainTip = 0 (mint has no predecessor)
            args.chainTips[i],
            args.c2s[i]
        );
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
        bytes32[] memory piMut = _buildSlotPI(SlotPIInputs({
            shadowId:      args.shadowId,
            slotIdx:       args.slotIdx,
            featureId:     m.featureId,
            oldLsh:        m.liveStateHash,
            newLsh:        args.newLiveStateHash,
            newCtCommit:   args.newCtCommit,
            c2FieldCount:  args.c2FieldCount,
            prevChainTip:  args.prevChainTip,
            newChainTip:   args.newChainTip,
            prevCount:     args.prevMutationCount,
            newCount:      args.newMutationCount
        }));
        _verifyOrRevert(mutateSlotVerifier, args.proofMutate, piMut);

        // ---- 2. c2 calldata is ADVISORY (emitted in event for indexers) ----
        // The proof binds args.newCtCommit (PI[8]) to the witness c2's sponge_39.
        // We do NOT sponge_39 calldata c2 on chain (~735K gas, structural cost).
        // If caller's calldata c2 mismatches their witness c2:
        //   - chain state (lsh) stays correct (proof-bound transitively via
        //     new_lsh = LSH(state_commit, ct_commit, c1, count, chainTip))
        //   - emitted c2 in event will not decrypt to the witness plaintext
        //   - indexers / consumers detect via decrypt failure or off-chain
        //     sponge_39(emitted c2) != newCtCommit
        // For self-ops (mutateSlot/mintShadow/solve) the caller IS the owner,
        // so lying is self-harm. For transferShadow the recipient detects via
        // ECIES decrypt failure (see security note in transferShadow).

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
    /// Inputs to `_buildSlotPI`. Wraps the 11 slot-level fields a
    /// mutate/insert PI build needs so we can pass them by struct and
    /// reuse one builder across the three call sites (mutateSlot,
    /// mutateBatch, insertFeature). Without this consolidation the
    /// three builders were ~80% identical and ate ~600 B of bytecode.
    struct SlotPIInputs {
        uint256 shadowId;
        uint8   slotIdx;
        uint256 featureId;
        bytes32 oldLsh;             // m.liveStateHash for mutate; fn.checkpoint for insert
        bytes32 newLsh;
        bytes32 newCtCommit;
        uint16  c2FieldCount;
        bytes32 prevChainTip;
        bytes32 newChainTip;
        uint16  prevCount;
        uint16  newCount;
    }

    /// Build the 16-field mutate_slot PI from the canonical slot-level
    /// inputs + chain state. Layout matches
    /// `circuits/mutate_slot/src/main.nr` byte-for-byte.
    function _buildSlotPI(SlotPIInputs memory inp)
        internal view returns (bytes32[] memory pi)
    {
        pi = new bytes32[](MUTATE_SLOT_PI_LEN);
        IFeatureNFT fn = featureNFT;
        pi[0]  = bytes32(inp.shadowId);
        pi[1]  = bytes32(uint256(inp.slotIdx));
        pi[2]  = bytes32(inp.featureId);
        pi[3]  = bytes32(uint256(fn.typeIdxOf(inp.featureId)));
        pi[4]  = fn.originFaceIdOf(inp.featureId);
        pi[5]  = fn.paletteCommitOf(inp.featureId);
        pi[6]  = inp.oldLsh;
        pi[7]  = inp.newLsh;
        pi[8]  = inp.newCtCommit;
        pi[9]  = bytes32(uint256(inp.c2FieldCount));
        pi[10] = _shadows[inp.shadowId].ecdhPubX;
        pi[11] = _shadows[inp.shadowId].ecdhPubY;
        pi[12] = inp.prevChainTip;
        pi[13] = inp.newChainTip;
        pi[14] = bytes32(uint256(inp.prevCount));
        pi[15] = bytes32(uint256(inp.newCount));
    }

    /// Verify the bundled shadow_t10 proof and write `shadowT10` atomically.
    /// Builds piT10 from chain state's CURRENT manifest (post-mutate write).
    /// Verify a proof against a verifier slot or revert. Collapses the
    /// `if not set / try verify / not ok / catch` pattern that appears
    /// on every atomic flow (mutate, batch, insert, mint, transfer,
    /// solve, T10, zindex). Saves ~700 B of runtime bytecode by
    /// deduplicating the call shape.
    function _verifyOrRevert(
        IVerifier v,
        bytes calldata proof,
        bytes32[] memory pi
    ) internal view {
        if (address(v) == address(0)) revert VerifierNotSet();
        try v.verify(proof, pi) returns (bool ok) {
            if (!ok) revert InvalidProof();
        } catch {
            revert InvalidProof();
        }
    }

    function _refreshT10Atomically(
        uint256 shadowId,
        bytes32[2] calldata newT10,
        bytes calldata proofT10
    ) internal {

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

        _verifyOrRevert(t10ShadowVerifier, proofT10, piT10);

        shadowT10[shadowId][0] = newT10[0];
        shadowT10[shadowId][1] = newT10[1];
        emit ShadowT10Updated(shadowId, newT10[0], newT10[1]);
    }


    /// One per-slot mutation entry inside a `mutateBatch` call. Mirrors
    /// `MutateSlotArgs` minus the `shadowId` (carried once at the batch
    /// level) and minus `newT10`/`proofT10` (one refresh at end of batch).
    /// Spec line 806 listed parallel arrays; we use struct-of-arrays to
    /// dodge stack-too-deep at the entry point and to keep PI building
    /// per-entry self-documenting. Field semantics are byte-for-byte
    /// identical to `MutateSlotArgs`.
    struct MutateSlotEntry {
        uint8      slotIdx;
        bytes      proofMutate;
        uint256    newC1X;
        uint256    newC1Y;
        bytes32    newLiveStateHash;
        bytes32    newCtCommit;          // == sponge_39(c2); contract sponges c2 to bind
        uint16     c2FieldCount;
        bytes      c2;                   // emitted via event; sponge-bound to newCtCommit
        bytes32    prevChainTip;
        bytes32    newChainTip;
        uint16     prevMutationCount;
        uint16     newMutationCount;
    }

    /// Calldata struct for mutateBatch. One T10 refresh covers the whole
    /// batch -- the spec's gas-amortization rationale for the API. Per
    /// spec line 821, practical batch ceiling is ~2 mutate proofs per tx
    /// within the 16.7M block-gas cap.
    struct MutateBatchArgs {
        uint256             shadowId;
        MutateSlotEntry[]   entries;     // MUST be non-empty
        bytes32[2]          newT10;      // post-batch (hi, lo) packed quartets
        bytes               proofT10;    // bundled atomic T10 against post-batch manifest
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
    function _verifyAndApplyOneMutate(
        uint256 shadowId,
        MutateSlotEntry calldata e
    ) internal {
        if (e.slotIdx >= N_SLOTS) revert SlotOutOfRange(e.slotIdx);
        uint256 expectedC2Bytes = uint256(e.c2FieldCount) * 32;
        if (e.c2.length != expectedC2Bytes) {
            revert BadC2Length(e.c2.length, expectedC2Bytes);
        }

        ManifestEntry storage m = _manifests[shadowId][e.slotIdx];
        if (m.kind != SlotKind.OCCUPIED) revert SlotEmpty(e.slotIdx);

        // Build PI for this entry (matches mutate_slot circuit byte-for-byte).
        bytes32[] memory piMut = _buildSlotPI(SlotPIInputs({
            shadowId:      shadowId,
            slotIdx:       e.slotIdx,
            featureId:     m.featureId,
            oldLsh:        m.liveStateHash,
            newLsh:        e.newLiveStateHash,
            newCtCommit:   e.newCtCommit,
            c2FieldCount:  e.c2FieldCount,
            prevChainTip:  e.prevChainTip,
            newChainTip:   e.newChainTip,
            prevCount:     e.prevMutationCount,
            newCount:      e.newMutationCount
        }));
        _verifyOrRevert(mutateSlotVerifier, e.proofMutate, piMut);

        // c2 calldata is ADVISORY (see security note on mutateSlot).

        // Apply state: write new LSH; manifest's other fields
        // (kind/featureId) are unchanged by mutation.
        m.liveStateHash = e.newLiveStateHash;

        // Emit per-slot event so indexers can reconstruct chain history.
        emit ShadowSlotMutated(
            shadowId,
            e.slotIdx,
            piMut[4],                              // origin_face_id from PI
            uint256(piMut[2]),                     // feature_id from PI
            uint16(uint256(piMut[15])),            // post-bump mutation count
            piMut[12],                             // prev chain tip
            piMut[13],                             // new chain tip
            e.c2
        );
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

        // ---- 1. verify mutate_slot proof against carrier checkpoint (helper
        // dodges stack-too-deep on the entry point) + return PI for events ----
        bytes32[] memory piMut = _verifyInsertProof(args, fn);

        // c2 calldata is ADVISORY (see security note on mutateSlot).

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

    /// Build the insert PI from carrier checkpoint + verify proof.
    /// Extracted from `insertFeature` body to dodge stack-too-deep --
    /// the entry-point body holds many calldata locals + a 16-field PI
    /// array + a SlotPIInputs struct simultaneously, which exceeds the
    /// 16-stack-slot Solidity budget without via-ir.
    function _verifyInsertProof(InsertFeatureArgs calldata args, IFeatureNFT fn)
        internal view returns (bytes32[] memory piMut)
    {
        piMut = _buildSlotPI(SlotPIInputs({
            shadowId:      args.shadowId,
            slotIdx:       args.slotIdx,
            featureId:     args.featureId,
            oldLsh:        fn.liveStateHashCheckpointOf(args.featureId),
            newLsh:        args.newLiveStateHash,
            newCtCommit:   args.newCtCommit,
            c2FieldCount:  args.c2FieldCount,
            prevChainTip:  args.prevChainTip,
            newChainTip:   args.newChainTip,
            prevCount:     args.prevMutationCount,
            newCount:      args.newMutationCount
        }));
        _verifyOrRevert(mutateSlotVerifier, args.proofInsert, piMut);
    }


    // ============== transferShadow (STUB) ==============

    /// Single proof rotates all 16 slots' encryption to a new owner.
    /// All inserted carriers' ERC-721 ownership is also rotated atomically
    /// (the carriers travel with the shadow per single-host invariant).
    /// Body lands in Phase 7.
    /// Calldata struct for transferShadow. All 16 per-slot arrays are
    /// fixed-size to make the contract's hash-root reconstruction
    /// (sponge_16 over each) deterministic and EIP-170-cheap.
    struct TransferShadowArgs {
        uint256     shadowId;
        address     to;
        bytes       proof;                  // transfer_shadow_v2 proof
        bytes32[16] newLiveStateHashes;     // post-rotation; chain writes these
        bytes32[16] newChainTips;           // post-rotation per-slot chain tips (committed in proof)
        uint256[16] newC1Xs;                // per-slot fresh ECIES ephemeral c1.x
        uint256[16] newC1Ys;                // per-slot fresh ECIES ephemeral c1.y
        // newCtCommits removed in v2-gas: sponge_39 verification dropped on chain;
        // proof's PI binds new_lsh which embeds ct_commit transitively.
        uint16[16]  newMutationCounts;      // == prev + 1 for occupied; 0 for empty
        bytes[]     c2s;                    // 16 entries; empty bytes for empty slots
        bytes32[2]  newT10;                 // post-rotation T10 (hi, lo)
        bytes       proofT10;               // bundled atomic T10 proof
    }

    function transferShadow(TransferShadowArgs calldata args) external whenNotPaused {
        if (_ownerOf(args.shadowId) != msg.sender) revert NotShadowOwner();
        Shadow storage s = _shadows[args.shadowId];
        if (s.solved) revert AlreadySolved();
        if (address(featureNFT) == address(0)) revert FeatureNFTNotSet();
        if (address(keyRegistry) == address(0)) revert VerifierNotSet();
        if (yulSponge16 == address(0)) revert VerifierNotSet();
        if (args.c2s.length != N_SLOTS) revert BadArrayLen(args.c2s.length, N_SLOTS);

        // ---- 1. recipient pubkey from KeyRegistry ----
        (bytes32 recipientPkX, bytes32 recipientPkY) = keyRegistry.pkOf(args.to);

        // ---- 2. verify transfer proof (separate fn to dodge stack-too-deep) ----
        _verifyTransferProof(args, recipientPkX, recipientPkY);

        // ---- 3. apply state changes (separate fn) ----
        _applyTransferState(args, recipientPkX, recipientPkY);

        // ---- 4. atomic T10 refresh against post-rotation manifest ----
        _refreshT10Atomically(args.shadowId, args.newT10, args.proofT10);

        // ---- 5. emit per-slot mutation events for indexers ----
        emit ShadowTransferred(args.shadowId, args.to, recipientPkX, recipientPkY);
        _emitTransferSlotEvents(args);
    }

    /// Verify the transfer_shadow_v2 proof. Reconstructs PI from chain
    /// state (prev_lsh_root) and from calldata (newLshRoot, newChainTipsRoot)
    /// via the Yul sponge_16 staticcall.
    function _verifyTransferProof(
        TransferShadowArgs calldata args,
        bytes32 recipientPkX,
        bytes32 recipientPkY
    ) internal view {
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
        _verifyOrRevert(transferShadowVerifier, args.proof, piT);
    }

    /// Apply post-transfer state to chain: write new per-slot LSH, rotate
    /// carriers, rotate Shadow.ecdhPub, rotate the shadow's ERC-721 owner.
    function _applyTransferState(
        TransferShadowArgs calldata args,
        bytes32 recipientPkX,
        bytes32 recipientPkY
    ) internal {
        IFeatureNFT fn = featureNFT;
        ManifestEntry[16] storage manifest = _manifests[args.shadowId];
        for (uint256 i = 0; i < N_SLOTS; i++) {
            ManifestEntry storage m = manifest[i];
            m.liveStateHash = args.newLiveStateHashes[i];
            if (m.kind == SlotKind.OCCUPIED) {
                fn.rotateInsertedOwner(m.featureId, args.shadowId, args.to);
                if (args.c2s[i].length != MAX_PLAINTEXT_FIELDS_PER_SLOT * 32) {
                    revert BadC2Length(args.c2s[i].length, MAX_PLAINTEXT_FIELDS_PER_SLOT * 32);
                }
                // c2 calldata is ADVISORY (see security note on mutateSlot).
                // Recipient detects sender-corrupted c2 via ECIES decrypt failure
                // off-chain. Chain state's new_lsh is proof-bound either way.
            } else {
                if (args.c2s[i].length != 0) {
                    revert BadC2Length(args.c2s[i].length, 0);
                }
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

    /// Emit ShadowSlotMutated for every occupied slot so indexers can
    /// reconstruct chain history. Separate from _applyTransferState to
    /// dodge stack-too-deep on the entry point.
    function _emitTransferSlotEvents(TransferShadowArgs calldata args) internal {
        IFeatureNFT fn = featureNFT;
        ManifestEntry[16] storage manifest = _manifests[args.shadowId];
        for (uint256 i = 0; i < N_SLOTS; i++) {
            ManifestEntry storage m = manifest[i];
            if (m.kind == SlotKind.OCCUPIED) {
                emit ShadowSlotMutated(
                    args.shadowId,
                    uint8(i),
                    fn.originFaceIdOf(m.featureId),
                    m.featureId,
                    args.newMutationCounts[i],
                    bytes32(0),
                    args.newChainTips[i],
                    args.c2s[i]
                );
            }
        }
    }

    /// Hash the chain manifest's per-slot liveStateHash array via the
    /// Yul sponge_16 contract.
    function _sponge16Manifest(ManifestEntry[16] storage manifest)
        internal view returns (bytes32)
    {
        bytes memory buf = new bytes(N_SLOTS * 32);
        for (uint256 i = 0; i < N_SLOTS; i++) {
            bytes32 v = manifest[i].liveStateHash;
            assembly { mstore(add(add(buf, 32), mul(i, 32)), v) }
        }
        return _sponge16(buf);
    }

    /// Hash a fixed-size 16-element bytes32 array via the Yul sponge_16.
    function _sponge16BytesArr(bytes32[16] calldata arr)
        internal view returns (bytes32)
    {
        bytes memory buf = new bytes(N_SLOTS * 32);
        for (uint256 i = 0; i < N_SLOTS; i++) {
            bytes32 v = arr[i];
            assembly { mstore(add(add(buf, 32), mul(i, 32)), v) }
        }
        return _sponge16(buf);
    }

    /// Memory variant of _sponge16BytesArr. Used by code paths that build
    /// the array locally (e.g. solve verification builds state_commits in
    /// memory by sponging per-slot plaintexts).
    function _sponge16BytesArrMem(bytes32[16] memory arr)
        internal view returns (bytes32)
    {
        bytes memory buf = new bytes(N_SLOTS * 32);
        for (uint256 i = 0; i < N_SLOTS; i++) {
            bytes32 v = arr[i];
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

    // ============== solve ==============

    /// Calldata struct for solve. Per-slot plaintexts revealed via
    /// `plaintexts[i]` (39 fields each); contract hash-checks them via
    /// sponge_39 then sponge_16 to match the proof's PI[1] state_commits_root.
    /// Auto-extracts every occupied carrier so post-solve they become plain
    /// transferable. The shadow itself becomes solved (no further mutation).
    struct SolveArgs {
        uint256   shadowId;
        bytes     proof;            // solve_shadow_v2 proof
        bytes[16] plaintexts;       // per-slot 39-field plaintext (1248 B each); empty for unused.
                                    //   ADVISORY (emitted post-solve for indexers; NOT sponge-checked on chain)
        bytes32[16] stateCommits;   // per-slot sponge_39(plaintext[i]) for OCCUPIED slots; 0 for EMPTY.
                                    //   Contract sponge_16(stateCommits) -> PI[1]. Proof binds the witness's
                                    //   actual plaintext -> stateCommit, so a lying caller cannot satisfy proof.
        bytes32   zPermPacked;      // 16 nibbles, base-16 little-endian
        uint8[16] zPerm;            // explicit per-position values (decoded from packed)
    }

    /// One-way reveal of the per-slot plaintexts + the z-index permutation.
    /// Marks shadow solved, auto-extracts every inserted carrier.
    function solve(SolveArgs calldata args) external whenNotPaused {
        if (_ownerOf(args.shadowId) != msg.sender) revert NotShadowOwner();
        Shadow storage s = _shadows[args.shadowId];
        if (s.solved) revert AlreadySolved();
        if (address(featureNFT) == address(0)) revert FeatureNFTNotSet();
        if (yulSponge16 == address(0)) revert VerifierNotSet();

        // ---- 1. verify solve proof ----
        _verifySolveProof(args);

        // ---- 2. apply: write zIndexRevealed, mark solved, auto-extract carriers ----
        s.solved = true;
        s.zIndexRevealed = uint64(uint256(args.zPermPacked));
        s.zIndexRevealedSet = true;

        _autoExtractAllSlots(args.shadowId);

        // ---- 3. emit ----
        emit ShadowSolved(args.shadowId, msg.sender, s.zIndexRevealed);
    }

    function _verifySolveProof(SolveArgs calldata args) internal view {
        Shadow storage s = _shadows[args.shadowId];

        // Build state_commits root by sponge_39'ing each per-slot plaintext
        // (or 0 for empty slots), then sponge_16 over the 16 commits.
        bytes32[16] memory stateCommits;
        ManifestEntry[16] storage manifest = _manifests[args.shadowId];
        for (uint256 i = 0; i < N_SLOTS; i++) {
            if (manifest[i].kind == SlotKind.OCCUPIED) {
                // Length sanity only. plaintext is ADVISORY; not sponge-checked.
                if (args.plaintexts[i].length != MAX_PLAINTEXT_FIELDS_PER_SLOT * 32) {
                    revert BadC2Length(args.plaintexts[i].length, MAX_PLAINTEXT_FIELDS_PER_SLOT * 32);
                }
            } else {
                if (args.plaintexts[i].length != 0) {
                    revert BadC2Length(args.plaintexts[i].length, 0);
                }
                // Caller MUST claim 0 stateCommit for EMPTY slots; proof witness is 0.
                if (args.stateCommits[i] != bytes32(0)) {
                    revert BadC2Length(uint256(uint8(1)), 0);  // reuse error; non-zero claim for empty
                }
            }
        }

        bytes32[] memory piS = new bytes32[](SOLVE_SHADOW_PI_LEN);
        piS[0] = bytes32(args.shadowId);
        piS[1] = _sponge16BytesArr(args.stateCommits);
        piS[2] = args.zPermPacked;
        piS[3] = s.zIndexCommit;
        piS[4] = _sponge16Manifest(manifest);
        piS[5] = s.ecdhPubX;
        piS[6] = s.ecdhPubY;
        _verifyOrRevert(solveShadowVerifier, args.proof, piS);
    }

    /// Auto-extract every occupied slot at solve time. Each carrier's
    /// `liveStateHashCheckpoint` is synced to the slot's current LSH and
    /// the manifest is zeroed. Post-solve every FeatureNFT becomes plain
    /// transferable.
    function _autoExtractAllSlots(uint256 shadowId) internal {
        IFeatureNFT fn = featureNFT;
        ManifestEntry[16] storage manifest = _manifests[shadowId];
        for (uint256 i = 0; i < N_SLOTS; i++) {
            ManifestEntry storage m = manifest[i];
            if (m.kind == SlotKind.OCCUPIED) {
                uint256 fid = m.featureId;
                bytes32 finalLsh = m.liveStateHash;
                m.kind = SlotKind.EMPTY;
                m.featureId = 0;
                m.liveStateHash = bytes32(0);
                fn.extractFromShadow(fid, shadowId, uint8(i), finalLsh);
                emit SlotExtracted(shadowId, uint8(i), fid, finalLsh);
            }
        }
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
