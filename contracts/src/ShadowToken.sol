// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {IVerifier} from "./IVerifier.sol";
import {IFeatureNFT} from "./IFeatureNFT.sol";
import {KeyRegistry} from "./KeyRegistry.sol";
import {PoseLib} from "./PoseLib.sol";
import {PausableMixin} from "./PausableMixin.sol";

/**
 * @title  ShadowToken
 * @notice Phase-2 composition NFT. Replaces the legacy `AmalgamToken` +
 *         `FeatureToken` pair from phase 0/1.
 *
 *         Each shadow holds:
 *           - immutable `faceOriginId`, `color`, `originPose[8]`, mintedAt
 *           - mutable `ecdhPubX/Y`, `c2Commit` (rotated on transfer),
 *             `manifest[16]` (rewritten by mutateSlot/extractSlot/insertFeature/removeFeature)
 *           - `solved` flag (set once by solve, irreversible)
 *
 *         Manifest = 16-slot rendering recipe:
 *           - slots 0..7  : ORIGINAL at mint, may become EMPTY after extractSlot
 *           - slots 8..15 : EMPTY at mint, may become INSERTED after insertFeature
 *
 *         "Origin doesn't update over time": originPose[8] is set at mint and
 *         never written again. mutateSlot updates manifest[i].pose only.
 *
 *         "Render in slot order, ignore overlap": the off-chain renderer
 *         iterates slot 0..15 in order; each slot's content is drawn at its
 *         pose, allowing later slots to paint over earlier. Contract just
 *         stores the data.
 *
 *         Crypto guarantees:
 *         - mintShadow + transferShadow include on-chain Yul Poseidon2 sponge
 *           verification: `sponge_249(c2) == pi.ct_commit`. Chain refuses to
 *           log mismatched ciphertext.
 *         - Recipient pk for self-mint and transfer recipients must match the
 *           caller's / target's `KeyRegistry` binding when registry is set.
 *           (Registry can be the zero-address during local dev for permissive
 *            mode; production deploys MUST set a real registry.)
 */
contract ShadowToken is ERC721, PausableMixin {
    // ============== types ==============

    enum SlotKind { EMPTY, ORIGINAL, INSERTED }

    /// One manifest entry. Fits in two storage slots conservatively (we
    /// don't pack across slots to keep the read API straightforward).
    struct ManifestEntry {
        SlotKind kind;
        uint8 originalTypeIdx;     // 0..7, valid only when kind=ORIGINAL
        uint256 insertedFeatureId; // valid only when kind=INSERTED
        uint64 pose;               // current pose (PoseLib-packed)
    }

    struct Shadow {
        bytes32 faceOriginId;      // immutable post-mint
        uint8   color;             // immutable post-mint
        bytes32 ecdhPubX;          // current owner's pk
        bytes32 ecdhPubY;
        bytes32 c2Commit;          // sponge_249 of original 8 features' pixels
        uint64  origPose0;         // origin pose for slot 0
        uint64  origPose1;
        uint64  origPose2;
        uint64  origPose3;
        uint64  origPose4;
        uint64  origPose5;
        uint64  origPose6;
        uint64  origPose7;
        uint64  mintIdx;           // sequential mint counter (for indexer ordering)
        uint64  mintedAt;          // block.number at mint (audit trail)
        bytes32 stateCommitsHash;  // keccak256(pi[0]||pi[1]||...||pi[7]) at mint;
                                   // used by solve to bind PI[0..7] = chain stateCommits
    }

    // ============== constants ==============

    uint256 public constant MINT_SHADOW_PI_LEN      = 18;  // adds image_commit at PI[17]
    uint256 public constant MINT_SHADOW_C2_BYTES    = 249 * 32;     // 7,968
    uint256 public constant TRANSFER_SHADOW_PI_LEN  = 8;
    uint256 public constant SOLVE_SHADOW_PI_LEN     = 261;
    uint256 public constant FACE_DISC_PI_LEN        = 1;   // image_commit only

    bytes32 public constant DOMAIN_SHADOW = keccak256("OMP_SHADOW_TOKEN_v2");

    /// bn254 Fr field modulus. shadowId is reduced mod FR_MOD so PI[0]
    /// equality (Field == Field) holds across circuit/contract boundary.
    uint256 public constant FR_MOD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// Per-feature region bounding-box dimensions (PROPORTIONAL canvas spec
    /// from the phase-1 circuit). Used by mutateSlot's on-frame check.
    /// Mirrors transfer_amalgam_8 / region_relay_geom REGION_W / REGION_H.
    uint8[8] internal REGION_W = [48, 33, 33, 24, 14, 14, 48, 48];
    uint8[8] internal REGION_H = [9, 8, 8, 11, 19, 19, 9, 8];

    // ============== storage ==============

    /// Deployer; gates one-shot setters.
    address public immutable deployer;

    /// Yul Poseidon2 sponge contract; immutable after construction.
    address public immutable yulSponge;

    /// Optional: KeyRegistry binding `msg.sender -> Grumpkin pk`. When set
    /// (non-zero), mintShadow / transferShadow assert recipient pk matches
    /// the registry. Zero address = permissive mode (testing only).
    KeyRegistry public keyRegistry;
    bool private _keyRegistryLocked;

    /// FeatureNFT back-reference; set once by deployer post-deploy.
    IFeatureNFT public featureNFT;
    bool private _featureNFTLocked;

    /// Per-circuit verifiers. Each is a one-shot deployer-only setter.
    IVerifier public mintShadowVerifier;
    IVerifier public transferShadowVerifier;
    IVerifier public extractSlotVerifier;
    IVerifier public solveShadowVerifier;
    IVerifier public t10ShadowVerifier;
    IVerifier public faceDiscVerifier;
    bool private _mintShadowVerifierLocked;
    bool private _transferShadowVerifierLocked;
    bool private _extractSlotVerifierLocked;
    bool private _solveShadowVerifierLocked;
    bool private _t10ShadowVerifierLocked;
    bool private _faceDiscVerifierLocked;

    mapping(uint256 => Shadow) private _shadows;
    mapping(uint256 => ManifestEntry[16]) private _manifests;
    mapping(uint256 => bool) public solved;
    mapping(bytes32 => bool) public mintedOrigins;

    /// T10 public-artifact storage. (hi, lo) packed quartets:
    ///   hi = q0 | (q1 << 128); lo = q2 | (q3 << 128).
    /// Set/refreshed via setShadowT10. Empty for shadows that haven't been
    /// refreshed since their last state change.
    mapping(uint256 => bytes32[2]) public shadowT10;

    /// State nonce: bumps on every call that mutates shadow state
    /// (mint, transfer, mutateSlot, extractSlot, insertFeature, removeFeature).
    /// T10 proofs bind to this nonce -- a stale T10 fixture cannot be replayed
    /// after any state change.
    mapping(uint256 => uint64) public stateNonce;

    /// Original mint geometry (boxes_packed PI[9]) preserved per shadow.
    /// Used by setShadowT10 to bind T10 PI[3] = boxes_packed.
    mapping(uint256 => bytes32) public boxesPackedOf;

    /// Sequential mint counter (audit fix #9): exposed in events for stable
    /// indexer ordering even when faceOriginId is non-monotonic.
    uint64 public mintCounter;

    // ============== events ==============

    event ShadowMinted(
        uint256 indexed shadowId,
        bytes32 indexed faceOriginId,
        address indexed minter,
        uint8 color,
        uint64 mintIdx
    );
    event ShadowCiphertext(
        uint256 indexed shadowId,
        bytes32 indexed ctCommit,
        bytes c2
    );
    event ShadowTransferred(
        uint256 indexed shadowId,
        address indexed to,
        bytes32 newEcdhPubX,
        bytes32 newEcdhPubY
    );
    event SlotMutated(
        uint256 indexed shadowId,
        uint8 indexed slotIdx,
        uint64 newPose
    );
    event SlotExtracted(
        uint256 indexed shadowId,
        uint8 indexed slotIdx,
        uint256 indexed featureNftId,
        address to
    );
    event FeatureInserted(
        uint256 indexed shadowId,
        uint8 indexed slotIdx,
        uint256 indexed featureNftId,
        uint64 pose
    );
    event FeatureRemoved(
        uint256 indexed shadowId,
        uint8 indexed slotIdx,
        uint256 indexed featureNftId
    );
    event ShadowSolved(uint256 indexed shadowId, address solver, bytes revealedPi);
    event ShadowT10Updated(uint256 indexed shadowId, uint64 indexed stateNonce, bytes32 hi, bytes32 lo);

    event MintShadowVerifierSet(IVerifier v);
    event TransferShadowVerifierSet(IVerifier v);
    event ExtractSlotVerifierSet(IVerifier v);
    event SolveShadowVerifierSet(IVerifier v);
    event T10ShadowVerifierSet(IVerifier v);
    event FaceDiscVerifierSet(IVerifier v);
    event KeyRegistrySet(KeyRegistry r);
    event FeatureNFTSet(IFeatureNFT f);

    // ============== errors ==============

    error NotDeployer();
    error NotShadowOwner();
    error AlreadyMinted(bytes32 faceOriginId);
    error AlreadySolved();
    error InvalidProof();
    error BadPILen(uint256 got, uint256 want);
    error BadC2Length(uint256 got);
    error CtCommitMismatch(bytes32 fromChain, bytes32 fromProof);
    error PkMismatch(bytes32 want, bytes32 got);

    error VerifierNotSet();
    error VerifierAlreadySet();
    error FeatureNFTAlreadySet();
    error FeatureNFTNotSet();
    error KeyRegistryAlreadySet();

    error SlotOutOfRange(uint8 slotIdx);
    error SlotNotEmpty(uint8 slotIdx);
    error SlotNotOriginal(uint8 slotIdx);
    error SlotNotInserted(uint8 slotIdx);
    error FeatureNotOwned(uint256 featureNftId);
    error FeatureFrozen(uint256 featureNftId);
    error TransferGated();

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

    function setTransferShadowVerifier(IVerifier v) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (_transferShadowVerifierLocked) revert VerifierAlreadySet();
        transferShadowVerifier = v;
        _transferShadowVerifierLocked = true;
        emit TransferShadowVerifierSet(v);
    }

    function setExtractSlotVerifier(IVerifier v) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (_extractSlotVerifierLocked) revert VerifierAlreadySet();
        extractSlotVerifier = v;
        _extractSlotVerifierLocked = true;
        emit ExtractSlotVerifierSet(v);
    }

    function setSolveShadowVerifier(IVerifier v) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (_solveShadowVerifierLocked) revert VerifierAlreadySet();
        solveShadowVerifier = v;
        _solveShadowVerifierLocked = true;
        emit SolveShadowVerifierSet(v);
    }

    function setT10ShadowVerifier(IVerifier v) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (_t10ShadowVerifierLocked) revert VerifierAlreadySet();
        t10ShadowVerifier = v;
        _t10ShadowVerifierLocked = true;
        emit T10ShadowVerifierSet(v);
    }

    // ============== mintShadow ==============

    /// Public PI layout (18 fields, landmark_regions circuit):
    ///   PI[0..7]   stateCommit_0..7  (per-slot Poseidon2 sponge_11)
    ///   PI[8]      faceOriginId
    ///   PI[9]      boxes_packed       (8 * (x|y|w|h) * 6 bits = 192 bits in one Field)
    ///   PI[10]     color
    ///   PI[11]     callerNonceCommit
    ///   PI[12,13]  c1_x, c1_y         (ECIES ephemeral pk)
    ///   PI[14]     ct_commit          (= sponge_249(c2))
    ///   PI[15,16]  recipient_pk_x, recipient_pk_y
    ///   PI[17]     image_commit       (= sponge_6912(image); shared with face_disc proof)
    ///
    /// face_disc proof PI is [image_commit] (length 1). The chain enforces
    /// pi[17] == proofDisc.PI[0] so a single image is BOTH face-attested by
    /// the discriminator AND envelope-bound by landmark_regions.
    function mintShadow(
        bytes calldata proof,
        bytes32[] calldata pi,
        bytes calldata c2,
        bytes calldata proofDisc
    ) external whenNotPaused returns (uint256 shadowId) {
        if (pi.length != MINT_SHADOW_PI_LEN) revert BadPILen(pi.length, MINT_SHADOW_PI_LEN);
        if (c2.length != MINT_SHADOW_C2_BYTES) revert BadC2Length(c2.length);

        bytes32 faceOriginId = pi[8];
        if (mintedOrigins[faceOriginId]) revert AlreadyMinted(faceOriginId);

        // Recipient pk binding (audit fix #3): if registry is set, the caller
        // must have registered (recipient_pk_x, recipient_pk_y) -- self-mint
        // convention.
        _requirePkMatchesCaller(pi[15], pi[16]);

        // Verify both proofs in a helper to keep mintShadow's stack budget
        // headroom for _writeShadowRow below. Order: face_disc first (cheap,
        // fail-fast for non-faces), then landmark+envelope.
        _verifyMintProofs(proof, pi, proofDisc);

        // On-chain Yul sponge_249 binding: chain refuses to log mismatched c2.
        uint256 digest = _sponge249(c2);
        if (bytes32(digest) != pi[14]) {
            revert CtCommitMismatch(bytes32(digest), pi[14]);
        }

        mintedOrigins[faceOriginId] = true;
        // chainId binding: prevents the same mint proof from being replayed on a
        // different chain. The id derivation includes block.chainid so a face
        // minted on chain A and chain B produces different shadowIds, which
        // means a proof bound to one chain's id will fail PI[0] on the other.
        shadowId = uint256(keccak256(abi.encode(DOMAIN_SHADOW, block.chainid, faceOriginId))) % FR_MOD;

        // Mint counter for indexer ordering.
        mintCounter += 1;
        uint64 mintIdx = mintCounter;

        // Write Shadow row + manifest in their own helpers (stack budget).
        _writeShadowRow(shadowId, faceOriginId, mintIdx, pi);
        _writeOriginalManifest(shadowId, pi[9]);

        // T10 binding: store boxes_packed (immutable from mint). The state
        // nonce stays at its storage default (0) for the post-mint state;
        // mutators bump it.
        boxesPackedOf[shadowId] = pi[9];

        _mint(msg.sender, shadowId);

        emit ShadowMinted(shadowId, faceOriginId, msg.sender, uint8(uint256(pi[10])), mintIdx);
        emit ShadowCiphertext(shadowId, pi[14], c2);
    }

    /// Verify face_disc proof (PI[0] == landmark.PI[17]) and the landmark
    /// mint proof. Reverts InvalidProof if either rejects. Kept as a helper
    /// so mintShadow's stack stays under the EVM 16-slot limit.
    function _verifyMintProofs(
        bytes calldata proof,
        bytes32[] calldata pi,
        bytes calldata proofDisc
    ) internal view {
        IVerifier vd = faceDiscVerifier;
        if (address(vd) == address(0)) revert VerifierNotSet();
        IVerifier v = mintShadowVerifier;
        if (address(v) == address(0)) revert VerifierNotSet();

        bytes32[] memory piDisc = new bytes32[](FACE_DISC_PI_LEN);
        piDisc[0] = pi[17];
        try vd.verify(proofDisc, piDisc) returns (bool okDisc) {
            if (!okDisc) revert InvalidProof();
        } catch {
            revert InvalidProof();
        }

        try v.verify(proof, pi) returns (bool ok) {
            if (!ok) revert InvalidProof();
        } catch {
            revert InvalidProof();
        }
    }

    function _writeShadowRow(
        uint256 shadowId,
        bytes32 faceOriginId,
        uint64 mintIdx,
        bytes32[] calldata pi
    ) internal {
        Shadow storage s = _shadows[shadowId];
        s.faceOriginId = faceOriginId;
        s.color = uint8(uint256(pi[10]));
        s.ecdhPubX = pi[15];
        s.ecdhPubY = pi[16];
        s.c2Commit = pi[14];
        s.mintIdx = mintIdx;
        s.mintedAt = uint64(block.number);
        s.stateCommitsHash = _hashStateCommits(pi);

        // Decode boxes_packed (24 bits per slot) -> origPose for slots 0..7.
        // Each (x, y, w, h) is 6 bits; identity pose = pack(x, y, 256, 32767, 0).
        uint256 bp = uint256(pi[9]);
        s.origPose0 = _identityPoseFromSlot(bp, 0);
        s.origPose1 = _identityPoseFromSlot(bp, 1);
        s.origPose2 = _identityPoseFromSlot(bp, 2);
        s.origPose3 = _identityPoseFromSlot(bp, 3);
        s.origPose4 = _identityPoseFromSlot(bp, 4);
        s.origPose5 = _identityPoseFromSlot(bp, 5);
        s.origPose6 = _identityPoseFromSlot(bp, 6);
        s.origPose7 = _identityPoseFromSlot(bp, 7);
    }

    function _identityPoseFromSlot(uint256 boxesPacked, uint8 typeIdx) internal pure returns (uint64) {
        uint256 slot = (boxesPacked >> (24 * typeIdx)) & 0xFFFFFF;
        uint8 x = uint8(slot & 0x3F);
        uint8 y = uint8((slot >> 6) & 0x3F);
        return PoseLib.identity(x, y);
    }

    function _writeOriginalManifest(uint256 shadowId, bytes32 boxesPacked) internal {
        ManifestEntry[16] storage m = _manifests[shadowId];
        uint256 bp = uint256(boxesPacked);
        for (uint8 i = 0; i < 8; i++) {
            m[i].kind = SlotKind.ORIGINAL;
            m[i].originalTypeIdx = i;
            m[i].pose = _identityPoseFromSlot(bp, i);
            // insertedFeatureId stays 0 by default.
        }
        // Slots 8..15 stay EMPTY (default zero-valued).
    }

    // ============== transferShadow ==============

    /// Re-encrypt this shadow's c2 to a new owner. Manifest unchanged.
    /// Inserted FeatureNFTs do NOT auto-transfer (per design: each token
    /// has independent ownership).
    ///
    /// PI layout (8 fields):
    ///   PI[0]    shadowId
    ///   PI[1,2]  next_pk_x, next_pk_y
    ///   PI[3,4]  c1_x, c1_y
    ///   PI[5]    c2_scalar  (= k_new + k_mask)
    ///   PI[6]    new_ct_commit  (= sponge_249(re-encrypted c2))
    ///   PI[7]    prev_ct_commit (must match chain)
    function transferShadow(
        uint256 shadowId,
        address to,
        bytes calldata proof,
        bytes32[] calldata pi,
        bytes calldata c2New
    ) external whenNotPaused {
        if (_ownerOf(shadowId) != msg.sender) revert NotShadowOwner();
        if (solved[shadowId]) revert AlreadySolved();
        if (pi.length != TRANSFER_SHADOW_PI_LEN) revert BadPILen(pi.length, TRANSFER_SHADOW_PI_LEN);
        if (c2New.length != MINT_SHADOW_C2_BYTES) revert BadC2Length(c2New.length);

        IVerifier v = transferShadowVerifier;
        if (address(v) == address(0)) revert VerifierNotSet();

        Shadow storage s = _shadows[shadowId];
        // Bind PI[0] = shadowId.
        if (pi[0] != bytes32(shadowId)) revert InvalidProof();
        // Bind PI[7] = chain's stored c2Commit (the prev binding).
        if (pi[7] != s.c2Commit) revert InvalidProof();
        // Recipient pk must match registry (if set).
        _requirePkMatches(to, pi[1], pi[2]);

        try v.verify(proof, pi) returns (bool ok) {
            if (!ok) revert InvalidProof();
        } catch {
            revert InvalidProof();
        }

        // On-chain c2New binding.
        uint256 digest = _sponge249(c2New);
        if (bytes32(digest) != pi[6]) revert CtCommitMismatch(bytes32(digest), pi[6]);

        // Rotate state.
        s.ecdhPubX = pi[1];
        s.ecdhPubY = pi[2];
        s.c2Commit = pi[6];

        _bumpNonce(shadowId);
        emit ShadowTransferred(shadowId, to, pi[1], pi[2]);
        emit ShadowCiphertext(shadowId, pi[6], c2New);

        // Use _update directly instead of _safeTransfer: skips the
        // onERC721Received callback. Recipient pk is already bound by the
        // proof + on-chain c2 sponge check, so the recipient is canonically
        // determined regardless of whether they have receiver-callback code.
        // (Avoids EIP-7702 delegated EOAs being treated as receiver-rejecting
        //  contracts.)
        _update(to, shadowId, address(0));
    }

    // ============== mutateSlot ==============

    /// Update one slot's pose. No proof: pose is plain calldata, range-checked.
    /// Works for both ORIGINAL and INSERTED slots.
    /// Note: only manifest pose changes; origPose stays immutable per spec.
    function mutateSlot(uint256 shadowId, uint8 slotIdx, uint64 newPose) external whenNotPaused {
        if (_ownerOf(shadowId) != msg.sender) revert NotShadowOwner();
        if (solved[shadowId]) revert AlreadySolved();
        if (slotIdx >= 16) revert SlotOutOfRange(slotIdx);

        ManifestEntry storage m = _manifests[shadowId][slotIdx];
        if (m.kind == SlotKind.EMPTY) revert SlotNotInserted(slotIdx);

        // Pose-format sanity (bit layout, scale > 0, unit rotation).
        PoseLib.requireSane(newPose);

        // Feature-aware on-frame check. Use the ACTUAL landmark dimensions
        // (decoded from boxes_packed at mint), not the conservative MAX
        // REGION_W/H, so PROGRAMMEs can re-anchor a small landmark anywhere on
        // the 48x48 canvas. INSERTED slots fall back to the inserted feature
        // type's MAX dims (no per-feature actual-size storage in MVP).
        uint8 frameW;
        uint8 frameH;
        if (m.kind == SlotKind.ORIGINAL) {
            uint256 bp = uint256(boxesPackedOf[shadowId]);
            uint256 sd = (bp >> (24 * uint256(slotIdx))) & 0xFFFFFF;
            frameW = uint8((sd >> 12) & 0x3F);
            frameH = uint8((sd >> 18) & 0x3F);
        } else {
            uint8 typeIdx = featureNFT.featureTypeOf(m.insertedFeatureId);
            frameW = REGION_W[typeIdx];
            frameH = REGION_H[typeIdx];
        }
        PoseLib.requireOnFrame(newPose, frameW, frameH);

        m.pose = newPose;
        _bumpNonce(shadowId);
        emit SlotMutated(shadowId, slotIdx, newPose);
    }

    // ============== extractSlot ==============

    /// Extract slot `slotIdx` (must be ORIGINAL) into a standalone FeatureNFT.
    /// Slot becomes EMPTY. Shadow's c2 doesn't change.
    ///
    /// PI layout (10 fields):
    ///   PI[0]   shadowId
    ///   PI[1]   slotIdx
    ///   PI[2]   featureType    (must equal slot's originalTypeIdx)
    ///   PI[3]   prev_shadow_ct_commit  (must match chain)
    ///   PI[4,5] next_pk_x, next_pk_y   (recipient pk for new FeatureNFT)
    ///   PI[6,7] c1_x, c1_y
    ///   PI[8]   c2_scalar
    ///   PI[9]   feature_ct_commit  (= sponge_42 of new FeatureNFT's c2)
    function extractSlot(
        uint256 shadowId,
        uint8 slotIdx,
        address to,
        bytes calldata proof,
        bytes32[] calldata pi,
        bytes calldata c2Feature
    ) external whenNotPaused returns (uint256 featureNftId) {
        if (_ownerOf(shadowId) != msg.sender) revert NotShadowOwner();
        if (solved[shadowId]) revert AlreadySolved();
        if (slotIdx >= 8) revert SlotOutOfRange(slotIdx);          // only ORIGINAL slots extract
        if (pi.length != 10) revert BadPILen(pi.length, 10);
        if (c2Feature.length != 42 * 32) revert BadC2Length(c2Feature.length);
        if (address(featureNFT) == address(0)) revert FeatureNFTNotSet();

        IVerifier v = extractSlotVerifier;
        if (address(v) == address(0)) revert VerifierNotSet();

        ManifestEntry storage m = _manifests[shadowId][slotIdx];
        if (m.kind != SlotKind.ORIGINAL) revert SlotNotOriginal(slotIdx);

        // Public-input bindings + proof verify (split out for stack budget).
        _verifyExtractInputs(shadowId, slotIdx, m.originalTypeIdx, to, proof, pi, c2Feature, v);

        // Mint the FeatureNFT. Helper captures m.* into its own frame, zeros the
        // manifest slot in storage, then calls featureNFT.mintFromExtraction.
        // Order #(zero) -> #(call) neutralizes cross-function reentrancy: any
        // callback into ShadowToken would observe an EMPTY slot.
        featureNftId = _mintExtractedFeature(shadowId, slotIdx, m, pi, to);

        _bumpNonce(shadowId);
        emit SlotExtracted(shadowId, slotIdx, featureNftId, to);
    }

    function _verifyExtractInputs(
        uint256 shadowId,
        uint8 slotIdx,
        uint8 originalTypeIdx,
        address to,
        bytes calldata proof,
        bytes32[] calldata pi,
        bytes calldata c2Feature,
        IVerifier v
    ) internal view {
        Shadow storage s = _shadows[shadowId];
        if (pi[0] != bytes32(shadowId)) revert InvalidProof();
        if (pi[1] != bytes32(uint256(slotIdx))) revert InvalidProof();
        if (pi[2] != bytes32(uint256(originalTypeIdx))) revert InvalidProof();
        if (pi[3] != s.c2Commit) revert InvalidProof();
        _requirePkMatches(to, pi[4], pi[5]);

        try v.verify(proof, pi) returns (bool ok) {
            if (!ok) revert InvalidProof();
        } catch {
            revert InvalidProof();
        }

        uint256 digest = _sponge42(c2Feature);
        if (bytes32(digest) != pi[9]) revert CtCommitMismatch(bytes32(digest), pi[9]);
    }

    function _mintExtractedFeature(
        uint256 shadowId,
        uint8 slotIdx,
        ManifestEntry storage m,
        bytes32[] calldata pi,
        address to
    ) internal returns (uint256) {
        // Capture before clearing.
        uint8  origType = m.originalTypeIdx;
        uint64 origPose = m.pose;
        // Clear before external call (reentrancy-no-eth fix).
        m.kind = SlotKind.EMPTY;
        m.originalTypeIdx = 0;
        m.insertedFeatureId = 0;
        m.pose = 0;
        Shadow storage s = _shadows[shadowId];
        return featureNFT.mintFromExtraction(
            shadowId,
            slotIdx,
            origType,
            s.color,
            pi[4],
            pi[5],
            pi[9],
            origPose,
            to
        );
    }

    // ============== insertFeature / removeFeature ==============

    /// Bind a FeatureNFT into an EMPTY slot. Caller must own both shadow
    /// and feature; feature must not be frozen. No proof: pose is plain
    /// calldata, range-checked.
    function insertFeature(
        uint256 shadowId,
        uint8 slotIdx,
        uint256 featureNftId,
        uint64 pose
    ) external whenNotPaused {
        if (_ownerOf(shadowId) != msg.sender) revert NotShadowOwner();
        if (solved[shadowId]) revert AlreadySolved();
        if (slotIdx >= 16) revert SlotOutOfRange(slotIdx);
        if (address(featureNFT) == address(0)) revert FeatureNFTNotSet();

        ManifestEntry storage m = _manifests[shadowId][slotIdx];
        if (m.kind != SlotKind.EMPTY) revert SlotNotEmpty(slotIdx);

        // Caller must own the FeatureNFT.
        if (featureNFT.ownerOfFeature(featureNftId) != msg.sender) {
            revert FeatureNotOwned(featureNftId);
        }
        if (featureNFT.isFrozen(featureNftId)) revert FeatureFrozen(featureNftId);

        // Range checks on pose.
        PoseLib.requireSane(pose);
        uint8 typeIdx = featureNFT.featureTypeOf(featureNftId);
        PoseLib.requireOnFrame(pose, REGION_W[typeIdx], REGION_H[typeIdx]);

        m.kind = SlotKind.INSERTED;
        m.originalTypeIdx = 0;
        m.insertedFeatureId = featureNftId;
        m.pose = pose;

        _bumpNonce(shadowId);
        emit FeatureInserted(shadowId, slotIdx, featureNftId, pose);
    }

    /// Symmetric to insertFeature: unbinds an INSERTED slot back to EMPTY.
    /// The FeatureNFT itself is not burned.
    function removeFeature(uint256 shadowId, uint8 slotIdx) external whenNotPaused {
        if (_ownerOf(shadowId) != msg.sender) revert NotShadowOwner();
        if (solved[shadowId]) revert AlreadySolved();
        if (slotIdx >= 16) revert SlotOutOfRange(slotIdx);

        ManifestEntry storage m = _manifests[shadowId][slotIdx];
        if (m.kind != SlotKind.INSERTED) revert SlotNotInserted(slotIdx);

        uint256 featureNftId = m.insertedFeatureId;
        m.kind = SlotKind.EMPTY;
        m.originalTypeIdx = 0;
        m.insertedFeatureId = 0;
        m.pose = 0;

        _bumpNonce(shadowId);
        emit FeatureRemoved(shadowId, slotIdx, featureNftId);
    }

    // ============== setShadowT10 ==============

    /// Refresh the public T10 grayscale shadow artifact for `shadowId`.
    /// Permissionless: anyone can call. Stale fixtures are rejected by
    /// state_nonce binding (PI[1]).
    ///
    /// PI layout (9 fields):
    ///   PI[0]   shadow_id
    ///   PI[1]   state_nonce
    ///   PI[2]   prev_ct_commit (= s.c2Commit)
    ///   PI[3]   boxes_packed   (= boxesPackedOf[shadowId])
    ///   PI[4]   poses_hash     (= sponge_16 of current manifest poses)
    ///   PI[5]   shadow_q0
    ///   PI[6]   shadow_q1
    ///   PI[7]   shadow_q2
    ///   PI[8]   shadow_q3
    function setShadowT10(
        uint256 shadowId,
        bytes calldata proof,
        bytes32[] calldata pi
    ) external whenNotPaused {
        if (pi.length != 9) revert BadPILen(pi.length, 9);
        IVerifier v = t10ShadowVerifier;
        if (address(v) == address(0)) revert VerifierNotSet();
        _verifyT10Inputs(shadowId, proof, pi, v);
        (bytes32 hi, bytes32 lo) = _packT10(pi);
        shadowT10[shadowId][0] = hi;
        shadowT10[shadowId][1] = lo;
        emit ShadowT10Updated(shadowId, stateNonce[shadowId], hi, lo);
    }

    function _verifyT10Inputs(
        uint256 shadowId,
        bytes calldata proof,
        bytes32[] calldata pi,
        IVerifier v
    ) internal view {
        Shadow storage s = _shadows[shadowId];
        if (s.faceOriginId == bytes32(0)) revert InvalidProof();
        if (pi[0] != bytes32(shadowId)) revert InvalidProof();
        if (pi[1] != bytes32(uint256(stateNonce[shadowId]))) revert InvalidProof();
        if (pi[2] != s.c2Commit) revert InvalidProof();
        if (pi[3] != boxesPackedOf[shadowId]) revert InvalidProof();
        if (pi[4] != _posesHash(shadowId)) revert InvalidProof();
        try v.verify(proof, pi) returns (bool ok) {
            if (!ok) revert InvalidProof();
        } catch {
            revert InvalidProof();
        }
    }

    /// Pack the 4 PI quartets into (hi, lo). Reverts if any quartet exceeds
    /// 128 bits (would alias the neighbouring slot).
    function _packT10(bytes32[] calldata pi) internal pure returns (bytes32 hi, bytes32 lo) {
        uint256 mask128 = (uint256(1) << 128) - 1;
        uint256 q0 = uint256(pi[5]); uint256 q1 = uint256(pi[6]);
        uint256 q2 = uint256(pi[7]); uint256 q3 = uint256(pi[8]);
        if (q0 > mask128 || q1 > mask128 || q2 > mask128 || q3 > mask128) {
            revert InvalidProof();
        }
        hi = bytes32(q0 | (q1 << 128));
        lo = bytes32(q2 | (q3 << 128));
    }


    // ============== solve ==============

    /// One-way reveal of the 252-Field plaintext. Marks shadow solved.
    /// Freezes any INSERTED FeatureNFTs in the manifest (so they can't be
    /// transferred elsewhere after the puzzle is solved).
    ///
    /// PI layout (261 fields, identical to phase-1 solve):
    ///   PI[0..7]     stateCommits (must match chain's origPose-derived per slot)
    ///   PI[8]        faceOriginId
    ///   PI[9..260]   252 packed plaintext fields
    function solve(
        uint256 shadowId,
        bytes calldata proof,
        bytes32[] calldata pi
    ) external whenNotPaused {
        if (_ownerOf(shadowId) != msg.sender) revert NotShadowOwner();
        if (solved[shadowId]) revert AlreadySolved();
        if (pi.length != SOLVE_SHADOW_PI_LEN) revert BadPILen(pi.length, SOLVE_SHADOW_PI_LEN);

        IVerifier v = solveShadowVerifier;
        if (address(v) == address(0)) revert VerifierNotSet();

        // PI[0..7] are stateCommits; bind them to alice's mint via stored hash.
        // PI[8] is the presence byte (not face_origin_id; that's in the witness).
        Shadow storage s = _shadows[shadowId];
        if (_hashStateCommits(pi) != s.stateCommitsHash) revert InvalidProof();

        try v.verify(proof, pi) returns (bool ok) {
            if (!ok) revert InvalidProof();
        } catch {
            revert InvalidProof();
        }

        solved[shadowId] = true;

        // Freeze any inserted FeatureNFTs (best-effort: ignore reverts so a
        // misbehaving FeatureNFT can't deadlock solve).
        ManifestEntry[16] storage m = _manifests[shadowId];
        for (uint8 i = 0; i < 16; i++) {
            if (m[i].kind == SlotKind.INSERTED) {
                try featureNFT.freezeFeature(m[i].insertedFeatureId) {} catch {}
            }
        }

        // Emit revealed PI as event data for indexers.
        bytes memory revealed = new bytes(pi.length * 32);
        for (uint256 i = 0; i < pi.length; i++) {
            bytes32 vv = pi[i];
            assembly ("memory-safe") {
                mstore(add(revealed, mul(32, add(i, 1))), vv)
            }
        }
        emit ShadowSolved(shadowId, msg.sender, revealed);
    }

    // ============== view accessors ==============

    function shadowOf(uint256 shadowId) external view returns (Shadow memory) {
        return _shadows[shadowId];
    }

    function manifestOf(uint256 shadowId) external view returns (ManifestEntry[16] memory) {
        return _manifests[shadowId];
    }

    function slotOf(uint256 shadowId, uint8 slotIdx) external view returns (ManifestEntry memory) {
        if (slotIdx >= 16) revert SlotOutOfRange(slotIdx);
        return _manifests[shadowId][slotIdx];
    }

    function origPoseOf(uint256 shadowId, uint8 typeIdx) external view returns (uint64) {
        if (typeIdx >= 8) revert SlotOutOfRange(typeIdx);
        Shadow storage s = _shadows[shadowId];
        if (typeIdx == 0) return s.origPose0;
        if (typeIdx == 1) return s.origPose1;
        if (typeIdx == 2) return s.origPose2;
        if (typeIdx == 3) return s.origPose3;
        if (typeIdx == 4) return s.origPose4;
        if (typeIdx == 5) return s.origPose5;
        if (typeIdx == 6) return s.origPose6;
        return s.origPose7;
    }

    function shadowIdOf(bytes32 faceOriginId) external view returns (uint256) {
        return uint256(keccak256(abi.encode(DOMAIN_SHADOW, block.chainid, faceOriginId))) % FR_MOD;
    }

    // ============== ERC-721 transfer lockdown ==============
    //
    // Plain transferFrom bypasses the proof-gated transferShadow path and
    // would leak the shadow without rotating ecdhPubX/Y -- breaking the
    // crypto invariant that the on-chain pk matches who can decrypt c2.
    // Allow plain transfers ONLY post-solve (solved shadows behave as
    // ordinary collectibles since the plaintext is already public).
    function transferFrom(address from, address to, uint256 tokenId)
        public
        override
    {
        if (!solved[tokenId]) revert TransferGated();
        super.transferFrom(from, to, tokenId);
    }

    // ============== internals ==============

    /// Yul Poseidon2 sponge_249. STATICCALL with 7,968 bytes of c2 calldata
    /// copied to memory; returns the squeezed 32-byte digest.
    function _sponge249(bytes calldata data) internal view returns (uint256 digest) {
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

    /// Yul Poseidon2 sponge_42. Same Yul contract; just shorter calldata
    /// (1,344 bytes = 42 * 32). Yul sponge handles any multiple-of-96 bytes.
    function _sponge42(bytes calldata data) internal view returns (uint256 digest) {
        return _sponge249(data); // same impl, different length
    }

    function _requirePkMatchesCaller(bytes32 px, bytes32 py) internal view {
        _requirePkMatches(msg.sender, px, py);
    }

    function _requirePkMatches(address who, bytes32 px, bytes32 py) internal view {
        KeyRegistry r = keyRegistry;
        if (address(r) == address(0)) return; // permissive mode
        if (!r.isRegistered(who)) return;     // not registered = no constraint (best-effort dev mode)
        (bytes32 wantX, bytes32 wantY) = r.pkOf(who);
        if (wantX != px) revert PkMismatch(wantX, px);
        if (wantY != py) revert PkMismatch(wantY, py);
    }

    /// Helper: keccak256 of pi[0..7] (8 fields = 256 bytes). Pulled out so
    /// neither mintShadow nor solve pushes a deep stack with 8 locals.
    function _hashStateCommits(bytes32[] calldata pi) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(pi[0], pi[1], pi[2], pi[3], pi[4], pi[5], pi[6], pi[7]));
    }

    /// Bump state nonce. Called from every state-change function so any T10
    /// fixture binds to the post-change state.
    function _bumpNonce(uint256 shadowId) internal {
        unchecked { stateNonce[shadowId] += 1; }
    }

    /// Sponge_18 over the shadow's manifest poses + 2 zero pads. The padding
    /// makes the input length a multiple of 3 (18 = 6 * 3), which the Yul
    /// Poseidon2YulSponge requires (it rejects non-multiple-of-96-byte calldata).
    /// The circuit pads identically.
    function _posesHash(uint256 shadowId) internal view returns (bytes32) {
        ManifestEntry[16] storage m = _manifests[shadowId];
        bytes memory buf = new bytes(18 * 32);
        for (uint256 i = 0; i < 16; i++) {
            uint256 p = uint256(m[i].pose);
            assembly ("memory-safe") { mstore(add(buf, mul(32, add(i, 1))), p) }
        }
        // bytes 16*32..18*32 stay zero (default-init memory).
        address y = yulSponge;
        uint256 digest;
        assembly ("memory-safe") {
            let ok := staticcall(gas(), y, add(buf, 32), 576, 0, 32)
            if iszero(ok) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
            digest := mload(0)
        }
        return bytes32(digest);
    }


    // ============== verifier rotation slot ids ==============
    uint8 public constant SLOT_MINT_SHADOW       = 0;
    uint8 public constant SLOT_TRANSFER_SHADOW   = 1;
    uint8 public constant SLOT_EXTRACT_SLOT      = 2;
    uint8 public constant SLOT_SOLVE_SHADOW      = 3;
    uint8 public constant SLOT_T10_SHADOW        = 4;

    function _writeVerifierSlot(uint8 slot, address newVerifier) internal override {
        if (slot == SLOT_MINT_SHADOW) {
            mintShadowVerifier = IVerifier(newVerifier);
        } else if (slot == SLOT_TRANSFER_SHADOW) {
            transferShadowVerifier = IVerifier(newVerifier);
        } else if (slot == SLOT_EXTRACT_SLOT) {
            extractSlotVerifier = IVerifier(newVerifier);
        } else if (slot == SLOT_SOLVE_SHADOW) {
            solveShadowVerifier = IVerifier(newVerifier);
        } else if (slot == SLOT_T10_SHADOW) {
            t10ShadowVerifier = IVerifier(newVerifier);
        } else {
            revert("unknown slot");
        }
    }
}
