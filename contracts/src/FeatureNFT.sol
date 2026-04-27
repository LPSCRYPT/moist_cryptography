// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {IVerifier} from "./IVerifier.sol";
import {IFeatureNFT} from "./IFeatureNFT.sol";
import {KeyRegistry} from "./KeyRegistry.sol";
import {PausableMixin} from "./PausableMixin.sol";

/**
 * @title  FeatureNFT (v2 carrier)
 * @notice ERC-721 carrier for an atom of pixels in the moist_cryptography
 *         system. Created exclusively by `ShadowToken.mintShadow` (which
 *         atomically mints 1 shadow + 8 carriers).
 *
 *         Carrier state:
 *           Immutable from mint:
 *             - typeIdx        landmark type 0..7
 *             - originFaceId   lineage anchor (the face this atom's
 *                              pixels first originated from)
 *             - paletteCommit  poseidon2 of the 16 palette colors
 *             - mintedAt       block.number at mint, audit trail
 *           Mutable:
 *             - liveStateHashCheckpoint  authoritative when held;
 *                                        stale while inserted
 *             - isInserted               true while a host shadow's slot
 *                                        binds this carrier
 *             - hostShadowId, hostSlotIdx  meaningful iff isInserted
 *
 *         Three invariants the contract enforces:
 *           1. Custody lock — ERC-721 transferFrom and `transferFeature`
 *              revert while `isInserted == true`. Only `extractSlot` on
 *              the host shadow can exit custody.
 *           2. Single-host invariant — a carrier is bound into at most
 *              one slot at any time.
 *           3. Live-state-on-host — while inserted, the slot's
 *              `liveStateHash` is authoritative; the carrier's
 *              `liveStateHashCheckpoint` is treated as stale and is only
 *              re-synced on `extractFromShadow`.
 *
 *         `transferFeature` rotates encryption to a new owner *while held*
 *         (i.e. with `isInserted == false`). The proof PI binds the
 *         carrier's `liveStateHashCheckpoint`; the new owner inherits
 *         the same checkpoint.
 */
contract FeatureNFT is ERC721, PausableMixin, IFeatureNFT {
    // ============== types ==============

    struct Feature {
        // Immutable from mint:
        uint8   typeIdx;
        bytes32 originFaceId;
        bytes32 paletteCommit;
        uint64  mintedAt;
        // Mutable:
        bytes32 liveStateHashCheckpoint;
        bool    isInserted;
        uint256 hostShadowId;
        uint8   hostSlotIdx;
        bool    paletteRevealed;        // flipped by `revealPalette`
    }

    // ============== constants ==============

    bytes32 public constant DOMAIN_FEATURE = keccak256("OMP_FEATURE_NFT_v2");

    /// transfer_feature proof PI layout: see `transferFeature` below.
    /// PI[0]    featureId
    /// PI[1,2]  next_pk_x, next_pk_y
    /// PI[3]    old_liveStateHashCheckpoint   (asserted unchanged on chain)
    /// PI[4]    new_liveStateHashCheckpoint   (post-rotation; written on success)
    /// PI[5]    paletteCommit                 (asserted unchanged)
    /// PI[6]    typeIdx                       (asserted unchanged)
    /// PI[7]    originFaceId                  (asserted unchanged)
    uint256 public constant TRANSFER_FEATURE_PI_LEN = 8;

    /// palette_reveal proof PI layout: see `revealPalette` below.
    /// PI[0]      featureId
    /// PI[1]      paletteCommit                  (asserted == storage)
    /// PI[2..10]  palette_packed[8]              (each = palette[2i] + palette[2i+1] * 2^24)
    uint256 public constant PALETTE_REVEAL_PI_LEN = 10;

    /// bn254 Fr field modulus. featureId is reduced mod FR_MOD so PI[0]
    /// equality (Field == Field) holds across circuit/contract boundary.
    uint256 public constant FR_MOD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // ============== storage ==============

    address public immutable deployer;
    address public immutable shadowToken; // back-reference; only this address may mint/extract/insert

    KeyRegistry public keyRegistry;
    bool private _keyRegistryLocked;

    IVerifier public transferFeatureVerifier;
    bool private _transferFeatureVerifierLocked;

    IVerifier public paletteRevealVerifier;
    bool private _paletteRevealVerifierLocked;

    mapping(uint256 => Feature) private _features;
    uint64 public mintCounter;

    // ============== events ==============

    event FeatureMinted(
        uint256 indexed featureId,
        uint256 indexed hostShadowId,
        uint8   indexed hostSlotIdx,
        address to,
        uint8   typeIdx,
        bytes32 originFaceId,
        bytes32 paletteCommit,
        bytes32 initialLiveStateHash
    );
    event FeaturePaletteRevealed(
        uint256 indexed featureId,
        bytes32 paletteCommit,
        bytes paletteRGB // 16 colors x 3 bytes = 48 bytes
    );
    /// Salt envelope for the per-carrier paletteCommit, ECIES-encrypted to
    /// the carrier's owner pk. Emitted alongside `FeatureMinted` at mint;
    /// not stored on chain. Owner decrypts off-chain to recover the salt
    /// needed to call `revealPalette`. Soundness of `revealPalette` does
    /// not depend on these values being honest -- the on-chain
    /// `paletteCommit` storage check is the binding; this event is purely
    /// the wire-format envelope so the owner can decrypt later.
    event FeaturePaletteSaltEnvelope(
        uint256 indexed featureId,
        bytes32 paletteSaltCt,
        bytes32 saltC1X,
        bytes32 saltC1Y
    );
    event FeatureExtracted(
        uint256 indexed featureId,
        uint256 indexed prevHostShadowId,
        uint8   indexed prevHostSlotIdx,
        bytes32 liveStateHashCheckpoint
    );
    event FeatureInserted(
        uint256 indexed featureId,
        uint256 indexed newHostShadowId,
        uint8   indexed newHostSlotIdx
    );
    event FeatureTransferred(
        uint256 indexed featureId,
        address indexed to,
        bytes32 newLiveStateHashCheckpoint
    );
    event FeatureInsertedOwnerRotated(
        uint256 indexed featureId,
        uint256 indexed hostShadowId,
        address indexed to
    );
    event TransferFeatureVerifierSet(IVerifier v);
    event PaletteRevealVerifierSet(IVerifier v);
    event KeyRegistrySet(KeyRegistry r);

    // ============== errors ==============

    error NotShadowToken();
    error NotDeployer();
    error NotFeatureOwner();
    error VerifierAlreadySet();
    error VerifierNotSet();
    error KeyRegistryAlreadySet();
    error InvalidProof();
    error BadPILen(uint256 got, uint256 want);
    error PkMismatch(bytes32 want, bytes32 got);
    error AlreadyInserted(uint256 featureId);
    error NotInserted(uint256 featureId);
    error WrongHost(uint256 featureId);
    error HostMismatch(uint256 featureId);
    error CustodyLocked(uint256 featureId);
    error TransferGated(uint256 featureId);
    error PaletteAlreadyRevealed(uint256 featureId);

    // ============== ctor ==============

    constructor(address shadowTokenAddr) ERC721("OMP Feature NFT", "OMPFN") {
        deployer = msg.sender;
        shadowToken = shadowTokenAddr;
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

    function setTransferFeatureVerifier(IVerifier v) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (_transferFeatureVerifierLocked) revert VerifierAlreadySet();
        transferFeatureVerifier = v;
        _transferFeatureVerifierLocked = true;
        emit TransferFeatureVerifierSet(v);
    }

    function setPaletteRevealVerifier(IVerifier v) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (_paletteRevealVerifierLocked) revert VerifierAlreadySet();
        paletteRevealVerifier = v;
        _paletteRevealVerifierLocked = true;
        emit PaletteRevealVerifierSet(v);
    }

    // ============== privileged: ShadowToken-only ==============

    function mintAtShadowMint(
        uint256 hostShadowId,
        uint8 hostSlotIdx,
        uint8 typeIdx,
        bytes32 originFaceId,
        IFeatureNFT.PaletteAtMint calldata palette,
        bytes32 initialLiveStateHash,
        address to
    ) external override returns (uint256 featureId) {
        if (msg.sender != shadowToken) revert NotShadowToken();

        mintCounter += 1;
        // chainId binding mirrors ShadowToken.shadowIdOf -- same-chain
        // prevention of cross-chain proof replay.
        featureId = uint256(keccak256(abi.encode(
            DOMAIN_FEATURE, block.chainid, hostShadowId, hostSlotIdx, mintCounter
        ))) % FR_MOD;

        Feature storage f = _features[featureId];
        f.typeIdx = typeIdx;
        f.originFaceId = originFaceId;
        f.paletteCommit = palette.commit;
        f.mintedAt = uint64(block.number);
        f.liveStateHashCheckpoint = initialLiveStateHash; // also the slot's value at mint
        f.isInserted = true;
        f.hostShadowId = hostShadowId;
        f.hostSlotIdx = hostSlotIdx;
        // f.paletteRevealed defaults to false; flipped by `revealPalette`.

        _mint(to, featureId);
        emit FeatureMinted(
            featureId, hostShadowId, hostSlotIdx, to,
            typeIdx, originFaceId, palette.commit, initialLiveStateHash
        );
        // Salt envelope is purely advisory wire-format for the owner; not
        // bound by chain state. Empty values are allowed (legacy / pre-spec
        // mints) and just disable the reveal path for that carrier.
        emit FeaturePaletteSaltEnvelope(featureId, palette.saltCt, palette.saltC1X, palette.saltC1Y);
    }

    function extractFromShadow(
        uint256 featureId,
        uint256 hostShadowId,
        uint8 hostSlotIdx,
        bytes32 finalLiveStateHash
    ) external override {
        if (msg.sender != shadowToken) revert NotShadowToken();
        Feature storage f = _features[featureId];
        if (!f.isInserted) revert NotInserted(featureId);
        if (f.hostShadowId != hostShadowId || f.hostSlotIdx != hostSlotIdx) {
            revert WrongHost(featureId);
        }
        f.liveStateHashCheckpoint = finalLiveStateHash;
        f.isInserted = false;
        f.hostShadowId = 0;
        f.hostSlotIdx = 0;
        emit FeatureExtracted(featureId, hostShadowId, hostSlotIdx, finalLiveStateHash);
    }

    function insertIntoShadow(
        uint256 featureId,
        uint256 newHostShadowId,
        uint8 newHostSlotIdx
    ) external override {
        if (msg.sender != shadowToken) revert NotShadowToken();
        Feature storage f = _features[featureId];
        if (f.isInserted) revert AlreadyInserted(featureId);
        f.isInserted = true;
        f.hostShadowId = newHostShadowId;
        f.hostSlotIdx = newHostSlotIdx;
        // checkpoint stays as it was at last extract; v2 lets the slot's
        // liveStateHash be the authoritative value while inserted.
        emit FeatureInserted(featureId, newHostShadowId, newHostSlotIdx);
    }

    /// @notice Rotate ERC-721 ownership of an inserted carrier when its host
    ///         shadow is being transferred. Privileged: only ShadowToken may
    ///         call. Bypasses the custody lock because the caller is the
    ///         host shadow itself, mid-transfer.
    /// @dev    `feature.isInserted` MUST be true and `feature.hostShadowId`
    ///         MUST equal `expectedHostShadowId`; otherwise revert. The
    ///         carrier's `liveStateHashCheckpoint` is unchanged (the slot's
    ///         current `liveStateHash` on the host shadow stays authoritative
    ///         while inserted). Emits a `FeatureInsertedOwnerRotated` event
    ///         so indexers can track the carrier's owner alongside the shadow's.
    function rotateInsertedOwner(
        uint256 featureId,
        uint256 expectedHostShadowId,
        address to
    ) external {
        if (msg.sender != shadowToken) revert NotShadowToken();
        Feature storage f = _features[featureId];
        if (!f.isInserted) revert NotInserted(featureId);
        if (f.hostShadowId != expectedHostShadowId) revert HostMismatch(featureId);
        // ERC721 _update bypasses the public transferFrom guards.
        _update(to, featureId, address(0));
        emit FeatureInsertedOwnerRotated(featureId, expectedHostShadowId, to);
    }

    // ============== transferFeature (held carriers only) ==============

    /// PI layout (8 fields):
    ///   PI[0]    featureId
    ///   PI[1,2]  next_pk_x, next_pk_y
    ///   PI[3]    old_liveStateHashCheckpoint  (must match storage)
    ///   PI[4]    new_liveStateHashCheckpoint  (written on success)
    ///   PI[5]    paletteCommit                (must match storage)
    ///   PI[6]    typeIdx                      (must match storage)
    ///   PI[7]    originFaceId                 (must match storage)
    function transferFeature(
        uint256 featureId,
        address to,
        bytes calldata proof,
        bytes32[] calldata pi
    ) external whenNotPaused {
        if (_ownerOf(featureId) != msg.sender) revert NotFeatureOwner();
        Feature storage f = _features[featureId];
        if (f.isInserted) revert CustodyLocked(featureId);
        if (pi.length != TRANSFER_FEATURE_PI_LEN) revert BadPILen(pi.length, TRANSFER_FEATURE_PI_LEN);

        IVerifier v = transferFeatureVerifier;
        if (address(v) == address(0)) revert VerifierNotSet();

        // Bind every immutable + the prior checkpoint.
        if (pi[0] != bytes32(featureId)) revert InvalidProof();
        if (pi[3] != f.liveStateHashCheckpoint) revert InvalidProof();
        if (pi[5] != f.paletteCommit) revert InvalidProof();
        if (pi[6] != bytes32(uint256(f.typeIdx))) revert InvalidProof();
        if (pi[7] != f.originFaceId) revert InvalidProof();
        _requirePkMatches(to, pi[1], pi[2]);

        try v.verify(proof, pi) returns (bool ok) {
            if (!ok) revert InvalidProof();
        } catch {
            revert InvalidProof();
        }

        f.liveStateHashCheckpoint = pi[4];
        emit FeatureTransferred(featureId, to, pi[4]);

        _update(to, featureId, address(0));
    }

    // ============== revealPalette (any held or inserted carrier) ==============

    /// @notice Open the carrier's `paletteCommit` to the actual 16-color
    ///         palette by exhibiting a `palette_reveal_v2` proof. Owner-
    ///         only (anti-grief). Single-shot: `paletteRevealed` is set
    ///         on success and a second call reverts.
    /// @dev    The proof binds `pi[1] == sponge_palette_salt(palette, salt)`
    ///         and `pi[2..10]` to two-color packings of the palette. The
    ///         contract checks `pi[1] == storage.paletteCommit`; soundness
    ///         flows from that check + the proof's commitment binding.
    ///         Callers off-chain ECIES-decrypt the salt envelope they got
    ///         at mint to obtain the salt witness.
    function revealPalette(
        uint256 featureId,
        bytes calldata proof,
        bytes32[] calldata pi
    ) external whenNotPaused {
        if (_ownerOf(featureId) != msg.sender) revert NotFeatureOwner();
        Feature storage f = _features[featureId];
        if (f.paletteRevealed) revert PaletteAlreadyRevealed(featureId);
        if (pi.length != PALETTE_REVEAL_PI_LEN) revert BadPILen(pi.length, PALETTE_REVEAL_PI_LEN);

        IVerifier v = paletteRevealVerifier;
        if (address(v) == address(0)) revert VerifierNotSet();

        if (pi[0] != bytes32(featureId)) revert InvalidProof();
        if (pi[1] != f.paletteCommit) revert InvalidProof();

        try v.verify(proof, pi) returns (bool ok) {
            if (!ok) revert InvalidProof();
        } catch {
            revert InvalidProof();
        }

        f.paletteRevealed = true;

        // Unpack pi[2..10] into 48 raw RGB bytes (16 colors x 3 bytes).
        // Each packed Field carries:
        //   palette[2i]   in bits  [0..24]   (low color)
        //   palette[2i+1] in bits  [24..48]  (high color)
        // Higher bits are ignored: an adversary who would only be lying
        // to themselves (only the owner has the salt) can't gain anything.
        bytes memory rgb = new bytes(48);
        for (uint256 i = 0; i < 8; i++) {
            uint256 packed = uint256(pi[2 + i]);
            uint256 lo = packed & 0xFFFFFF;
            uint256 hi = (packed >> 24) & 0xFFFFFF;
            rgb[i * 6 + 0] = bytes1(uint8(lo >> 16));
            rgb[i * 6 + 1] = bytes1(uint8(lo >> 8));
            rgb[i * 6 + 2] = bytes1(uint8(lo));
            rgb[i * 6 + 3] = bytes1(uint8(hi >> 16));
            rgb[i * 6 + 4] = bytes1(uint8(hi >> 8));
            rgb[i * 6 + 5] = bytes1(uint8(hi));
        }

        emit FeaturePaletteRevealed(featureId, f.paletteCommit, rgb);
    }

    // ============== view accessors (IFeatureNFT) ==============

    function ownerOfFeature(uint256 featureId) external view override returns (address) {
        return _ownerOf(featureId);
    }

    function typeIdxOf(uint256 featureId) external view override returns (uint8) {
        return _features[featureId].typeIdx;
    }

    function originFaceIdOf(uint256 featureId) external view override returns (bytes32) {
        return _features[featureId].originFaceId;
    }

    function paletteCommitOf(uint256 featureId) external view override returns (bytes32) {
        return _features[featureId].paletteCommit;
    }

    function liveStateHashCheckpointOf(uint256 featureId) external view override returns (bytes32) {
        return _features[featureId].liveStateHashCheckpoint;
    }

    function isInserted(uint256 featureId) external view override returns (bool) {
        return _features[featureId].isInserted;
    }

    function hostShadowIdOf(uint256 featureId) external view override returns (uint256) {
        return _features[featureId].hostShadowId;
    }

    function hostSlotIdxOf(uint256 featureId) external view override returns (uint8) {
        return _features[featureId].hostSlotIdx;
    }

    function featureOf(uint256 featureId) external view returns (Feature memory) {
        return _features[featureId];
    }

    function paletteRevealedOf(uint256 featureId) external view returns (bool) {
        return _features[featureId].paletteRevealed;
    }

    // ============== ERC-721 transfer lockdown ==============
    //
    // Plain ERC-721 transferFrom is fully disabled. Two cases:
    //   - inserted: only `extractSlot` on the host shadow can release
    //     custody. Reverts `CustodyLocked`.
    //   - held:     ownership rotation requires the proof-bound
    //     `transferFeature` path so the new owner inherits ciphertext
    //     they can decrypt. Reverts `TransferGated`.
    function transferFrom(address from, address to, uint256 tokenId)
        public
        override
    {
        from; to; // silence unused-variable warnings
        if (_features[tokenId].isInserted) revert CustodyLocked(tokenId);
        revert TransferGated(tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data)
        public
        override
    {
        from; to; data; // silence unused-variable warnings
        if (_features[tokenId].isInserted) revert CustodyLocked(tokenId);
        revert TransferGated(tokenId);
    }

    // ============== internals ==============

    function _requirePkMatches(address who, bytes32 px, bytes32 py) internal view {
        KeyRegistry r = keyRegistry;
        if (address(r) == address(0)) return;
        if (!r.isRegistered(who)) return;
        (bytes32 wantX, bytes32 wantY) = r.pkOf(who);
        if (wantX != px) revert PkMismatch(wantX, px);
        if (wantY != py) revert PkMismatch(wantY, py);
    }

    // ============== verifier rotation slot ids ==============
    uint8 public constant SLOT_TRANSFER_FEATURE = 0;
    uint8 public constant SLOT_PALETTE_REVEAL  = 1;

    function _writeVerifierSlot(uint8 slot, address newVerifier) internal override {
        if (slot == SLOT_TRANSFER_FEATURE) {
            transferFeatureVerifier = IVerifier(newVerifier);
        } else if (slot == SLOT_PALETTE_REVEAL) {
            paletteRevealVerifier = IVerifier(newVerifier);
        } else {
            revert("unknown slot");
        }
    }
}
