// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {IVerifier} from "./IVerifier.sol";
import {IFeatureNFT} from "./IFeatureNFT.sol";
import {KeyRegistry} from "./KeyRegistry.sol";
import {PausableMixin} from "./PausableMixin.sol";

/**
 * @title  FeatureNFT
 * @notice ERC-721 for features extracted from a `ShadowToken`. Created
 *         exclusively by `ShadowToken.extractSlot`. Carries:
 *           - immutable: originShadowId, originSlotIdx, featureType, color
 *           - mutable on transferFeature: ecdhPubX/Y, c2Commit
 *           - mutable on transferFeature: pose (the new owner can re-pose)
 *           - frozen flag set by ShadowToken.solve when origin shadow solved
 *
 *         c2 is a 42-Field ECIES envelope (sponge_42-bound). Smaller than
 *         shadow's 249-Field c2: stores ONE feature's pixel data only.
 *
 *         transferFeature: re-encrypts c2 to new owner. Ownership rotation
 *         only -- pose travels with the token (no automatic re-pose). The
 *         new owner can call ShadowToken.insertFeature with their own pose.
 */
contract FeatureNFT is ERC721, PausableMixin, IFeatureNFT {
    // ============== types ==============

    struct Feature {
        uint256 originShadowId;
        uint8 originSlotIdx;
        uint8 featureType;
        uint8 color;
        bytes32 ecdhPubX;
        bytes32 ecdhPubY;
        bytes32 c2Commit;
        uint64 pose;          // current pose at last extract/transfer
        uint64 mintedAt;      // block.number
    }

    // ============== constants ==============

    bytes32 public constant DOMAIN_FEATURE = keccak256("OMP_FEATURE_NFT_v2");
    uint256 public constant TRANSFER_FEATURE_PI_LEN = 8;
    uint256 public constant FEATURE_C2_BYTES = 42 * 32; // 1,344

    /// bn254 Fr field modulus. featureNftId is reduced mod FR_MOD so PI[0]
    /// equality (Field == Field) holds across circuit/contract boundary.
    uint256 public constant FR_MOD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // ============== storage ==============

    address public immutable deployer;
    address public immutable yulSponge;
    address public immutable shadowToken;   // back-reference; only this address may extract / freeze

    KeyRegistry public keyRegistry;
    bool private _keyRegistryLocked;

    IVerifier public transferFeatureVerifier;
    bool private _transferFeatureVerifierLocked;

    mapping(uint256 => Feature) private _features;
    mapping(uint256 => bool) private _frozen;
    uint64 public mintCounter;

    // ============== events ==============

    event FeatureMinted(
        uint256 indexed featureNftId,
        uint256 indexed originShadowId,
        uint8 indexed originSlotIdx,
        address to,
        uint8 featureType,
        uint8 color
    );
    event FeatureCiphertext(
        uint256 indexed featureNftId,
        bytes32 indexed ctCommit,
        bytes c2
    );
    event FeatureTransferred(
        uint256 indexed featureNftId,
        address indexed to,
        bytes32 newEcdhPubX,
        bytes32 newEcdhPubY
    );
    event FeatureFrozen(uint256 indexed featureNftId);
    event TransferFeatureVerifierSet(IVerifier v);
    event KeyRegistrySet(KeyRegistry r);

    // ============== errors ==============

    error NotShadowToken();
    error NotDeployer();
    error NotFeatureOwner();
    error AlreadyFrozen();
    error VerifierAlreadySet();
    error VerifierNotSet();
    error KeyRegistryAlreadySet();
    error InvalidProof();
    error BadPILen(uint256 got, uint256 want);
    error BadC2Length(uint256 got);
    error CtCommitMismatch(bytes32 fromChain, bytes32 fromProof);
    error PkMismatch(bytes32 want, bytes32 got);
    error TransferGatedFrozen();
    error FrozenError(uint256 featureNftId);

    // ============== ctor ==============

    constructor(address shadowTokenAddr, address yulSpongeAddr)
        ERC721("OMP Feature NFT", "OMPFN")
    {
        deployer = msg.sender;
        shadowToken = shadowTokenAddr;
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

    function setTransferFeatureVerifier(IVerifier v) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (_transferFeatureVerifierLocked) revert VerifierAlreadySet();
        transferFeatureVerifier = v;
        _transferFeatureVerifierLocked = true;
        emit TransferFeatureVerifierSet(v);
    }

    // ============== mint (only via ShadowToken.extractSlot) ==============

    function mintFromExtraction(
        uint256 originShadowId,
        uint8 originSlotIdx,
        uint8 featureType,
        uint8 color,
        bytes32 ecdhPubX,
        bytes32 ecdhPubY,
        bytes32 c2Commit,
        uint64 pose,
        address to
    ) external override returns (uint256 featureNftId) {
        if (msg.sender != shadowToken) revert NotShadowToken();

        mintCounter += 1;
        // chainId binding: same as ShadowToken.shadowIdOf -- prevents cross-chain
        // proof replay by tying the feature's id to this chain.
        featureNftId = uint256(keccak256(abi.encode(
            DOMAIN_FEATURE, block.chainid, originShadowId, originSlotIdx, mintCounter
        ))) % FR_MOD;

        Feature storage f = _features[featureNftId];
        f.originShadowId = originShadowId;
        f.originSlotIdx = originSlotIdx;
        f.featureType = featureType;
        f.color = color;
        f.ecdhPubX = ecdhPubX;
        f.ecdhPubY = ecdhPubY;
        f.c2Commit = c2Commit;
        f.pose = pose;
        f.mintedAt = uint64(block.number);

        _mint(to, featureNftId);
        emit FeatureMinted(featureNftId, originShadowId, originSlotIdx, to, featureType, color);
    }

    // ============== transferFeature ==============

    /// PI layout (8 fields):
    ///   PI[0]    featureNftId
    ///   PI[1,2]  next_pk_x, next_pk_y
    ///   PI[3,4]  c1_x, c1_y
    ///   PI[5]    c2_scalar
    ///   PI[6]    new_ct_commit  (= sponge_42 of new c2)
    ///   PI[7]    prev_ct_commit (must match chain)
    function transferFeature(
        uint256 featureNftId,
        address to,
        bytes calldata proof,
        bytes32[] calldata pi,
        bytes calldata c2New
    ) external whenNotPaused {
        if (_ownerOf(featureNftId) != msg.sender) revert NotFeatureOwner();
        if (_frozen[featureNftId]) revert FrozenError(featureNftId);
        if (pi.length != TRANSFER_FEATURE_PI_LEN) revert BadPILen(pi.length, TRANSFER_FEATURE_PI_LEN);
        if (c2New.length != FEATURE_C2_BYTES) revert BadC2Length(c2New.length);

        IVerifier v = transferFeatureVerifier;
        if (address(v) == address(0)) revert VerifierNotSet();

        Feature storage f = _features[featureNftId];
        if (pi[0] != bytes32(featureNftId)) revert InvalidProof();
        if (pi[7] != f.c2Commit) revert InvalidProof();
        _requirePkMatches(to, pi[1], pi[2]);

        try v.verify(proof, pi) returns (bool ok) {
            if (!ok) revert InvalidProof();
        } catch {
            revert InvalidProof();
        }

        // On-chain c2New binding via Yul Poseidon2 sponge_42.
        uint256 digest = _sponge(c2New);
        if (bytes32(digest) != pi[6]) revert CtCommitMismatch(bytes32(digest), pi[6]);

        f.ecdhPubX = pi[1];
        f.ecdhPubY = pi[2];
        f.c2Commit = pi[6];

        emit FeatureTransferred(featureNftId, to, pi[1], pi[2]);
        emit FeatureCiphertext(featureNftId, pi[6], c2New);

        // _update directly instead of _safeTransfer (avoid receiver callback;
        // recipient pk is bound by the proof + sponge check).
        _update(to, featureNftId, address(0));
    }

    // ============== freeze (only via ShadowToken.solve) ==============

    function freezeFeature(uint256 featureNftId) external override {
        if (msg.sender != shadowToken) revert NotShadowToken();
        if (_frozen[featureNftId]) revert AlreadyFrozen();
        _frozen[featureNftId] = true;
        emit FeatureFrozen(featureNftId);
    }

    // ============== view accessors (IFeatureNFT) ==============

    function ownerOfFeature(uint256 featureNftId) external view override returns (address) {
        return _ownerOf(featureNftId);
    }

    function isFrozen(uint256 featureNftId) external view override returns (bool) {
        return _frozen[featureNftId];
    }

    function colorOf(uint256 featureNftId) external view override returns (uint8) {
        return _features[featureNftId].color;
    }

    function featureTypeOf(uint256 featureNftId) external view override returns (uint8) {
        return _features[featureNftId].featureType;
    }

    function featureOf(uint256 featureNftId) external view returns (Feature memory) {
        return _features[featureNftId];
    }

    // ============== ERC-721 transfer lockdown ==============
    //
    // Plain transferFrom is gated to prevent moves that bypass the proof-
    // bound pk rotation. Frozen features are unrestricted (the puzzle is
    // solved; behaves like an ordinary collectible).
    function transferFrom(address from, address to, uint256 tokenId)
        public
        override
    {
        if (!_frozen[tokenId]) revert TransferGatedFrozen();
        super.transferFrom(from, to, tokenId);
    }

    // ============== internals ==============

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

    function _writeVerifierSlot(uint8 slot, address newVerifier) internal override {
        if (slot == SLOT_TRANSFER_FEATURE) {
            transferFeatureVerifier = IVerifier(newVerifier);
        } else {
            revert("unknown slot");
        }
    }
}
