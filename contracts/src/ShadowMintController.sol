// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {IVerifier} from "./IVerifier.sol";
import {KeyRegistry} from "./KeyRegistry.sol";
import {ShadowToken} from "./ShadowToken.sol";

/// @notice Chunked mint coordinator. Holds pending mint sessions and verifies
/// ciphertext payloads in user-sized batches, then asks ShadowToken to install
/// the fully-loaded 8-slot shadow at the fixed recipient.
contract ShadowMintController {
    uint256 internal constant N_MINT_ATOMS = 8;
    uint256 internal constant N_SLOTS = 16;
    uint256 internal constant MAX_PLAINTEXT_FIELDS_PER_SLOT = 39;
    uint256 internal constant MINT_SHADOW_PI_LEN = 9;
    uint256 internal constant FR_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    ShadowToken public immutable shadowToken;
    KeyRegistry public immutable keyRegistry;
    IVerifier public immutable mintShadowVerifier;
    address public immutable yulSponge;
    address public immutable yulSponge16;
    address public immutable yulHash2;

    struct PendingMint {
        address recipient;
        bytes32 imageCommit;
        bytes32 ownerPkX;
        bytes32 ownerPkY;
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
        uint8 submittedBitmap;
        bool exists;
    }

    struct MintBatch {
        bool doRegisterImage;
        bytes32 imageCommit;
        bytes proofDisc;
        bool doBeginMint;
        ShadowToken.MintShadowArgs mintArgs;
        address recipient;
        uint256 shadowId;
        uint8[] submitSlots;
        bytes[] submitC2s;
        bool doFinalize;
        bytes proofT10;
    }

    mapping(bytes32 => bool) public pendingOrigins;
    mapping(uint256 => PendingMint) private _pendingMints;

    event ShadowMintStarted(uint256 indexed shadowId, address indexed recipient, bytes32 indexed imageCommit);
    event MintCiphertextSubmitted(uint256 indexed shadowId, uint8 indexed slotIdx, bytes32 indexed ctCommit, bytes c2);

    error AlreadyMinted(bytes32 imageCommit);
    error ImageNotRegistered(bytes32 imageCommit);
    error PendingMintExists(bytes32 imageCommit);
    error PendingMintNotFound(uint256 shadowId);
    error MintIncomplete(uint8 submittedBitmap, uint8 requiredBitmap);
    error SlotOutOfRange(uint8 slotIdx);
    error SlotAlreadySubmitted(uint8 slotIdx);
    error ZeroRecipient();
    error InvalidProof();
    error BadArrayLen(uint256 got, uint256 want);
    error BadC2Length(uint256 got, uint256 want);
    error DigestMismatch();
    error NonCanonicalField();
    error ImageCommitMismatch(bytes32 registered, bytes32 mintArg);
    error ShadowIdMismatch(uint256 supplied, uint256 derived);
    error MissingShadowId();
    constructor(
        ShadowToken shadowToken_,
        KeyRegistry keyRegistry_,
        IVerifier mintShadowVerifier_,
        address yulSponge_,
        address yulSponge16_,
        address yulHash2_
    ) {
        shadowToken = shadowToken_;
        keyRegistry = keyRegistry_;
        mintShadowVerifier = mintShadowVerifier_;
        yulSponge = yulSponge_;
        yulSponge16 = yulSponge16_;
        yulHash2 = yulHash2_;
    }

    function beginMintShadow(ShadowToken.MintShadowArgs calldata args, address recipient)
        external
        returns (uint256 shadowId)
    {
        return _beginMintShadow(args, recipient);
    }

    function submitMintCiphertexts(uint256 shadowId, uint8[] calldata slots, bytes[] calldata c2s) external {
        _submitMintCiphertexts(shadowId, slots, c2s);
    }

    function finalizeMintShadow(uint256 shadowId, bytes calldata proofT10) external returns (uint256 mintedShadowId) {
        return _finalizeMintShadow(shadowId, proofT10);
    }

    /// @notice Executes any ordered subset of the mint pipeline in one transaction.
    /// @dev Steps always run in canonical order: register, begin, submit, finalize.
    ///      If `doBeginMint` is true, later submit/finalize steps use the derived
    ///      shadowId from that begin step. If `batch.shadowId != 0`, it must match
    ///      the derived ID. Without begin, submit/finalize require `batch.shadowId`.
    ///      `submitSlots` and `submitC2s` must both be empty or have the same
    ///      nonzero length.
    function executeMintBatch(MintBatch calldata batch) external returns (uint256 shadowId, uint256 mintedShadowId) {
        if (batch.doRegisterImage) {
            if (batch.doBeginMint && batch.imageCommit != batch.mintArgs.imageCommit) {
                revert ImageCommitMismatch(batch.imageCommit, batch.mintArgs.imageCommit);
            }
            shadowToken.registerImage(batch.imageCommit, batch.proofDisc);
        }

        shadowId = batch.shadowId;
        if (batch.doBeginMint) {
            shadowId = _beginMintShadow(batch.mintArgs, batch.recipient);
            if (batch.shadowId != 0 && batch.shadowId != shadowId) {
                revert ShadowIdMismatch(batch.shadowId, shadowId);
            }
        } else if (shadowId == 0 && (batch.submitSlots.length != 0 || batch.submitC2s.length != 0 || batch.doFinalize)) {
            revert MissingShadowId();
        }

        if (batch.submitSlots.length != 0 || batch.submitC2s.length != 0) {
            _submitMintCiphertexts(shadowId, batch.submitSlots, batch.submitC2s);
        }

        if (batch.doFinalize) {
            mintedShadowId = _finalizeMintShadow(shadowId, batch.proofT10);
        }
    }

    function _beginMintShadow(ShadowToken.MintShadowArgs calldata args, address recipient)
        internal
        returns (uint256 shadowId)
    {
        if (recipient == address(0)) revert ZeroRecipient();
        bytes32 imageCommit = args.imageCommit;
        if (shadowToken.mintedOrigins(imageCommit)) revert AlreadyMinted(imageCommit);
        if (pendingOrigins[imageCommit]) revert PendingMintExists(imageCommit);
        if (!shadowToken.registeredImages(imageCommit)) revert ImageNotRegistered(imageCommit);

        shadowId = uint256(imageCommit) % FR_MOD;
        if (_pendingMints[shadowId].exists) revert PendingMintExists(imageCommit);

        (bytes32 ownerPkX, bytes32 ownerPkY) = keyRegistry.pkOf(recipient);
        _verifyMintProof(args, shadowId, imageCommit, ownerPkX, ownerPkY);
        _validateOriginFaceIds(args);

        PendingMint storage p = _pendingMints[shadowId];
        p.exists = true;
        p.recipient = recipient;
        p.imageCommit = imageCommit;
        p.ownerPkX = ownerPkX;
        p.ownerPkY = ownerPkY;
        p.ctCommits = args.ctCommits;
        p.liveStateHashInits = args.liveStateHashInits;
        p.chainTips = args.chainTips;
        p.c1Xs = args.c1Xs;
        p.c1Ys = args.c1Ys;
        p.paletteCommits = args.paletteCommits;
        p.paletteSaltCts = args.paletteSaltCts;
        p.saltC1Xs = args.saltC1Xs;
        p.saltC1Ys = args.saltC1Ys;
        p.originFaceIds = args.originFaceIds;
        p.newT10 = args.newT10;
        pendingOrigins[imageCommit] = true;

        emit ShadowMintStarted(shadowId, recipient, imageCommit);
    }

    function _submitMintCiphertexts(uint256 shadowId, uint8[] calldata slots, bytes[] calldata c2s) internal {
        PendingMint storage p = _pendingMints[shadowId];
        if (!p.exists) revert PendingMintNotFound(shadowId);
        uint256 n = slots.length;
        if (n == 0 || n != c2s.length) revert BadArrayLen(n, c2s.length);

        uint8 seen = 0;
        for (uint256 j = 0; j < n; j++) {
            uint8 slot = slots[j];
            if (slot >= N_MINT_ATOMS) revert SlotOutOfRange(slot);
            uint8 bit = uint8(1) << slot;
            if (seen & bit != 0) revert SlotAlreadySubmitted(slot);
            if (p.submittedBitmap & bit != 0) revert SlotAlreadySubmitted(slot);
            _assertCtCommitBinding(c2s[j], p.ctCommits[slot]);
            seen |= bit;
            emit MintCiphertextSubmitted(shadowId, slot, p.ctCommits[slot], c2s[j]);
        }
        p.submittedBitmap |= seen;
    }

    function _finalizeMintShadow(uint256 shadowId, bytes calldata proofT10) internal returns (uint256 mintedShadowId) {
        PendingMint storage p = _pendingMints[shadowId];
        if (!p.exists) revert PendingMintNotFound(shadowId);
        if (p.submittedBitmap != 0xff) revert MintIncomplete(p.submittedBitmap, 0xff);
        if (shadowToken.mintedOrigins(p.imageCommit)) revert AlreadyMinted(p.imageCommit);

        ShadowToken.MintShadowArgs memory args;
        args.imageCommit = p.imageCommit;
        args.ctCommits = p.ctCommits;
        args.liveStateHashInits = p.liveStateHashInits;
        args.chainTips = p.chainTips;
        args.c1Xs = p.c1Xs;
        args.c1Ys = p.c1Ys;
        args.paletteCommits = p.paletteCommits;
        args.paletteSaltCts = p.paletteSaltCts;
        args.saltC1Xs = p.saltC1Xs;
        args.saltC1Ys = p.saltC1Ys;
        args.originFaceIds = p.originFaceIds;
        args.newT10 = p.newT10;

        pendingOrigins[p.imageCommit] = false;
        mintedShadowId = shadowToken.finalizeMintFromController(args, p.recipient, p.ownerPkX, p.ownerPkY, proofT10);
        delete _pendingMints[shadowId];
    }

    function pendingMintSubmittedBitmap(uint256 shadowId) external view returns (uint8) {
        return _pendingMints[shadowId].submittedBitmap;
    }

    function _verifyMintProof(
        ShadowToken.MintShadowArgs calldata args,
        uint256 shadowId,
        bytes32 imageCommit,
        bytes32 ownerPkX,
        bytes32 ownerPkY
    ) internal view {
        bytes32[] memory piMint = new bytes32[](MINT_SHADOW_PI_LEN);
        piMint[0] = bytes32(shadowId);
        piMint[1] = imageCommit;
        piMint[2] = ownerPkX;
        piMint[3] = ownerPkY;
        piMint[4] = _sponge8Pad16(args.liveStateHashInits);
        piMint[5] = _sponge8Pad16(args.ctCommits);
        piMint[6] = _sponge8Pad16(args.chainTips);
        piMint[7] = _sponge8Pad16(args.c1Xs);
        piMint[8] = _sponge8Pad16(args.c1Ys);
        try mintShadowVerifier.verify(args.proofMint, piMint) returns (bool ok) {
            if (!ok) revert InvalidProof();
        } catch {
            revert InvalidProof();
        }
    }

    function _validateOriginFaceIds(ShadowToken.MintShadowArgs calldata args) internal view {
        for (uint256 i = 0; i < N_MINT_ATOMS; i++) {
            if (_hash2(args.imageCommit, bytes32(i)) != args.originFaceIds[i]) revert InvalidProof();
        }
    }

    function _assertCtCommitBinding(bytes calldata c2, bytes32 expected) internal view {
        uint256 expectedLen = MAX_PLAINTEXT_FIELDS_PER_SLOT * 32;
        if (c2.length != expectedLen) revert BadC2Length(c2.length, expectedLen);
        _assertCanonicalFields(c2);
        if (bytes32(_sponge(c2)) != expected) revert DigestMismatch();
    }

    function _assertCanonicalFields(bytes calldata data) internal pure {
        if (data.length % 32 != 0) revert BadC2Length(data.length, MAX_PLAINTEXT_FIELDS_PER_SLOT * 32);
        for (uint256 off = 0; off < data.length; off += 32) {
            uint256 v;
            assembly { v := calldataload(add(data.offset, off)) }
            if (v >= FR_MOD) revert NonCanonicalField();
        }
    }

    function _sponge8Pad16(bytes32[8] calldata arr) internal view returns (bytes32) {
        bytes memory buf = new bytes(N_SLOTS * 32);
        for (uint256 i = 0; i < N_MINT_ATOMS; i++) {
            bytes32 v = arr[i];
            if (uint256(v) >= FR_MOD) revert NonCanonicalField();
            assembly { mstore(add(add(buf, 32), mul(i, 32)), v) }
        }
        return _sponge16(buf);
    }

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
}
