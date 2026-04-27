// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {IShadowToken} from "./IShadowToken.sol";
import {ICrossDomainMessenger} from "./ICrossDomainMessenger.sol";

/// @title  ShadowMirrorL1 (v2)
/// @notice Receives bridged solved-shadow snapshots from `ShadowBridgeL2`
///         on Base Sepolia and mints a mirror ERC721 on Ethereum Sepolia.
///
///         v2 payload carries (a) the shadow's public T10 hash, (b) the
///         16-slot manifest, (c) per-slot lineage anchors (typeIdx,
///         originFaceId, paletteCommit) for OCCUPIED slots, (d) the
///         revealed z-index permutation, and (e) the solve PI as raw
///         bytes so off-chain renderers can reconstruct the visuals
///         without contacting L2.
contract ShadowMirrorL1 is ERC721 {
    uint32 public constant DEFAULT_L2_GAS_LIMIT = 200_000;

    address public immutable l1Messenger;
    address public l2Bridge;
    address public immutable deployer;

    /// On-chain mirror state. Per-slot arrays parallel `manifest`; entries
    /// are zeroed when `manifest[i].kind == EMPTY`.
    struct MirrorState {
        bytes32 ecdhPubX;
        bytes32 ecdhPubY;
        bytes32 t10Hi;
        bytes32 t10Lo;
        bytes32 zIndexCommit;
        uint64  zIndexRevealed;
        IShadowToken.ManifestEntry[16] manifest;
        uint8[16]   typeIdxs;
        bytes32[16] originFaceIds;
        bytes32[16] paletteCommits;
    }

    /// Payload struct sent across the L2->L1 messenger from ShadowBridgeL2.
    struct BridgePayload {
        uint256 shadowId;
        address recipient;
        bytes32 ecdhPubX;
        bytes32 ecdhPubY;
        bytes32 t10Hi;
        bytes32 t10Lo;
        bytes32 zIndexCommit;
        uint64  zIndexRevealed;
        IShadowToken.ManifestEntry[16] manifest;
        uint8[16]   typeIdxs;
        bytes32[16] originFaceIds;
        bytes32[16] paletteCommits;
        bytes       revealedPi;
    }

    mapping(uint256 => MirrorState) private _mirrors;
    mapping(uint256 => bytes) private _revealedPi;
    mapping(uint256 => bool) public mintedFromBridge;

    error NotMessenger();
    error NotL2Bridge(address actual);
    error AlreadyMinted(uint256 shadowId);
    error L2BridgeNotSet();
    error L2BridgeAlreadySet();
    error ZeroAddress();
    error NotDeployer();
    error NotMirrorOwner();

    event L2BridgeSet(address indexed l2Bridge);
    event ShadowMirrored(uint256 indexed shadowId, address indexed recipient, bytes32 t10Hi, bytes32 t10Lo);
    event ShadowUnmirrored(uint256 indexed shadowId, address indexed l2Recipient);

    modifier onlyDeployer() {
        if (msg.sender != deployer) revert NotDeployer();
        _;
    }

    modifier onlyMessenger() {
        if (msg.sender != l1Messenger) revert NotMessenger();
        _;
    }

    constructor(address _l1Messenger) ERC721("Shadow Mirror", "SHMIRROR") {
        if (_l1Messenger == address(0)) revert ZeroAddress();
        l1Messenger = _l1Messenger;
        deployer = msg.sender;
    }

    function setL2Bridge(address _l2Bridge) external onlyDeployer {
        if (_l2Bridge == address(0)) revert ZeroAddress();
        if (l2Bridge != address(0)) revert L2BridgeAlreadySet();
        l2Bridge = _l2Bridge;
        emit L2BridgeSet(_l2Bridge);
    }

    /// Mint the L1 mirror. Only callable by the L1 messenger relay AND only
    /// when the cross-domain sender is the paired L2 bridge.
    function mintFromBridge(BridgePayload calldata p) external onlyMessenger {
        address xsender = ICrossDomainMessenger(l1Messenger).xDomainMessageSender();
        if (l2Bridge == address(0)) revert L2BridgeNotSet();
        if (xsender != l2Bridge) revert NotL2Bridge(xsender);
        if (mintedFromBridge[p.shadowId]) revert AlreadyMinted(p.shadowId);

        mintedFromBridge[p.shadowId] = true;

        MirrorState storage st = _mirrors[p.shadowId];
        st.ecdhPubX = p.ecdhPubX;
        st.ecdhPubY = p.ecdhPubY;
        st.t10Hi = p.t10Hi;
        st.t10Lo = p.t10Lo;
        st.zIndexCommit = p.zIndexCommit;
        st.zIndexRevealed = p.zIndexRevealed;
        for (uint256 i = 0; i < 16; i++) {
            st.manifest[i] = p.manifest[i];
            st.typeIdxs[i] = p.typeIdxs[i];
            st.originFaceIds[i] = p.originFaceIds[i];
            st.paletteCommits[i] = p.paletteCommits[i];
        }
        _revealedPi[p.shadowId] = p.revealedPi;

        _mint(p.recipient, p.shadowId);
        emit ShadowMirrored(p.shadowId, p.recipient, p.t10Hi, p.t10Lo);
    }

    /// Round-trip: burn L1 mirror, send unbridge message back to L2.
    /// Only the current owner may initiate.
    function burnAndUnbridge(uint256 shadowId, address l2Recipient) external {
        if (l2Bridge == address(0)) revert L2BridgeNotSet();
        if (ownerOf(shadowId) != msg.sender) revert NotMirrorOwner();

        _burn(shadowId);
        delete _mirrors[shadowId];
        delete _revealedPi[shadowId];

        bytes memory message = abi.encodeWithSignature(
            "unbridgeShadow(uint256,address)",
            shadowId,
            l2Recipient
        );
        ICrossDomainMessenger(l1Messenger).sendMessage(l2Bridge, message, DEFAULT_L2_GAS_LIMIT);

        emit ShadowUnmirrored(shadowId, l2Recipient);
    }

    function stateOf(uint256 shadowId) external view returns (MirrorState memory) {
        return _mirrors[shadowId];
    }

    function revealedPiOf(uint256 shadowId) external view returns (bytes memory) {
        return _revealedPi[shadowId];
    }
}
