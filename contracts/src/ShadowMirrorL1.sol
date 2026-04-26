// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {IShadowToken} from "./IShadowToken.sol";
import {ICrossDomainMessenger} from "./ICrossDomainMessenger.sol";

/// @title ShadowMirrorL1
/// @notice Receives bridged solved-shadow snapshots from `ShadowBridgeL2` on
///         Base Sepolia (via the OP-Stack `L1CrossDomainMessenger` after the
///         standard withdrawal challenge period) and mints a mirror ERC721
///         on Ethereum Sepolia. Token id == L2 shadowId so off-chain
///         indexers can join L1 mirror records to L2 solve events.
///
/// Symmetric round-trip:
///     - mintFromBridge: L2 lock + relay -> L1 mint
///     - burnAndUnbridge: L1 burn + relay -> L2 unlock
contract ShadowMirrorL1 is ERC721 {
    /// Default gas limit for the L2 unbridge relay (~80k actual cost).
    uint32 public constant DEFAULT_L2_GAS_LIMIT = 200_000;

    address public immutable l1Messenger;
    address public l2Bridge;

    address public immutable deployer;

    /// Mirror state stored in struct form so external callers can read with one call.
    struct MirrorState {
        bytes32 faceOriginId;
        uint8   color;
        bytes32 c2Commit;
        bytes32 stateCommitsHash;
        bytes32 ecdhPubX;
        uint64[8] origPoses;
        IShadowToken.ManifestEntry[16] manifest;
    }

    /// Payload struct sent across the L2->L1 messenger from ShadowBridgeL2.
    /// Defined here so the test can reference it as ShadowMirrorL1.BridgePayload.
    struct BridgePayload {
        uint256 shadowId;
        address recipient;
        bytes32 faceOriginId;
        uint8   color;
        bytes32 c2Commit;
        bytes32 stateCommitsHash;
        bytes32 ecdhPubX;
        uint64[8] origPoses;
        IShadowToken.ManifestEntry[16] manifest;
        bytes   revealedPi;
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
    event ShadowMirrored(uint256 indexed shadowId, address indexed recipient, bytes32 c2Commit);
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
        st.faceOriginId = p.faceOriginId;
        st.color = p.color;
        st.c2Commit = p.c2Commit;
        st.stateCommitsHash = p.stateCommitsHash;
        st.ecdhPubX = p.ecdhPubX;
        for (uint256 i = 0; i < 8; i++) {
            st.origPoses[i] = p.origPoses[i];
        }
        for (uint256 i = 0; i < 16; i++) {
            st.manifest[i] = p.manifest[i];
        }
        _revealedPi[p.shadowId] = p.revealedPi;

        _mint(p.recipient, p.shadowId);
        emit ShadowMirrored(p.shadowId, p.recipient, p.c2Commit);
    }

    /// Round-trip: burn L1 mirror, send unbridge message back to L2.
    /// Only the current owner may initiate.
    function burnAndUnbridge(uint256 shadowId, address l2Recipient) external {
        if (l2Bridge == address(0)) revert L2BridgeNotSet();
        if (ownerOf(shadowId) != msg.sender) revert NotMirrorOwner();

        // Burn the mirror; mintedFromBridge stays true (history of having
        // been bridged) but ownerOf(shadowId) reverts after this point.
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
