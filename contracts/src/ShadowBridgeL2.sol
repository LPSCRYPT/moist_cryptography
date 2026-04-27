// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {IShadowToken} from "./IShadowToken.sol";
import {IFeatureNFT} from "./IFeatureNFT.sol";
import {ShadowMirrorL1} from "./ShadowMirrorL1.sol";
import {ICrossDomainMessenger} from "./ICrossDomainMessenger.sol";

/// @title  ShadowBridgeL2 (v2)
/// @notice Locks a *solved* ShadowToken on Base Sepolia and dispatches a
///         cross-domain message via the OP-Stack `L2CrossDomainMessenger`
///         predeploy so the paired `ShadowMirrorL1` on Ethereum Sepolia
///         can mint a mirror NFT after the standard withdrawal challenge
///         period.
///
///         v2 differs from v1 only in the payload contents: solved-state
///         shadows in v2 carry per-slot lineage (originFaceId, paletteCommit,
///         typeIdx) rather than per-shadow `(c2Commit, faceOriginId,
///         color, origPose0..7, stateCommitsHash)`.
contract ShadowBridgeL2 {
    address public constant L2_MESSENGER = 0x4200000000000000000000000000000000000007;
    uint32 public constant DEFAULT_L1_GAS_LIMIT = 600_000;
    uint32 public constant DEFAULT_L2_GAS_LIMIT = 200_000;

    enum BridgeState { OWNED_ON_L2, OWNED_ON_L1 }

    IShadowToken public immutable shadowToken;
    IFeatureNFT  public immutable featureNFT;
    address public l1Mirror;
    address public immutable deployer;

    mapping(uint256 => BridgeState) public bridged;

    error L1MirrorNotSet();
    error L1MirrorAlreadySet();
    error ZeroAddress();
    error NotShadowOwner();
    error NotSolved();
    error NotMessenger();
    error NotL1Mirror(address actual);
    error NotOwnedOnL1(uint256 shadowId);
    error BadRevealedPi();
    error NotDeployer();

    event L1MirrorSet(address indexed l1Mirror);
    event ShadowBridged(uint256 indexed shadowId, address indexed sender, bytes32 messageHash);
    event ShadowUnbridged(uint256 indexed shadowId, address indexed l2Recipient);

    modifier onlyDeployer() {
        if (msg.sender != deployer) revert NotDeployer();
        _;
    }

    modifier onlyMessenger() {
        if (msg.sender != L2_MESSENGER) revert NotMessenger();
        _;
    }

    constructor(IShadowToken _shadowToken, IFeatureNFT _featureNFT) {
        shadowToken = _shadowToken;
        featureNFT = _featureNFT;
        deployer = msg.sender;
    }

    function setL1Mirror(address _l1Mirror) external onlyDeployer {
        if (_l1Mirror == address(0)) revert ZeroAddress();
        if (l1Mirror != address(0)) revert L1MirrorAlreadySet();
        l1Mirror = _l1Mirror;
        emit L1MirrorSet(_l1Mirror);
    }

    /// Bridge a SOLVED shadow from L2 to L1.
    /// `revealedPi` is the serialized solve PI bytes; its exact length
    /// is determined by the v2 solve circuit and validated off-chain
    /// by the L1 indexer.
    function bridgeShadow(uint256 shadowId, bytes calldata revealedPi) external {
        if (l1Mirror == address(0)) revert L1MirrorNotSet();
        if (shadowToken.ownerOf(shadowId) != msg.sender) revert NotShadowOwner();
        if (!shadowToken.isSolved(shadowId)) revert NotSolved();
        if (revealedPi.length == 0 || revealedPi.length % 32 != 0) revert BadRevealedPi();

        IShadowToken.Shadow memory s = shadowToken.shadowOf(shadowId);
        IShadowToken.ManifestEntry[16] memory m = shadowToken.manifestOf(shadowId);

        ShadowMirrorL1.BridgePayload memory p;
        p.shadowId = shadowId;
        p.recipient = msg.sender;
        p.ecdhPubX = s.ecdhPubX;
        p.ecdhPubY = s.ecdhPubY;
        p.t10Hi = shadowToken.shadowT10(shadowId, 0);
        p.t10Lo = shadowToken.shadowT10(shadowId, 1);
        p.zIndexCommit = s.zIndexCommit;
        p.zIndexRevealed = s.zIndexRevealed;
        for (uint256 i = 0; i < 16; i++) {
            p.manifest[i] = m[i];
            if (m[i].kind == IShadowToken.SlotKind.OCCUPIED) {
                p.typeIdxs[i] = featureNFT.typeIdxOf(m[i].featureId);
                p.originFaceIds[i] = featureNFT.originFaceIdOf(m[i].featureId);
                p.paletteCommits[i] = featureNFT.paletteCommitOf(m[i].featureId);
            }
        }
        p.revealedPi = revealedPi;

        bridged[shadowId] = BridgeState.OWNED_ON_L1;
        shadowToken.transferFrom(msg.sender, address(this), shadowId);

        bytes memory message = abi.encodeWithSelector(
            ShadowMirrorL1.mintFromBridge.selector,
            p
        );

        ICrossDomainMessenger(L2_MESSENGER).sendMessage(l1Mirror, message, DEFAULT_L1_GAS_LIMIT);

        emit ShadowBridged(shadowId, msg.sender, keccak256(message));
    }

    function unbridgeShadow(uint256 shadowId, address l2Recipient) external onlyMessenger {
        address xsender = ICrossDomainMessenger(L2_MESSENGER).xDomainMessageSender();
        if (xsender != l1Mirror) revert NotL1Mirror(xsender);
        if (bridged[shadowId] != BridgeState.OWNED_ON_L1) revert NotOwnedOnL1(shadowId);

        bridged[shadowId] = BridgeState.OWNED_ON_L2;
        shadowToken.transferFrom(address(this), l2Recipient, shadowId);

        emit ShadowUnbridged(shadowId, l2Recipient);
    }
}
