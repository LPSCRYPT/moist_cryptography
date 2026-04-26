// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {IShadowToken} from "./IShadowToken.sol";
import {ShadowMirrorL1} from "./ShadowMirrorL1.sol";
import {ICrossDomainMessenger} from "./ICrossDomainMessenger.sol";

/// @title ShadowBridgeL2
/// @notice Locks a *solved* ShadowToken on Base Sepolia and dispatches a
///         cross-domain message via the OP-Stack `L2CrossDomainMessenger`
///         predeploy so the paired `ShadowMirrorL1` on Ethereum Sepolia can
///         mint a mirror NFT after the standard withdrawal challenge period.
///
/// State machine (per shadowId):
///
///     OWNED_ON_L2 --bridgeShadow--> OWNED_ON_L1
///         ^                              |
///         +---unbridgeShadow (from L1)---+
///
/// Trust model:
///   - The only authority that can release a locked shadow back to its
///     owner on L2 is the `unbridgeShadow` path, gated to the canonical L2
///     messenger and a cross-domain sender == `l1Mirror`.
///   - The L1 messenger has its own 7-day finalization window for L2->L1
///     messages; L1->L2 messages settle in seconds.
contract ShadowBridgeL2 {
    /// L2CrossDomainMessenger predeploy on every OP-Stack L2.
    address public constant L2_MESSENGER = 0x4200000000000000000000000000000000000007;

    /// Default gas limit for the L1 mint relay. ~600k is comfortable for
    /// the L1 mintFromBridge (which costs ~150-200k) plus the messenger
    /// dispatch overhead.
    uint32 public constant DEFAULT_L1_GAS_LIMIT = 600_000;

    /// Default gas limit for the L2 unbridge relay (~80k).
    uint32 public constant DEFAULT_L2_GAS_LIMIT = 200_000;

    enum BridgeState { OWNED_ON_L2, OWNED_ON_L1 }

    /// Layout of the bridge payload sent across to ShadowMirrorL1. Defined
    /// at the contract level so its ABI matches what mintFromBridge expects.
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

    IShadowToken public immutable shadowToken;
    address public l1Mirror;

    /// One-shot post-deploy wiring. Restricted to deployer (no admin
    /// transfer; matches the rest of the phase-2 design: deploy-set-forget).
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
    error StateCommitMismatch(bytes32 expected, bytes32 actual);
    error BadRevealedPi();
    error NotDeployer();

    event L1MirrorSet(address indexed l1Mirror);
    event ShadowBridged(
        uint256 indexed shadowId,
        address indexed sender,
        bytes32 messageHash
    );
    event ShadowUnbridged(uint256 indexed shadowId, address indexed l2Recipient);

    modifier onlyDeployer() {
        if (msg.sender != deployer) revert NotDeployer();
        _;
    }

    modifier onlyMessenger() {
        if (msg.sender != L2_MESSENGER) revert NotMessenger();
        _;
    }

    constructor(IShadowToken _shadowToken) {
        shadowToken = _shadowToken;
        deployer = msg.sender;
    }

    function setL1Mirror(address _l1Mirror) external onlyDeployer {
        if (_l1Mirror == address(0)) revert ZeroAddress();
        if (l1Mirror != address(0)) revert L1MirrorAlreadySet();
        l1Mirror = _l1Mirror;
        emit L1MirrorSet(_l1Mirror);
    }

    /// Bridge a SOLVED shadow from L2 to L1.
    ///
    /// `revealedPi` is the serialized 261-field solve PI bytes (for L1
    /// renderers that need the per-feature `state_commit` values without
    /// re-fetching from L2 events). Its hash MUST match the on-chain
    /// `stateCommitsHash` recorded at mint, which solve already verified.
    ///
    /// @param shadowId    L2 shadowId (must be solved + owned by msg.sender)
    /// @param revealedPi  The 261-field solve PI as raw bytes (== 261 * 32)
    function bridgeShadow(uint256 shadowId, bytes calldata revealedPi) external {
        if (l1Mirror == address(0)) revert L1MirrorNotSet();
        if (shadowToken.ownerOf(shadowId) != msg.sender) revert NotShadowOwner();
        if (!shadowToken.solved(shadowId)) revert NotSolved();
        if (revealedPi.length != 261 * 32) revert BadRevealedPi();

        // Defense-in-depth: verify revealedPi hashes to what mint stored.
        IShadowToken.Shadow memory s = shadowToken.shadowOf(shadowId);
        bytes32 stateHash = _hashFirst8Fields(revealedPi);
        if (stateHash != s.stateCommitsHash) {
            revert StateCommitMismatch(s.stateCommitsHash, stateHash);
        }

        IShadowToken.ManifestEntry[16] memory m = shadowToken.manifestOf(shadowId);

        bridged[shadowId] = BridgeState.OWNED_ON_L1;
        shadowToken.transferFrom(msg.sender, address(this), shadowId);

        // Build the BridgePayload struct that ShadowMirrorL1.mintFromBridge expects.
        bytes memory message = abi.encodeWithSignature(
            "mintFromBridge((uint256,address,bytes32,uint8,bytes32,bytes32,bytes32,uint64[8],(uint8,uint8,uint256,uint64)[16],bytes))",
            ShadowMirrorL1.BridgePayload({
                shadowId: shadowId,
                recipient: msg.sender,
                faceOriginId: s.faceOriginId,
                color: s.color,
                c2Commit: s.c2Commit,
                stateCommitsHash: s.stateCommitsHash,
                ecdhPubX: s.ecdhPubX,
                origPoses: [s.origPose0, s.origPose1, s.origPose2, s.origPose3,
                            s.origPose4, s.origPose5, s.origPose6, s.origPose7],
                manifest: m,
                revealedPi: revealedPi
            })
        );

        ICrossDomainMessenger(L2_MESSENGER).sendMessage(l1Mirror, message, DEFAULT_L1_GAS_LIMIT);

        emit ShadowBridged(shadowId, msg.sender, keccak256(message));
    }

    /// Round-trip: release a locked shadow back to an L2 recipient. Only
    /// callable by the canonical L2 messenger when the cross-domain sender
    /// is the L1 mirror.
    function unbridgeShadow(uint256 shadowId, address l2Recipient) external onlyMessenger {
        address xsender = ICrossDomainMessenger(L2_MESSENGER).xDomainMessageSender();
        if (xsender != l1Mirror) revert NotL1Mirror(xsender);
        if (bridged[shadowId] != BridgeState.OWNED_ON_L1) revert NotOwnedOnL1(shadowId);

        bridged[shadowId] = BridgeState.OWNED_ON_L2;
        // Token currently owned by this contract; release to recipient.
        shadowToken.transferFrom(address(this), l2Recipient, shadowId);

        emit ShadowUnbridged(shadowId, l2Recipient);
    }


    function _hashFirst8Fields(bytes calldata revealedPi) internal pure returns (bytes32) {
        // PI[0..7] are stateCommits, ABI-encoded as 32-byte big-endian.
        // stateCommitsHash = keccak256(pi[0] || pi[1] || ... || pi[7]).
        bytes memory first256 = revealedPi[0:256];
        return keccak256(first256);
    }
}
