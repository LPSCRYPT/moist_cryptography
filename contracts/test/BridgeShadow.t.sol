// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test, Vm} from "forge-std/Test.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";
import {IShadowToken} from "../src/IShadowToken.sol";
import {ShadowBridgeL2} from "../src/ShadowBridgeL2.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {TestableShadowToken, TestableFeatureNFT} from "./Testable.sol";

/// @notice Spec non-goal #1: "Changing the bridge or the L1 mirror" --
///         the v1 ShadowBridgeL2 stays as-is. But the bridge's
///         `bridgeShadow` reads v2 ShadowToken storage (manifestOf,
///         shadowOf, shadowT10) which has a different layout than v1.
///         This test pins that the v1 bridge contract correctly reads
///         the v2 storage and emits a payload with v2 lineage fields.
///
/// What we test:
///   - bridgeShadow on a SOLVED shadow succeeds:
///       (a) shadow ownership transfers to bridge
///       (b) bridged[shadowId] flips to OWNED_ON_L1
///       (c) ShadowBridged event fires
///       (d) the L2 messenger receives a sendMessage call carrying a
///           ShadowMirrorL1.mintFromBridge calldata blob
///   - bridgeShadow reverts on UNSOLVED shadow (NotSolved)
///   - bridgeShadow reverts when caller is not shadow owner
///   - bridgeShadow reverts when L1 mirror not set
///
/// We do NOT exercise the L1 mirror's mintFromBridge on actual L1; that
/// is OP-Stack territory + spec non-goal. We DO assert the messenger
/// received a call with non-empty calldata so an indexer-side schema
/// check has something to round-trip against.
///
/// Messenger stub: the L2 cross-domain messenger is a predeploy at
/// `0x4200000000000000000000000000000000000007`. We `vm.etch` a tiny
/// stub there that records the last sendMessage call so the test can
/// assert against it.
contract BridgeShadowTest is Test {
    TestableShadowToken internal st;
    TestableFeatureNFT  internal fn;
    Poseidon2YulSponge  internal sponge;
    ShadowBridgeL2      internal bridge;

    address internal constant L2_MESSENGER = 0x4200000000000000000000000000000000000007;
    address internal alice = makeAddr("alice");
    address internal mallory = makeAddr("mallory");
    address internal l1Mirror = makeAddr("l1Mirror");

    uint256 internal shadowId;
    bytes32 internal t10Hi  = bytes32(uint256(0x1111));
    bytes32 internal t10Lo  = bytes32(uint256(0x2222));
    bytes32 internal ecdhPubX = bytes32(uint256(0xa1));
    bytes32 internal ecdhPubY = bytes32(uint256(0xa2));
    bytes32 internal zIndexCommit = bytes32(uint256(0xbeef));
    uint64  internal zIndexRevealed = 0xfedcba9876543210;

    event ShadowBridged(uint256 indexed shadowId, address indexed sender, bytes32 messageHash);

    function setUp() public {
        sponge = new Poseidon2YulSponge();
        st = new TestableShadowToken(address(sponge));
        fn = new TestableFeatureNFT(address(st));
        st.setFeatureNFT(IFeatureNFT(address(fn)));

        bridge = new ShadowBridgeL2(IShadowToken(address(st)), IFeatureNFT(address(fn)));
        bridge.setL1Mirror(l1Mirror);

        // Etch a messenger stub at the predeploy address. The stub
        // implements `sendMessage(target,message,minGasLimit)` by
        // storing the last call's blob; tests can read it back via the
        // `lastTarget()` / `lastMessage()` view fns.
        L2MessengerStub stub = new L2MessengerStub();
        vm.etch(L2_MESSENGER, address(stub).code);

        shadowId = uint256(keccak256(abi.encode("v2-bridge-test-shadow")));

        // Seed: shadow with EMPTY manifest (post-solve auto-extract has
        // already cleared all slots), solved=true, T10 + zIndex set.
        st.seedShadowOnly(shadowId, alice, ecdhPubX, ecdhPubY);
        st.setShadowZIndexCommitForTest(shadowId, zIndexCommit);
        st.setShadowSolvedForTest(shadowId, zIndexRevealed, t10Hi, t10Lo);
    }

    function _revealedPi() internal pure returns (bytes memory) {
        // 7-field solve PI; content irrelevant to this test (the bridge
        // just length-checks % 32 == 0 and forwards). Spec line 80:
        // `revealedPi.length % 32 == 0 && != 0`.
        bytes memory pi = new bytes(7 * 32);
        for (uint256 i = 0; i < 7; i++) {
            bytes32 v = bytes32(uint256(0x5010 + i));
            assembly { mstore(add(add(pi, 32), mul(i, 32)), v) }
        }
        return pi;
    }

    function test_bridgeShadow_success_against_v2_storage() public {
        bytes memory pi = _revealedPi();

        // Pre-state: alice owns the shadow.
        assertEq(st.ownerOf(shadowId), alice, "alice owns pre-bridge");
        assertEq(uint256(bridge.bridged(shadowId)), uint256(ShadowBridgeL2.BridgeState.OWNED_ON_L2));

        // Approval: ERC-721 transferFrom requires the caller (bridge)
        // to be approved by the owner. Real-world UX: a wallet wraps
        // approve+bridgeShadow into a single confirmation.
        vm.prank(alice);
        st.approve(address(bridge), shadowId);

        vm.recordLogs();
        vm.prank(alice);
        bridge.bridgeShadow(shadowId, pi);

        // Post: ownership transferred to bridge.
        assertEq(st.ownerOf(shadowId), address(bridge), "bridge custody");
        assertEq(uint256(bridge.bridged(shadowId)), uint256(ShadowBridgeL2.BridgeState.OWNED_ON_L1));

        // Messenger stub recorded the sendMessage call.
        L2MessengerStub stub = L2MessengerStub(L2_MESSENGER);
        assertEq(stub.lastTarget(), l1Mirror, "message target = L1 mirror");
        assertGt(stub.lastMessage().length, 0, "non-empty mintFromBridge calldata");
        assertEq(stub.lastGasLimit(), bridge.DEFAULT_L1_GAS_LIMIT(), "default L1 gas limit");

        // ShadowBridged event with messageHash matching keccak of message.
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool seen = false;
        bytes32 sig = keccak256("ShadowBridged(uint256,address,bytes32)");
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter != address(bridge)) continue;
            if (logs[i].topics[0] != sig) continue;
            seen = true;
            // topic[1] = shadowId (indexed); topic[2] = sender (indexed)
            assertEq(uint256(logs[i].topics[1]), shadowId, "event shadowId");
            assertEq(address(uint160(uint256(logs[i].topics[2]))), alice, "event sender");
            // data = messageHash (1 word). Compute expected.
            bytes32 expectedHash = keccak256(stub.lastMessage());
            bytes32 emittedHash = abi.decode(logs[i].data, (bytes32));
            assertEq(emittedHash, expectedHash, "messageHash matches keccak(message)");
        }
        assertTrue(seen, "ShadowBridged event fired");
    }

    function test_bridgeShadow_reverts_when_unsolved() public {
        // Fresh shadow without solve flag set.
        uint256 freshId = uint256(keccak256(abi.encode("v2-fresh-shadow")));
        st.seedShadowOnly(freshId, alice, ecdhPubX, ecdhPubY);
        // No setShadowSolvedForTest -- shadow.solved == false.

        vm.prank(alice);
        vm.expectRevert(ShadowBridgeL2.NotSolved.selector);
        bridge.bridgeShadow(freshId, _revealedPi());
    }

    function test_bridgeShadow_reverts_when_not_owner() public {
        vm.prank(mallory);
        vm.expectRevert(ShadowBridgeL2.NotShadowOwner.selector);
        bridge.bridgeShadow(shadowId, _revealedPi());
    }

    function test_bridgeShadow_reverts_when_l1_mirror_unset() public {
        // Deploy a fresh bridge without setL1Mirror.
        ShadowBridgeL2 freshBridge = new ShadowBridgeL2(
            IShadowToken(address(st)),
            IFeatureNFT(address(fn))
        );
        vm.prank(alice);
        vm.expectRevert(ShadowBridgeL2.L1MirrorNotSet.selector);
        freshBridge.bridgeShadow(shadowId, _revealedPi());
    }

    function test_bridgeShadow_reverts_on_bad_revealed_pi_length() public {
        // length not a multiple of 32 -> BadRevealedPi
        bytes memory pi = new bytes(33);   // 1 odd byte
        vm.prank(alice);
        vm.expectRevert(ShadowBridgeL2.BadRevealedPi.selector);
        bridge.bridgeShadow(shadowId, pi);
    }

    function test_bridgeShadow_reverts_on_zero_length_revealed_pi() public {
        bytes memory pi = new bytes(0);
        vm.prank(alice);
        vm.expectRevert(ShadowBridgeL2.BadRevealedPi.selector);
        bridge.bridgeShadow(shadowId, pi);
    }
}

/// Minimal L2 messenger stub. Captures the last sendMessage call so
/// tests can assert the bridge wrote the expected payload.
contract L2MessengerStub {
    address public lastTarget;
    bytes   public lastMessage;
    uint32  public lastGasLimit;

    function sendMessage(address _target, bytes calldata _message, uint32 _minGasLimit) external {
        lastTarget = _target;
        lastMessage = _message;
        lastGasLimit = _minGasLimit;
    }

    /// Required by the messenger interface in some flows; returns a
    /// dummy address. Bridge unbridge path uses this; outside this
    /// test's scope.
    function xDomainMessageSender() external pure returns (address) {
        return address(0);
    }
}
