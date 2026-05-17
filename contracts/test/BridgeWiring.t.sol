// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test, Vm} from "forge-std/Test.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";
import {IShadowToken} from "../src/IShadowToken.sol";
import {ShadowBridgeL2} from "../src/ShadowBridgeL2.sol";
import {ShadowMirrorL1} from "../src/ShadowMirrorL1.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {TestableShadowToken, TestableFeatureNFT} from "./Testable.sol";

/// @notice Coverage for bridge WIRING setters and the L1 mirror's
/// receive-side path. Existing BridgeShadow.t.sol covers the L2-leg
/// happy path + L2-side revert cases; this file fills the gaps:
///
///   - ShadowBridgeL2.setL1Mirror: zero-addr, only-deployer, **already-set
///     (one-shot)** -- the exact bug that stranded pipeline-#5's first
///     bridge `0x9Ef3f7a3` against the historical `0x89dB0113` mirror.
///     Re-pointing to a fresh mirror reverts -- the only fix is a fresh
///     bridge deploy.
///   - ShadowMirrorL1.setL2Bridge: symmetric same-shape revert set.
///   - ShadowMirrorL1.mintFromBridge: cross-domain sender check
///     (NotMessenger when a non-messenger calls; NotL2Bridge when the
///     messenger relays a call whose xsender is not the paired L2
///     bridge); already-minted; happy path mints an ERC721 to the
///     recipient and stores the per-slot mirror state.
///   - ShadowMirrorL1.burnAndUnbridge: NotMirrorOwner, L2BridgeNotSet,
///     happy path burns + sends unbridge message back to L2.
///   - ShadowBridgeL2.unbridgeShadow: NotMessenger when called direct,
///     NotL1Mirror when xsender != l1Mirror, NotOwnedOnL1 when shadow
///     wasn't bridged, happy path returns custody.
contract BridgeWiringTest is Test {
    address internal constant L1_MESSENGER = 0xC34855F4De64F1840e5686e64278da901e261f20;
    address internal constant L2_MESSENGER = 0x4200000000000000000000000000000000000007;

    address internal alice    = makeAddr("alice");
    address internal mallory  = makeAddr("mallory");
    address internal newOwner = makeAddr("newOwner");

    function _newMessengerStub(address at) internal returns (StubMessenger) {
        StubMessenger stub = new StubMessenger();
        vm.etch(at, address(stub).code);
        return StubMessenger(at);
    }

    // ============== ShadowBridgeL2.setL1Mirror ==============

    function test_setL1Mirror_zero_address_reverts() public {
        ShadowBridgeL2 br = _freshL2Bridge();
        vm.expectRevert(ShadowBridgeL2.ZeroAddress.selector);
        br.setL1Mirror(address(0));
    }

    function test_setL1Mirror_only_deployer_reverts() public {
        ShadowBridgeL2 br = _freshL2Bridge();
        vm.prank(mallory);
        vm.expectRevert(ShadowBridgeL2.NotDeployer.selector);
        br.setL1Mirror(makeAddr("anyMirror"));
    }

    /// @dev This is the bug that stranded the pipeline-#5 first bridge.
    ///      Once `l1Mirror` is non-zero, NO subsequent setL1Mirror call
    ///      can rewire it -- not by the deployer, not with a fresh
    ///      address. The only recourse is deploying a fresh L2 bridge.
    function test_setL1Mirror_one_shot_reverts_on_re_point() public {
        ShadowBridgeL2 br = _freshL2Bridge();
        address firstMirror = makeAddr("firstMirror");
        br.setL1Mirror(firstMirror);
        assertEq(br.l1Mirror(), firstMirror, "first set should land");

        // Same address -> revert.
        vm.expectRevert(ShadowBridgeL2.L1MirrorAlreadySet.selector);
        br.setL1Mirror(firstMirror);

        // Fresh address -> still revert.
        vm.expectRevert(ShadowBridgeL2.L1MirrorAlreadySet.selector);
        br.setL1Mirror(makeAddr("secondMirror"));

        // l1Mirror unchanged.
        assertEq(br.l1Mirror(), firstMirror, "l1Mirror must stay pinned");
    }

    // ============== ShadowMirrorL1.setL2Bridge ==============

    function test_setL2Bridge_zero_address_reverts() public {
        ShadowMirrorL1 mirror = _freshL1Mirror();
        vm.expectRevert(ShadowMirrorL1.ZeroAddress.selector);
        mirror.setL2Bridge(address(0));
    }

    function test_setL2Bridge_only_deployer_reverts() public {
        ShadowMirrorL1 mirror = _freshL1Mirror();
        vm.prank(mallory);
        vm.expectRevert(ShadowMirrorL1.NotDeployer.selector);
        mirror.setL2Bridge(makeAddr("anyBridge"));
    }

    function test_setL2Bridge_one_shot_reverts_on_re_point() public {
        ShadowMirrorL1 mirror = _freshL1Mirror();
        address first = makeAddr("firstBridge");
        mirror.setL2Bridge(first);
        assertEq(mirror.l2Bridge(), first);

        vm.expectRevert(ShadowMirrorL1.L2BridgeAlreadySet.selector);
        mirror.setL2Bridge(makeAddr("secondBridge"));
        assertEq(mirror.l2Bridge(), first, "l2Bridge must stay pinned");
    }

    // ============== ShadowMirrorL1.mintFromBridge ==============

    function test_mintFromBridge_reverts_when_caller_not_messenger() public {
        (ShadowMirrorL1 mirror, , ) = _wiredPair();
        ShadowMirrorL1.BridgePayload memory p = _payload(uint256(0xC1), alice);
        vm.expectRevert(ShadowMirrorL1.NotMessenger.selector);
        mirror.mintFromBridge(p);
    }

    function test_mintFromBridge_reverts_when_xsender_not_l2_bridge() public {
        (ShadowMirrorL1 mirror, , ) = _wiredPair();
        // The messenger relays the call but xDomainMessageSender returns
        // mallory (not the registered L2 bridge).
        StubMessenger(L1_MESSENGER).setXSender(mallory);
        ShadowMirrorL1.BridgePayload memory p = _payload(uint256(0xC2), alice);
        vm.prank(L1_MESSENGER);
        vm.expectRevert(abi.encodeWithSelector(
            ShadowMirrorL1.NotL2Bridge.selector, mallory
        ));
        mirror.mintFromBridge(p);
    }

    function test_mintFromBridge_reverts_when_l2_bridge_not_set() public {
        // Mirror with no setL2Bridge call.
        ShadowMirrorL1 mirror = _freshL1Mirror();
        ShadowMirrorL1.BridgePayload memory p = _payload(uint256(0xC3), alice);
        vm.prank(L1_MESSENGER);
        vm.expectRevert(ShadowMirrorL1.L2BridgeNotSet.selector);
        mirror.mintFromBridge(p);
    }

    function test_mintFromBridge_reverts_on_replay() public {
        (ShadowMirrorL1 mirror, ShadowBridgeL2 br, ) = _wiredPair();
        StubMessenger(L1_MESSENGER).setXSender(address(br));
        uint256 sid = uint256(0xCAFE);
        ShadowMirrorL1.BridgePayload memory p = _payload(sid, alice);

        vm.prank(L1_MESSENGER);
        mirror.mintFromBridge(p);
        assertEq(mirror.ownerOf(sid), alice);

        // Replay with same shadowId -> AlreadyMinted.
        vm.prank(L1_MESSENGER);
        vm.expectRevert(abi.encodeWithSelector(
            ShadowMirrorL1.AlreadyMinted.selector, sid
        ));
        mirror.mintFromBridge(p);
    }

    function test_mintFromBridge_happy_path_mints_and_stores_state() public {
        (ShadowMirrorL1 mirror, ShadowBridgeL2 br, ) = _wiredPair();
        StubMessenger(L1_MESSENGER).setXSender(address(br));
        uint256 sid = uint256(0xBEEF1234);
        ShadowMirrorL1.BridgePayload memory p = _payload(sid, alice);

        vm.prank(L1_MESSENGER);
        mirror.mintFromBridge(p);

        assertEq(mirror.ownerOf(sid), alice, "ERC721 minted to recipient");
        assertTrue(mirror.mintedFromBridge(sid), "marker set");

        ShadowMirrorL1.MirrorState memory st = mirror.stateOf(sid);
        assertEq(st.ecdhPubX, p.ecdhPubX);
        assertEq(st.ecdhPubY, p.ecdhPubY);
        assertEq(st.t10Hi,    p.t10Hi);
        assertEq(st.t10Lo,    p.t10Lo);
        assertEq(st.zIndexCommit, p.zIndexCommit);
        assertEq(st.zIndexRevealed, p.zIndexRevealed);

        // revealedPi round-trip
        bytes memory storedPi = mirror.revealedPiOf(sid);
        assertEq(storedPi.length, p.revealedPi.length);
        assertEq(keccak256(storedPi), keccak256(p.revealedPi));
    }

    // ============== ShadowMirrorL1.burnAndUnbridge ==============

    function test_burnAndUnbridge_reverts_when_l2_bridge_not_set() public {
        ShadowMirrorL1 mirror = _freshL1Mirror();
        // Can't even mint without l2Bridge, but the not-set check fires
        // BEFORE ownerOf, so we don't need a valid token here -- the
        // path reverts L2BridgeNotSet regardless.
        vm.expectRevert(ShadowMirrorL1.L2BridgeNotSet.selector);
        mirror.burnAndUnbridge(uint256(0xDEAD), alice);
    }

    function test_burnAndUnbridge_reverts_when_not_owner() public {
        (ShadowMirrorL1 mirror, ShadowBridgeL2 br, ) = _wiredPair();
        StubMessenger(L1_MESSENGER).setXSender(address(br));
        uint256 sid = uint256(0xACE0);
        ShadowMirrorL1.BridgePayload memory p = _payload(sid, alice);
        vm.prank(L1_MESSENGER);
        mirror.mintFromBridge(p);

        // mallory tries to burn alice's mirror
        vm.prank(mallory);
        vm.expectRevert(ShadowMirrorL1.NotMirrorOwner.selector);
        mirror.burnAndUnbridge(sid, mallory);
    }

    function test_burnAndUnbridge_happy_path_burns_and_sends_message() public {
        (ShadowMirrorL1 mirror, ShadowBridgeL2 br, ) = _wiredPair();
        StubMessenger(L1_MESSENGER).setXSender(address(br));
        uint256 sid = uint256(0xACE1);
        ShadowMirrorL1.BridgePayload memory p = _payload(sid, alice);
        vm.prank(L1_MESSENGER);
        mirror.mintFromBridge(p);

        // owner burns -> mirror sends unbridge message to L1 messenger.
        vm.prank(alice);
        mirror.burnAndUnbridge(sid, newOwner);

        // ERC721 burned.
        vm.expectRevert();
        mirror.ownerOf(sid);

        // Storage cleared.
        ShadowMirrorL1.MirrorState memory st = mirror.stateOf(sid);
        assertEq(st.ecdhPubX, bytes32(0), "state cleared");
        assertEq(mirror.revealedPiOf(sid).length, 0, "revealedPi cleared");

        // Messenger received a sendMessage to the L2 bridge with
        // unbridgeShadow(sid, newOwner) calldata.
        StubMessenger m = StubMessenger(L1_MESSENGER);
        assertEq(m.lastTarget(), address(br), "message target = L2 bridge");
        bytes memory expected = abi.encodeWithSignature(
            "unbridgeShadow(uint256,address)", sid, newOwner
        );
        assertEq(keccak256(m.lastMessage()), keccak256(expected),
            "L2 unbridge calldata exact-match");
    }

    // ============== ShadowBridgeL2.unbridgeShadow ==============

    function test_unbridgeShadow_reverts_when_caller_not_messenger() public {
        (, ShadowBridgeL2 br, ) = _wiredPair();
        vm.expectRevert(ShadowBridgeL2.NotMessenger.selector);
        br.unbridgeShadow(uint256(0x1), alice);
    }

    function test_unbridgeShadow_reverts_when_xsender_not_l1_mirror() public {
        (ShadowMirrorL1 mirror, ShadowBridgeL2 br, ) = _wiredPair();
        StubMessenger(L2_MESSENGER).setXSender(mallory);  // not the mirror
        vm.prank(L2_MESSENGER);
        vm.expectRevert(abi.encodeWithSelector(
            ShadowBridgeL2.NotL1Mirror.selector, mallory
        ));
        br.unbridgeShadow(uint256(0x1), alice);
        // (suppress warnings about mirror unused)
        mirror.l2Bridge();
    }

    function test_unbridgeShadow_reverts_when_not_owned_on_l1() public {
        (ShadowMirrorL1 mirror, ShadowBridgeL2 br, ) = _wiredPair();
        StubMessenger(L2_MESSENGER).setXSender(address(mirror));
        uint256 sid = uint256(0xC0FFEE);
        // Bridge state is OWNED_ON_L2 by default (the enum's zero value);
        // unbridge should reject because the shadow was never bridged.
        vm.prank(L2_MESSENGER);
        vm.expectRevert(abi.encodeWithSelector(
            ShadowBridgeL2.NotOwnedOnL1.selector, sid
        ));
        br.unbridgeShadow(sid, alice);
    }

    // ============== audit M-07: burnAndUnbridge zero-recipient guard ==============

    /// Audit M-07: pre-fix, ShadowMirrorL1.burnAndUnbridge accepted
    /// l2Recipient == address(0). The burn would land, then the L2 side
    /// would revert in ERC-721 transferFrom(_, address(0), _), stranding
    /// the L2 token in bridge custody with no L1 owner left to retry.
    /// Now MUST revert before any state change.
    function test_burnAndUnbridge_reverts_when_l2Recipient_is_zero() public {
        (ShadowMirrorL1 mirror, ShadowBridgeL2 br, ) = _wiredPair();
        StubMessenger(L1_MESSENGER).setXSender(address(br));
        uint256 sid = uint256(0xACE2);
        ShadowMirrorL1.BridgePayload memory p = _payload(sid, alice);
        vm.prank(L1_MESSENGER);
        mirror.mintFromBridge(p);
        // owner attempts to unbridge to zero
        vm.prank(alice);
        vm.expectRevert(ShadowMirrorL1.ZeroAddress.selector);
        mirror.burnAndUnbridge(sid, address(0));
        // mirror state preserved (no partial burn)
        assertEq(mirror.ownerOf(sid), alice, "alice still owns mirror");
        assertTrue(mirror.mintedFromBridge(sid), "marker still set");
    }

    // ============== audit M-08: bridgeShadow requires non-zero L1 recipient ==============

    /// Audit M-08: pre-fix, bridgeShadow always minted the L1 mirror to
    /// msg.sender (the L2 caller). Contract wallets / multisigs whose L2
    /// address has no L1 controller produce an unreachable mirror. The
    /// caller now passes l1Recipient explicitly; address(0) is rejected.
    function test_bridgeShadow_reverts_when_l1Recipient_is_zero() public {
        (, ShadowBridgeL2 br, ) = _wiredPair();
        // We don't actually need a solved shadow; the zero check fires first.
        // But we do need l1Mirror set (it is, via _wiredPair) and a non-empty PI
        // so we don't trip BadRevealedPi.
        bytes memory pi = new bytes(32);
        vm.prank(alice);
        vm.expectRevert(ShadowBridgeL2.ZeroAddress.selector);
        br.bridgeShadow(uint256(0xDEAD), address(0), pi);
    }

    // ============== audit H-06: round-trip + re-bridge does not strand L2 ==============

    /// Audit H-06: pre-fix, ShadowMirrorL1.mintedFromBridge was set-once and
    /// never cleared. The first round-trip (mint -> burnAndUnbridge ->
    /// unbridgeShadow) succeeded, but the SECOND bridgeShadow on the same
    /// shadow would call mintFromBridge again, hit AlreadyMinted, and lock
    /// the L2 token forever in ShadowBridgeL2's custody. burnAndUnbridge
    /// now clears the marker so a future cycle can mint the mirror fresh.
    function test_round_trip_bridgeShadow_then_rebridge_does_not_strand() public {
        (ShadowMirrorL1 mirror, ShadowBridgeL2 br, ) = _wiredPair();
        StubMessenger(L1_MESSENGER).setXSender(address(br));
        uint256 sid = uint256(0xC0FFEE01);

        // ---- Cycle 1: mint L1 mirror ----
        ShadowMirrorL1.BridgePayload memory p = _payload(sid, alice);
        vm.prank(L1_MESSENGER);
        mirror.mintFromBridge(p);
        assertEq(mirror.ownerOf(sid), alice, "cycle 1 mint");
        assertTrue(mirror.mintedFromBridge(sid), "marker set after cycle 1");

        // ---- Round-trip: alice burns + unbridges ----
        vm.prank(alice);
        mirror.burnAndUnbridge(sid, alice);
        assertFalse(mirror.mintedFromBridge(sid), "marker CLEARED on burnAndUnbridge");

        // ---- Cycle 2: same shadowId re-bridges and re-mints L1 mirror ----
        // (The L2 side's bridge state is not modeled here -- we just verify
        //  that the L1 contract no longer rejects with AlreadyMinted.)
        ShadowMirrorL1.BridgePayload memory p2 = _payload(sid, mallory);
        vm.prank(L1_MESSENGER);
        mirror.mintFromBridge(p2);
        assertEq(mirror.ownerOf(sid), mallory, "cycle 2 mint to new recipient");
        assertTrue(mirror.mintedFromBridge(sid), "marker set after cycle 2");
    }

    // ============== helpers ==============

    function _freshL2Bridge() internal returns (ShadowBridgeL2 br) {
        Poseidon2YulSponge sp = new Poseidon2YulSponge();
        TestableShadowToken s = new TestableShadowToken(address(sp));
        TestableFeatureNFT f = new TestableFeatureNFT(address(s));
        s.setFeatureNFT(IFeatureNFT(address(f)));
        br = new ShadowBridgeL2(IShadowToken(address(s)), IFeatureNFT(address(f)));
    }

    function _freshL1Mirror() internal returns (ShadowMirrorL1) {
        // Etch a stub at the L1 messenger so the constructor's non-zero
        // address check is satisfied with a real(ish) target.
        _newMessengerStub(L1_MESSENGER);
        return new ShadowMirrorL1(L1_MESSENGER);
    }

    /// Returns (mirror, l2Bridge, messengerStub-at-L1). Both directions wired.
    function _wiredPair() internal returns (
        ShadowMirrorL1 mirror,
        ShadowBridgeL2 br,
        StubMessenger l1Stub
    ) {
        l1Stub = _newMessengerStub(L1_MESSENGER);
        _newMessengerStub(L2_MESSENGER);
        mirror = new ShadowMirrorL1(L1_MESSENGER);
        br = _freshL2Bridge();
        mirror.setL2Bridge(address(br));
        br.setL1Mirror(address(mirror));
    }

    function _payload(uint256 sid, address recipient)
        internal pure returns (ShadowMirrorL1.BridgePayload memory p)
    {
        p.shadowId = sid;
        p.recipient = recipient;
        p.ecdhPubX = bytes32(uint256(0xa1));
        p.ecdhPubY = bytes32(uint256(0xa2));
        p.t10Hi    = bytes32(uint256(0x1111));
        p.t10Lo    = bytes32(uint256(0x2222));
        p.zIndexCommit = bytes32(uint256(0xbeef));
        p.zIndexRevealed = 0xfedcba9876543210;
        // Manifest, typeIdxs, originFaceIds, paletteCommits left zero
        // (EMPTY shadow post-auto-extract).
        p.revealedPi = new bytes(7 * 32);
        // Stamp shadowId at PI[0] so the blob is non-trivial.
        bytes32 b = bytes32(sid);
        bytes memory pi = p.revealedPi;
        assembly { mstore(add(pi, 32), b) }
    }
}

/// Mock cross-domain messenger that captures the last sendMessage call
/// AND lets tests configure xDomainMessageSender (which the real OP
/// Stack messenger uses to relay the original sender across chains).
contract StubMessenger {
    address public lastTarget;
    bytes   public lastMessage;
    uint32  public lastGasLimit;
    address private _xsender;

    function sendMessage(address _target, bytes calldata _message, uint32 _minGasLimit) external {
        lastTarget = _target;
        lastMessage = _message;
        lastGasLimit = _minGasLimit;
    }

    function setXSender(address sender) external {
        _xsender = sender;
    }

    function xDomainMessageSender() external view returns (address) {
        return _xsender;
    }
}
