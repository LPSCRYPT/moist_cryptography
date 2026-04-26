// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";

import {IVerifier} from "../src/IVerifier.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {IShadowToken} from "../src/IShadowToken.sol";
import {ShadowBridgeL2} from "../src/ShadowBridgeL2.sol";
import {ShadowMirrorL1} from "../src/ShadowMirrorL1.sol";
import {ICrossDomainMessenger} from "../src/ICrossDomainMessenger.sol";

/// @notice Cross-chain bridge tests using a mock messenger pair to simulate
///         L2 -> L1 -> L2 round trips in a single Foundry process.
contract MockCrossDomainMessenger is ICrossDomainMessenger {
    address public xDomainMsgSender;
    address public lastTarget;
    bytes   public lastMessage;
    uint32  public lastGasLimit;

    /// Setter so tests can simulate the cross-chain delivery: caller A's
    /// sendMessage is treated by the receiving side as if A is the
    /// xDomainMessageSender. Test harness flips this manually before relaying.
    function setXDomainMessageSender(address s) external {
        xDomainMsgSender = s;
    }

    function sendMessage(address target, bytes calldata message, uint32 gasLimit) external {
        lastTarget = target;
        lastMessage = message;
        lastGasLimit = gasLimit;
    }

    function xDomainMessageSender() external view returns (address) {
        return xDomainMsgSender;
    }

    /// Helper: call `target` with the captured `lastMessage`, while pretending
    /// `originalSender` was the xDomainMessageSender. Returns the success flag.
    function relay(address target, address originalSender) external returns (bool) {
        xDomainMsgSender = originalSender;
        (bool ok,) = target.call(lastMessage);
        return ok;
    }
}

contract BridgeTest is Test {
    bytes mintProof;
    bytes32[] mintPi;
    bytes mintC2;
    bytes mintProofDisc;

    bytes solveProof;
    bytes32[] solvePi;
    bytes solvePiBytes;  // serialized form for bridgeShadow's revealedPi arg

    IVerifier mintVerifier;
    IVerifier solveVerifier;
    ShadowToken st;
    FeatureNFT fn;

    MockCrossDomainMessenger l2Messenger;
    MockCrossDomainMessenger l1Messenger;
    ShadowBridgeL2 bridge;
    ShadowMirrorL1 mirror;

    address alice = address(0xA11CE);
    address bob   = address(0xB0B);

    uint256 sid;

    function setUp() public {
        mintProof = vm.readFileBinary("test/fixtures/mint_shadow/alice0/proof");
        mintPi    = _readFieldArray("test/fixtures/mint_shadow/alice0/public_inputs");
        mintC2    = vm.readFileBinary("test/fixtures/mint_shadow/alice0/c2.bin");
        mintProofDisc = vm.readFileBinary("test/fixtures/face_disc/alice0/proof");

        solveProof = vm.readFileBinary("test/fixtures/solve_shadow/alice0/proof");
        solvePi    = _readFieldArray("test/fixtures/solve_shadow/alice0/public_inputs");
        solvePiBytes = vm.readFileBinary("test/fixtures/solve_shadow/alice0/public_inputs");

        require(mintPi.length == 18 && solvePi.length == 261, "fixture shape");
        require(solvePiBytes.length == 261 * 32, "solvePi bytes shape");

        mintVerifier  = IVerifier(deployCode("MintShadowVerifier.sol:MintShadowVerifier"));
        solveVerifier = IVerifier(deployCode("SolveShadowVerifier.sol:SolveShadowVerifier"));
        IVerifier discVerifier = IVerifier(deployCode("FaceDiscVerifier.sol:FaceDiscVerifier"));

        Poseidon2YulSponge sponge = new Poseidon2YulSponge();
        st = new ShadowToken(address(sponge));
        fn = new FeatureNFT(address(st), address(sponge));
        st.setFeatureNFT(fn);
        st.setMintShadowVerifier(mintVerifier);
        st.setSolveShadowVerifier(solveVerifier);
        st.setFaceDiscVerifier(discVerifier);

        // Mint + solve as alice so we have a solved shadow to bridge.
        vm.prank(alice);
        sid = st.mintShadow(mintProof, mintPi, mintC2, mintProofDisc);
        vm.prank(alice);
        st.solve(sid, solveProof, solvePi);

        // Stand up bridge + mirror with mock messengers. We deploy the L2
        // messenger at the canonical predeploy address so the immutable
        // L2_MESSENGER constant in ShadowBridgeL2 hits our mock.
        l2Messenger = new MockCrossDomainMessenger();
        l1Messenger = new MockCrossDomainMessenger();
        vm.etch(0x4200000000000000000000000000000000000007, address(l2Messenger).code);
        // Re-bind: at the predeploy address the storage is fresh, so we use the
        // predeploy as the "real" L2 messenger and call its setters there.
        l2Messenger = MockCrossDomainMessenger(0x4200000000000000000000000000000000000007);

        bridge = new ShadowBridgeL2(IShadowToken(address(st)));
        mirror = new ShadowMirrorL1(address(l1Messenger));

        bridge.setL1Mirror(address(mirror));
        mirror.setL2Bridge(address(bridge));

        // Alice (the shadow owner) pre-approves the bridge so it can transferFrom
        // the locked token. This is the production caller flow as well.
        vm.prank(alice);
        st.setApprovalForAll(address(bridge), true);
    }

    function _readFieldArray(string memory path) internal view returns (bytes32[] memory out) {
        bytes memory raw = vm.readFileBinary(path);
        require(raw.length % 32 == 0, "alignment");
        uint256 n = raw.length / 32;
        out = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 v;
            uint256 off = 32 + i * 32;
            assembly ("memory-safe") { v := mload(add(raw, off)) }
            out[i] = v;
        }
    }

    // ============== bridge sanity ==============

    function test_BridgeRequiresL1MirrorSet() public {
        ShadowBridgeL2 freshBridge = new ShadowBridgeL2(IShadowToken(address(st)));
        vm.expectRevert(ShadowBridgeL2.L1MirrorNotSet.selector);
        vm.prank(alice);
        freshBridge.bridgeShadow(sid, solvePiBytes);
    }

    function test_BridgeRequiresOwner() public {
        vm.expectRevert(ShadowBridgeL2.NotShadowOwner.selector);
        vm.prank(bob);
        bridge.bridgeShadow(sid, solvePiBytes);
    }

    function test_BridgeRequiresSolved() public {
        // Mint a fresh, unsolved shadow and try to bridge it.
        // The fixture only has one mint, so we re-use the same proof; this
        // would revert AlreadyMinted on the chain. Skip by reverting earlier:
        // pre-solve gate is checked via the live `sid` in a separate setup.
        // Easier path: deploy a second ShadowToken and try to bridge a never-
        // solved id from there. But we'd need a different bridge. Inline check
        // is sufficient: confirm st.solved(sid) is true here, and rely on the
        // direct revert assertion in the require below.
        assertTrue(st.solved(sid), "sid must be solved for this run");

        // Drop the solved bit by deploying a parallel ShadowToken with a fresh
        // mint but no solve.
        Poseidon2YulSponge sponge = new Poseidon2YulSponge();
        ShadowToken st2 = new ShadowToken(address(sponge));
        FeatureNFT  fn2 = new FeatureNFT(address(st2), address(sponge));
        st2.setFeatureNFT(fn2);
        st2.setMintShadowVerifier(mintVerifier);
        st2.setFaceDiscVerifier(IVerifier(deployCode("FaceDiscVerifier.sol:FaceDiscVerifier")));
        vm.prank(alice);
        uint256 sid2 = st2.mintShadow(mintProof, mintPi, mintC2, mintProofDisc);

        ShadowBridgeL2 bridge2 = new ShadowBridgeL2(IShadowToken(address(st2)));
        bridge2.setL1Mirror(address(mirror));

        vm.expectRevert(ShadowBridgeL2.NotSolved.selector);
        vm.prank(alice);
        bridge2.bridgeShadow(sid2, solvePiBytes);
    }

    function test_BridgeRequiresStateCommitsMatch() public {
        // Mutate the first 256 bytes of revealedPi -> hash mismatch.
        bytes memory bad = bytes.concat(solvePiBytes);
        bad[0] = bytes1(uint8(bad[0]) ^ 0x01);
        vm.expectRevert();  // StateCommitMismatch is dynamic; just expect revert
        vm.prank(alice);
        bridge.bridgeShadow(sid, bad);
    }

    function test_BridgeRequiresPiLength() public {
        bytes memory short_ = new bytes(100);
        vm.expectRevert();
        vm.prank(alice);
        bridge.bridgeShadow(sid, short_);
    }

    // ============== full L2 -> L1 round trip ==============

    function test_BridgeShadowL2toL1AndBack() public {
        // ---- L2 leg: lock + dispatch ----
        vm.prank(alice);
        bridge.bridgeShadow(sid, solvePiBytes);

        assertEq(uint8(bridge.bridged(sid)), uint8(ShadowBridgeL2.BridgeState.OWNED_ON_L1), "L2 marked as on-L1");
        assertEq(st.ownerOf(sid), address(bridge), "L2 token locked in bridge");

        bytes memory msg_ = l2Messenger.lastMessage();
        assertEq(l2Messenger.lastTarget(), address(mirror), "messenger target = L1 mirror");
        assertGt(msg_.length, 0, "message non-empty");

        // ---- L1 leg: simulate the relay. We move the captured message
        //              over to l1Messenger and play it back, with the
        //              xDomainMessageSender pretending to be the L2 bridge.
        l1Messenger.setXDomainMessageSender(address(bridge));
        // sendMessage capture isn't relevant for the inbound side; we directly
        // call the target with the captured calldata, while spoofing msg.sender
        // as the L1 messenger.
        vm.prank(address(l1Messenger));
        (bool ok,) = address(mirror).call(msg_);
        require(ok, "mintFromBridge call failed");

        assertTrue(mirror.mintedFromBridge(sid), "L1 mintedFromBridge set");
        assertEq(mirror.ownerOf(sid), alice, "L1 mirror minted to alice");

        ShadowMirrorL1.MirrorState memory mst = mirror.stateOf(sid);
        ShadowToken.Shadow memory shadow = st.shadowOf(sid);
        assertEq(mst.faceOriginId, shadow.faceOriginId, "faceOriginId carried");
        assertEq(uint256(mst.color), uint256(shadow.color), "color carried");
        assertEq(mst.stateCommitsHash, shadow.stateCommitsHash, "stateCommitsHash carried");
        assertEq(mirror.revealedPiOf(sid).length, solvePiBytes.length, "revealedPi length carried");

        // ---- L1 -> L2 unbridge leg ----
        vm.prank(alice);
        mirror.burnAndUnbridge(sid, alice);

        // L1 token burned.
        vm.expectRevert();  // OZ ERC721 ownerOf reverts on burned
        mirror.ownerOf(sid);

        bytes memory unbridgeMsg = l1Messenger.lastMessage();
        assertEq(l1Messenger.lastTarget(), address(bridge), "unbridge target = L2 bridge");

        // Replay on L2 side.
        l2Messenger.setXDomainMessageSender(address(mirror));
        vm.prank(address(l2Messenger));
        (bool ok2,) = address(bridge).call(unbridgeMsg);
        require(ok2, "unbridgeShadow call failed");

        assertEq(uint8(bridge.bridged(sid)), uint8(ShadowBridgeL2.BridgeState.OWNED_ON_L2), "L2 marked back");
        assertEq(st.ownerOf(sid), alice, "L2 token returned to alice");
    }

    // ============== negative auth tests ==============

    function test_MintFromBridgeRejectsNonMessenger() public {
        ShadowMirrorL1.BridgePayload memory p;
        p.shadowId = sid;
        vm.expectRevert(ShadowMirrorL1.NotMessenger.selector);
        mirror.mintFromBridge(p);
    }

    function test_MintFromBridgeRejectsWrongCounterpart() public {
        ShadowMirrorL1.BridgePayload memory p;
        p.shadowId = sid;
        l1Messenger.setXDomainMessageSender(bob); // not the L2 bridge
        vm.expectRevert();
        vm.prank(address(l1Messenger));
        mirror.mintFromBridge(p);
    }

    function test_UnbridgeRejectsNonMessenger() public {
        vm.expectRevert(ShadowBridgeL2.NotMessenger.selector);
        bridge.unbridgeShadow(sid, alice);
    }

    function test_UnbridgeRejectsWrongCounterpart() public {
        l2Messenger.setXDomainMessageSender(bob);
        vm.expectRevert();
        vm.prank(address(l2Messenger));
        bridge.unbridgeShadow(sid, alice);
    }

    function test_BridgePreventsDoubleBridge() public {
        vm.prank(alice);
        bridge.bridgeShadow(sid, solvePiBytes);

        // After lock alice no longer owns it; second bridge fails NotShadowOwner.
        vm.expectRevert(ShadowBridgeL2.NotShadowOwner.selector);
        vm.prank(alice);
        bridge.bridgeShadow(sid, solvePiBytes);
    }

    function test_MirrorPreventsDoubleMint() public {
        vm.prank(alice);
        bridge.bridgeShadow(sid, solvePiBytes);
        bytes memory msg_ = l2Messenger.lastMessage();

        l1Messenger.setXDomainMessageSender(address(bridge));
        vm.prank(address(l1Messenger));
        (bool ok,) = address(mirror).call(msg_);
        require(ok, "first mint");

        vm.prank(address(l1Messenger));
        (bool ok2,) = address(mirror).call(msg_);
        assertFalse(ok2, "second mint must revert");
    }
}
