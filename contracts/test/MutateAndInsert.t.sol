// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";

import {IVerifier} from "../src/IVerifier.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {KeyRegistry} from "../src/KeyRegistry.sol";
import {PoseLib} from "../src/PoseLib.sol";

/// Tests the no-proof manifest mutators on a freshly minted alice0 shadow:
///   - mutateSlot   (range-checked pose update)
///   - insertFeature  (bind FeatureNFT into EMPTY slot)
///   - removeFeature  (unbind back to EMPTY)
///
/// Uses MintShadowTest's setUp pattern (alice0 fixture + new contracts).
contract MutateAndInsertTest is Test {
    bytes proof;
    bytes32[] pi;
    bytes c2;
    bytes proofDisc;

    IVerifier verifier;
    ShadowToken st;
    FeatureNFT fn;

    address alice = address(0xA11CE);
    address bob   = address(0xB0B);

    uint256 sid;

    function setUp() public {
        proof = vm.readFileBinary("test/fixtures/mint_shadow/alice0/proof");
        pi    = _readFieldArray("test/fixtures/mint_shadow/alice0/public_inputs");
        c2    = vm.readFileBinary("test/fixtures/mint_shadow/alice0/c2.bin");
        proofDisc = vm.readFileBinary("test/fixtures/face_disc/alice0/proof");

        verifier = IVerifier(deployCode("MintShadowVerifier.sol:MintShadowVerifier"));
        IVerifier discVerifier = IVerifier(deployCode("FaceDiscVerifier.sol:FaceDiscVerifier"));

        Poseidon2YulSponge sponge = new Poseidon2YulSponge();
        st = new ShadowToken(address(sponge));
        fn = new FeatureNFT(address(st), address(sponge));
        st.setFeatureNFT(fn);
        st.setMintShadowVerifier(verifier);
        st.setFaceDiscVerifier(discVerifier);

        // Mint alice0's shadow.
        vm.prank(alice);
        sid = st.mintShadow(proof, pi, c2, proofDisc);
    }

    function _readFieldArray(string memory path) internal view returns (bytes32[] memory out) {
        bytes memory raw = vm.readFileBinary(path);
        require(raw.length % 32 == 0);
        uint256 n = raw.length / 32;
        out = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 v;
            uint256 off = 32 + i * 32;
            assembly ("memory-safe") { v := mload(add(raw, off)) }
            out[i] = v;
        }
    }

    // -------- mutateSlot --------

    function test_MutateSlot_OriginalSlot_Translate() public {
        // Slot 0 (forehead): from origPose to (0, 0) -- forehead is 48x9 so curX=0
        // is the only valid position (0+48 == 48). Use scale change for translation
        // semantics test.
        uint64 origPose = st.origPoseOf(sid, 0);
        (uint8 x, uint8 y, , , ) = _unpack(origPose);

        // Translate slot 1 (eye, 33x8) -- has more freedom.
        uint64 origPose1 = st.origPoseOf(sid, 1);
        (uint8 x1, uint8 y1, , , ) = _unpack(origPose1);
        // Move 2 px right + 1 px down. eye is 33x8: as long as x1+2+33 <= 48 it's OK.
        uint64 newPose = PoseLib.identity(x1 + 2, y1 + 1);

        vm.prank(alice);
        st.mutateSlot(sid, 1, newPose);

        ShadowToken.ManifestEntry memory m = st.slotOf(sid, 1);
        assertEq(m.pose, newPose, "manifestPose updated");
        assertEq(uint8(m.kind), uint8(ShadowToken.SlotKind.ORIGINAL), "kind unchanged");
        assertEq(m.originalTypeIdx, 1, "typeIdx unchanged");

        // origPose stayed untouched.
        assertEq(st.origPoseOf(sid, 1), origPose1, "origPose immutable");

        // Suppress unused-warning for the slot-0 vars.
        x;
        y;
    }

    function test_MutateSlot_RevertsOnEmptySlot() public {
        // Slots 8..15 start EMPTY.
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.SlotNotInserted.selector, uint8(8)));
        st.mutateSlot(sid, 8, PoseLib.identity(10, 10));
    }

    function test_MutateSlot_RevertsOnSlotOutOfRange() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.SlotOutOfRange.selector, uint8(16)));
        st.mutateSlot(sid, 16, PoseLib.identity(10, 10));
    }

    function test_MutateSlot_RevertsOnNonOwner() public {
        vm.prank(bob);
        vm.expectRevert(ShadowToken.NotShadowOwner.selector);
        st.mutateSlot(sid, 1, PoseLib.identity(10, 10));
    }

    function test_MutateSlot_RevertsOnZeroScale() public {
        vm.prank(alice);
        vm.expectRevert(PoseLib.PoseScaleZero.selector);
        // pack(curX=10, curY=10, scale=0, cos=32767, sin=0) — zero scale.
        st.mutateSlot(sid, 1, PoseLib.pack(10, 10, 0, int16(32767), int16(0)));
    }

    function test_MutateSlot_RevertsOnOffFrame() public {
        // Slot 0 (forehead, alice0 actual w=21, h=6): max curX = 27 (48-21).
        // cx=28 with the actual landmark width should off-frame.
        vm.prank(alice);
        vm.expectRevert();
        st.mutateSlot(sid, 0, PoseLib.identity(28, 0));
    }

    function test_MutateSlot_RevertsOnNonUnitRotation() public {
        vm.prank(alice);
        vm.expectRevert();
        // cos=0, sin=0: not unit.
        st.mutateSlot(sid, 1, PoseLib.pack(10, 10, 256, int16(0), int16(0)));
    }

    // -------- insertFeature --------

    function test_InsertFeature_RevertsOnNonEmptySlot() public {
        // Slot 0 is ORIGINAL after mint. Insert should reject.
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.SlotNotEmpty.selector, uint8(0)));
        st.insertFeature(sid, 0, 12345 /* fake id */, PoseLib.identity(10, 10));
    }

    function test_InsertFeature_RevertsOnSlotOutOfRange() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.SlotOutOfRange.selector, uint8(16)));
        st.insertFeature(sid, 16, 12345, PoseLib.identity(10, 10));
    }

    function test_InsertFeature_RevertsOnNonOwner() public {
        vm.prank(bob);
        vm.expectRevert(ShadowToken.NotShadowOwner.selector);
        st.insertFeature(sid, 8, 12345, PoseLib.identity(10, 10));
    }

    function test_InsertFeature_RevertsOnUnownedFeatureNFT() public {
        // Slot 8 is EMPTY. Need a featureNftId that exists but is owned by someone else.
        // Without extractSlot working (verifier not deployed), we just assert the
        // FeatureNotOwned path triggers when ownerOfFeature returns address(0).
        vm.prank(alice);
        // ownerOfFeature for nonexistent id returns address(0), and msg.sender != address(0),
        // so FeatureNotOwned fires.
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.FeatureNotOwned.selector, uint256(99999)));
        st.insertFeature(sid, 8, 99999, PoseLib.identity(10, 10));
    }

    // -------- removeFeature --------

    function test_RemoveFeature_RevertsOnEmptySlot() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.SlotNotInserted.selector, uint8(8)));
        st.removeFeature(sid, 8);
    }

    function test_RemoveFeature_RevertsOnOriginalSlot() public {
        // Slot 0 is ORIGINAL, removeFeature should reject (only INSERTED slots
        // can be removed).
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.SlotNotInserted.selector, uint8(0)));
        st.removeFeature(sid, 0);
    }

    // -------- ERC-721 transfer lockdown --------

    function test_TransferFrom_GatedPreSolve() public {
        vm.prank(alice);
        vm.expectRevert(ShadowToken.TransferGated.selector);
        st.transferFrom(alice, bob, sid);
    }

    // -------- helpers --------

    function _unpack(uint64 p)
        internal
        pure
        returns (uint8, uint8, uint16, int16, int16)
    {
        return PoseLib.unpack(p);
    }
}
