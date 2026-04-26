// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";

import {IVerifier} from "../src/IVerifier.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {PausableMixin} from "../src/PausableMixin.sol";
import {PoseLib} from "../src/PoseLib.sol";

contract PausableAndRotationTest is Test {
    bytes proof;
    bytes32[] pi;
    bytes c2;
    bytes proofDisc;

    IVerifier mintVerifier;
    ShadowToken st;
    FeatureNFT fn;

    address deployer = address(this);
    address alice = address(0xA11CE);
    address bob   = address(0xB0B);

    function setUp() public {
        proof = vm.readFileBinary("test/fixtures/mint_shadow/alice0/proof");
        pi    = _readFieldArray("test/fixtures/mint_shadow/alice0/public_inputs");
        c2    = vm.readFileBinary("test/fixtures/mint_shadow/alice0/c2.bin");
        proofDisc = vm.readFileBinary("test/fixtures/face_disc/alice0/proof");

        mintVerifier = IVerifier(deployCode("MintShadowVerifier.sol:MintShadowVerifier"));
        IVerifier discVerifier = IVerifier(deployCode("FaceDiscVerifier.sol:FaceDiscVerifier"));
        Poseidon2YulSponge sponge = new Poseidon2YulSponge();
        st = new ShadowToken(address(sponge));
        fn = new FeatureNFT(address(st), address(sponge));
        st.setFeatureNFT(fn);
        st.setMintShadowVerifier(mintVerifier);
        st.setFaceDiscVerifier(discVerifier);
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

    // ---------- Pause control ----------

    function test_Pause_Succeeds_AndBlocksMint() public {
        st.pause();
        assertTrue(st.paused(), "paused");

        vm.prank(alice);
        vm.expectRevert(PausableMixin.PausableContractIsPaused.selector);
        st.mintShadow(proof, pi, c2, proofDisc);
    }

    function test_Pause_RevertsForNonDeployer() public {
        vm.prank(alice);
        vm.expectRevert(PausableMixin.PausableNotDeployer.selector);
        st.pause();
    }

    function test_Pause_DoubleRevert() public {
        st.pause();
        vm.expectRevert(PausableMixin.PausableAlreadyPaused.selector);
        st.pause();
    }

    function test_Unpause_RestoresOperation() public {
        st.pause();
        st.unpause();
        assertFalse(st.paused(), "unpaused");

        vm.prank(alice);
        st.mintShadow(proof, pi, c2, proofDisc);
        // No revert -- mint succeeds.
    }

    function test_Unpause_RevertsWhenNotPaused() public {
        vm.expectRevert(PausableMixin.PausableNotPaused.selector);
        st.unpause();
    }

    function test_Pause_BlocksMutateSlot() public {
        // Mint first, then pause, then try to mutate.
        vm.prank(alice);
        uint256 sid = st.mintShadow(proof, pi, c2, proofDisc);

        st.pause();
        vm.prank(alice);
        vm.expectRevert(PausableMixin.PausableContractIsPaused.selector);
        st.mutateSlot(sid, 1, PoseLib.identity(10, 10));
    }

    // ---------- Verifier rotation ----------

    function test_RotationProposal_Records() public {
        address newV = address(0x1234);
        st.proposeVerifier(st.SLOT_MINT_SHADOW(), newV);
        assertEq(st.proposedVerifier(st.SLOT_MINT_SHADOW()), newV);
        uint64 ts = st.proposedAt(st.SLOT_MINT_SHADOW());
        assertEq(ts, block.timestamp);
    }

    function test_Rotation_RevertsBeforeTimelockExpires() public {
        address newV = address(0x1234);
        st.proposeVerifier(st.SLOT_MINT_SHADOW(), newV);

        uint8 slot = st.SLOT_MINT_SHADOW();

        // Try to apply immediately.
        vm.expectPartialRevert(PausableMixin.VerifierTimelockNotExpired.selector);
        st.applyVerifier(slot);

        // Try after 6 days (still too early).
        vm.warp(block.timestamp + 6 days);
        vm.expectPartialRevert(PausableMixin.VerifierTimelockNotExpired.selector);
        st.applyVerifier(slot);
    }

    function test_Rotation_AppliesAfterTimelock() public {
        address newV = address(0x9999);
        st.proposeVerifier(st.SLOT_MINT_SHADOW(), newV);

        vm.warp(block.timestamp + 7 days + 1);
        st.applyVerifier(st.SLOT_MINT_SHADOW());
        assertEq(address(st.mintShadowVerifier()), newV, "verifier rotated");

        // Pending state cleared.
        assertEq(st.proposedVerifier(st.SLOT_MINT_SHADOW()), address(0));
        assertEq(st.proposedAt(st.SLOT_MINT_SHADOW()), 0);
    }

    function test_Rotation_AnyoneCanApplyAfterTimelock() public {
        address newV = address(0x9999);
        st.proposeVerifier(st.SLOT_TRANSFER_SHADOW(), newV);
        vm.warp(block.timestamp + 7 days + 1);

        // bob (random EOA) can apply -- the proposal was deployer-gated.
        vm.prank(bob);
        st.applyVerifier(st.SLOT_TRANSFER_SHADOW());
        assertEq(address(st.transferShadowVerifier()), newV);
    }

    function test_RotationCancel() public {
        uint8 slot = st.SLOT_MINT_SHADOW();
        st.proposeVerifier(slot, address(0x9999));
        st.cancelVerifierRotation(slot);
        assertEq(st.proposedVerifier(slot), address(0));

        vm.warp(block.timestamp + 7 days + 1);
        vm.expectPartialRevert(PausableMixin.NoPendingRotation.selector);
        st.applyVerifier(slot);
    }

    function test_RotationImmediate_OnlyWhenPaused() public {
        address newV = address(0x9999);
        uint8 slot = st.SLOT_MINT_SHADOW();
        st.proposeVerifier(slot, newV);

        // Not paused: revert
        vm.expectRevert(PausableMixin.PausableNotPaused.selector);
        st.applyVerifierImmediate(slot);

        // Paused: works immediately, no timelock.
        st.pause();
        st.applyVerifierImmediate(slot);
        assertEq(address(st.mintShadowVerifier()), newV);
    }

    function test_RotationImmediate_OnlyDeployer() public {
        uint8 slot = st.SLOT_MINT_SHADOW();
        st.proposeVerifier(slot, address(0x9999));
        st.pause();
        vm.prank(bob);
        vm.expectRevert(PausableMixin.PausableNotDeployer.selector);
        st.applyVerifierImmediate(slot);
    }

    function test_FeatureNFT_RotationWorks() public {
        address newV = address(0x42);
        fn.proposeVerifier(fn.SLOT_TRANSFER_FEATURE(), newV);
        vm.warp(block.timestamp + 7 days + 1);
        fn.applyVerifier(fn.SLOT_TRANSFER_FEATURE());
        assertEq(address(fn.transferFeatureVerifier()), newV);
    }
}
