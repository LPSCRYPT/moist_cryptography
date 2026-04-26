// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";

import {IVerifier} from "../src/IVerifier.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {KeyRegistry} from "../src/KeyRegistry.sol";
import {PoseLib} from "../src/PoseLib.sol";

/// Integration test for ShadowToken.mintShadow using alice0's existing
/// landmark_regions proof + PI + c2 (PI shape is identical between
/// landmark_regions and mint_shadow; the contract constructs the 16-slot
/// manifest from PI[9] = boxes_packed deterministically).
contract MintShadowTest is Test {
    bytes proof;
    bytes32[] pi;
    bytes c2;
    bytes proofDisc;

    IVerifier verifier;
    ShadowToken st;
    FeatureNFT fn;

    address alice = address(0xA11CE);

    function setUp() public {
        proof = vm.readFileBinary("test/fixtures/mint_shadow/alice0/proof");
        pi    = _readFieldArray("test/fixtures/mint_shadow/alice0/public_inputs");
        c2    = vm.readFileBinary("test/fixtures/mint_shadow/alice0/c2.bin");
        proofDisc = vm.readFileBinary("test/fixtures/face_disc/alice0/proof");

        require(pi.length == 18, "PI must be 18 fields");
        require(c2.length == 7968, "c2 must be 7968 bytes");

        verifier = IVerifier(deployCode("MintShadowVerifier.sol:MintShadowVerifier"));
        IVerifier discVerifier = IVerifier(deployCode("FaceDiscVerifier.sol:FaceDiscVerifier"));

        Poseidon2YulSponge sponge = new Poseidon2YulSponge();
        st = new ShadowToken(address(sponge));
        fn = new FeatureNFT(address(st), address(sponge));

        st.setFeatureNFT(fn);
        st.setMintShadowVerifier(verifier);
        st.setFaceDiscVerifier(discVerifier);
    }

    // ---------- helpers ----------

    function _readFieldArray(string memory path) internal view returns (bytes32[] memory out) {
        bytes memory raw = vm.readFileBinary(path);
        require(raw.length % 32 == 0, "PI not multiple of 32");
        uint256 n = raw.length / 32;
        out = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 v;
            uint256 off = 32 + i * 32;
            assembly ("memory-safe") { v := mload(add(raw, off)) }
            out[i] = v;
        }
    }

    function _expectedShadowId() internal view returns (uint256) {
        return st.shadowIdOf(pi[8]);
    }

    // ---------- tests ----------

    function test_RawVerifierAcceptsFixture() public view {
        bool ok = verifier.verify(proof, pi);
        assertTrue(ok, "raw verifier rejected canonical fixture");
    }

    function test_MintShadow_Succeeds_AndAssignsToCaller() public {
        uint256 expected = _expectedShadowId();
        vm.prank(alice);
        uint256 sid = st.mintShadow(proof, pi, c2, proofDisc);
        assertEq(sid, expected, "shadowId derivation");
        assertEq(st.ownerOf(sid), alice, "owner");
    }

    function test_MintShadow_WritesShadowMetadata() public {
        vm.prank(alice);
        uint256 sid = st.mintShadow(proof, pi, c2, proofDisc);

        ShadowToken.Shadow memory s = st.shadowOf(sid);
        assertEq(s.faceOriginId, pi[8], "faceOriginId");
        assertEq(s.color, uint8(uint256(pi[10])), "color");
        assertEq(s.ecdhPubX, pi[15], "ecdhPubX");
        assertEq(s.ecdhPubY, pi[16], "ecdhPubY");
        assertEq(s.c2Commit, pi[14], "c2Commit");
        assertEq(s.mintIdx, 1, "mintIdx == 1 for first mint");
    }

    function test_MintShadow_BuildsOriginalManifest_Slots0to7() public {
        vm.prank(alice);
        uint256 sid = st.mintShadow(proof, pi, c2, proofDisc);
        ShadowToken.ManifestEntry[16] memory m = st.manifestOf(sid);

        for (uint8 i = 0; i < 8; i++) {
            assertEq(uint8(m[i].kind), uint8(ShadowToken.SlotKind.ORIGINAL), "slot is ORIGINAL");
            assertEq(m[i].originalTypeIdx, i, "typeIdx == slot index");
            assertEq(m[i].insertedFeatureId, 0, "no inserted id on ORIGINAL slot");

            // Pose must equal identity at the slot's (x, y) decoded from PI[9].
            uint256 boxesPacked = uint256(pi[9]);
            uint256 slot = (boxesPacked >> (24 * i)) & 0xFFFFFF;
            uint8 x = uint8(slot & 0x3F);
            uint8 y = uint8((slot >> 6) & 0x3F);
            assertEq(m[i].pose, PoseLib.identity(x, y), "pose == identity at orig (x, y)");
        }
    }

    function test_MintShadow_BuildsEmptyManifest_Slots8to15() public {
        vm.prank(alice);
        uint256 sid = st.mintShadow(proof, pi, c2, proofDisc);
        ShadowToken.ManifestEntry[16] memory m = st.manifestOf(sid);

        for (uint8 i = 8; i < 16; i++) {
            assertEq(uint8(m[i].kind), uint8(ShadowToken.SlotKind.EMPTY), "slot is EMPTY");
            assertEq(m[i].originalTypeIdx, 0, "no typeIdx on EMPTY slot");
            assertEq(m[i].insertedFeatureId, 0, "no inserted id on EMPTY slot");
            assertEq(m[i].pose, 0, "pose==0 on EMPTY slot");
        }
    }

    function test_MintShadow_StoresOrigPoses() public {
        vm.prank(alice);
        uint256 sid = st.mintShadow(proof, pi, c2, proofDisc);

        uint256 boxesPacked = uint256(pi[9]);
        for (uint8 i = 0; i < 8; i++) {
            uint256 slot = (boxesPacked >> (24 * i)) & 0xFFFFFF;
            uint8 x = uint8(slot & 0x3F);
            uint8 y = uint8((slot >> 6) & 0x3F);
            uint64 expected = PoseLib.identity(x, y);
            assertEq(st.origPoseOf(sid, i), expected, "origPose immutable identity");
        }
    }

    function test_MintShadow_RevertsOnDuplicateFaceOrigin() public {
        vm.prank(alice);
        st.mintShadow(proof, pi, c2, proofDisc);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.AlreadyMinted.selector, pi[8]));
        st.mintShadow(proof, pi, c2, proofDisc);
    }

    function test_MintShadow_RevertsOnTamperedC2() public {
        bytes memory tampered = c2;
        tampered[100] = bytes1(uint8(tampered[100]) ^ 0x01);

        vm.prank(alice);
        vm.expectPartialRevert(ShadowToken.CtCommitMismatch.selector);
        st.mintShadow(proof, pi, tampered, proofDisc);
    }

    function test_MintShadow_RevertsOnTamperedC2_Middle() public {
        bytes memory tampered = c2;
        // 1024 bytes in to mutate a different region of the sponge
        tampered[1024] = bytes1(uint8(tampered[1024]) ^ 0x42);

        vm.prank(alice);
        vm.expectPartialRevert(ShadowToken.CtCommitMismatch.selector);
        st.mintShadow(proof, pi, tampered, proofDisc);
    }

    function test_MintShadow_RevertsOnBadPILen() public {
        bytes32[] memory shortPi = new bytes32[](17);
        for (uint256 i = 0; i < 17; i++) shortPi[i] = pi[i];

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.BadPILen.selector, 17, 18));
        st.mintShadow(proof, shortPi, c2, proofDisc);
    }

    function test_MintShadow_RevertsOnBadC2Length() public {
        bytes memory short_ = new bytes(7000);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.BadC2Length.selector, 7000));
        st.mintShadow(proof, pi, short_, proofDisc);
    }

    function test_MintShadow_RevertsOnTamperedProof() public {
        bytes memory tampered = proof;
        tampered[100] = bytes1(uint8(tampered[100]) ^ 0x01);

        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.mintShadow(tampered, pi, c2, proofDisc);
    }

    function test_MintShadow_RevertsOnTamperedPI() public {
        bytes32[] memory tampered = new bytes32[](18);
        for (uint256 i = 0; i < 18; i++) tampered[i] = pi[i];
        tampered[14] = bytes32(uint256(tampered[14]) ^ 1); // tweak ct_commit

        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.mintShadow(proof, tampered, c2, proofDisc);
    }

    function test_MintShadow_RevertsWithoutVerifierSet() public {
        // Fresh deploy without setMintShadowVerifier.
        Poseidon2YulSponge sponge = new Poseidon2YulSponge();
        ShadowToken stFresh = new ShadowToken(address(sponge));
        new FeatureNFT(address(stFresh), address(sponge));

        vm.prank(alice);
        vm.expectRevert(ShadowToken.VerifierNotSet.selector);
        stFresh.mintShadow(proof, pi, c2, proofDisc);
    }

    function test_MintShadow_IncrementsMintCounter() public {
        assertEq(st.mintCounter(), 0, "counter starts at 0");
        vm.prank(alice);
        st.mintShadow(proof, pi, c2, proofDisc);
        assertEq(st.mintCounter(), 1, "counter == 1 after mint");
    }
}
