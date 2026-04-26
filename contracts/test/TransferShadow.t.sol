// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";

import {IVerifier} from "../src/IVerifier.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";

/// Integration test for ShadowToken.transferShadow using a real proof produced
/// by `phase2/harness/build_transfer_shadow_fixture.py`. The fixture re-encrypts
/// alice0's mint c2 to bob; the contract verifies the proof + on-chain Yul
/// sponge_249(new_c2) binding + PI bindings + ECIES envelope.
contract TransferShadowTest is Test {
    bytes mintProof;
    bytes32[] mintPi;
    bytes mintC2;
    bytes mintProofDisc;

    bytes xferProof;
    bytes32[] xferPi;
    bytes xferNewC2;

    IVerifier mintVerifier;
    IVerifier xferVerifier;
    ShadowToken st;
    FeatureNFT fn;

    address alice = address(0xA11CE);
    address bob   = address(0xB0B);

    uint256 sid;

    function setUp() public {
        // Mint fixture (alice0).
        mintProof = vm.readFileBinary("test/fixtures/mint_shadow/alice0/proof");
        mintPi    = _readFieldArray("test/fixtures/mint_shadow/alice0/public_inputs");
        mintC2    = vm.readFileBinary("test/fixtures/mint_shadow/alice0/c2.bin");
        mintProofDisc = vm.readFileBinary("test/fixtures/face_disc/alice0/proof");

        // Transfer fixture (alice0 -> bob).
        xferProof = vm.readFileBinary("test/fixtures/transfer_shadow/alice0_to_bob/proof");
        xferPi    = _readFieldArray("test/fixtures/transfer_shadow/alice0_to_bob/public_inputs");
        xferNewC2 = vm.readFileBinary("test/fixtures/transfer_shadow/alice0_to_bob/new_c2.bin");

        require(mintPi.length == 18, "mint PI must be 18");
        require(xferPi.length == 8, "xfer PI must be 8");
        require(xferNewC2.length == 7968, "new_c2 must be 7968 bytes");

        mintVerifier = IVerifier(deployCode("MintShadowVerifier.sol:MintShadowVerifier"));
        xferVerifier = IVerifier(deployCode("TransferShadowVerifier.sol:TransferShadowVerifier"));
        IVerifier discVerifier = IVerifier(deployCode("FaceDiscVerifier.sol:FaceDiscVerifier"));

        Poseidon2YulSponge sponge = new Poseidon2YulSponge();
        st = new ShadowToken(address(sponge));
        fn = new FeatureNFT(address(st), address(sponge));
        st.setFeatureNFT(fn);
        st.setMintShadowVerifier(mintVerifier);
        st.setTransferShadowVerifier(xferVerifier);
        st.setFaceDiscVerifier(discVerifier);

        // Mint alice0 first.
        vm.prank(alice);
        sid = st.mintShadow(mintProof, mintPi, mintC2, mintProofDisc);
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

    function test_RawVerifierAcceptsFixture() public view {
        bool ok = xferVerifier.verify(xferProof, xferPi);
        assertTrue(ok, "raw transfer_shadow verifier rejected fixture");
    }

    function test_TransferShadow_FixturePiBindsToShadowId() public view {
        // PI[0] is shadow_id (mod FR_MOD), should equal the on-chain shadowId.
        assertEq(uint256(xferPi[0]), sid, "pi[0] == shadowId");
        // PI[7] is prev_ct_commit, should equal the chain's c2Commit.
        ShadowToken.Shadow memory s = st.shadowOf(sid);
        assertEq(xferPi[7], s.c2Commit, "pi[7] == prev c2Commit");
    }

    function test_TransferShadow_Succeeds_AndRotatesOwnership() public {
        bytes32 prevCommit = st.shadowOf(sid).c2Commit;

        vm.prank(alice);
        st.transferShadow(sid, bob, xferProof, xferPi, xferNewC2);

        assertEq(st.ownerOf(sid), bob, "owner rotated to bob");

        ShadowToken.Shadow memory s = st.shadowOf(sid);
        assertEq(s.ecdhPubX, xferPi[1], "ecdhPubX rotated to bob");
        assertEq(s.ecdhPubY, xferPi[2], "ecdhPubY rotated to bob");
        assertEq(s.c2Commit, xferPi[6], "c2Commit updated to new ct_commit");
        assertTrue(s.c2Commit != prevCommit, "c2Commit changed");
    }

    function test_TransferShadow_PreservesManifest() public {
        ShadowToken.ManifestEntry[16] memory before_ = st.manifestOf(sid);
        vm.prank(alice);
        st.transferShadow(sid, bob, xferProof, xferPi, xferNewC2);
        ShadowToken.ManifestEntry[16] memory after_ = st.manifestOf(sid);
        for (uint8 i = 0; i < 16; i++) {
            assertEq(uint8(before_[i].kind), uint8(after_[i].kind), "manifest kind preserved");
            assertEq(before_[i].originalTypeIdx, after_[i].originalTypeIdx, "typeIdx preserved");
            assertEq(before_[i].insertedFeatureId, after_[i].insertedFeatureId, "insertedFeatureId preserved");
            assertEq(before_[i].pose, after_[i].pose, "pose preserved");
        }
    }

    function test_TransferShadow_RevertsOnNonOwner() public {
        vm.prank(bob);
        vm.expectRevert(ShadowToken.NotShadowOwner.selector);
        st.transferShadow(sid, bob, xferProof, xferPi, xferNewC2);
    }

    function test_TransferShadow_RevertsOnTamperedC2() public {
        bytes memory tampered = xferNewC2;
        tampered[0] = bytes1(uint8(tampered[0]) ^ 0x01);

        vm.prank(alice);
        vm.expectPartialRevert(ShadowToken.CtCommitMismatch.selector);
        st.transferShadow(sid, bob, xferProof, xferPi, tampered);
    }

    function test_TransferShadow_RevertsOnBadPILen() public {
        bytes32[] memory shortPi = new bytes32[](7);
        for (uint256 i = 0; i < 7; i++) shortPi[i] = xferPi[i];

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.BadPILen.selector, 7, 8));
        st.transferShadow(sid, bob, xferProof, shortPi, xferNewC2);
    }

    function test_TransferShadow_RevertsOnTamperedProof() public {
        bytes memory tampered = xferProof;
        tampered[100] = bytes1(uint8(tampered[100]) ^ 0x01);

        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.transferShadow(sid, bob, tampered, xferPi, xferNewC2);
    }

    function test_TransferShadow_RevertsOnPiShadowIdMismatch() public {
        bytes32[] memory pi = new bytes32[](8);
        for (uint256 i = 0; i < 8; i++) pi[i] = xferPi[i];
        pi[0] = bytes32(uint256(pi[0]) ^ 1); // tweak shadow_id

        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.transferShadow(sid, bob, xferProof, pi, xferNewC2);
    }

    function test_TransferShadow_RevertsOnPrevCtCommitMismatch() public {
        bytes32[] memory pi = new bytes32[](8);
        for (uint256 i = 0; i < 8; i++) pi[i] = xferPi[i];
        pi[7] = bytes32(uint256(pi[7]) ^ 1); // tweak prev_ct_commit

        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.transferShadow(sid, bob, xferProof, pi, xferNewC2);
    }
}
