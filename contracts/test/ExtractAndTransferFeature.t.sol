// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";

import {IVerifier} from "../src/IVerifier.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {PoseLib} from "../src/PoseLib.sol";

/// Integration tests for ShadowToken.extractSlot + FeatureNFT.transferFeature
/// using real proofs from build_extract_slot_fixture.py +
/// build_transfer_feature_fixture.py.
///
/// IMPORTANT: the extract_slot fixture's PI[0] is a placeholder shadow_id_field
/// (computed pre-mint). After mintShadow runs, the actual on-chain shadowId is
/// the same value (mintShadow computes shadowId = keccak256(...) % FR_MOD; the
/// fixture builder computes the same way). So the binding holds.
contract ExtractAndTransferFeatureTest is Test {
    bytes mintProof;
    bytes32[] mintPi;
    bytes mintC2;
    bytes mintProofDisc;

    bytes extractProof;
    bytes32[] extractPi;
    bytes featureC2;

    bytes xferFeatProof;
    bytes32[] xferFeatPi;
    bytes xferFeatNewC2;

    IVerifier mintVerifier;
    IVerifier extractVerifier;
    IVerifier xferFeatVerifier;
    ShadowToken st;
    FeatureNFT fn;

    address alice = address(0xA11CE);
    address bob   = address(0xB0B);
    address carol = address(0xCAB01);
    address dave  = address(0xDA7E);

    uint256 sid;

    function setUp() public {
        mintProof = vm.readFileBinary("test/fixtures/mint_shadow/alice0/proof");
        mintPi    = _readFieldArray("test/fixtures/mint_shadow/alice0/public_inputs");
        mintC2    = vm.readFileBinary("test/fixtures/mint_shadow/alice0/c2.bin");
        mintProofDisc = vm.readFileBinary("test/fixtures/face_disc/alice0/proof");

        extractProof = vm.readFileBinary("test/fixtures/extract_slot/alice0_slot3_to_carol/proof");
        extractPi    = _readFieldArray("test/fixtures/extract_slot/alice0_slot3_to_carol/public_inputs");
        featureC2    = vm.readFileBinary("test/fixtures/extract_slot/alice0_slot3_to_carol/feature_c2.bin");

        xferFeatProof = vm.readFileBinary("test/fixtures/transfer_feature/carol_to_dave/proof");
        xferFeatPi    = _readFieldArray("test/fixtures/transfer_feature/carol_to_dave/public_inputs");
        xferFeatNewC2 = vm.readFileBinary("test/fixtures/transfer_feature/carol_to_dave/new_c2.bin");

        require(mintPi.length == 18 && extractPi.length == 10 && xferFeatPi.length == 8, "PI lengths");
        require(featureC2.length == 1344, "feature_c2 must be 1344 bytes (42*32)");
        require(xferFeatNewC2.length == 1344, "xfer_feat new_c2 must be 1344 bytes");

        mintVerifier     = IVerifier(deployCode("MintShadowVerifier.sol:MintShadowVerifier"));
        extractVerifier  = IVerifier(deployCode("ExtractSlotVerifier.sol:ExtractSlotVerifier"));
        xferFeatVerifier = IVerifier(deployCode("TransferFeatureVerifier.sol:TransferFeatureVerifier"));
        IVerifier discVerifier = IVerifier(deployCode("FaceDiscVerifier.sol:FaceDiscVerifier"));

        Poseidon2YulSponge sponge = new Poseidon2YulSponge();
        st = new ShadowToken(address(sponge));
        fn = new FeatureNFT(address(st), address(sponge));
        st.setFeatureNFT(fn);
        st.setMintShadowVerifier(mintVerifier);
        st.setExtractSlotVerifier(extractVerifier);
        fn.setTransferFeatureVerifier(xferFeatVerifier);
        st.setFaceDiscVerifier(discVerifier);

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

    // ---------- extractSlot ----------

    function test_RawExtractVerifierAcceptsFixture() public view {
        bool ok = extractVerifier.verify(extractProof, extractPi);
        assertTrue(ok, "raw extract verifier rejected fixture");
    }

    function test_ExtractFixturePiBindsToOnChainShadowId() public view {
        // PI[0] (mod FR_MOD) should equal the chain's shadowId.
        assertEq(uint256(extractPi[0]), sid, "PI[0] == shadowId");
        // PI[1] = slot 3
        assertEq(uint256(extractPi[1]), 3, "PI[1] == slot 3");
        // PI[2] = feature_type 3
        assertEq(uint256(extractPi[2]), 3, "PI[2] == featureType 3");
        // PI[3] = chain.c2Commit
        assertEq(extractPi[3], st.shadowOf(sid).c2Commit, "PI[3] == chain c2Commit");
    }

    function test_ExtractSlot_Succeeds_AndMintsFeatureNFT() public {
        ShadowToken.ManifestEntry memory mBefore = st.slotOf(sid, 3);
        assertEq(uint8(mBefore.kind), uint8(ShadowToken.SlotKind.ORIGINAL), "before: ORIGINAL");
        assertEq(mBefore.originalTypeIdx, 3, "before: typeIdx 3");

        vm.prank(alice);
        uint256 fid = st.extractSlot(sid, 3, carol, extractProof, extractPi, featureC2);
        assertGt(fid, 0, "feature id is non-zero");

        // Slot 3 now EMPTY.
        ShadowToken.ManifestEntry memory mAfter = st.slotOf(sid, 3);
        assertEq(uint8(mAfter.kind), uint8(ShadowToken.SlotKind.EMPTY), "after: EMPTY");
        assertEq(mAfter.originalTypeIdx, 0, "after: typeIdx cleared");
        assertEq(mAfter.insertedFeatureId, 0, "after: insertedFeatureId cleared");
        assertEq(mAfter.pose, 0, "after: pose cleared");

        // FeatureNFT minted to carol.
        assertEq(fn.ownerOfFeature(fid), carol, "FeatureNFT owner is carol");

        FeatureNFT.Feature memory f = fn.featureOf(fid);
        assertEq(f.originShadowId, sid, "originShadowId");
        assertEq(f.originSlotIdx, 3, "originSlotIdx");
        assertEq(f.featureType, 3, "featureType");
        assertEq(f.color, st.shadowOf(sid).color, "color matches shadow");
        assertEq(f.ecdhPubX, extractPi[4], "ecdhPubX = carol pk");
        assertEq(f.ecdhPubY, extractPi[5], "ecdhPubY = carol pk");
        assertEq(f.c2Commit, extractPi[9], "c2Commit = pi[9]");
    }

    function test_ExtractSlot_RevertsOnNonOriginalSlot() public {
        // Try to extract slot 8 (EMPTY at mint).
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.SlotOutOfRange.selector, uint8(8)));
        st.extractSlot(sid, 8, carol, extractProof, extractPi, featureC2);
    }

    function test_ExtractSlot_RevertsOnNonOwner() public {
        vm.prank(bob);
        vm.expectRevert(ShadowToken.NotShadowOwner.selector);
        st.extractSlot(sid, 3, carol, extractProof, extractPi, featureC2);
    }

    function test_ExtractSlot_RevertsOnTamperedFeatureC2() public {
        bytes memory tampered = featureC2;
        tampered[0] = bytes1(uint8(tampered[0]) ^ 0x01);

        vm.prank(alice);
        vm.expectPartialRevert(ShadowToken.CtCommitMismatch.selector);
        st.extractSlot(sid, 3, carol, extractProof, extractPi, tampered);
    }

    function test_ExtractSlot_RevertsOnSlotIdxMismatchInPi() public {
        // Try to extract slot 5 with a proof whose PI says slot 3.
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.extractSlot(sid, 5, carol, extractProof, extractPi, featureC2);
    }

    // ---------- transferFeature (carol -> dave) ----------
    //
    // Pre-condition: extractSlot must have run successfully so a FeatureNFT
    // with carol's pk + correct c2Commit exists.

    function _extractAlice0Slot3() internal returns (uint256) {
        vm.prank(alice);
        return st.extractSlot(sid, 3, carol, extractProof, extractPi, featureC2);
    }

    function test_TransferFeature_Succeeds() public {
        uint256 fid = _extractAlice0Slot3();
        // The fixture's prev_ct_commit MUST equal the on-chain c2Commit of fid.
        assertEq(xferFeatPi[7], fn.featureOf(fid).c2Commit, "transfer PI[7] == feature c2Commit");

        // After the fid-binding fix in build_transfer_feature_fixture.py, PI[0]
        // is the deterministic chain-side fid mod FR_MOD. The contract should
        // accept the proof.
        bytes32 expectedFid = bytes32(fid);
        // The fixture's PI[0] is the chain fid mod FR_MOD; the contract
        // compares pi[0] != bytes32(featureNftId). uint256 fid <= 2^256-1, but
        // FR_MOD ~= 2^254, so fid % FR_MOD == fid iff fid < FR_MOD. For the
        // alice0_slot3_to_carol fixture the chain fid happens to be < FR_MOD,
        // so the assertion holds.
        // (If fid >= FR_MOD, the test would need a chain-side mod adjust.)
        require(uint256(expectedFid) < (1 << 254), "chain fid > FR_MOD; need mod adjust path");
        assertEq(xferFeatPi[0], expectedFid, "PI[0] == chain feature_nft_id");

        vm.prank(carol);
        fn.transferFeature(fid, dave, xferFeatProof, xferFeatPi, xferFeatNewC2);
        assertEq(fn.ownerOfFeature(fid), dave, "transfer succeeded; dave owns");
    }

    function test_TransferFeature_RawVerifierAcceptsFixture() public view {
        // Even though the contract test can't accept this proof for a real fid
        // mismatch, the proof itself is valid for its own PI[0] value.
        bool ok = xferFeatVerifier.verify(xferFeatProof, xferFeatPi);
        assertTrue(ok, "raw transfer_feature verifier rejected fixture");
    }
}
