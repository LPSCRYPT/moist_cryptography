// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";

import {IVerifier} from "../src/IVerifier.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {PoseLib} from "../src/PoseLib.sol";

/// Integration test for ShadowToken.setShadowT10. Uses:
///   - alice0's mint proof (test/fixtures/mint_shadow/alice0/...)
///   - shadow_t10/step_00's proof (post-mint, no mutations, state_nonce=0)
contract SetShadowT10Test is Test {
    bytes mintProof;
    bytes32[] mintPi;
    bytes mintC2;
    bytes mintProofDisc;

    bytes t10Proof;
    bytes32[] t10Pi;

    IVerifier mintVerifier;
    IVerifier t10Verifier;
    ShadowToken st;
    FeatureNFT fn;

    address alice = address(0xA11CE);

    function setUp() public {
        mintProof = vm.readFileBinary("test/fixtures/mint_shadow/alice0/proof");
        mintPi    = _readFieldArray("test/fixtures/mint_shadow/alice0/public_inputs");
        mintC2    = vm.readFileBinary("test/fixtures/mint_shadow/alice0/c2.bin");
        mintProofDisc = vm.readFileBinary("test/fixtures/face_disc/alice0/proof");

        t10Proof = vm.readFileBinary("test/fixtures/shadow_t10/step_00/proof");
        t10Pi    = _readFieldArray("test/fixtures/shadow_t10/step_00/public_inputs");

        require(mintPi.length == 18, "mint PI must be 18");
        require(mintC2.length == 7968, "c2 must be 7968 bytes");
        require(t10Pi.length == 9, "t10 PI must be 9");

        mintVerifier = IVerifier(deployCode("MintShadowVerifier.sol:MintShadowVerifier"));
        t10Verifier  = IVerifier(deployCode("T10ShadowVerifier.sol:T10ShadowVerifier"));
        IVerifier discVerifier = IVerifier(deployCode("FaceDiscVerifier.sol:FaceDiscVerifier"));

        Poseidon2YulSponge sponge = new Poseidon2YulSponge();
        st = new ShadowToken(address(sponge));
        fn = new FeatureNFT(address(st), address(sponge));

        st.setFeatureNFT(fn);
        st.setMintShadowVerifier(mintVerifier);
        st.setT10ShadowVerifier(t10Verifier);
        st.setFaceDiscVerifier(discVerifier);
    }

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

    function _mintAlice() internal returns (uint256 shadowId) {
        vm.prank(alice);
        shadowId = st.mintShadow(mintProof, mintPi, mintC2, mintProofDisc);
    }

    // ---------- tests ----------

    function test_RawT10VerifierAcceptsFixture() public view {
        bool ok = t10Verifier.verify(t10Proof, t10Pi);
        assertTrue(ok, "raw verifier rejected canonical T10 fixture");
    }

    function test_SetT10_Succeeds_StoresQuartets() public {
        uint256 sid = _mintAlice();
        assertEq(st.stateNonce(sid), 0, "fresh mint has state_nonce = 0");
        assertEq(uint256(t10Pi[0]), sid, "PI[0] == shadowId");

        st.setShadowT10(sid, t10Proof, t10Pi);

        // Verify shadowT10 was stored.
        bytes32 hi = st.shadowT10(sid, 0);
        bytes32 lo = st.shadowT10(sid, 1);
        // hi = q0 | (q1 << 128); lo = q2 | (q3 << 128)
        uint256 q0 = uint256(t10Pi[5]); uint256 q1 = uint256(t10Pi[6]);
        uint256 q2 = uint256(t10Pi[7]); uint256 q3 = uint256(t10Pi[8]);
        assertEq(uint256(hi), q0 | (q1 << 128), "hi packing");
        assertEq(uint256(lo), q2 | (q3 << 128), "lo packing");

        // setShadowT10 does not bump state_nonce.
        assertEq(st.stateNonce(sid), 0, "T10 set does not bump nonce");
    }

    function test_SetT10_EmitsEvent() public {
        uint256 sid = _mintAlice();
        uint256 q0 = uint256(t10Pi[5]); uint256 q1 = uint256(t10Pi[6]);
        uint256 q2 = uint256(t10Pi[7]); uint256 q3 = uint256(t10Pi[8]);
        bytes32 expectedHi = bytes32(q0 | (q1 << 128));
        bytes32 expectedLo = bytes32(q2 | (q3 << 128));

        vm.expectEmit(true, true, true, true);
        emit ShadowToken.ShadowT10Updated(sid, 0, expectedHi, expectedLo);
        st.setShadowT10(sid, t10Proof, t10Pi);
    }

    function test_SetT10_PermissionlessCaller() public {
        uint256 sid = _mintAlice();
        // Call from a non-owner address: still allowed (T10 is permissionless).
        address bob = address(0xB0B);
        vm.prank(bob);
        st.setShadowT10(sid, t10Proof, t10Pi);
        assertTrue(st.shadowT10(sid, 0) != bytes32(0), "T10 stored");
    }

    function test_SetT10_RevertsOnUnknownShadow() public {
        // Don't mint -- shadow doesn't exist.
        uint256 fakeId = uint256(t10Pi[0]);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.setShadowT10(fakeId, t10Proof, t10Pi);
    }

    function test_SetT10_RevertsOnTamperedNonce() public {
        uint256 sid = _mintAlice();
        bytes32[] memory tampered = new bytes32[](9);
        for (uint256 i = 0; i < 9; i++) tampered[i] = t10Pi[i];
        tampered[1] = bytes32(uint256(1)); // wrong nonce -- chain has nonce 0

        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.setShadowT10(sid, t10Proof, tampered);
    }

    function test_SetT10_RevertsOnTamperedProof() public {
        uint256 sid = _mintAlice();
        bytes memory tampered = t10Proof;
        tampered[100] = bytes1(uint8(tampered[100]) ^ 0x01);

        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.setShadowT10(sid, tampered, t10Pi);
    }

    function test_SetT10_RevertsOnTamperedCtCommit() public {
        uint256 sid = _mintAlice();
        bytes32[] memory tampered = new bytes32[](9);
        for (uint256 i = 0; i < 9; i++) tampered[i] = t10Pi[i];
        tampered[2] = bytes32(uint256(tampered[2]) ^ 1); // tweak ct_commit

        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.setShadowT10(sid, t10Proof, tampered);
    }

    function test_SetT10_RevertsOnBadPILen() public {
        uint256 sid = _mintAlice();
        bytes32[] memory shortPi = new bytes32[](8);
        for (uint256 i = 0; i < 8; i++) shortPi[i] = t10Pi[i];

        vm.expectRevert(abi.encodeWithSelector(ShadowToken.BadPILen.selector, 8, 9));
        st.setShadowT10(sid, t10Proof, shortPi);
    }

    function test_SetT10_RevertsWithoutVerifierSet() public {
        // Fresh deploy without setT10ShadowVerifier.
        Poseidon2YulSponge sponge = new Poseidon2YulSponge();
        ShadowToken stFresh = new ShadowToken(address(sponge));
        new FeatureNFT(address(stFresh), address(sponge));
        stFresh.setMintShadowVerifier(mintVerifier);
        stFresh.setFaceDiscVerifier(IVerifier(deployCode("FaceDiscVerifier.sol:FaceDiscVerifier")));
        // setT10ShadowVerifier deliberately NOT called.

        vm.prank(alice);
        uint256 sid = stFresh.mintShadow(mintProof, mintPi, mintC2, mintProofDisc);

        vm.expectRevert(ShadowToken.VerifierNotSet.selector);
        stFresh.setShadowT10(sid, t10Proof, t10Pi);
    }

    function test_SetT10_RevertsAfterMutate_StaleNonce() public {
        uint256 sid = _mintAlice();

        // First mutation bumps nonce 0 -> 1. The step_00 fixture binds
        // to nonce=0, which is now stale.
        // Use slot 4 (jaw L) -- REGION_W/H = 14/19 admits the existing mint pose.
        ShadowToken.ManifestEntry memory m4 = st.slotOf(sid, 4);
        vm.prank(alice);
        st.mutateSlot(sid, 4, m4.pose); // pose unchanged but nonce bumps
        assertEq(st.stateNonce(sid), 1, "mutate bumped nonce to 1");

        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.setShadowT10(sid, t10Proof, t10Pi);
    }
}
