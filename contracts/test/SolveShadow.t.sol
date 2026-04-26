// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";

import {IVerifier} from "../src/IVerifier.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";

contract SolveShadowTest is Test {
    bytes mintProof;
    bytes32[] mintPi;
    bytes mintC2;
    bytes mintProofDisc;

    bytes solveProof;
    bytes32[] solvePi;

    IVerifier mintVerifier;
    IVerifier solveVerifier;
    ShadowToken st;
    FeatureNFT fn;

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

        require(mintPi.length == 18 && solvePi.length == 261);

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

    function test_RawSolveVerifierAcceptsFixture() public view {
        bool ok = solveVerifier.verify(solveProof, solvePi);
        assertTrue(ok, "raw solve verifier rejected fixture");
    }

    function test_SolvePiBindsToStateCommitsHash() public view {
        // PI[0..7] are stateCommits; check they match alice's mint PI[0..7].
        for (uint256 i = 0; i < 8; i++) {
            assertEq(solvePi[i], mintPi[i], "solve PI[i] == mint PI[i]");
        }
        // PI[8] is the presence byte (0xff = all 8 slots bound).
        assertEq(solvePi[8], bytes32(uint256(0xff)), "PI[8] = presence_byte");
    }

    function test_Solve_Succeeds_AndMarksSolved() public {
        assertFalse(st.solved(sid), "not solved pre-solve");

        vm.prank(alice);
        st.solve(sid, solveProof, solvePi);

        assertTrue(st.solved(sid), "solved");
    }

    function test_Solve_RevertsOnAlreadySolved() public {
        vm.prank(alice);
        st.solve(sid, solveProof, solvePi);

        vm.prank(alice);
        vm.expectRevert(ShadowToken.AlreadySolved.selector);
        st.solve(sid, solveProof, solvePi);
    }

    function test_Solve_RevertsOnNonOwner() public {
        vm.prank(bob);
        vm.expectRevert(ShadowToken.NotShadowOwner.selector);
        st.solve(sid, solveProof, solvePi);
    }

    function test_Solve_RevertsOnWrongFaceOrigin() public {
        // Tweak PI[8] so it doesn't match chain.faceOriginId.
        bytes32[] memory tampered = new bytes32[](261);
        for (uint256 i = 0; i < 261; i++) tampered[i] = solvePi[i];
        tampered[8] = bytes32(uint256(tampered[8]) ^ 1);

        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.solve(sid, solveProof, tampered);
    }

    function test_Solve_RevertsOnTamperedProof() public {
        bytes memory tampered = solveProof;
        tampered[100] = bytes1(uint8(tampered[100]) ^ 0x01);

        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.solve(sid, tampered, solvePi);
    }

    function test_Solve_RevertsOnBadPILen() public {
        bytes32[] memory shortPi = new bytes32[](260);
        for (uint256 i = 0; i < 260; i++) shortPi[i] = solvePi[i];

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.BadPILen.selector, 260, 261));
        st.solve(sid, solveProof, shortPi);
    }

    function test_Solve_AllowsTransferFrom_PostSolve() public {
        vm.prank(alice);
        st.solve(sid, solveProof, solvePi);

        // After solve, transferFrom should be unlocked.
        vm.prank(alice);
        st.transferFrom(alice, bob, sid);
        assertEq(st.ownerOf(sid), bob, "post-solve transfer succeeds");
    }
}
