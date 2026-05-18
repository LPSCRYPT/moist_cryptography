// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ZIndexCommitVerifier} from "../src/ZIndexCommitVerifier.sol";

/// @notice Real-proof verifier round-trip for the v2 zindex_commit circuit.
///
/// Loads the proof + public_inputs blobs produced by
/// `tools/build_zindex_commit_fixture.py --seed zidx_demo`. Asserts the
/// verifier accepts a valid proof and rejects PI / proof tampering.
contract ZIndexCommitVerifierTest is Test {
    ZIndexCommitVerifier internal v;
    bytes internal proof;
    bytes32[] internal pi;

    string internal constant PROOF_PATH = "./test/fixtures/zindex_commit/zidx_demo/proof.bin";
    string internal constant PI_PATH = "./test/fixtures/zindex_commit/zidx_demo/public_inputs.bin";
    uint256 internal constant EXPECTED_PI_LEN = 2;

    function setUp() public {
        v = new ZIndexCommitVerifier();
        proof = vm.readFileBinary(PROOF_PATH);
        bytes memory piRaw = vm.readFileBinary(PI_PATH);
        require(piRaw.length == EXPECTED_PI_LEN * 32, "PI fixture length mismatch");

        pi = new bytes32[](EXPECTED_PI_LEN);
        for (uint256 i = 0; i < EXPECTED_PI_LEN; i++) {
            bytes32 word;
            assembly { word := mload(add(piRaw, add(0x20, mul(i, 32)))) }
            pi[i] = word;
        }
    }

    function test_verify_accepts_real_proof() public view {
        bool ok = v.verify(proof, pi);
        assertTrue(ok, "verifier rejected a valid permutation proof");
    }

    function test_verify_rejects_tampered_z_commit() public {
        bytes32[] memory corrupted = new bytes32[](EXPECTED_PI_LEN);
        for (uint256 i = 0; i < EXPECTED_PI_LEN; i++) {
            corrupted[i] = pi[i];
        }
        corrupted[1] = bytes32(uint256(corrupted[1]) ^ 1);

        try v.verify(proof, corrupted) returns (bool ok) {
            assertFalse(ok, "verifier accepted a tampered z_commit");
        } catch {}
    }

    function test_verify_rejects_tampered_proof() public {
        bytes memory tampered = bytes.concat(proof);
        tampered[256] = bytes1(uint8(tampered[256]) ^ 0x40);

        try v.verify(tampered, pi) returns (bool ok) {
            assertFalse(ok, "verifier accepted a tampered proof");
        } catch {}
    }
}
