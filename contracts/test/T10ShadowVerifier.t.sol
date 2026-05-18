// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {T10ShadowVerifier} from "../src/T10ShadowVerifier.sol";

/// @notice Real-proof verifier round-trip for the v2 shadow_t10 circuit.
contract T10ShadowVerifierTest is Test {
    T10ShadowVerifier internal v;
    bytes internal proof;
    bytes32[] internal pi;

    string internal constant PROOF_PATH = "./test/fixtures/shadow_t10/t10_demo/proof.bin";
    string internal constant PI_PATH = "./test/fixtures/shadow_t10/t10_demo/public_inputs.bin";
    // shadow_id, z_commit, t10_hi, t10_lo, 16 x liveStateHash = 20 fields.
    uint256 internal constant EXPECTED_PI_LEN = 20;

    function setUp() public {
        v = new T10ShadowVerifier();
        proof = vm.readFileBinary(PROOF_PATH);
        bytes memory piRaw = vm.readFileBinary(PI_PATH);
        require(piRaw.length == EXPECTED_PI_LEN * 32, "PI fixture length mismatch (regenerate?)");

        pi = new bytes32[](EXPECTED_PI_LEN);
        for (uint256 i = 0; i < EXPECTED_PI_LEN; i++) {
            bytes32 word;
            assembly { word := mload(add(piRaw, add(0x20, mul(i, 32)))) }
            pi[i] = word;
        }
    }

    function test_verify_accepts_real_proof() public view {
        bool ok = v.verify(proof, pi);
        assertTrue(ok, "verifier rejected a valid t10 proof");
    }

    function test_verify_rejects_tampered_t10_hi() public {
        bytes32[] memory corrupted = new bytes32[](EXPECTED_PI_LEN);
        for (uint256 i = 0; i < EXPECTED_PI_LEN; i++) {
            corrupted[i] = pi[i];
        }
        corrupted[2] = bytes32(uint256(corrupted[2]) ^ 1); // PI[2] = t10_hi

        try v.verify(proof, corrupted) returns (bool ok) {
            assertFalse(ok, "verifier accepted a tampered t10_hi");
        } catch {}
    }

    function test_verify_rejects_tampered_lsh() public {
        // Flip a bit in liveStateHash[0] (PI[4]).
        bytes32[] memory corrupted = new bytes32[](EXPECTED_PI_LEN);
        for (uint256 i = 0; i < EXPECTED_PI_LEN; i++) {
            corrupted[i] = pi[i];
        }
        corrupted[4] = bytes32(uint256(corrupted[4]) ^ uint256(1) << 32);

        try v.verify(proof, corrupted) returns (bool ok) {
            assertFalse(ok, "verifier accepted a tampered liveStateHash[0]");
        } catch {}
    }
}
