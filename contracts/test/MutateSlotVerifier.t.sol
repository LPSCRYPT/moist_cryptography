// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {MutateSlotVerifier} from "../src/MutateSlotVerifier.sol";

/// @notice Real-proof verifier round-trip for the v2 mutate_slot circuit.
///
/// Loads the proof + public_inputs blobs produced by
/// `tools/build_mutate_slot_fixture.py --seed mutate_demo_v2`. Asserts:
///   1. the verifier accepts the proof + PI as-is (positive)
///   2. flipping any bit in PI causes verification to revert/return false (negative)
///
/// The proof is bb's UltraHonk(keccak) format; matches the verifier emitted
/// by `bb write_solidity_verifier --verifier_target evm`.
contract MutateSlotVerifierTest is Test {
    MutateSlotVerifier internal v;

    bytes internal proof;
    bytes32[] internal pi;

    string internal constant PROOF_PATH = "./test/fixtures/mutate_slot/mutate_demo_v2/proof.bin";
    string internal constant PI_PATH    = "./test/fixtures/mutate_slot/mutate_demo_v2/public_inputs.bin";

    uint256 internal constant EXPECTED_PI_LEN = 16;

    function setUp() public {
        v = new MutateSlotVerifier();

        proof = vm.readFileBinary(PROOF_PATH);
        bytes memory piRaw = vm.readFileBinary(PI_PATH);
        require(piRaw.length == EXPECTED_PI_LEN * 32,
            "PI fixture length mismatch (regenerate?)");

        pi = new bytes32[](EXPECTED_PI_LEN);
        for (uint256 i = 0; i < EXPECTED_PI_LEN; i++) {
            bytes32 word;
            assembly {
                word := mload(add(piRaw, add(0x20, mul(i, 32))))
            }
            pi[i] = word;
        }
    }

    function test_verify_accepts_real_proof() public view {
        bool ok = v.verify(proof, pi);
        assertTrue(ok, "verifier rejected a valid proof");
    }

    function test_verify_rejects_corrupted_pi_owner_pk() public {
        // Corrupting PI[10] (owner_pk_x) breaks the binding asserted in-circuit.
        bytes32[] memory corrupted = new bytes32[](EXPECTED_PI_LEN);
        for (uint256 i = 0; i < EXPECTED_PI_LEN; i++) corrupted[i] = pi[i];
        corrupted[10] = bytes32(uint256(corrupted[10]) ^ 1);

        // Verifier may revert OR return false; either is acceptable rejection.
        try v.verify(proof, corrupted) returns (bool ok) {
            assertFalse(ok, "verifier accepted a tampered owner_pk_x");
        } catch {
            // Reverted is also a valid rejection signal.
        }
    }

    function test_verify_rejects_corrupted_pi_new_lsh() public {
        // Corrupting PI[7] (new_live_state_hash) is the most direct chain-state lie.
        bytes32[] memory corrupted = new bytes32[](EXPECTED_PI_LEN);
        for (uint256 i = 0; i < EXPECTED_PI_LEN; i++) corrupted[i] = pi[i];
        corrupted[7] = bytes32(uint256(corrupted[7]) ^ uint256(1) << 8);

        try v.verify(proof, corrupted) returns (bool ok) {
            assertFalse(ok, "verifier accepted a tampered new_live_state_hash");
        } catch {
            // ok
        }
    }

    function test_verify_rejects_corrupted_proof() public {
        // Flip a bit deep in the proof body.
        bytes memory tampered = bytes.concat(proof);
        // Mid-proof flip; offset 1024 picked to land outside structural
        // headers and inside actual coefficients.
        tampered[1024] = bytes1(uint8(tampered[1024]) ^ 0x40);

        try v.verify(tampered, pi) returns (bool ok) {
            assertFalse(ok, "verifier accepted a tampered proof");
        } catch {
            // ok
        }
    }
}
