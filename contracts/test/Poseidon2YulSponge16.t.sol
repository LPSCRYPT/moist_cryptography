// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {Poseidon2YulSponge16} from "../src/Poseidon2YulSponge16.sol";

/// @notice Byte-equal cross-check between the Yul sponge_16 contract and the
/// reference Python implementation in `tools/v2_circuit_helpers.py`.
contract Poseidon2YulSponge16Test is Test {
    Poseidon2YulSponge16 internal sponge;

    function setUp() public {
        sponge = new Poseidon2YulSponge16();
    }

    function test_sponge16_matches_python_reference() public view {
        bytes memory input = new bytes(512);
        for (uint256 i = 0; i < 16; i++) {
            uint256 v = (i + 1) * 0x12345678abcdef01;
            // Big-endian 32 bytes.
            for (uint256 b = 0; b < 32; b++) {
                input[i * 32 + b] = bytes1(uint8(v >> (8 * (31 - b))));
            }
        }
        (bool ok, bytes memory ret) = address(sponge).staticcall(input);
        assertTrue(ok, "sponge16 staticcall failed");
        assertEq(ret.length, 32);
        bytes32 result;
        assembly { result := mload(add(ret, 32)) }
        // Reference value computed by tools/v2_circuit_helpers.py::sponge_16
        // over [(i+1) * 0x12345678abcdef01 for i in range(16)].
        assertEq(result, bytes32(uint256(0x1a6d6f967eb33d37443fe3cb7eb3e3343268bb3603613f800da2e256b256e471)));
    }

    function test_sponge16_rejects_wrong_size() public {
        bytes memory input = new bytes(480); // 15 fields, not 16
        (bool ok,) = address(sponge).staticcall(input);
        assertFalse(ok, "sponge16 should reject non-512-byte calldata");
    }

    function test_sponge16_zeros_deterministic() public view {
        bytes memory input = new bytes(512); // all zeros
        (bool ok, bytes memory ret) = address(sponge).staticcall(input);
        assertTrue(ok);
        bytes32 result;
        assembly { result := mload(add(ret, 32)) }
        // sponge_16([0; 16]) is deterministic; just assert it's nonzero
        // (it's the sentinel-padded permutation of an all-zero state).
        assertTrue(result != bytes32(0), "sponge16([0;16]) should be nonzero (sentinel + perm)");
    }
}
