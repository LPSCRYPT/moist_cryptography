// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Poseidon2YulSpongePaletteSalt} from "../src/Poseidon2YulSpongePaletteSalt.sol";

/// @notice Confirms the 11-input Yul palette sponge is byte-equivalent to
///         Python helper `sponge_palette_salt`.
///
///         Test fixture: contracts/test/fixtures/onchain_palette_reveal/
///                       palette_reveal_demo  (palette[10], salt, commit).
contract Poseidon2YulSpongePaletteSaltTest is Test {
    using stdJson for string;

    string internal constant FIX = "./test/fixtures/onchain_palette_reveal/palette_reveal_demo";

    Poseidon2YulSpongePaletteSalt internal sponge;

    function setUp() public {
        sponge = new Poseidon2YulSpongePaletteSalt();
    }

    function test_sponge11_matches_python_helper() public {
        string memory j = vm.readFile(string.concat(FIX, "/meta.json"));
        bytes32[10] memory palette;
        for (uint256 i = 0; i < 10; i++) {
            palette[i] = j.readBytes32(string.concat(".palette[", vm.toString(i), "]"));
        }
        bytes32 salt = j.readBytes32(".palette_salt");
        bytes32 expected = j.readBytes32(".palette_commit");

        // Pack 11 fields = 352 bytes calldata.
        bytes memory buf = new bytes(11 * 32);
        for (uint256 i = 0; i < 10; i++) {
            bytes32 v = palette[i];
            assembly { mstore(add(add(buf, 32), mul(i, 32)), v) }
        }
        assembly { mstore(add(add(buf, 32), mul(10, 32)), salt) }

        (bool ok, bytes memory ret) = address(sponge).staticcall(buf);
        require(ok, "sponge call reverted");
        require(ret.length == 32, "sponge return wrong length");
        bytes32 got;
        assembly { got := mload(add(ret, 32)) }

        assertEq(got, expected, "sponge_11 != Python sponge_palette_salt");
    }

    function test_sponge11_rejects_non_352_calldata() public {
        // 320 bytes (one field short) -> reject
        bytes memory buf = new bytes(320);
        (bool ok,) = address(sponge).staticcall(buf);
        assertFalse(ok, "should revert on 320-byte input");

        // 384 bytes (one-too-many) -> reject
        buf = new bytes(384);
        (ok,) = address(sponge).staticcall(buf);
        assertFalse(ok, "should revert on 384-byte input");

        // 352 bytes (correct size) -> ok (returns whatever, but doesn't revert)
        buf = new bytes(352);
        (ok,) = address(sponge).staticcall(buf);
        assertTrue(ok, "352-byte input should not revert");
    }
}
