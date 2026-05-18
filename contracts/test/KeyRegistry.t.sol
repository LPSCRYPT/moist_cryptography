// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import {KeyRegistry} from "../src/KeyRegistry.sol";

contract KeyRegistryTest is Test {
    KeyRegistry r;

    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    bytes32 alicePkX = bytes32(uint256(0x1111111111111111111111111111111111111111111111111111111111111111));
    bytes32 alicePkY = bytes32(uint256(0x2222222222222222222222222222222222222222222222222222222222222222));
    bytes32 bobPkX = bytes32(uint256(0x3333333333333333333333333333333333333333333333333333333333333333));
    bytes32 bobPkY = bytes32(uint256(0x4444444444444444444444444444444444444444444444444444444444444444));

    function setUp() public {
        r = new KeyRegistry();
    }

    function test_Register_Succeeds() public {
        vm.prank(alice);
        r.register(alicePkX, alicePkY);
        (bytes32 x, bytes32 y) = r.pkOf(alice);
        assertEq(x, alicePkX);
        assertEq(y, alicePkY);
        assertTrue(r.isRegistered(alice));
    }

    function test_Register_RevertsOnDoubleRegister() public {
        vm.prank(alice);
        r.register(alicePkX, alicePkY);

        vm.prank(alice);
        vm.expectRevert(KeyRegistry.AlreadyRegistered.selector);
        r.register(bobPkX, bobPkY);
    }

    function test_TwoActorsHaveIndependentBindings() public {
        vm.prank(alice);
        r.register(alicePkX, alicePkY);
        vm.prank(bob);
        r.register(bobPkX, bobPkY);

        (bytes32 ax, bytes32 ay) = r.pkOf(alice);
        (bytes32 bx, bytes32 by) = r.pkOf(bob);
        assertEq(ax, alicePkX);
        assertEq(ay, alicePkY);
        assertEq(bx, bobPkX);
        assertEq(by, bobPkY);
    }

    function test_PkOf_Reverts_WhenNotRegistered() public {
        vm.expectRevert(abi.encodeWithSelector(KeyRegistry.NotRegistered.selector, alice));
        r.pkOf(alice);
    }

    function test_IsRegistered_FalseUntilRegister() public {
        assertFalse(r.isRegistered(alice));
        vm.prank(alice);
        r.register(alicePkX, alicePkY);
        assertTrue(r.isRegistered(alice));
    }

    /// Audit M-04: (0, 0) is documented as the unregistered sentinel, but
    /// the pre-fix `register` accepted it. That violated the one-shot
    /// immutability claim (an attacker could emit Registered(0,0) then
    /// later register a different pk because `pkX|pkY != 0` checks failed).
    function test_Register_RevertsOnZeroSentinel() public {
        vm.prank(alice);
        vm.expectRevert(KeyRegistry.InvalidPk.selector);
        r.register(bytes32(0), bytes32(0));
        assertFalse(r.isRegistered(alice));
    }

    /// (0, x) and (x, 0) are NOT the sentinel and ARE still allowed -- only
    /// the all-zero pair is rejected. This documents the chosen invariant.
    function test_Register_AllowsPartialZero() public {
        vm.prank(alice);
        r.register(bytes32(0), alicePkY);
        assertTrue(r.isRegistered(alice));
    }
}
