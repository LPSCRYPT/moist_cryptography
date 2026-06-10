// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {TestableShadowToken} from "./Testable.sol";

contract ShadowTransferLockdownTest is Test {
    TestableShadowToken internal st;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    function setUp() public {
        st = new TestableShadowToken(address(new Poseidon2YulSponge()));
    }

    function test_plain_transfer_allowed_when_shadow_has_no_bound_features() public {
        uint256 shadowId = 1;
        st.seedShadowOnly(shadowId, alice, bytes32(uint256(11)), bytes32(uint256(12)));

        vm.prank(alice);
        st.transferFrom(alice, bob, shadowId);

        assertEq(st.ownerOf(shadowId), bob, "featureless shadow transfers normally");
    }

    function test_plain_transfer_reverts_when_shadow_has_occupied_feature() public {
        uint256 shadowId = 2;
        st.seedShadowAndSlot(
            shadowId,
            alice,
            bytes32(uint256(21)),
            bytes32(uint256(22)),
            0,
            1001,
            bytes32(uint256(23))
        );

        vm.prank(alice);
        vm.expectRevert(ShadowToken.TransferGated.selector);
        st.transferFrom(alice, bob, shadowId);

        assertEq(st.ownerOf(shadowId), alice, "bounded shadow owner unchanged");
    }

    function test_safe_transfer_reverts_when_shadow_has_occupied_feature() public {
        uint256 shadowId = 3;
        st.seedShadowAndSlot(
            shadowId,
            alice,
            bytes32(uint256(31)),
            bytes32(uint256(32)),
            0,
            1002,
            bytes32(uint256(33))
        );

        vm.prank(alice);
        vm.expectRevert(ShadowToken.TransferGated.selector);
        st.safeTransferFrom(alice, bob, shadowId, "");

        assertEq(st.ownerOf(shadowId), alice, "bounded shadow owner unchanged");
    }

    function test_transferShadow_entrypoint_is_disabled_for_bounded_shadow() public {
        uint256 shadowId = 4;
        st.seedShadowAndSlot(
            shadowId,
            alice,
            bytes32(uint256(41)),
            bytes32(uint256(42)),
            0,
            1003,
            bytes32(uint256(43))
        );

        ShadowToken.TransferShadowArgs memory args;
        args.shadowId = shadowId;
        args.to = bob;
        args.c2s = new bytes[](16);

        vm.prank(alice);
        vm.expectRevert(ShadowToken.TransferGated.selector);
        st.transferShadow(args);

        assertEq(st.ownerOf(shadowId), alice, "proof-transfer path disabled");
    }
}
