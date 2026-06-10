// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {TestableShadowToken} from "./Testable.sol";

/// @notice Max-occupancy transfer is intentionally disabled: any bound feature
/// makes the Shadow NFT non-transferable. This replaces the former high-water
/// transferShadow gas test because the protocol no longer supports that path.
contract TransferShadowMaxOccupancyTest is Test {
    TestableShadowToken internal st;
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    function setUp() public {
        st = new TestableShadowToken(address(new Poseidon2YulSponge()));
        uint8[] memory slots = new uint8[](16);
        uint256[] memory featureIds = new uint256[](16);
        bytes32[] memory lshs = new bytes32[](16);
        for (uint256 i = 0; i < 16; i++) {
            slots[i] = uint8(i);
            featureIds[i] = 10_000 + i;
            lshs[i] = bytes32(uint256(20_000 + i));
        }
        st.seedShadowMultiSlot(0x5150, alice, bytes32(uint256(1)), bytes32(uint256(2)), slots, featureIds, lshs);
    }

    function test_transferFrom_max_occupancy_reverts() public {
        vm.prank(alice);
        vm.expectRevert(ShadowToken.TransferGated.selector);
        st.transferFrom(alice, bob, 0x5150);
        assertEq(st.ownerOf(0x5150), alice);
    }

    function test_transferShadow_max_occupancy_reverts_before_proof_work() public {
        ShadowToken.TransferShadowArgs memory args;
        args.shadowId = 0x5150;
        args.to = bob;
        args.c2s = new bytes[](16);

        vm.prank(alice);
        vm.expectRevert(ShadowToken.TransferGated.selector);
        st.transferShadow(args);
        assertEq(st.ownerOf(0x5150), alice);
    }
}
