// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {TestableShadowToken} from "./Testable.sol";

/// @notice transferShadow is intentionally disabled. Shadow NFTs may move only
/// when no features are bound to any slot; then normal ERC-721 transfer is used.
/// Generated transfer verifier assurance remains in GeneratedVerifierMatrix.t.sol.
contract TransferShadowE2ETest is Test {
    TestableShadowToken internal st;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    function setUp() public {
        st = new TestableShadowToken(address(new Poseidon2YulSponge()));
    }

    function test_transferShadow_reverts_for_owner_with_bound_feature() public {
        uint256 shadowId = 0xA11CE;
        st.seedShadowAndSlot(
            shadowId,
            alice,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            0,
            0xF00D,
            bytes32(uint256(3))
        );

        ShadowToken.TransferShadowArgs memory args;
        args.shadowId = shadowId;
        args.to = bob;
        args.c2s = new bytes[](16);

        vm.prank(alice);
        vm.expectRevert(ShadowToken.TransferGated.selector);
        st.transferShadow(args);

        assertEq(st.ownerOf(shadowId), alice, "owner unchanged");
    }

    function test_transferShadow_still_rejects_non_owner_first() public {
        uint256 shadowId = 0xB0B;
        st.seedShadowAndSlot(
            shadowId,
            alice,
            bytes32(uint256(11)),
            bytes32(uint256(12)),
            0,
            0xF00E,
            bytes32(uint256(13))
        );

        ShadowToken.TransferShadowArgs memory args;
        args.shadowId = shadowId;
        args.to = bob;
        args.c2s = new bytes[](16);

        vm.prank(bob);
        vm.expectRevert(ShadowToken.NotShadowOwner.selector);
        st.transferShadow(args);

        assertEq(st.ownerOf(shadowId), alice, "owner unchanged");
    }
}
