// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {ShadowBridgeL2} from "../src/ShadowBridgeL2.sol";

/// Initiate L2->L1 bridgeShadow on Base Sepolia.
///
/// Pre-conditions (verified at runtime; will revert loud rather than silent):
///   - msg.sender == ShadowToken.ownerOf(shadowId)
///   - ShadowToken.isSolved(shadowId)
///   - L2 bridge has L1 mirror set
///   - L2 bridge has approval to transfer the shadow (requires the owner
///     to have called setApprovalForAll(bridge, true) OR approve(bridge,
///     shadowId)).
///
/// Run:
///   ST_ADDRESS=0x... L2_BRIDGE=0x... \
///   SHADOW_ID=0x... PI_PATH=./test/fixtures/.../public_inputs.bin \
///     forge script script/BridgeShadowOnSepolia.s.sol:BridgeShadowOnSepolia \
///       --rpc-url $BASE_SEPOLIA_RPC --broadcast \
///       --gas-estimate-multiplier 130 \
///       --sender $DEPLOYER_ADDRESS --private-key $PRIVATE_KEY
contract BridgeShadowOnSepolia is Script {
    function run() external {
        address stAddr  = vm.envAddress("ST_ADDRESS");
        address brAddr  = vm.envAddress("L2_BRIDGE");
        uint256 shadowId = uint256(vm.envBytes32("SHADOW_ID"));
        bytes memory revealedPi = vm.readFileBinary(vm.envString("PI_PATH"));
        // L1 mirror recipient. Falls back to msg.sender if not set, which
        // preserves pre-audit behaviour for EOA-controlled flows.
        address l1Recipient = vm.envOr("L1_RECIPIENT", msg.sender);

        require(revealedPi.length > 0 && revealedPi.length % 32 == 0,
            "revealedPi must be non-empty + multiple of 32");

        ShadowBridgeL2 br = ShadowBridgeL2(brAddr);
        ShadowToken    st = ShadowToken(stAddr);

        require(br.l1Mirror() != address(0), "L2 bridge: l1Mirror not set");
        require(st.isSolved(shadowId), "shadow not solved");

        console.log("=== bridgeShadow ===");
        console.log("ST       :", stAddr);
        console.log("L2 bridge:", brAddr);
        console.log("L1 mirror:", br.l1Mirror());
        console.log("shadowId :");
        console.logBytes32(bytes32(shadowId));
        console.log("revealed PI bytes:", revealedPi.length);

        vm.startBroadcast();

        // Approve bridge to take custody if not already.
        if (st.getApproved(shadowId) != brAddr && !st.isApprovedForAll(msg.sender, brAddr)) {
            st.approve(brAddr, shadowId);
            console.log("approved bridge for shadow");
        }

        br.bridgeShadow(shadowId, l1Recipient, revealedPi);

        vm.stopBroadcast();

        // Post: bridge now owns the shadow on L2.
        require(st.ownerOf(shadowId) == brAddr, "post: bridge should own shadow on L2");
        console.log("post-state: shadow now held by bridge on L2");
        console.log("L1 finalize requires: 1hr output proposal -> proveWithdrawal -> 7d -> finalize");
    }
}
