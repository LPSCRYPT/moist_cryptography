// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {IShadowToken} from "../src/IShadowToken.sol";
import {ShadowBridgeL2} from "../src/ShadowBridgeL2.sol";

/// Deploys ShadowBridgeL2 on Base Sepolia. Reads the existing ShadowToken
/// address from the SHADOW_TOKEN env var.
contract DeployShadowBridgeL2 is Script {
    function run() external {
        address shadowToken = vm.envAddress("SHADOW_TOKEN");
        require(shadowToken != address(0), "SHADOW_TOKEN env required");
        vm.startBroadcast();
        ShadowBridgeL2 bridge = new ShadowBridgeL2(IShadowToken(shadowToken));
        console.log("ShadowBridgeL2:", address(bridge));
        vm.stopBroadcast();
    }
}
