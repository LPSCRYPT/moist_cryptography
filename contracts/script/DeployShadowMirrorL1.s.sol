// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {ShadowMirrorL1} from "../src/ShadowMirrorL1.sol";

/// Deploys ShadowMirrorL1 on Ethereum Sepolia. The L1 messenger address is
/// the L1CrossDomainMessenger proxy for Base Sepolia, deployed at a known
/// fixed address per Base's published deployments.
contract DeployShadowMirrorL1 is Script {
    /// L1CrossDomainMessenger proxy for Base Sepolia (deployed on Eth Sepolia).
    /// Source: https://docs.base.org/base-chain/network-information/base-contracts
    address public constant L1_MESSENGER = 0xC34855F4De64F1840e5686e64278da901e261f20;

    function run() external {
        vm.startBroadcast();
        ShadowMirrorL1 mirror = new ShadowMirrorL1(L1_MESSENGER);
        console.log("ShadowMirrorL1:", address(mirror));
        vm.stopBroadcast();
    }
}
