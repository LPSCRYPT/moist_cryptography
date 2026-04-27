// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {IShadowToken} from "../src/IShadowToken.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";
import {ShadowBridgeL2} from "../src/ShadowBridgeL2.sol";

/// Deploys ShadowBridgeL2 on Base Sepolia. Reads the existing ShadowToken
/// and FeatureNFT addresses from env.
contract DeployShadowBridgeL2 is Script {
    function run() external {
        address shadowToken = vm.envAddress("SHADOW_TOKEN");
        address featureNft  = vm.envAddress("FEATURE_NFT");
        require(shadowToken != address(0), "SHADOW_TOKEN env required");
        require(featureNft  != address(0), "FEATURE_NFT env required");
        vm.startBroadcast();
        ShadowBridgeL2 bridge = new ShadowBridgeL2(
            IShadowToken(shadowToken),
            IFeatureNFT(featureNft)
        );
        console.log("ShadowBridgeL2:", address(bridge));
        vm.stopBroadcast();
    }
}