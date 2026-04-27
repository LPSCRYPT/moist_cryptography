// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {TransferFeatureV2Verifier} from "../src/TransferFeatureV2Verifier.sol";

/// Deploy the v2 transferFeature verifier and one-shot wire it into the
/// already-live FeatureNFT.
///
/// Pre-conditions checked at runtime:
///   - msg.sender == FeatureNFT.deployer()
///   - FeatureNFT.transferFeatureVerifier() == address(0)
///     (the lock is engaged on first set; if already set this reverts
///      VerifierAlreadySet — fail loud instead of silently rotating.)
///
/// Usage:
///   forge script script/DeployTransferFeatureV2.s.sol:DeployTransferFeatureV2 \
///     --rpc-url $BASE_SEPOLIA_RPC --broadcast \
///     --gas-estimate-multiplier 150 \
///     --sender $DEPLOYER_ADDRESS --private-key $PRIVATE_KEY
contract DeployTransferFeatureV2 is Script {
    /// FeatureNFT on Base Sepolia (deployment #3 from DEPLOYMENT.md).
    address internal constant FEATURE_NFT = 0x82cd6763cB7362EA5652b63E12617fBa06702D69;

    function run() external returns (address verifierAddr) {
        FeatureNFT fn = FeatureNFT(FEATURE_NFT);

        // Sanity: lock must be open before broadcasting.
        require(
            address(fn.transferFeatureVerifier()) == address(0),
            "transferFeatureVerifier already set; lock engaged"
        );

        vm.startBroadcast();

        TransferFeatureV2Verifier v = new TransferFeatureV2Verifier();
        verifierAddr = address(v);
        console.log("TransferFeatureV2Verifier:", verifierAddr);

        fn.setTransferFeatureVerifier(IVerifier(verifierAddr));
        console.log("setTransferFeatureVerifier called; lock now engaged.");

        vm.stopBroadcast();
    }
}
