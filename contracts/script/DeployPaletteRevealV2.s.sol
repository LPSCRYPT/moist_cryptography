// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {PaletteRevealV2Verifier} from "../src/PaletteRevealV2Verifier.sol";

/// Deploy the palette_reveal_v2 verifier and one-shot wire it into the
/// already-live FeatureNFT.
///
/// Pre-conditions checked at runtime:
///   - msg.sender == FeatureNFT.deployer()
///   - FeatureNFT.paletteRevealVerifier() == address(0)
///     (the lock is engaged on first set; if already set this reverts
///      VerifierAlreadySet -- fail loud instead of silently rotating.)
///
/// Usage:
///   forge script script/DeployPaletteRevealV2.s.sol:DeployPaletteRevealV2 \
///     --rpc-url $BASE_SEPOLIA_RPC --broadcast \
///     --gas-estimate-multiplier 150 \
///     --sender $DEPLOYER_ADDRESS --private-key $PRIVATE_KEY
contract DeployPaletteRevealV2 is Script {
    /// FeatureNFT on Base Sepolia (deployment #3 from DEPLOYMENT.md).
    address internal constant FEATURE_NFT = 0x82cd6763cB7362EA5652b63E12617fBa06702D69;

    function run() external returns (address verifierAddr) {
        FeatureNFT fn = FeatureNFT(FEATURE_NFT);

        // Sanity: lock must be open before broadcasting.
        require(
            address(fn.paletteRevealVerifier()) == address(0),
            "paletteRevealVerifier already set; lock engaged"
        );

        vm.startBroadcast();

        PaletteRevealV2Verifier v = new PaletteRevealV2Verifier();
        verifierAddr = address(v);
        console.log("PaletteRevealV2Verifier:", verifierAddr);

        fn.setPaletteRevealVerifier(IVerifier(verifierAddr));
        console.log("setPaletteRevealVerifier called; lock now engaged.");

        vm.stopBroadcast();
    }
}
