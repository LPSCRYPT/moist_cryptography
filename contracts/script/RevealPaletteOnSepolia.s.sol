// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";

/// @notice Broadcast revealPalette on Base Sepolia (pipeline #4) for one
///         carrier of a freshly-minted shadow.
///
/// Idempotent: if `paletteRevealedOf(featureId) == true` the script
/// short-circuits and prints the cached state.
///
/// Usage:
///   FN_ADDRESS=0x578eda36Dc4750c35c29E5F12a0789DaD35e2072 \
///   FIX=./test/fixtures/onchain_palette_reveal/palette_reveal_live_slot0 \
///   forge script script/RevealPaletteOnSepolia.s.sol:RevealPaletteOnSepolia \
///     --rpc-url $BASE_SEPOLIA_RPC \
///     --broadcast \
///     --gas-estimate-multiplier 150 \
///     --private-key $PRIVATE_KEY
contract RevealPaletteOnSepolia is Script {
    using stdJson for string;

    uint256 internal constant PI_LEN = 10;

    function run() external {
        address fnAddr = vm.envAddress("FN_ADDRESS");
        string memory fix = vm.envString("FIX");

        FeatureNFT fn = FeatureNFT(fnAddr);

        // Load proof + PI from fixture.
        bytes memory proof = vm.readFileBinary(string.concat(fix, "/proof.bin"));
        bytes memory raw   = vm.readFileBinary(string.concat(fix, "/public_inputs.bin"));
        require(raw.length == PI_LEN * 32, "PI length mismatch");
        bytes32[] memory pi = new bytes32[](PI_LEN);
        for (uint256 i = 0; i < PI_LEN; i++) {
            bytes32 word;
            assembly { word := mload(add(raw, add(0x20, mul(i, 32)))) }
            pi[i] = word;
        }
        uint256 featureId = uint256(pi[0]);

        // Sanity vs meta.json.
        string memory j = vm.readFile(string.concat(fix, "/meta.json"));
        bytes32 metaCommit = j.readBytes32(".palette_commit");
        require(pi[1] == metaCommit, "fixture inconsistent: PI vs meta");

        console.log("=== revealPalette on pipeline #4 ===");
        console.log("FeatureNFT  :", fnAddr);
        console.log("featureId   :");
        console.logBytes32(bytes32(featureId));
        console.log("paletteCommit (off-chain):");
        console.logBytes32(pi[1]);

        // Pre-state.
        bytes32 storedCommit = fn.paletteCommitOf(featureId);
        bool revealed = fn.paletteRevealedOf(featureId);
        console.log("paletteCommit (on-chain):");
        console.logBytes32(storedCommit);
        console.log("paletteRevealed (pre):", revealed);

        require(storedCommit == pi[1], "stored paletteCommit != fixture paletteCommit");

        if (revealed) {
            console.log("Already revealed; nothing to broadcast.");
            return;
        }

        vm.startBroadcast();
        fn.revealPalette(featureId, proof, pi);
        vm.stopBroadcast();

        console.log("revealPalette: tx broadcast");
        console.log("paletteRevealed (post):", fn.paletteRevealedOf(featureId));
    }
}
