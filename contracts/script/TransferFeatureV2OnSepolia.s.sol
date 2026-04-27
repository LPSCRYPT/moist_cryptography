// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console, stdJson} from "forge-std/Script.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";

/// Broadcast a single `transferFeature` against the live Base Sepolia
/// FeatureNFT, using a fixture produced by
/// `tools/build_transfer_feature_v2_fixture.py`.
///
/// PI layout (8 fields, frozen by FeatureNFT.transferFeature):
///   PI[0] feature_id        — keccak-derived per-carrier id
///   PI[1] next_pk_x         — recipient pubkey x (must match KeyRegistry)
///   PI[2] next_pk_y         — recipient pubkey y
///   PI[3] old_lsh           — must equal `f.liveStateHashCheckpoint` now
///   PI[4] new_lsh           — written on success
///   PI[5] palette_commit    — must equal `f.paletteCommit`
///   PI[6] type_idx          — must equal `f.typeIdx`
///   PI[7] origin_face_id    — must equal `f.originFaceId`
///
/// Idempotency: skip if `_ownerOf(featureId)` is already the recipient.
///
/// Run:
///   FN_ADDRESS=0x82cd6763cB7362EA5652b63E12617fBa06702D69 \
///   FIX=./test/fixtures/onchain_transfer_feature_v2/transfer_feature_v2_a_slot0 \
///     forge script script/TransferFeatureV2OnSepolia.s.sol:TransferFeatureV2OnSepolia \
///       --rpc-url $RPC --broadcast --gas-estimate-multiplier 150 \
///       --sender $DEPLOYER_ADDRESS --private-key $PRIVATE_KEY
contract TransferFeatureV2OnSepolia is Script {
    using stdJson for string;

    uint256 internal constant TRANSFER_FEATURE_PI_LEN = 8;

    function run() external {
        address fnAddr = vm.envAddress("FN_ADDRESS");
        string memory fix = vm.envString("FIX");

        FeatureNFT fn = FeatureNFT(fnAddr);

        bytes memory proof = vm.readFileBinary(string.concat(fix, "/proof.bin"));
        bytes memory piRaw = vm.readFileBinary(string.concat(fix, "/public_inputs.bin"));
        require(piRaw.length == TRANSFER_FEATURE_PI_LEN * 32, "bad PI length");

        string memory j = vm.readFile(string.concat(fix, "/meta.json"));
        uint256 featureId  = uint256(j.readBytes32(".feature_id"));
        address recipient  = j.readAddress(".to_addr");
        bytes32 expOldLsh  = j.readBytes32(".old_lsh");
        bytes32 expNewLsh  = j.readBytes32(".new_lsh");

        bytes32[] memory pi = _piFromBytes(piRaw);

        // Idempotency: if already transferred, skip.
        if (fn.ownerOfFeature(featureId) == recipient) {
            console.log("SKIP: feature already owned by recipient");
            return;
        }

        // Pre-broadcast sanity: PI[3] must match storage.
        bytes32 onChainLsh = fn.liveStateHashCheckpointOf(featureId);
        require(onChainLsh == expOldLsh,
            "fixture old_lsh does not match on-chain liveStateHashCheckpoint");
        require(pi[3] == expOldLsh, "PI[3] != fixture old_lsh");
        require(pi[4] == expNewLsh, "PI[4] != fixture new_lsh");

        console.log("=== transferFeature broadcast ===");
        console.log("FN       :", fnAddr);
        console.log("featureId:");
        console.logBytes32(bytes32(featureId));
        console.log("from     :", fn.ownerOfFeature(featureId));
        console.log("to       :", recipient);
        console.log("proof len:", proof.length);
        console.logBytes32(expOldLsh);
        console.log("  ^ old_lsh (on chain)");
        console.logBytes32(expNewLsh);
        console.log("  ^ new_lsh (post-tx)");

        vm.startBroadcast();
        fn.transferFeature(featureId, recipient, proof, pi);
        vm.stopBroadcast();

        // Post-broadcast verification.
        require(fn.ownerOfFeature(featureId) == recipient,
            "post: feature owner not recipient");
        require(fn.liveStateHashCheckpointOf(featureId) == expNewLsh,
            "post: liveStateHashCheckpoint not updated to new_lsh");
        console.log("post-state ok: owner rotated, lsh updated");
    }

    /// Decode raw 32*N bytes (big-endian fields) into bytes32[].
    function _piFromBytes(bytes memory raw) internal pure returns (bytes32[] memory pi) {
        uint256 n = raw.length / 32;
        pi = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 w;
            assembly { w := mload(add(raw, add(0x20, mul(i, 32)))) }
            pi[i] = w;
        }
    }
}
