// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console, stdJson} from "forge-std/Script.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";

/// Broadcast a single `insertFeature` against the live Base Sepolia
/// deployment, using a fixture produced by
/// `tools/build_insert_onchain.py`.
///
/// Witness binding (verified by the contract via `_verifyInsertProof`):
///   - PI[0]   shadow_id          = host (target) shadow B
///   - PI[1]   slot_idx           = empty target slot in B (8..15 in our path)
///   - PI[2]   feature_id         = the carrier's existing FeatureNFT id (from A's mint)
///   - PI[3]   type_idx           = `featureNFT.typeIdxOf(feature_id)`
///   - PI[4]   origin_face_id     = `featureNFT.originFaceIdOf(feature_id)`
///   - PI[5]   palette_commit     = `featureNFT.paletteCommitOf(feature_id)`
///   - PI[6]   old_lsh            = `featureNFT.liveStateHashCheckpointOf(feature_id)`
///   - PI[10]  ecdh pub_x         = `_shadows[shadowId].ecdhPubX` (B's owner key,
///                                  which equals A's because the same wallet owns both)
///   - PI[11]  ecdh pub_y         = `_shadows[shadowId].ecdhPubY`
///
/// Idempotency:
///   - Skips if `featureNFT.isInserted(feature_id) == true` (carrier already
///     placed somewhere — re-running would revert with FeatureAlreadyInserted).
///   - Skips if the target slot is not EMPTY (would revert with SlotOccupied).
///
/// Run:
///   ST_ADDRESS=0x... FN_ADDRESS=0x... \
///   FIX=./test/fixtures/onchain_insert/onchain_insert_src1_host8 \
///     forge script script/InsertOnSepolia.s.sol:InsertOnSepolia \
///         --rpc-url $RPC --broadcast --gas-estimate-multiplier 150 \
///         --sender $DEPLOYER_ADDRESS \
///         --private-key $PRIVATE_KEY
contract InsertOnSepolia is Script {
    using stdJson for string;

    uint256 internal constant MUT_PI_LEN = 16;
    uint256 internal constant T10_PI_LEN = 20;

    struct Loaded {
        bytes proofIns;
        bytes proofT10;
        bytes piIns;
        bytes piT10;
        bytes newC2;
    }

    function run() external {
        address stAddr = vm.envAddress("ST_ADDRESS");
        address fnAddr = vm.envAddress("FN_ADDRESS");
        Loaded memory L = _loadFixture(vm.envString("FIX"));

        ShadowToken.InsertFeatureArgs memory args = _buildArgs(L);
        ShadowToken st = ShadowToken(stAddr);
        IFeatureNFT fn = IFeatureNFT(fnAddr);

        // Idempotency: don't broadcast a guaranteed-revert.
        if (fn.isInserted(args.featureId)) {
            console.log("SKIP: feature already inserted somewhere");
            console.log("featureId:");
            console.logBytes32(bytes32(args.featureId));
            return;
        }
        ShadowToken.ManifestEntry memory m = st.slotOf(args.shadowId, args.slotIdx);
        if (m.kind != ShadowToken.SlotKind.EMPTY) {
            console.log("SKIP: target slot not EMPTY");
            console.log("shadowId:");
            console.logBytes32(bytes32(args.shadowId));
            console.log("slotIdx :", uint256(args.slotIdx));
            return;
        }
        // Cross-check: chain's checkpoint must match fixture's old_lsh
        // (PI[6]). If a prior call mutated/extracted the carrier between
        // fixture build and broadcast, the chain checkpoint would have
        // moved, and the proof would revert anyway -- pre-check here for
        // a clear error.
        bytes32 chainCheckpoint = fn.liveStateHashCheckpointOf(args.featureId);
        bytes32 fixtureOldLsh = _word(L.piIns, 6);
        require(chainCheckpoint == fixtureOldLsh,
            "checkpoint moved since fixture built");

        console.log("=== insertFeature broadcast ===");
        console.log("ST       :", stAddr);
        console.log("FN       :", fnAddr);
        console.log("shadowId :");
        console.logBytes32(bytes32(args.shadowId));
        console.log("slotIdx  :", uint256(args.slotIdx));
        console.log("featureId:");
        console.logBytes32(bytes32(args.featureId));
        console.log("c2 length:", args.c2.length);
        console.log("proof len:", args.proofInsert.length);

        vm.startBroadcast();
        st.insertFeature(args);
        vm.stopBroadcast();

        console.log("done");

        // Post-broadcast verification:
        ShadowToken.ManifestEntry memory mPost = st.slotOf(args.shadowId, args.slotIdx);
        require(mPost.kind == ShadowToken.SlotKind.OCCUPIED, "post: slot not OCCUPIED");
        require(mPost.featureId == args.featureId, "post: featureId not written");
        require(mPost.liveStateHash == args.newLiveStateHash, "post: lsh not written");
        require(fn.isInserted(args.featureId), "post: isInserted not true");
        require(fn.hostShadowIdOf(args.featureId) == args.shadowId, "post: hostShadow mismatch");
        console.log("post-state ok");
    }

    function _loadFixture(string memory fix) internal returns (Loaded memory L) {
        L.proofIns = vm.readFileBinary(string.concat(fix, "/proof_ins.bin"));
        L.piIns    = vm.readFileBinary(string.concat(fix, "/public_inputs_ins.bin"));
        require(L.piIns.length == MUT_PI_LEN * 32, "bad insert PI length");
        L.proofT10 = vm.readFileBinary(string.concat(fix, "/proof_t10.bin"));
        L.piT10    = vm.readFileBinary(string.concat(fix, "/public_inputs_t10.bin"));
        require(L.piT10.length == T10_PI_LEN * 32, "bad T10 PI length");
        L.newC2    = vm.readFileBinary(string.concat(fix, "/c2.bin"));
    }

    function _buildArgs(Loaded memory L)
        internal pure returns (ShadowToken.InsertFeatureArgs memory args)
    {
        args.shadowId          = uint256(_word(L.piIns, 0));
        args.slotIdx           = uint8(uint256(_word(L.piIns, 1)));
        args.featureId         = uint256(_word(L.piIns, 2));
        args.proofInsert       = L.proofIns;
        // newC1{X,Y} are unused on chain (newLiveStateHash already binds c1
        // via the proof's sponge_6); kept zero like MutateOnSepolia.
        args.newC1X            = 0;
        args.newC1Y            = 0;
        args.newLiveStateHash  = _word(L.piIns, 7);
        args.newCtCommit       = _word(L.piIns, 8);
        args.c2FieldCount      = uint16(L.newC2.length / 32);
        args.c2                = L.newC2;
        args.prevChainTip      = _word(L.piIns, 12);
        args.newChainTip       = _word(L.piIns, 13);
        args.prevMutationCount = uint16(uint256(_word(L.piIns, 14)));
        args.newMutationCount  = uint16(uint256(_word(L.piIns, 15)));
        args.newT10[0]         = _word(L.piT10, 2);
        args.newT10[1]         = _word(L.piT10, 3);
        args.proofT10          = L.proofT10;
    }

    function _word(bytes memory raw, uint256 idx) internal pure returns (bytes32 word) {
        assembly { word := mload(add(raw, add(0x20, mul(idx, 32)))) }
    }
}
