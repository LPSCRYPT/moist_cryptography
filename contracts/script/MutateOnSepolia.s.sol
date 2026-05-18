// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console, stdJson} from "forge-std/Script.sol";
import {ShadowToken} from "../src/ShadowToken.sol";

/// Broadcast a single `mutateSlot` against the live Base Sepolia
/// deployment, using a fixture produced by
/// `tools/build_mutate_slot_onchain.py`.
///
/// The fixture's witness is bound to the live mint state of shadow A.
/// Specifically:
///   - PI[2] feature_id matches the chain-derived featureId for slot.
///   - PI[6] old_lsh matches the chain's manifest[shadowId][slot].liveStateHash.
///   - PI[10..11] owner_pk match _shadows[shadowId].ecdhPubX/Y.
///   - The bundled T10 proof binds to the post-mutate manifest with the
///     OTHER 7 slots' lsh values from the on-chain mint (not zeros).
///
/// Idempotency: if the slot's mutationCount > 0, this script's witness
/// will not match (proof binds prev_count = 0). The check below skips
/// the broadcast in that case to avoid a guaranteed revert.
///
/// Run:
///   ST_ADDRESS=0x... FIX=./test/fixtures/onchain_mutate/onchain_mutate_atomic_mint_demo_slot0 \
///     forge script script/MutateOnSepolia.s.sol:MutateOnSepolia \
///         --rpc-url $RPC --broadcast --gas-estimate-multiplier 150 \
///         --sender $DEPLOYER_ADDRESS \
///         --private-key $PRIVATE_KEY
contract MutateOnSepolia is Script {
    using stdJson for string;

    uint256 internal constant MUT_PI_LEN = 16;
    uint256 internal constant T10_PI_LEN = 20;

    struct Loaded {
        bytes proofMut;
        bytes proofT10;
        bytes piMut;
        bytes piT10;
        bytes newC2;
    }

    function run() external {
        address stAddr = vm.envAddress("ST_ADDRESS");
        Loaded memory L = _loadFixture(vm.envString("FIX"));

        ShadowToken.MutateSlotArgs memory args = _buildArgs(L);
        ShadowToken st = ShadowToken(stAddr);

        // Idempotency guard.
        ShadowToken.ManifestEntry memory m = st.slotOf(args.shadowId, args.slotIdx);
        require(m.kind == ShadowToken.SlotKind.OCCUPIED, "slot must be OCCUPIED for mutate");
        bytes32 expectedOldLsh = _word(L.piMut, 6);
        if (m.liveStateHash != expectedOldLsh) {
            console.log("SKIP: on-chain lsh != fixture old_lsh");
            console.log("      slot already mutated past this fixture's binding");
            console.log("on-chain lsh:");
            console.logBytes32(m.liveStateHash);
            console.log("fixture old_lsh:");
            console.logBytes32(expectedOldLsh);
            return;
        }

        console.log("=== mutateSlot broadcast ===");
        console.log("ST       :", stAddr);
        console.log("shadowId :");
        console.logBytes32(bytes32(args.shadowId));
        console.log("slotIdx  :", uint256(args.slotIdx));
        console.log("c2 length:", args.c2.length);
        console.log("proof len:", args.proofMutate.length);

        vm.startBroadcast();
        st.mutateSlot(args);
        vm.stopBroadcast();

        console.log("done");
    }

    function _loadFixture(string memory fix) internal returns (Loaded memory L) {
        L.proofMut = vm.readFileBinary(string.concat(fix, "/proof_mut.bin"));
        L.piMut = vm.readFileBinary(string.concat(fix, "/public_inputs_mut.bin"));
        require(L.piMut.length == MUT_PI_LEN * 32, "bad mutate PI length");
        L.proofT10 = vm.readFileBinary(string.concat(fix, "/proof_t10.bin"));
        L.piT10 = vm.readFileBinary(string.concat(fix, "/public_inputs_t10.bin"));
        require(L.piT10.length == T10_PI_LEN * 32, "bad T10 PI length");
        L.newC2 = vm.readFileBinary(string.concat(fix, "/c2.bin"));
    }

    function _buildArgs(Loaded memory L) internal pure returns (ShadowToken.MutateSlotArgs memory args) {
        args.shadowId = uint256(_word(L.piMut, 0));
        args.slotIdx = uint8(uint256(_word(L.piMut, 1)));
        args.proofMutate = L.proofMut;
        args.newC1X = 0;
        args.newC1Y = 0;
        args.newLiveStateHash = _word(L.piMut, 7);
        args.newCtCommit = _word(L.piMut, 8);
        args.c2FieldCount = uint16(L.newC2.length / 32);
        args.c2 = L.newC2;
        args.prevChainTip = _word(L.piMut, 12);
        args.newChainTip = _word(L.piMut, 13);
        args.prevMutationCount = uint16(uint256(_word(L.piMut, 14)));
        args.newMutationCount = uint16(uint256(_word(L.piMut, 15)));
        args.newT10[0] = _word(L.piT10, 2);
        args.newT10[1] = _word(L.piT10, 3);
        args.proofT10 = L.proofT10;
    }

    function _word(bytes memory raw, uint256 idx) internal pure returns (bytes32 word) {
        // raw[idx*32 : idx*32+32]
        assembly { word := mload(add(raw, add(0x20, mul(idx, 32)))) }
    }
}
