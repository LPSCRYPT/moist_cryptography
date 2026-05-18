// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console, stdJson} from "forge-std/Script.sol";
import {ShadowToken} from "../src/ShadowToken.sol";

/// Broadcast a `mutateBatch` against the live Base Sepolia deployment,
/// using a fixture produced by `tools/build_mutate_batch_onchain.py`.
///
/// Two mutate_slot proofs (slot A, slot B of the same shadow) plus one
/// shadow_t10 proof against the post-batch manifest.
///
/// Idempotency: each entry's old_lsh must equal the chain's current
/// liveStateHash for that slot. If either slot has already been mutated
/// past the fixture's binding, we skip to avoid a guaranteed revert.
///
/// Run:
///   ST_ADDRESS=0x... FIX=./test/fixtures/onchain_mutate_batch/onchain_mutate_batch_b \
///     forge script script/MutateBatchOnSepolia.s.sol:MutateBatchOnSepolia \
///         --rpc-url $RPC --broadcast --gas-estimate-multiplier 150 \
///         --sender $DEPLOYER_ADDRESS_2 \
///         --private-key $PRIVATE_KEY_2
contract MutateBatchOnSepolia is Script {
    using stdJson for string;

    uint256 internal constant MUT_PI_LEN = 16;
    uint256 internal constant T10_PI_LEN = 20;

    struct Loaded {
        bytes proofMutA;
        bytes proofMutB;
        bytes proofT10;
        bytes piMutA;
        bytes piMutB;
        bytes piT10;
        bytes c2A;
        bytes c2B;
    }

    function run() external {
        address stAddr = vm.envAddress("ST_ADDRESS");
        Loaded memory L = _loadFixture(vm.envString("FIX"));

        ShadowToken.MutateBatchArgs memory args = _buildArgs(L);
        ShadowToken st = ShadowToken(stAddr);

        // Idempotency: check both slots' on-chain lsh against the
        // fixture's witnessed old_lsh values. The contract loop applies
        // entry 0 BEFORE reading entry 1's old_lsh, so the chain-state
        // we read here is the pre-batch state for both.
        ShadowToken.ManifestEntry memory ma = st.slotOf(args.shadowId, args.entries[0].slotIdx);
        ShadowToken.ManifestEntry memory mb = st.slotOf(args.shadowId, args.entries[1].slotIdx);
        bytes32 expectedOldA = _word(L.piMutA, 6);
        bytes32 expectedOldB = _word(L.piMutB, 6);

        if (ma.kind != ShadowToken.SlotKind.OCCUPIED) {
            console.log("SKIP: slot A not OCCUPIED");
            return;
        }
        if (mb.kind != ShadowToken.SlotKind.OCCUPIED) {
            console.log("SKIP: slot B not OCCUPIED");
            return;
        }
        if (ma.liveStateHash != expectedOldA) {
            console.log("SKIP: slot A on-chain lsh != fixture old_lsh");
            console.log("on-chain lsh A:");
            console.logBytes32(ma.liveStateHash);
            console.log("fixture old_lsh A:");
            console.logBytes32(expectedOldA);
            return;
        }
        if (mb.liveStateHash != expectedOldB) {
            console.log("SKIP: slot B on-chain lsh != fixture old_lsh");
            console.log("on-chain lsh B:");
            console.logBytes32(mb.liveStateHash);
            console.log("fixture old_lsh B:");
            console.logBytes32(expectedOldB);
            return;
        }

        console.log("=== mutateBatch broadcast ===");
        console.log("ST       :", stAddr);
        console.log("shadowId :");
        console.logBytes32(bytes32(args.shadowId));
        console.log("slotA    :", uint256(args.entries[0].slotIdx));
        console.log("slotB    :", uint256(args.entries[1].slotIdx));
        console.log("proofA   :", args.entries[0].proofMutate.length);
        console.log("proofB   :", args.entries[1].proofMutate.length);
        console.log("c2A      :", args.entries[0].c2.length);
        console.log("c2B      :", args.entries[1].c2.length);
        console.log("proofT10 :", args.proofT10.length);

        vm.startBroadcast();
        st.mutateBatch(args);
        vm.stopBroadcast();

        console.log("done");
    }

    function _loadFixture(string memory fix) internal returns (Loaded memory L) {
        L.proofMutA = vm.readFileBinary(string.concat(fix, "/proof_mut_a.bin"));
        L.piMutA = vm.readFileBinary(string.concat(fix, "/public_inputs_mut_a.bin"));
        require(L.piMutA.length == MUT_PI_LEN * 32, "bad mutate A PI length");

        L.proofMutB = vm.readFileBinary(string.concat(fix, "/proof_mut_b.bin"));
        L.piMutB = vm.readFileBinary(string.concat(fix, "/public_inputs_mut_b.bin"));
        require(L.piMutB.length == MUT_PI_LEN * 32, "bad mutate B PI length");

        L.proofT10 = vm.readFileBinary(string.concat(fix, "/proof_t10.bin"));
        L.piT10 = vm.readFileBinary(string.concat(fix, "/public_inputs_t10.bin"));
        require(L.piT10.length == T10_PI_LEN * 32, "bad T10 PI length");

        L.c2A = vm.readFileBinary(string.concat(fix, "/c2_a.bin"));
        L.c2B = vm.readFileBinary(string.concat(fix, "/c2_b.bin"));
    }

    function _buildArgs(Loaded memory L) internal pure returns (ShadowToken.MutateBatchArgs memory args) {
        // Both mutate proofs must reference the same shadow_id (PI[0]).
        uint256 sidA = uint256(_word(L.piMutA, 0));
        uint256 sidB = uint256(_word(L.piMutB, 0));
        require(sidA == sidB, "shadow_id mismatch across batch entries");
        args.shadowId = sidA;

        args.entries = new ShadowToken.MutateSlotEntry[](2);
        args.entries[0] = _entryFrom(L.piMutA, L.proofMutA, L.c2A);
        args.entries[1] = _entryFrom(L.piMutB, L.proofMutB, L.c2B);

        args.newT10[0] = _word(L.piT10, 2);
        args.newT10[1] = _word(L.piT10, 3);
        args.proofT10 = L.proofT10;
    }

    function _entryFrom(bytes memory pi, bytes memory proof, bytes memory c2)
        internal
        pure
        returns (ShadowToken.MutateSlotEntry memory e)
    {
        e.slotIdx = uint8(uint256(_word(pi, 1)));
        e.proofMutate = proof;
        e.newC1X = 0; // unused on-chain (sponge_39 binds c2)
        e.newC1Y = 0;
        e.newLiveStateHash = _word(pi, 7);
        e.newCtCommit = _word(pi, 8);
        e.c2FieldCount = uint16(c2.length / 32);
        e.c2 = c2;
        e.prevChainTip = _word(pi, 12);
        e.newChainTip = _word(pi, 13);
        e.prevMutationCount = uint16(uint256(_word(pi, 14)));
        e.newMutationCount = uint16(uint256(_word(pi, 15)));
    }

    function _word(bytes memory raw, uint256 idx) internal pure returns (bytes32 word) {
        assembly { word := mload(add(raw, add(0x20, mul(idx, 32)))) }
    }
}
