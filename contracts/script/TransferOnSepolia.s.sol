// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console, stdJson} from "forge-std/Script.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {KeyRegistry} from "../src/KeyRegistry.sol";

/// Broadcast a single `transferShadow` against the live Base Sepolia
/// deployment, using a fixture produced by
/// `tools/build_transfer_onchain.py`.
///
/// Witness binding (verified by the contract via `_verifyTransferProof`):
///   - PI[0]   shadow_id            = host shadow B
///   - PI[1..2] recipient_pk_x/y    = `keyRegistry.pkOf(args.to)`; the
///                                    recipient MUST have called
///                                    `KeyRegistry.register(pk_x, pk_y)`
///                                    from their own EOA before this tx.
///   - PI[3]   prev_lsh_root        = sponge_16 over `_manifests[shadow]`
///                                    (chain reads); MUST equal
///                                    `meta.prev_lsh_root` in the fixture.
///   - PI[4]   new_lsh_root         = sponge_16 over args.newLiveStateHashes.
///   - PI[5..6] prev_owner_pk_x/y   = `_shadows[shadow].ecdhPubX/Y`.
///   - PI[7]   new_chain_tips_root  = sponge_16 over args.newChainTips.
///   - PI[8]   new_ct_commits_root  = sponge_16 over args.newCtCommits.
///   - PI[9]   new_c1_x_root        = sponge_16 over args.newC1Xs.
///   - PI[10]  new_c1_y_root        = sponge_16 over args.newC1Ys.
///
/// Idempotency: skip if `_ownerOf(shadowId)` is already the recipient.
///
/// Run:
///   ST_ADDRESS=0x... KR_ADDRESS=0x... \
///   FIX=./test/fixtures/onchain_transfer/onchain_transfer_transfer_recipient_demo \
///     forge script script/TransferOnSepolia.s.sol:TransferOnSepolia \
///         --rpc-url $RPC --broadcast --gas-estimate-multiplier 150 \
///         --sender $DEPLOYER_ADDRESS --private-key $PRIVATE_KEY
contract TransferOnSepolia is Script {
    using stdJson for string;

    uint256 internal constant TRANSFER_PI_LEN = 11;
    uint256 internal constant T10_PI_LEN = 20;
    uint256 internal constant N_SLOTS = 16;
    uint256 internal constant C2_FIELD_COUNT = 39;

    struct Loaded {
        bytes proof;
        bytes proofT10;
        bytes piT;          // raw 11x32 bytes
        bytes piT10;        // raw 20x32 bytes
        uint256 shadowId;
        address recipient;
        bytes32[2] newT10;
        bytes32[16] newLshs;
        bytes32[16] newChainTips;
        uint256[16] newC1Xs;
        uint256[16] newC1Ys;
        uint16[16]  newCounts;
        bytes32[16] newCtCommits;
        bytes[]     c2s;    // length 16 (empty bytes for empty slots)
    }

    function run() external {
        address stAddr = vm.envAddress("ST_ADDRESS");
        address krAddr = vm.envAddress("KR_ADDRESS");
        Loaded memory L = _loadFixture(vm.envString("FIX"));

        ShadowToken st = ShadowToken(stAddr);
        KeyRegistry kr = KeyRegistry(krAddr);

        // Idempotency: already transferred?
        if (st.ownerOf(L.shadowId) == L.recipient) {
            console.log("SKIP: shadow already owned by recipient");
            return;
        }
        // Recipient must be registered in KeyRegistry; otherwise pkOf reverts.
        require(kr.isRegistered(L.recipient),
            "recipient not registered in KeyRegistry; ask them to call register() first");

        ShadowToken.TransferShadowArgs memory args = _buildArgs(L);

        console.log("=== transferShadow broadcast ===");
        console.log("ST       :", stAddr);
        console.log("KR       :", krAddr);
        console.log("shadowId :");
        console.logBytes32(bytes32(args.shadowId));
        console.log("recipient:", args.to);
        console.log("proof len:", args.proof.length);
        console.log("proofT10 :", args.proofT10.length);

        vm.startBroadcast();
        st.transferShadow(args);
        vm.stopBroadcast();

        console.log("done");

        // Post-broadcast verification.
        require(st.ownerOf(args.shadowId) == args.to, "post: shadow owner not recipient");
        // Spot-check first occupied slot wrote new lsh.
        ShadowToken.ManifestEntry memory m0 = st.slotOf(args.shadowId, 0);
        require(m0.liveStateHash == args.newLiveStateHashes[0], "post: slot 0 lsh not written");
        console.log("post-state ok");
    }

    function _loadFixture(string memory fix) internal returns (Loaded memory L) {
        L.proof    = vm.readFileBinary(string.concat(fix, "/proof.bin"));
        L.piT      = vm.readFileBinary(string.concat(fix, "/public_inputs.bin"));
        require(L.piT.length == TRANSFER_PI_LEN * 32, "bad transfer PI length");
        L.proofT10 = vm.readFileBinary(string.concat(fix, "/proof_t10.bin"));
        L.piT10    = vm.readFileBinary(string.concat(fix, "/public_inputs_t10.bin"));
        require(L.piT10.length == T10_PI_LEN * 32, "bad T10 PI length");

        string memory j = vm.readFile(string.concat(fix, "/meta.json"));
        L.shadowId  = uint256(j.readBytes32(".host_shadow_id"));
        L.recipient = j.readAddress(".recipient_addr");
        L.newT10[0] = _word(L.piT10, 2);
        L.newT10[1] = _word(L.piT10, 3);

        L.c2s = new bytes[](N_SLOTS);
        for (uint256 i = 0; i < N_SLOTS; i++) {
            string memory idx = vm.toString(i);
            L.newLshs[i]      = j.readBytes32(string.concat(".new_lsh[", idx, "]"));
            L.newChainTips[i] = j.readBytes32(string.concat(".new_chain_tip[", idx, "]"));
            L.newC1Xs[i]      = uint256(j.readBytes32(string.concat(".new_c1_x[", idx, "]")));
            L.newC1Ys[i]      = uint256(j.readBytes32(string.concat(".new_c1_y[", idx, "]")));
            L.newCounts[i]    = uint16(j.readUint(string.concat(".new_mutation_count[", idx, "]")));
            L.newCtCommits[i] = j.readBytes32(string.concat(".new_ct_commit[", idx, "]"));

            // c2_per_slot is a JSON array; empty slots have []. Build a
            // 39*32 buffer per occupied slot, empty bytes otherwise.
            // Probe the first element to detect empty arrays.
            bool occupied = j.keyExists(string.concat(".c2_per_slot[", idx, "][0]"));
            if (!occupied) {
                L.c2s[i] = new bytes(0);
                continue;
            }
            bytes memory buf = new bytes(C2_FIELD_COUNT * 32);
            for (uint256 k = 0; k < C2_FIELD_COUNT; k++) {
                bytes32 v = j.readBytes32(string.concat(
                    ".c2_per_slot[", idx, "][", vm.toString(k), "]"));
                assembly { mstore(add(add(buf, 32), mul(k, 32)), v) }
            }
            L.c2s[i] = buf;
        }
    }

    function _buildArgs(Loaded memory L)
        internal pure returns (ShadowToken.TransferShadowArgs memory args)
    {
        args.shadowId            = L.shadowId;
        args.to                  = L.recipient;
        args.proof               = L.proof;
        args.newLiveStateHashes  = L.newLshs;
        args.newChainTips        = L.newChainTips;
        args.newC1Xs             = L.newC1Xs;
        args.newC1Ys             = L.newC1Ys;
        args.newMutationCounts   = L.newCounts;
        args.newCtCommits        = L.newCtCommits;
        args.c2s                 = L.c2s;
        args.newT10              = L.newT10;
        args.proofT10            = L.proofT10;
    }

    function _word(bytes memory raw, uint256 idx) internal pure returns (bytes32 word) {
        assembly { word := mload(add(raw, add(0x20, mul(idx, 32)))) }
    }
}
