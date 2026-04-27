// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test, stdJson, Vm} from "forge-std/Test.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {KeyRegistry} from "../src/KeyRegistry.sol";
import {TransferShadowVerifier} from "../src/TransferShadowVerifier.sol";
import {T10ShadowVerifier} from "../src/T10ShadowVerifier.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {Poseidon2YulSponge16} from "../src/Poseidon2YulSponge16.sol";
import {TestableShadowToken, TestableFeatureNFT} from "./Testable.sol";

/// @notice Real-proof e2e test for `ShadowToken.transferShadow`.
///
/// Loads the linked atomic_transfer fixture (4 occupied slots out of 16),
/// seeds the shadow + carriers + KeyRegistry to match the prover's witness,
/// then calls transferShadow and asserts:
///   - shadow's ERC-721 owner rotated alice -> bob
///   - shadow.ecdhPub rotated to recipient_pk
///   - each occupied slot's liveStateHash advanced
///   - each FeatureNFT carrier's ERC-721 owner rotated alice -> bob
///   - shadowT10 reflects the post-transfer LSH array
///   - ShadowTransferred + ShadowSlotMutated + ShadowT10Updated emitted
contract TransferShadowE2ETest is Test {
    using stdJson for string;

    TestableShadowToken    internal st;
    TestableFeatureNFT     internal fn;
    TransferShadowVerifier internal vT;
    T10ShadowVerifier      internal vT10;
    Poseidon2YulSponge     internal sponge;
    Poseidon2YulSponge16   internal sponge16;
    KeyRegistry            internal kr;

    string internal constant FIX = "./test/fixtures/atomic_transfer/atomic_transfer_demo";

    bytes internal proofTransfer;
    bytes32[] internal piTransfer;
    bytes internal proofT10;
    bytes32[] internal piT10;

    uint256 internal shadowId;
    bytes32 internal recipientPkX;
    bytes32 internal recipientPkY;
    bytes32 internal prevOwnerPkX;
    bytes32 internal prevOwnerPkY;

    address internal alice = makeAddr("alice");
    address internal bob   = makeAddr("bob");

    uint256 internal constant TRANSFER_PI_LEN = 8;
    uint256 internal constant T10_PI_LEN = 20;

    /// Cached per-slot post-rotation values from the fixture meta.json.
    bytes32[16] internal newLsh;
    bytes32[16] internal newCt;
    uint256[16] internal newC1X;
    uint256[16] internal newC1Y;
    bytes32[16] internal newChainTip;
    uint16[16]  internal newCount;
    uint8[]     internal occupiedIdxs;
    uint256[]   internal featureIds;

    function setUp() public {
        sponge = new Poseidon2YulSponge();
        sponge16 = new Poseidon2YulSponge16();
        st = new TestableShadowToken(address(sponge));
        fn = new TestableFeatureNFT(address(st));
        st.setFeatureNFT(IFeatureNFT(address(fn)));
        st.setYulSponge16(address(sponge16));
        vT = new TransferShadowVerifier();
        vT10 = new T10ShadowVerifier();
        st.setVerifier(st.SLOT_TRANSFER_SHADOW(), IVerifier(address(vT)));
        st.setVerifier(st.SLOT_T10_SHADOW(), IVerifier(address(vT10)));

        kr = new KeyRegistry();
        st.setKeyRegistry(kr);

        // Load proofs.
        proofTransfer = vm.readFileBinary(string.concat(FIX, "/proof_transfer.bin"));
        piTransfer    = _loadFields(string.concat(FIX, "/public_inputs_transfer.bin"), TRANSFER_PI_LEN);
        proofT10      = vm.readFileBinary(string.concat(FIX, "/proof_t10.bin"));
        piT10         = _loadFields(string.concat(FIX, "/public_inputs_t10.bin"), T10_PI_LEN);

        shadowId      = uint256(piTransfer[0]);
        recipientPkX  = piTransfer[1];
        recipientPkY  = piTransfer[2];
        prevOwnerPkX  = piTransfer[5];
        prevOwnerPkY  = piTransfer[6];

        _loadFromMeta();
        _seedChainState();
    }

    function _loadFields(string memory path, uint256 expectedLen) internal returns (bytes32[] memory out) {
        bytes memory raw = vm.readFileBinary(path);
        require(raw.length == expectedLen * 32, "PI length mismatch");
        out = new bytes32[](expectedLen);
        for (uint256 i = 0; i < expectedLen; i++) {
            bytes32 word;
            assembly { word := mload(add(raw, add(0x20, mul(i, 32)))) }
            out[i] = word;
        }
    }

    function _loadFromMeta() internal {
        string memory j = vm.readFile(string.concat(FIX, "/meta.json"));
        // Per-slot arrays at full 16-length.
        for (uint256 i = 0; i < 16; i++) {
            string memory idx = vm.toString(i);
            newLsh[i]  = j.readBytes32(string.concat(".new_lsh[", idx, "]"));
            newCt[i]   = j.readBytes32(string.concat(".new_ct_commit[", idx, "]"));
            newC1X[i]  = uint256(j.readBytes32(string.concat(".new_c1_x[", idx, "]")));
            newC1Y[i]  = uint256(j.readBytes32(string.concat(".new_c1_y[", idx, "]")));
            newChainTip[i] = j.readBytes32(string.concat(".new_chain_tip[", idx, "]"));
            newCount[i] = uint16(j.readUint(string.concat(".new_mutation_count[", idx, "]")));
        }
        uint256[] memory occ = j.readUintArray(".occupied_idxs");
        occupiedIdxs = new uint8[](occ.length);
        for (uint256 i = 0; i < occ.length; i++) {
            occupiedIdxs[i] = uint8(occ[i]);
        }
    }

    function _seedChainState() internal {
        // 1. Register prev owner (alice) and recipient (bob) in KeyRegistry.
        vm.prank(alice);
        kr.register(prevOwnerPkX, prevOwnerPkY);
        vm.prank(bob);
        kr.register(recipientPkX, recipientPkY);

        // 2. Seed shadow with occupied slots populated.
        string memory j = vm.readFile(string.concat(FIX, "/meta.json"));
        bytes32[] memory prevLshArr = new bytes32[](occupiedIdxs.length);
        uint256[] memory featIds = new uint256[](occupiedIdxs.length);
        featureIds = new uint256[](occupiedIdxs.length);
        for (uint256 i = 0; i < occupiedIdxs.length; i++) {
            uint8 sIdx = occupiedIdxs[i];
            string memory sIdxStr = vm.toString(uint256(sIdx));
            prevLshArr[i] = j.readBytes32(string.concat(".prev_lsh[", sIdxStr, "]"));
            // Synth a unique featureId per slot. Doesn't need to match a circuit
            // PI since transferShadow's PI doesn't carry per-slot featureIds.
            featIds[i] = uint256(keccak256(abi.encode(shadowId, sIdx, "feature")));
            featureIds[i] = featIds[i];
        }
        st.seedShadowMultiSlot(
            shadowId, alice, prevOwnerPkX, prevOwnerPkY,
            occupiedIdxs, featIds, prevLshArr
        );

        // 3. Seed each feature as inserted in its slot, owned by alice.
        for (uint256 i = 0; i < occupiedIdxs.length; i++) {
            uint8 sIdx = occupiedIdxs[i];
            string memory sIdxStr = vm.toString(uint256(sIdx));
            // typeIdx + originFaceId + paletteCommit are not used by transferShadow
            // PI, so use deterministic stand-ins.
            uint8 typeIdx = uint8(i);
            bytes32 originFaceId = keccak256(abi.encode("origin", shadowId, sIdx));
            bytes32 paletteCommit = keccak256(abi.encode("palette", shadowId, sIdx));
            // Initial checkpoint = prev_lsh[i]. The carrier is INSERTED so
            // the manifest's lsh is authoritative; checkpoint stays stale.
            bytes32 prevLsh = j.readBytes32(string.concat(".prev_lsh[", sIdxStr, "]"));
            fn.seedFeature(
                featIds[i], shadowId, sIdx, typeIdx,
                originFaceId, paletteCommit, prevLsh, alice
            );
        }
    }

    /// Build the contract call args from cached fixture state.
    function _buildArgs() internal returns (ShadowToken.TransferShadowArgs memory args) {
        args.shadowId = shadowId;
        args.to = bob;
        args.proof = proofTransfer;
        args.newLiveStateHashes = newLsh;
        args.newChainTips = newChainTip;
        args.newC1Xs = newC1X;
        args.newC1Ys = newC1Y;
        // newCtCommits dropped in v2-gas: c2 calldata is advisory now.
        args.newMutationCounts = newCount;

        // Per-slot c2 (39 fields = 1248 bytes) for occupied; empty bytes for empty.
        bytes[] memory c2s = new bytes[](16);
        string memory j = vm.readFile(string.concat(FIX, "/meta.json"));
        for (uint256 i = 0; i < occupiedIdxs.length; i++) {
            uint8 sIdx = occupiedIdxs[i];
            string memory sIdxStr = vm.toString(uint256(sIdx));
            // c2_per_slot is a string-keyed map of 39-element bytes32 arrays.
            bytes memory buf = new bytes(39 * 32);
            for (uint256 k = 0; k < 39; k++) {
                bytes32 v = j.readBytes32(string.concat(".c2_per_slot.", sIdxStr, "[", vm.toString(k), "]"));
                assembly { mstore(add(add(buf, 32), mul(k, 32)), v) }
            }
            c2s[sIdx] = buf;
        }
        args.c2s = c2s;

        bytes32[2] memory t10;
        t10[0] = piT10[2];
        t10[1] = piT10[3];
        args.newT10 = t10;
        args.proofT10 = proofT10;
    }

    function test_transferShadow_success_rotates_owner_and_carriers() public {
        ShadowToken.TransferShadowArgs memory args = _buildArgs();

        // Pre-state.
        assertEq(st.ownerOf(shadowId), alice);
        for (uint256 i = 0; i < occupiedIdxs.length; i++) {
            uint8 sIdx = occupiedIdxs[i];
            assertEq(uint256(st.slotOf(shadowId, sIdx).kind), uint256(ShadowToken.SlotKind.OCCUPIED));
            assertEq(fn.ownerOf(featureIds[i]), alice);
            assertTrue(fn.isInserted(featureIds[i]));
            assertEq(fn.hostShadowIdOf(featureIds[i]), shadowId);
        }

        vm.recordLogs();
        vm.prank(alice);
        st.transferShadow(args);

        // ---- Post-state assertions ----
        assertEq(st.ownerOf(shadowId), bob, "shadow owner rotated");

        ShadowToken.Shadow memory s = st.shadowOf(shadowId);
        assertEq(s.ecdhPubX, recipientPkX, "ecdhPubX rotated");
        assertEq(s.ecdhPubY, recipientPkY, "ecdhPubY rotated");

        for (uint256 i = 0; i < occupiedIdxs.length; i++) {
            uint8 sIdx = occupiedIdxs[i];
            assertEq(st.slotOf(shadowId, sIdx).liveStateHash, newLsh[sIdx], "slot LSH rotated");
            assertEq(fn.ownerOf(featureIds[i]), bob, "carrier owner rotated");
            assertTrue(fn.isInserted(featureIds[i]), "carrier still inserted");
            assertEq(fn.hostShadowIdOf(featureIds[i]), shadowId, "host unchanged");
        }

        assertEq(st.shadowT10(shadowId, 0), args.newT10[0]);
        assertEq(st.shadowT10(shadowId, 1), args.newT10[1]);

        // Check expected events fired (via topic hash matching to dodge cross-
        // contract event-name collisions).
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool sawTransferred = false;
        bool sawT10 = false;
        uint256 sawSlotMutated = 0;
        bytes32 sigTransferred = keccak256("ShadowTransferred(uint256,address,bytes32,bytes32)");
        bytes32 sigT10 = keccak256("ShadowT10Updated(uint256,bytes32,bytes32)");
        bytes32 sigSM  = keccak256("ShadowSlotMutated(uint256,uint8,bytes32,uint256,uint16,bytes32,bytes32,bytes)");
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter != address(st)) continue;
            if (logs[i].topics[0] == sigTransferred) sawTransferred = true;
            else if (logs[i].topics[0] == sigT10) sawT10 = true;
            else if (logs[i].topics[0] == sigSM) sawSlotMutated++;
        }
        assertTrue(sawTransferred, "ShadowTransferred emitted");
        assertTrue(sawT10, "ShadowT10Updated emitted");
        assertEq(sawSlotMutated, occupiedIdxs.length, "one ShadowSlotMutated per occupied slot");
    }

    function test_transferShadow_reverts_when_not_owner() public {
        ShadowToken.TransferShadowArgs memory args = _buildArgs();
        // bob (not the current owner) tries to call.
        vm.prank(bob);
        vm.expectRevert(ShadowToken.NotShadowOwner.selector);
        st.transferShadow(args);
    }

    function test_transferShadow_reverts_when_proof_tampered() public {
        ShadowToken.TransferShadowArgs memory args = _buildArgs();
        // Flip a byte in the middle of the proof.
        args.proof[256] = bytes1(uint8(args.proof[256]) ^ 0x40);
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.transferShadow(args);
    }

    function test_transferShadow_reverts_when_lsh_tampered() public {
        ShadowToken.TransferShadowArgs memory args = _buildArgs();
        // Tamper with one occupied slot's LSH; sponge_16 root mismatches PI.
        args.newLiveStateHashes[occupiedIdxs[0]] =
            bytes32(uint256(args.newLiveStateHashes[occupiedIdxs[0]]) ^ 1);
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.transferShadow(args);
    }

    /// Gas-pin: transferShadow rotates ownership for shadow + every
    /// occupied carrier + 16-slot LSH chain. Budget: 14M -- ~16% above
    /// current ~12.1M baseline (4 occupied slots).
    function test_transferShadow_gas_under_block_budget() public {
        ShadowToken.TransferShadowArgs memory args = _buildArgs();
        vm.prank(alice);
        uint256 gasBefore = gasleft();
        st.transferShadow(args);
        uint256 used = gasBefore - gasleft();
        // v2-gas: 4-occ ~6.2M post-sponge-drop. Budget 7M.
        assertLt(used, 7_000_000, "transferShadow gas regressed");
    }
}
