// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test, stdJson, Vm} from "forge-std/Test.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {MutateSlotVerifier} from "../src/MutateSlotVerifier.sol";
import {T10ShadowVerifier} from "../src/T10ShadowVerifier.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {TestableShadowToken, TestableFeatureNFT} from "./Testable.sol";

/// @notice E2E real-proof test for `ShadowToken.insertFeature`.
///
/// Reuses the `atomic_demo` mutate fixture: per spec Open Q2, the
/// `insertFeature` proof shape is identical to `mutate_slot`. The same
/// proof binding works whether the "old" state lives on a manifest
/// entry (mutate) or on a held FeatureNFT's checkpoint (insert).
///
/// Setup:
///   - carrier minted as INSERTED somewhere, then immediately extracted
///     so isInserted=false and liveStateHashCheckpoint = oldLsh from PI.
///   - destination shadow's slot is EMPTY.
///
/// After insertFeature:
///   - destination slot becomes OCCUPIED with newLsh
///   - carrier becomes inserted at the new host
///   - T10 reflects the new LSH array
///   - ShadowFeatureInserted + ShadowSlotMutated + ShadowT10Updated emitted
contract InsertFeatureE2ETest is Test {
    using stdJson for string;

    TestableShadowToken internal st;
    TestableFeatureNFT internal fn;
    MutateSlotVerifier internal vMut;
    T10ShadowVerifier internal vT10;
    Poseidon2YulSponge internal sponge;

    string internal constant FIX = "./test/fixtures/atomic_mutate/atomic_demo";

    bytes internal proofMut;
    bytes32[] internal piMut;
    bytes internal proofT10;
    bytes32[] internal piT10;
    bytes internal newC2;

    uint256 internal shadowId;
    uint8 internal slotIdx;
    uint256 internal featureId;
    uint8 internal typeIdx;
    bytes32 internal originFaceId;
    bytes32 internal paletteCommit;
    bytes32 internal oldLsh;
    bytes32 internal newLsh;
    bytes32 internal newCtCommit;
    bytes32 internal ownerPkX;
    bytes32 internal ownerPkY;
    bytes32 internal prevChainTip;
    bytes32 internal newChainTip;
    uint16 internal prevMutationCount;
    uint16 internal newMutationCount;

    address internal alice = makeAddr("alice");
    uint256 internal constant SOURCE_SHADOW = 0xDEADBEEF;
    uint8 internal constant SOURCE_SLOT = 9;

    uint256 internal constant MUT_PI_LEN = 16;
    uint256 internal constant T10_PI_LEN = 20;

    event ShadowSlotMutated(
        uint256 indexed shadowId,
        uint8 indexed slotIdx,
        bytes32 indexed originFaceId,
        uint256 featureId,
        uint16 mutationCount,
        bytes32 prevChainTip,
        bytes32 newChainTip,
        bytes c2
    );
    event ShadowFeatureInserted(uint256 indexed shadowId, uint8 indexed slotIdx, uint256 indexed featureId);
    event ShadowT10Updated(uint256 indexed shadowId, bytes32 hi, bytes32 lo);

    function setUp() public {
        sponge = new Poseidon2YulSponge();
        st = new TestableShadowToken(address(sponge));
        fn = new TestableFeatureNFT(address(st));
        st.setFeatureNFT(IFeatureNFT(address(fn)));
        vMut = new MutateSlotVerifier();
        vT10 = new T10ShadowVerifier();
        st.setVerifier(st.SLOT_MUTATE_SLOT(), IVerifier(address(vMut)));
        st.setVerifier(st.SLOT_T10_SHADOW(), IVerifier(address(vT10)));

        proofMut = vm.readFileBinary(string.concat(FIX, "/proof_mut.bin"));
        piMut = _loadFields(string.concat(FIX, "/public_inputs_mut.bin"), MUT_PI_LEN);
        proofT10 = vm.readFileBinary(string.concat(FIX, "/proof_t10.bin"));
        piT10 = _loadFields(string.concat(FIX, "/public_inputs_t10.bin"), T10_PI_LEN);
        newC2 = vm.readFileBinary(string.concat(FIX, "/c2.bin"));

        shadowId = uint256(piMut[0]);
        slotIdx = uint8(uint256(piMut[1]));
        featureId = uint256(piMut[2]);
        typeIdx = uint8(uint256(piMut[3]));
        originFaceId = piMut[4];
        paletteCommit = piMut[5];
        oldLsh = piMut[6];
        newLsh = piMut[7];
        newCtCommit = piMut[8];
        ownerPkX = piMut[10];
        ownerPkY = piMut[11];
        prevChainTip = piMut[12];
        newChainTip = piMut[13];
        prevMutationCount = uint16(uint256(piMut[14]));
        newMutationCount = uint16(uint256(piMut[15]));

        // Seed: carrier was at SOURCE_SHADOW slot SOURCE_SLOT, then extracted
        // (so isInserted=false, checkpoint=oldLsh). Destination shadow has
        // an EMPTY slot at slotIdx.
        fn.seedFeature(featureId, SOURCE_SHADOW, SOURCE_SLOT, typeIdx, originFaceId, paletteCommit, oldLsh, alice);
        // Force the seeded carrier to the held state (matches a post-extract carrier).
        // We do this with a storage poke since the v2 carrier API does not
        // expose a "release without sync" helper outside extractFromShadow.
        // _features mapping is at slot 11; Feature struct layout: typeIdx (slot 0
        // byte 0), originFaceId (slot 1), paletteCommit (slot 2), mintedAt (slot 0
        // byte 1+), liveStateHashCheckpoint (slot 3), isInserted (slot 4 byte 0),
        // hostShadowId (slot 5), hostSlotIdx (slot 4 byte 1).
        // Simpler: use FeatureNFT.extractFromShadow via the shadowToken-only gate.
        // Trick: shadowToken is a contract; we vm.prank to it.
        vm.prank(address(st));
        fn.extractFromShadow(featureId, SOURCE_SHADOW, SOURCE_SLOT, oldLsh);

        // Destination shadow with NO manifest entries (all slots EMPTY).
        // The atomic_demo T10 proof was built against the LSH array with
        // only slot[3]=newLsh post-mutate; in our insert scenario, the
        // pre-insert state is all-zero, and post-insert is slot[3]=newLsh,
        // matching the same proof.
        st.seedShadowOnly(shadowId, alice, ownerPkX, ownerPkY);
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

    function _writeField(bytes memory data, uint256 fieldIndex, uint256 value) internal pure {
        assembly { mstore(add(add(data, 32), mul(fieldIndex, 32)), value) }
    }

    function _decodeShadowSlotMutatedC2(bytes memory data) internal pure returns (bytes memory emittedC2) {
        (uint256 featureId_, uint16 count_, bytes32 prevTip_, bytes32 newTip_, bytes memory c2_) =
            abi.decode(data, (uint256, uint16, bytes32, bytes32, bytes));
        featureId_;
        count_;
        prevTip_;
        newTip_;
        return c2_;
    }

    function _buildArgs() internal view returns (ShadowToken.InsertFeatureArgs memory args) {
        bytes32[2] memory newT10;
        newT10[0] = piT10[2];
        newT10[1] = piT10[3];
        return ShadowToken.InsertFeatureArgs({
            shadowId: shadowId,
            slotIdx: slotIdx,
            featureId: featureId,
            proofInsert: proofMut,
            newC1X: 0,
            newC1Y: 0,
            newLiveStateHash: newLsh,
            newCtCommit: newCtCommit,
            c2FieldCount: uint16(newC2.length / 32),
            c2: newC2,
            prevChainTip: prevChainTip,
            newChainTip: newChainTip,
            prevMutationCount: prevMutationCount,
            newMutationCount: newMutationCount,
            newT10: newT10,
            proofT10: proofT10
        });
    }

    function test_insertFeature_success_advances_state_and_T10() public {
        ShadowToken.InsertFeatureArgs memory args = _buildArgs();

        // Pre-state.
        assertEq(uint256(st.slotOf(shadowId, slotIdx).kind), uint256(ShadowToken.SlotKind.EMPTY));
        assertFalse(fn.isInserted(featureId));
        assertEq(fn.liveStateHashCheckpointOf(featureId), oldLsh);

        // Capture all logs across the call; assert ShadowToken-emitted events
        // independently. (Inline expectEmit cannot reliably distinguish the
        // FeatureNFT.FeatureInserted vs ShadowToken.ShadowFeatureInserted pair.)
        vm.recordLogs();

        vm.prank(alice);
        st.insertFeature(args);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool sawT10 = false;
        bool sawFeatureInserted = false;
        bool sawSlotMutated = false;
        bytes32 sigT10 = keccak256("ShadowT10Updated(uint256,bytes32,bytes32)");
        bytes32 sigFI = keccak256("ShadowFeatureInserted(uint256,uint8,uint256)");
        bytes32 sigSM = keccak256("ShadowSlotMutated(uint256,uint8,bytes32,uint256,uint16,bytes32,bytes32,bytes)");
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter != address(st)) continue;
            if (logs[i].topics[0] == sigT10) {
                sawT10 = true;
            } else if (logs[i].topics[0] == sigFI) {
                sawFeatureInserted = true;
            } else if (logs[i].topics[0] == sigSM) {
                bytes memory emittedC2 = _decodeShadowSlotMutatedC2(logs[i].data);
                assertEq(emittedC2, args.c2, "insert ShadowSlotMutated c2");
                sawSlotMutated = true;
            }
        }
        assertTrue(sawT10, "ShadowT10Updated emitted");
        assertTrue(sawFeatureInserted, "ShadowFeatureInserted emitted");
        assertTrue(sawSlotMutated, "ShadowSlotMutated emitted");

        // Post-state.
        ShadowToken.ManifestEntry memory mPost = st.slotOf(shadowId, slotIdx);
        assertEq(uint256(mPost.kind), uint256(ShadowToken.SlotKind.OCCUPIED));
        assertEq(mPost.featureId, featureId);
        assertEq(mPost.liveStateHash, newLsh);

        assertTrue(fn.isInserted(featureId));
        assertEq(fn.hostShadowIdOf(featureId), shadowId);
        assertEq(fn.hostSlotIdxOf(featureId), slotIdx);
        // Checkpoint stays stale until next extract.
        assertEq(fn.liveStateHashCheckpointOf(featureId), oldLsh);

        assertEq(st.shadowT10(shadowId, 0), args.newT10[0]);
        assertEq(st.shadowT10(shadowId, 1), args.newT10[1]);
    }

    function test_insertFeature_reverts_when_carrier_already_inserted() public {
        // Force the carrier back to inserted state via the privileged path.
        vm.prank(address(st));
        fn.insertIntoShadow(featureId, SOURCE_SHADOW, SOURCE_SLOT);

        ShadowToken.InsertFeatureArgs memory args = _buildArgs();
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.FeatureAlreadyInserted.selector, featureId));
        st.insertFeature(args);
    }

    function test_insertFeature_reverts_when_slot_occupied() public {
        // Pre-occupy the destination slot via storage poke (avoid double-mint).
        // _manifests mapping is slot 21; ManifestEntry now spans 5 storage slots.
        bytes32 outerBase = keccak256(abi.encode(shadowId, uint256(21)));
        bytes32 entryBase = bytes32(uint256(outerBase) + uint256(slotIdx) * 5);
        // entry slot 0: kind packed in low byte (1 = OCCUPIED)
        vm.store(address(st), entryBase, bytes32(uint256(1)));

        ShadowToken.InsertFeatureArgs memory args = _buildArgs();
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.SlotOccupied.selector, slotIdx));
        st.insertFeature(args);
    }

    function test_insertFeature_reverts_when_caller_not_shadow_owner() public {
        // Caller is not the shadow's owner (alice is). NotShadowOwner check fires
        // before the carrier-owner check.
        address mallory = makeAddr("mallory");
        ShadowToken.InsertFeatureArgs memory args = _buildArgs();
        vm.prank(mallory);
        vm.expectRevert(ShadowToken.NotShadowOwner.selector);
        st.insertFeature(args);
    }

    /// Envelope-binding cutover (audit H-02): tampered c2 in insertFeature
    /// MUST revert. Pre-cutover the c2 calldata was advisory and only the
    /// proof-bound newCtCommit was authoritative. The contract now
    /// STATICCALLs sponge_39 over args.c2 and asserts equality with
    /// args.newCtCommit before any FN.insertIntoShadow / manifest write.
    function test_insertFeature_reverts_when_c2_tampered() public {
        ShadowToken.InsertFeatureArgs memory args = _buildArgs();
        // Snapshot pre-state so revert atomicity is provable.
        ShadowToken.SlotKind kindBefore = st.slotOf(shadowId, slotIdx).kind;
        args.c2[7] = bytes1(uint8(args.c2[7]) ^ 0x01);
        vm.prank(alice);
        vm.expectRevert();
        st.insertFeature(args);
        assertEq(
            uint256(st.slotOf(shadowId, slotIdx).kind), uint256(kindBefore), "slot kind unchanged on tampered-c2 revert"
        );
    }

    function test_insertFeature_reverts_when_c2_field_noncanonical() public {
        ShadowToken.InsertFeatureArgs memory args = _buildArgs();
        ShadowToken.SlotKind kindBefore = st.slotOf(shadowId, slotIdx).kind;
        uint256 fr = st.FR_MOD();
        _writeField(args.c2, 0, fr);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.NonCanonicalField.selector, uint256(0), fr));
        st.insertFeature(args);
        assertEq(uint256(st.slotOf(shadowId, slotIdx).kind), uint256(kindBefore), "slot kind unchanged");
        assertFalse(fn.isInserted(featureId), "feature remains held");
    }

    function _featureCheckpointSlot(uint256 id) internal returns (bytes32) {
        bytes32 baseSlot = keccak256(abi.encode(id, uint256(12)));
        bytes32 originalCheckpoint = fn.liveStateHashCheckpointOf(id);
        bytes32 sentinel = bytes32(uint256(0xA11CE));
        for (uint256 offset = 0; offset < 8; offset++) {
            bytes32 slot = bytes32(uint256(baseSlot) + offset);
            bytes32 oldWord = vm.load(address(fn), slot);
            vm.store(address(fn), slot, sentinel);
            bool matched = fn.liveStateHashCheckpointOf(id) == sentinel;
            vm.store(address(fn), slot, oldWord);
            if (matched) {
                assertEq(fn.liveStateHashCheckpointOf(id), originalCheckpoint, "checkpoint restored after slot probe");
                return slot;
            }
        }
        revert("checkpoint slot not found");
    }

    function test_insertFeature_reverts_when_proof_public_input_tampered() public {
        ShadowToken.InsertFeatureArgs memory args = _buildArgs();
        args.proofInsert[args.proofInsert.length / 2] =
            bytes1(uint8(args.proofInsert[args.proofInsert.length / 2]) ^ 0x01);

        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.insertFeature(args);
        assertFalse(fn.isInserted(featureId), "feature remains held");
    }

    function test_insertFeature_reverts_when_checkpoint_old_lsh_mismatch() public {
        bytes32 checkpointSlot = _featureCheckpointSlot(featureId);
        vm.store(address(fn), checkpointSlot, bytes32(uint256(oldLsh) ^ 1));
        assertEq(fn.liveStateHashCheckpointOf(featureId), bytes32(uint256(oldLsh) ^ 1), "checkpoint tampered");

        ShadowToken.InsertFeatureArgs memory args = _buildArgs();
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.insertFeature(args);
        assertFalse(fn.isInserted(featureId), "feature remains held");
    }

    function test_insertFeature_reverts_when_t10_public_input_tampered() public {
        ShadowToken.InsertFeatureArgs memory args = _buildArgs();
        args.newT10[0] = bytes32(uint256(args.newT10[0]) ^ 1);

        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.insertFeature(args);
        assertFalse(fn.isInserted(featureId), "feature remains held");
    }

    /// Gas regression: insertFeature does a mutate_slot verify (proves the
    /// re-encryption) + a T10 verify + manifest writes + carrier rotation.
    /// On-chain observed: ~7.3M (B7, E6). Cap at 9M.
    function test_insertFeature_gas_under_block_budget() public {
        ShadowToken.InsertFeatureArgs memory args = _buildArgs();
        vm.prank(alice);
        uint256 gasBefore = gasleft();
        st.insertFeature(args);
        uint256 used = gasBefore - gasleft();
        assertLt(used, 9_000_000, "insertFeature gas regressed past 9M");
    }
}
