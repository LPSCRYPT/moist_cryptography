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

/// @notice Real-proof test for chained mutations on the SAME slot.
///
/// Complements ReplayProtection.t.sol's negative case:
///   ReplayProtection: proves a STALE proof (re-submit identical args)
///                     fails after chain advance.
///   ChainedMutate:    proves a FRESH proof bound to the current chain
///                     state succeeds, and the chain advances byte-equal
///                     to the prover's witness.
///
/// Fixture (`tools/build_chained_mutate_fixture.py --seed chained_demo`)
/// produces:
///   - proof_m1 / public_inputs_m1: mint-time -> state_A
///       (count 0 -> 1, chain_tip 0_genesis -> ct_1, lsh 0_init -> lsh_1)
///   - proof_m2 / public_inputs_m2: state_A -> state_B
///       (count 1 -> 2, chain_tip ct_1 -> ct_2, lsh lsh_1 -> lsh_2)
///   - proof_t10_after_m1: T10 bound to manifest with slot[3]=lsh_1
///   - proof_t10_after_m2: T10 bound to manifest with slot[3]=lsh_2
///
/// What this pins:
///   1. The chain DOES advance correctly: M2's prev_chain_tip == M1's
///      new_chain_tip. The fixture builder asserts this; the test
///      indirectly verifies it via successful M2 verification on chain.
///   2. The carrier identity (featureId, originFaceId, paletteCommit)
///      is STABLE across mutations on the same slot. Only the slot's
///      pose/dims/indices change.
///   3. Two consecutive `mutateSlot` calls on the same slot don't
///      desync any of: manifest LSH, shadowT10, ERC-721 ownership,
///      mutation count emitted in events.
contract ChainedMutateTest is Test {
    using stdJson for string;

    TestableShadowToken internal st;
    TestableFeatureNFT  internal fn;
    MutateSlotVerifier  internal vMut;
    T10ShadowVerifier   internal vT10;
    Poseidon2YulSponge  internal sponge;

    string internal constant FIX = "./test/fixtures/chained_mutate/chained_demo";

    address internal alice = makeAddr("alice");

    // Per-step witness fields parsed from public_inputs_*.bin.
    // Layout matches the mutate_slot circuit's 16-field PI:
    //   PI[0]  shadow_id
    //   PI[1]  slot_idx
    //   PI[2]  feature_id
    //   PI[3]  type_idx
    //   PI[4]  origin_face_id
    //   PI[5]  palette_commit
    //   PI[6]  old_lsh
    //   PI[7]  new_lsh
    //   PI[8]  new_ct_commit
    //   PI[9]  c2_field_count (always 39 in v2)
    //   PI[10] owner_pk_x
    //   PI[11] owner_pk_y
    //   PI[12] prev_chain_tip
    //   PI[13] new_chain_tip
    //   PI[14] prev_mutation_count
    //   PI[15] new_mutation_count
    struct Step {
        bytes proof;
        bytes32[] pi;
        bytes c2;
        bytes32 t10Hi;
        bytes32 t10Lo;
        bytes proofT10;
    }

    Step internal m1;
    Step internal m2;
    uint256 internal shadowId;
    uint8   internal slotIdx;
    uint256 internal featureId;
    bytes32 internal originFaceId;
    bytes32 internal paletteCommit;

    event ShadowSlotMutated(
        uint256 indexed shadowId,
        uint8   indexed slotIdx,
        bytes32 indexed originFaceId,
        uint256 featureId,
        uint16  mutationCount,
        bytes32 prevChainTip,
        bytes32 newChainTip,
        bytes   c2
    );
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

        _loadStep(m1, "_m1", "_t10_after_m1");
        _loadStep(m2, "_m2", "_t10_after_m2");

        // Pull stable identities from M1's PI. These must match M2's PI;
        // we sanity-check below.
        shadowId      = uint256(m1.pi[0]);
        slotIdx       = uint8(uint256(m1.pi[1]));
        featureId     = uint256(m1.pi[2]);
        originFaceId  = m1.pi[4];
        paletteCommit = m1.pi[5];

        // Sanity: chained mutations on the same slot bind the same
        // carrier identity. If the fixture builder regressed, this fails.
        assertEq(uint256(m2.pi[0]), shadowId,                   "shadow_id stable");
        assertEq(uint8(uint256(m2.pi[1])), slotIdx,             "slot_idx stable");
        assertEq(uint256(m2.pi[2]), featureId,                  "feature_id stable");
        assertEq(m2.pi[4], originFaceId,                        "origin_face_id stable");
        assertEq(m2.pi[5], paletteCommit,                       "palette_commit stable");
        // Chain-step continuity: M2.old_lsh == M1.new_lsh, etc.
        assertEq(m2.pi[6], m1.pi[7],                            "M2.old_lsh == M1.new_lsh");
        assertEq(m2.pi[12], m1.pi[13],                          "M2.prev_chain_tip == M1.new_chain_tip");
        assertEq(uint16(uint256(m2.pi[14])), uint16(uint256(m1.pi[15])), "M2.prev_count == M1.new_count");

        // Seed: feature inserted, shadow + manifest with M1.old_lsh at slotIdx.
        bytes32 ownerPkX = m1.pi[10];
        bytes32 ownerPkY = m1.pi[11];
        bytes32 m1OldLsh = m1.pi[6];

        fn.seedFeature(
            featureId, shadowId, slotIdx, uint8(uint256(m1.pi[3])),
            originFaceId, paletteCommit, m1OldLsh, alice
        );
        st.seedShadowAndSlot(
            shadowId, alice, ownerPkX, ownerPkY,
            slotIdx, featureId, m1OldLsh
        );
    }

    function _loadStep(Step storage s, string memory mutSuffix, string memory t10Suffix) internal {
        s.proof = vm.readFileBinary(string.concat(FIX, "/proof", mutSuffix, ".bin"));
        s.pi    = _loadFields(string.concat(FIX, "/public_inputs", mutSuffix, ".bin"), 16);
        s.c2    = vm.readFileBinary(string.concat(FIX, "/c2", mutSuffix, ".bin"));
        s.proofT10 = vm.readFileBinary(string.concat(FIX, "/proof", t10Suffix, ".bin"));

        string memory meta = vm.readFile(string.concat(FIX, "/meta.json"));
        // Read t10 hi/lo from meta. Path: .t10_after_m1.hi etc.
        // mutSuffix "_m1" -> meta path "t10_after_m1"
        string memory metaKey = string.concat("t10_after", mutSuffix);
        s.t10Hi = vm.parseJsonBytes32(meta, string.concat(".", metaKey, ".hi"));
        s.t10Lo = vm.parseJsonBytes32(meta, string.concat(".", metaKey, ".lo"));
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

    function _buildArgs(Step storage s) internal view returns (ShadowToken.MutateSlotArgs memory args) {
        bytes32[2] memory newT10;
        newT10[0] = s.t10Hi;
        newT10[1] = s.t10Lo;
        args = ShadowToken.MutateSlotArgs({
            shadowId: uint256(s.pi[0]),
            slotIdx:  uint8(uint256(s.pi[1])),
            proofMutate: s.proof,
            newC1X: 0, newC1Y: 0,
            newLiveStateHash: s.pi[7],
            newCtCommit:      s.pi[8],
            c2FieldCount: uint16(s.c2.length / 32),
            c2: s.c2,
            prevChainTip: s.pi[12],
            newChainTip:  s.pi[13],
            prevMutationCount: uint16(uint256(s.pi[14])),
            newMutationCount:  uint16(uint256(s.pi[15])),
            newT10: newT10,
            proofT10: s.proofT10
        });
    }

    /// Two chained mutations on the same slot succeed. The chain advances
    /// byte-equal to each step's witness output:
    ///   - manifest[slot].liveStateHash: m1.old_lsh -> m1.new_lsh -> m2.new_lsh
    ///   - shadowT10: 0 -> t10_after_m1 -> t10_after_m2
    ///   - mutation_count emitted in events: 0 -> 1 -> 2
    function test_chained_mutate_advances_chain_byte_equal() public {
        ShadowToken.MutateSlotArgs memory args1 = _buildArgs(m1);
        ShadowToken.MutateSlotArgs memory args2 = _buildArgs(m2);

        // ---- M1 ----
        vm.recordLogs();
        vm.prank(alice);
        st.mutateSlot(args1);

        // Post-M1 storage.
        ShadowToken.ManifestEntry memory mPostM1 = st.slotOf(shadowId, slotIdx);
        assertEq(mPostM1.liveStateHash, m1.pi[7], "M1: lsh = m1.new_lsh");
        assertEq(uint256(mPostM1.kind), uint256(ShadowToken.SlotKind.OCCUPIED));
        assertEq(st.shadowT10(shadowId, 0), m1.t10Hi, "M1: T10 hi");
        assertEq(st.shadowT10(shadowId, 1), m1.t10Lo, "M1: T10 lo");
        // Carrier identity unchanged.
        assertEq(fn.ownerOf(featureId), alice, "M1: carrier still owned");
        assertEq(fn.originFaceIdOf(featureId), originFaceId, "M1: originFaceId stable");
        assertEq(fn.paletteCommitOf(featureId), paletteCommit, "M1: paletteCommit stable");

        Vm.Log[] memory logs1 = vm.getRecordedLogs();
        _assertSlotMutatedEmitted(logs1, m1.pi[15], m1.pi[12], m1.pi[13], "M1");

        // ---- M2 (chained: prev=M1.new_*) ----
        vm.recordLogs();
        vm.prank(alice);
        st.mutateSlot(args2);

        // Post-M2 storage.
        ShadowToken.ManifestEntry memory mPostM2 = st.slotOf(shadowId, slotIdx);
        assertEq(mPostM2.liveStateHash, m2.pi[7], "M2: lsh = m2.new_lsh");
        assertEq(uint256(mPostM2.kind), uint256(ShadowToken.SlotKind.OCCUPIED));
        assertEq(st.shadowT10(shadowId, 0), m2.t10Hi, "M2: T10 hi (overwrites M1's)");
        assertEq(st.shadowT10(shadowId, 1), m2.t10Lo, "M2: T10 lo (overwrites M1's)");
        assertEq(fn.ownerOf(featureId), alice, "M2: carrier still owned");
        // Single-host invariant: feature still inserted at same shadow+slot.
        assertTrue(fn.isInserted(featureId), "M2: feature still inserted");
        assertEq(fn.hostShadowIdOf(featureId), shadowId, "M2: hostShadowId stable");
        assertEq(fn.hostSlotIdxOf(featureId), slotIdx, "M2: hostSlotIdx stable");

        Vm.Log[] memory logs2 = vm.getRecordedLogs();
        _assertSlotMutatedEmitted(logs2, m2.pi[15], m2.pi[12], m2.pi[13], "M2");

        // Cross-step invariant: mutation count strictly monotonic (0 -> 1 -> 2).
        assertEq(uint16(uint256(m1.pi[15])), 1, "M1.new_count == 1");
        assertEq(uint16(uint256(m2.pi[15])), 2, "M2.new_count == 2");
    }

    /// Negative case: M2's proof is bound to M1's post-state. Replaying
    /// it BEFORE M1 has run -- against the mint-time chain -- must fail
    /// because the chain reads m1.old_lsh from storage, not m1.new_lsh.
    /// Pins that M2 cannot be applied out-of-order.
    function test_chained_mutate_M2_fails_without_M1_first() public {
        ShadowToken.MutateSlotArgs memory args2 = _buildArgs(m2);
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.mutateSlot(args2);
    }

    function _assertSlotMutatedEmitted(
        Vm.Log[] memory logs,
        bytes32 expectedNewCount,
        bytes32 expectedPrevChainTip,
        bytes32 expectedNewChainTip,
        string memory label
    ) internal view {
        bytes32 sig = keccak256("ShadowSlotMutated(uint256,uint8,bytes32,uint256,uint16,bytes32,bytes32,bytes)");
        bool seen = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter != address(st)) continue;
            if (logs[i].topics[0] != sig) continue;
            seen = true;
            (uint256 fid, uint16 count, bytes32 prevCT, bytes32 newCT, ) =
                abi.decode(logs[i].data, (uint256, uint16, bytes32, bytes32, bytes));
            assertEq(fid, featureId, string.concat(label, ": event featureId"));
            assertEq(count, uint16(uint256(expectedNewCount)),
                     string.concat(label, ": event new_count"));
            assertEq(prevCT, expectedPrevChainTip,
                     string.concat(label, ": event prev_chain_tip"));
            assertEq(newCT, expectedNewChainTip,
                     string.concat(label, ": event new_chain_tip"));
        }
        assertTrue(seen, string.concat(label, ": ShadowSlotMutated emitted"));
    }
}
