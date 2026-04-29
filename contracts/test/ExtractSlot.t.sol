// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test, stdJson} from "forge-std/Test.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {T10ShadowVerifier} from "../src/T10ShadowVerifier.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {TestableShadowToken, TestableFeatureNFT} from "./Testable.sol";

/// @notice E2E real-proof test for `ShadowToken.extractSlot`.
///
/// extractSlot is proofless on the body; only the bundled shadow_t10
/// refresh proof is required. The fixture
/// (`tools/build_atomic_extract_fixture.py --seed extract_demo`) generates
/// a shadow_t10 proof bound to the post-extract LSH array (target slot
/// becomes 0; rest are 0). The test seeds the chain so the OCCUPIED slot
/// matches `lsh_pre`, calls `extractSlot`, and asserts the carrier's
/// checkpoint, slot zeroing, T10 update, and event emission.
contract ExtractSlotE2ETest is Test {
    using stdJson for string;

    TestableShadowToken internal st;
    TestableFeatureNFT  internal fn;
    T10ShadowVerifier   internal vT10;
    Poseidon2YulSponge  internal sponge;

    string internal constant FIX = "./test/fixtures/atomic_extract/extract_demo";

    bytes internal proofT10;
    bytes32[] internal piT10;

    uint256 internal shadowId;
    uint8   internal slotIdx;
    uint256 internal featureId;
    uint8   internal typeIdx;
    bytes32 internal originFaceId;
    bytes32 internal paletteCommit;
    bytes32 internal lshPre;
    bytes32[2] internal newT10;

    address internal alice = makeAddr("alice");

    uint256 internal constant T10_PI_LEN = 20;

    event SlotExtracted(
        uint256 indexed shadowId,
        uint8   indexed slotIdx,
        uint256 indexed featureId,
        bytes32 finalLiveStateHash
    );
    event ShadowT10Updated(uint256 indexed shadowId, bytes32 hi, bytes32 lo);

    function setUp() public {
        sponge = new Poseidon2YulSponge();
        st = new TestableShadowToken(address(sponge));
        fn = new TestableFeatureNFT(address(st));
        st.setFeatureNFT(IFeatureNFT(address(fn)));
        vT10 = new T10ShadowVerifier();
        st.setVerifier(st.SLOT_T10_SHADOW(), IVerifier(address(vT10)));

        proofT10 = vm.readFileBinary(string.concat(FIX, "/proof_t10.bin"));
        bytes memory raw = vm.readFileBinary(string.concat(FIX, "/public_inputs_t10.bin"));
        require(raw.length == T10_PI_LEN * 32, "PI length mismatch");
        piT10 = new bytes32[](T10_PI_LEN);
        for (uint256 i = 0; i < T10_PI_LEN; i++) {
            bytes32 word;
            assembly { word := mload(add(raw, add(0x20, mul(i, 32)))) }
            piT10[i] = word;
        }

        // Read meta.json for the rest.
        string memory meta = vm.readFile(string.concat(FIX, "/meta.json"));
        shadowId      = vm.parseJsonUint(meta, ".shadow_id");
        slotIdx       = uint8(vm.parseJsonUint(meta, ".slot_idx"));
        featureId     = vm.parseJsonUint(meta, ".feature_id");
        typeIdx       = uint8(vm.parseJsonUint(meta, ".type_idx"));
        originFaceId  = vm.parseJsonBytes32(meta, ".origin_face_id");
        paletteCommit = vm.parseJsonBytes32(meta, ".palette_commit");
        lshPre        = vm.parseJsonBytes32(meta, ".lsh_pre");
        newT10[0]     = vm.parseJsonBytes32(meta, ".t10_hi");
        newT10[1]     = vm.parseJsonBytes32(meta, ".t10_lo");

        // Seed: feature inserted, shadow + manifest with lshPre at slotIdx.
        fn.seedFeature(
            featureId, shadowId, slotIdx, typeIdx,
            originFaceId, paletteCommit, lshPre, alice
        );
        st.seedShadowAndSlot(
            shadowId, alice,
            bytes32(uint256(0xaa)),
            bytes32(uint256(0xbb)),
            slotIdx, featureId, lshPre
        );
    }

    function test_extractSlot_success() public {
        // Pre.
        ShadowToken.ManifestEntry memory mPre = st.slotOf(shadowId, slotIdx);
        assertEq(uint256(mPre.kind), uint256(ShadowToken.SlotKind.OCCUPIED));
        assertEq(mPre.liveStateHash, lshPre);
        assertTrue(fn.isInserted(featureId));

        vm.expectEmit(true, false, false, true);
        emit ShadowT10Updated(shadowId, newT10[0], newT10[1]);
        vm.expectEmit(true, true, true, true);
        emit SlotExtracted(shadowId, slotIdx, featureId, lshPre);

        vm.prank(alice);
        uint256 returnedFid = st.extractSlot(shadowId, slotIdx, newT10, proofT10);
        assertEq(returnedFid, featureId);

        // Post.
        ShadowToken.ManifestEntry memory mPost = st.slotOf(shadowId, slotIdx);
        assertEq(uint256(mPost.kind), uint256(ShadowToken.SlotKind.EMPTY));
        assertEq(mPost.featureId, 0);
        assertEq(mPost.liveStateHash, bytes32(0));

        // Carrier: isInserted cleared, checkpoint synced.
        assertFalse(fn.isInserted(featureId));
        assertEq(fn.liveStateHashCheckpointOf(featureId), lshPre);
        assertEq(fn.hostShadowIdOf(featureId), 0);
        assertEq(fn.hostSlotIdxOf(featureId), 0);

        // T10 written.
        assertEq(st.shadowT10(shadowId, 0), newT10[0]);
        assertEq(st.shadowT10(shadowId, 1), newT10[1]);
    }

    function test_extractSlot_reverts_when_not_owner() public {
        address mallory = makeAddr("mallory");
        vm.prank(mallory);
        vm.expectRevert(ShadowToken.NotShadowOwner.selector);
        st.extractSlot(shadowId, slotIdx, newT10, proofT10);
    }

    function test_extractSlot_reverts_when_slot_empty() public {
        // Slot 7 is EMPTY by default.
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.SlotEmpty.selector, uint8(7)));
        st.extractSlot(shadowId, 7, newT10, proofT10);
    }

    function test_extractSlot_reverts_when_T10_proof_lies() public {
        // Tamper with newT10 hi; the chain's piT10 will diverge from the proof.
        bytes32[2] memory bad;
        bad[0] = bytes32(uint256(newT10[0]) ^ 1);
        bad[1] = newT10[1];
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.extractSlot(shadowId, slotIdx, bad, proofT10);
    }

    /// Gas regression: extractSlot is a single T10 verify + manifest write.
    /// On-chain observed: ~3.4M (B6, E5). Cap at 5M to leave headroom for
    /// future T10 circuit growth.
    function test_extractSlot_gas_under_block_budget() public {
        vm.prank(alice);
        uint256 gasBefore = gasleft();
        st.extractSlot(shadowId, slotIdx, newT10, proofT10);
        uint256 used = gasBefore - gasleft();
        assertLt(used, 5_000_000, "extractSlot gas regressed past 5M");
    }
}
