// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {TestableShadowToken} from "./Testable.sol";

/// @dev Gas-only verifier double. It removes cryptographic verifier cost so the
///      max-occupancy reveal chunk overhead can be measured independently. Real
///      proof coverage for the same verifier surface lives in
///      `SolveShadowRealProof.t.sol`, `GeneratedVerifierMatrix.t.sol`, and
///      `ProofFuzz.t.sol`.
contract AlwaysOkFeatureRevealVerifier is IVerifier {
    function verify(bytes calldata, bytes32[] calldata publicInputs) external pure returns (bool) {
        return publicInputs.length == 9 || publicInputs.length == 20;
    }
}

/// @dev Minimal `IFeatureNFT` double for max-occupancy reveal gas measurement.
///      It records reveal state only; real FeatureNFT behavior is covered by
///      `FeatureNFT.t.sol` and the real-proof reveal integration test.
contract MaxRevealFeatureNFT is IFeatureNFT {
    struct FeatureState {
        address owner;
        uint256 hostShadowId;
        uint8 hostSlotIdx;
        bytes32 originFaceId;
        bytes32 paletteCommit;
        bytes32 liveStateHash;
        bool inserted;
        bool revealed;
    }

    mapping(uint256 => FeatureState) internal features;

    function seed(uint256 featureId, address owner, uint256 shadowId, uint8 slotIdx, bytes32 originFaceId, bytes32 paletteCommit, bytes32 lsh) external {
        features[featureId] = FeatureState(owner, shadowId, slotIdx, originFaceId, paletteCommit, lsh, true, false);
    }

    function mintAtShadowMint(uint256, uint8, uint8, bytes32, PaletteAtMint calldata, bytes32, address) external pure returns (uint256) { revert("unused"); }
    function extractFromShadow(uint256 featureId, uint256, uint8, bytes32 finalLiveStateHash) external { features[featureId].liveStateHash = finalLiveStateHash; features[featureId].inserted = false; }
    function insertIntoShadow(uint256, uint256, uint8) external pure { revert("unused"); }
    function rotateInsertedOwner(uint256 featureId, uint256, address to) external { features[featureId].owner = to; }
    function revealInsertedFeature(uint256 featureId, uint256, uint8, bytes32[16] calldata, bytes32, bytes calldata) external { features[featureId].revealed = true; }
    function ownerOfFeature(uint256 featureId) external view returns (address) { return features[featureId].owner; }
    function typeIdxOf(uint256) external pure returns (uint8) { return 0; }
    function originFaceIdOf(uint256 featureId) external view returns (bytes32) { return features[featureId].originFaceId; }
    function paletteCommitOf(uint256 featureId) external view returns (bytes32) { return features[featureId].paletteCommit; }
    function liveStateHashCheckpointOf(uint256 featureId) external view returns (bytes32) { return features[featureId].liveStateHash; }
    function isInserted(uint256 featureId) external view returns (bool) { return features[featureId].inserted; }
    function hostShadowIdOf(uint256 featureId) external view returns (uint256) { return features[featureId].hostShadowId; }
    function hostSlotIdxOf(uint256 featureId) external view returns (uint8) { return features[featureId].hostSlotIdx; }
    function paletteRevealedOf(uint256 featureId) external view returns (bool) { return features[featureId].revealed; }
}

/// @notice Max-occupancy gas regression for incremental feature reveal.
/// @dev Uses verifier/feature doubles to isolate contract overhead only. Real
///      generated-verifier gas and proof validity are measured by the real-proof
///      fixture tests named above, not by this gas diagnostic.
contract SolveShadowMaxOccupancyTest is Test {
    TestableShadowToken internal st;
    Poseidon2YulSponge internal sponge;
    MaxRevealFeatureNFT internal fn;
    AlwaysOkFeatureRevealVerifier internal verifier;

    address internal alice = makeAddr("alice");
    uint256 internal constant SHADOW_ID = 777;

    function setUp() public {
        sponge = new Poseidon2YulSponge();
        verifier = new AlwaysOkFeatureRevealVerifier();
        st = new TestableShadowToken(address(sponge));
        fn = new MaxRevealFeatureNFT();
        st.setFeatureNFT(IFeatureNFT(address(fn)));
        st.setVerifier(3, IVerifier(address(verifier)));
        st.setVerifier(6, IVerifier(address(verifier)));

        uint8[] memory slots = new uint8[](16);
        uint256[] memory featureIds = new uint256[](16);
        bytes32[] memory liveStateHashes = new bytes32[](16);
        for (uint8 i = 0; i < 16; i++) {
            slots[i] = i;
            featureIds[i] = 10_000 + i;
            liveStateHashes[i] = bytes32(uint256(i + 1));
            fn.seed(10_000 + i, alice, SHADOW_ID, i, bytes32(uint256(20_000 + i)), bytes32(uint256(30_000 + i)), liveStateHashes[i]);
        }
        st.seedShadowMultiSlot(SHADOW_ID, alice, bytes32(uint256(1)), bytes32(uint256(2)), slots, featureIds, liveStateHashes);
        st.setShadowZIndexCommitForTest(SHADOW_ID, bytes32(uint256(3)));
    }

    function test_incrementalReveal_max_occupancy_succeeds_without_extracting_slots() public {
        _revealAllSlots();

        (,, bool solved,) = st.shadowHeaderOf(SHADOW_ID);
        assertTrue(solved, "fully revealed");
        for (uint8 i = 0; i < 16; i++) {
            ShadowToken.ManifestEntry memory m = st.slotOf(SHADOW_ID, i);
            assertEq(uint256(m.kind), uint256(ShadowToken.SlotKind.REVEALED), "carrier remains locked and public");
            assertEq(m.featureId, 10_000 + i, "feature id retained");
            assertTrue(fn.paletteRevealedOf(10_000 + i), "feature revealed");
        }
    }

    function test_incrementalReveal_4_slot_chunk_gas_under_16m_contract_overhead() public {
        (uint256 total, uint256 maxChunk) = _revealAllSlotsMeasured(4);
        emit log_named_uint("incremental reveal 16 occ total mocked gas", total);
        emit log_named_uint("incremental reveal 4-slot max mocked tx gas", maxChunk);

        assertLt(maxChunk, 16_000_000, "incremental reveal chunk overhead exceeds 16M");
    }

    function _revealAllSlots() internal {
        vm.startPrank(alice);
        for (uint8 i = 0; i < 16; i++) {
            ShadowToken.RevealSlotArgs[] memory reveals = new ShadowToken.RevealSlotArgs[](1);
            reveals[0] = _revealArgs(i);
            st.revealSlots(SHADOW_ID, reveals);
        }
        vm.stopPrank();
    }

    function _revealAllSlotsMeasured(uint8 chunkSize) internal returns (uint256 total, uint256 maxChunk) {
        vm.startPrank(alice);
        for (uint8 start = 0; start < 16; start += chunkSize) {
            uint8 n = start + chunkSize > 16 ? 16 - start : chunkSize;
            ShadowToken.RevealSlotArgs[] memory reveals = new ShadowToken.RevealSlotArgs[](n);
            for (uint8 j = 0; j < n; j++) {
                reveals[j] = _revealArgs(start + j);
            }
            uint256 gasBefore = gasleft();
            st.revealSlots(SHADOW_ID, reveals);
            uint256 used = gasBefore - gasleft();
            total += used;
            if (used > maxChunk) maxChunk = used;
        }
        vm.stopPrank();
    }

    function _revealArgs(uint8 slotIdx) internal pure returns (ShadowToken.RevealSlotArgs memory args) {
        args.slotIdx = slotIdx;
        args.proof = hex"01";
        args.plaintext = new bytes(39 * 32);
        args.revealedRank = slotIdx;
        args.newT10 = [bytes32(uint256(1)), bytes32(uint256(2))];
        args.proofT10 = hex"10";
    }
}
