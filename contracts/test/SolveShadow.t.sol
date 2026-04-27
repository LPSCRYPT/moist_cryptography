// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test, stdJson, Vm} from "forge-std/Test.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {SolveShadowVerifier} from "../src/SolveShadowVerifier.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {Poseidon2YulSponge16} from "../src/Poseidon2YulSponge16.sol";
import {TestableShadowToken, TestableFeatureNFT} from "./Testable.sol";

/// @notice Real-proof e2e test for `ShadowToken.solve`.
///
/// Loads the solve_shadow_v2 fixture, seeds the chain to match the prover's
/// witness, then calls solve(). Asserts:
///   - shadow.solved = true
///   - shadow.zIndexRevealed matches the witnessed permutation packed
///   - every occupied slot becomes EMPTY
///   - every carrier becomes uninserted (host fields cleared, checkpoint synced)
///   - SlotExtracted events fired for every previously-occupied slot
///   - ShadowSolved event fired
contract SolveShadowE2ETest is Test {
    using stdJson for string;

    TestableShadowToken  internal st;
    TestableFeatureNFT   internal fn;
    SolveShadowVerifier  internal vS;
    Poseidon2YulSponge   internal sponge;
    Poseidon2YulSponge16 internal sponge16;

    string internal constant FIX = "./test/fixtures/solve_shadow_v2/solve_demo";

    bytes internal proofSolve;
    bytes32[] internal piSolve;

    uint256 internal shadowId;
    bytes32 internal stateCommitsRoot;
    bytes32 internal zPermPacked;
    bytes32 internal zIndexCommit;
    bytes32 internal lshRoot;
    bytes32 internal ownerPkX;
    bytes32 internal ownerPkY;

    address internal alice = makeAddr("alice");

    uint256 internal constant SOLVE_PI_LEN = 7;

    uint8[]   internal occupiedIdxs;
    uint256[] internal featureIds;
    bytes32[16] internal prevLsh;
    bytes32[16] internal stateCommits;
    bytes[16] internal plaintextBytes;
    uint8[16] internal zPerm;

    function setUp() public {
        sponge = new Poseidon2YulSponge();
        sponge16 = new Poseidon2YulSponge16();
        st = new TestableShadowToken(address(sponge));
        fn = new TestableFeatureNFT(address(st));
        st.setFeatureNFT(IFeatureNFT(address(fn)));
        st.setYulSponge16(address(sponge16));
        vS = new SolveShadowVerifier();
        st.setSolveShadowVerifier(IVerifier(address(vS)));

        proofSolve = vm.readFileBinary(string.concat(FIX, "/proof.bin"));
        piSolve    = _loadFields(string.concat(FIX, "/public_inputs.bin"), SOLVE_PI_LEN);

        shadowId         = uint256(piSolve[0]);
        stateCommitsRoot = piSolve[1];
        zPermPacked      = piSolve[2];
        zIndexCommit     = piSolve[3];
        lshRoot          = piSolve[4];
        ownerPkX         = piSolve[5];
        ownerPkY         = piSolve[6];

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
        for (uint256 i = 0; i < 16; i++) {
            string memory idx = vm.toString(i);
            prevLsh[i]      = j.readBytes32(string.concat(".prev_lsh[", idx, "]"));
            stateCommits[i] = j.readBytes32(string.concat(".state_commits[", idx, "]"));
            zPerm[i]        = uint8(j.readUint(string.concat(".z_perm[", idx, "]")));
        }
        uint256[] memory occ = j.readUintArray(".occupied_idxs");
        occupiedIdxs = new uint8[](occ.length);
        for (uint256 i = 0; i < occ.length; i++) {
            occupiedIdxs[i] = uint8(occ[i]);
        }

        // Per-slot c2-style plaintexts. The fixture doesn't ship the raw
        // 39-Field plaintexts directly (they're sensitive even in test).
        // Reconstruct them by sponge_39 against the witnessed state_commit.
        // For the test we don't need the raw plaintext bytes — we need a
        // bytes blob whose sponge_39 == stateCommits[i] for occupied slots.
        // The fixture's Prover.toml has them, but we can also run sponge_39
        // off-line. Easiest: synth deterministic plaintexts here that match
        // the fixture's encode_plaintext_v2(pose, w, h, indices) output.
        //
        // Actually: since we don't have direct access to plaintext bytes
        // here, we'll fall back to reading them from circuits/Prover.toml
        // which the fixture builder always writes. But that's brittle.
        //
        // Cleanest: extend the fixture meta.json to include per-slot
        // plaintext bytes. For now, leave plaintextBytes empty and let
        // each test that needs it call _materializePlaintexts().
    }

    /// Read per-slot plaintext bytes from the fixture's Prover.toml. The
    /// fixture builder always writes that file alongside the proof.
    function _materializePlaintexts() internal {
        // Format of Prover.toml's plaintexts entry:
        //   plaintexts = [
        //     [field0, field1, ..., field38],
        //     ...
        //   ]
        // We avoid TOML parsing in Solidity. Instead, the fixture builder
        // emits a side-car JSON `plaintexts.json` for forge consumption.
        // Read it.
        string memory j = vm.readFile(string.concat(FIX, "/plaintexts.json"));
        for (uint256 i = 0; i < 16; i++) {
            string memory idx = vm.toString(i);
            // Each slot's plaintext is a 39-element bytes32 array.
            bytes memory buf = new bytes(39 * 32);
            for (uint256 k = 0; k < 39; k++) {
                bytes32 v = j.readBytes32(string.concat(".plaintexts[", idx, "][", vm.toString(k), "]"));
                assembly { mstore(add(add(buf, 32), mul(k, 32)), v) }
            }
            // Empty slots have all-zero plaintext, but the contract requires
            // empty bytes for unoccupied slots.
            bool isOccupied = false;
            for (uint256 q = 0; q < occupiedIdxs.length; q++) {
                if (occupiedIdxs[q] == i) { isOccupied = true; break; }
            }
            if (isOccupied) {
                plaintextBytes[i] = buf;
            } else {
                plaintextBytes[i] = new bytes(0);
            }
        }
    }

    function _seedChainState() internal {
        // Build occupied seed arrays.
        uint256[] memory featIds = new uint256[](occupiedIdxs.length);
        bytes32[] memory prevLshArr = new bytes32[](occupiedIdxs.length);
        featureIds = new uint256[](occupiedIdxs.length);
        for (uint256 i = 0; i < occupiedIdxs.length; i++) {
            uint8 sIdx = occupiedIdxs[i];
            featIds[i] = uint256(keccak256(abi.encode(shadowId, sIdx, "feature_solve")));
            featureIds[i] = featIds[i];
            prevLshArr[i] = prevLsh[sIdx];
        }
        st.seedShadowMultiSlot(
            shadowId, alice, ownerPkX, ownerPkY,
            occupiedIdxs, featIds, prevLshArr
        );
        // Set zIndexCommit so the solve proof's PI[3] matches chain.
        st.setShadowZIndexCommitForTest(shadowId, zIndexCommit);

        for (uint256 i = 0; i < occupiedIdxs.length; i++) {
            uint8 sIdx = occupiedIdxs[i];
            uint8 typeIdx = uint8(i);
            bytes32 originFaceId = keccak256(abi.encode("origin", shadowId, sIdx));
            bytes32 paletteCommit = keccak256(abi.encode("palette", shadowId, sIdx));
            fn.seedFeature(
                featIds[i], shadowId, sIdx, typeIdx,
                originFaceId, paletteCommit, prevLsh[sIdx], alice
            );
        }
    }

    function _buildArgs() internal returns (ShadowToken.SolveArgs memory args) {
        _materializePlaintexts();
        args.shadowId = shadowId;
        args.proof = proofSolve;
        args.plaintexts = plaintextBytes;
        args.zPermPacked = zPermPacked;
        args.zPerm = zPerm;
    }

    function test_solve_success_freezes_shadow_and_extracts_carriers() public {
        ShadowToken.SolveArgs memory args = _buildArgs();

        // Pre-state.
        assertFalse(st.isSolved(shadowId));
        for (uint256 i = 0; i < occupiedIdxs.length; i++) {
            uint8 sIdx = occupiedIdxs[i];
            assertEq(uint256(st.slotOf(shadowId, sIdx).kind), uint256(ShadowToken.SlotKind.OCCUPIED));
            assertTrue(fn.isInserted(featureIds[i]));
        }

        vm.recordLogs();
        vm.prank(alice);
        st.solve(args);

        // Post-state.
        assertTrue(st.isSolved(shadowId), "shadow solved");
        ShadowToken.Shadow memory s = st.shadowOf(shadowId);
        assertEq(uint256(s.zIndexRevealed), uint256(uint64(uint256(zPermPacked))), "z_revealed matches packed");
        assertTrue(s.zIndexRevealedSet);

        for (uint256 i = 0; i < occupiedIdxs.length; i++) {
            uint8 sIdx = occupiedIdxs[i];
            // Slot now empty.
            assertEq(uint256(st.slotOf(shadowId, sIdx).kind), uint256(ShadowToken.SlotKind.EMPTY));
            assertEq(st.slotOf(shadowId, sIdx).featureId, 0);
            assertEq(st.slotOf(shadowId, sIdx).liveStateHash, bytes32(0));
            // Carrier no longer inserted; checkpoint synced to final lsh.
            assertFalse(fn.isInserted(featureIds[i]));
            assertEq(fn.liveStateHashCheckpointOf(featureIds[i]), prevLsh[sIdx]);
        }

        // Events.
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool sawSolved = false;
        uint256 sawExtracted = 0;
        bytes32 sigSolved = keccak256("ShadowSolved(uint256,address,uint64)");
        bytes32 sigExtracted = keccak256("SlotExtracted(uint256,uint8,uint256,bytes32)");
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter != address(st)) continue;
            if (logs[i].topics[0] == sigSolved) sawSolved = true;
            else if (logs[i].topics[0] == sigExtracted) sawExtracted++;
        }
        assertTrue(sawSolved, "ShadowSolved emitted");
        assertEq(sawExtracted, occupiedIdxs.length, "SlotExtracted per occupied slot");
    }

    function test_solve_reverts_when_not_owner() public {
        ShadowToken.SolveArgs memory args = _buildArgs();
        address bob = makeAddr("bob");
        vm.prank(bob);
        vm.expectRevert(ShadowToken.NotShadowOwner.selector);
        st.solve(args);
    }

    function test_solve_reverts_when_already_solved() public {
        ShadowToken.SolveArgs memory args = _buildArgs();
        vm.prank(alice);
        st.solve(args);
        // Try again.
        vm.prank(alice);
        vm.expectRevert(ShadowToken.AlreadySolved.selector);
        st.solve(args);
    }

    function test_solve_reverts_when_proof_tampered() public {
        ShadowToken.SolveArgs memory args = _buildArgs();
        args.proof[256] = bytes1(uint8(args.proof[256]) ^ 0x40);
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.solve(args);
    }

    function test_solve_reverts_when_plaintext_tampered() public {
        ShadowToken.SolveArgs memory args = _buildArgs();
        // Flip a byte in the first occupied slot's plaintext.
        uint8 sIdx = occupiedIdxs[0];
        args.plaintexts[sIdx][100] = bytes1(uint8(args.plaintexts[sIdx][100]) ^ 1);
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.solve(args);
    }
}
