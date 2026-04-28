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
import {Poseidon2YulSpongePaletteSalt} from "../src/Poseidon2YulSpongePaletteSalt.sol";
import {TestableShadowToken, TestableFeatureNFT} from "./Testable.sol";

/// @notice High-water-mark solve test: ALL 16 slots occupied.
///
/// solve auto-extracts every occupied carrier. The canonical
/// SolveShadow.t.sol exercises 4 occupied slots; this test stresses
/// the auto-extract loop at the maximum.
///
/// What this pins:
///   - solve verifier handles a 16-state-commit transcript correctly
///   - _autoExtractAllSlots loops over all 16 entries; every carrier
///     transitions OCCUPIED -> EMPTY, isInserted -> false, checkpoint
///     synced to final_lsh
///   - Gas profile fits under block budget at high-water mark
///
/// Fixture: tools/build_solve_shadow_v2_fixture.py --seed solve_max
///          --n-occupied 16
contract SolveShadowMaxOccupancyTest is Test {
    using stdJson for string;

    TestableShadowToken  internal st;
    TestableFeatureNFT   internal fn;
    SolveShadowVerifier  internal vS;
    Poseidon2YulSponge   internal sponge;
    Poseidon2YulSponge16 internal sponge16;
    Poseidon2YulSpongePaletteSalt internal sponge17;

    string internal constant FIX = "./test/fixtures/solve_shadow_v2/solve_max";

    bytes internal proofSolve;
    bytes32[] internal piSolve;

    uint256 internal shadowId;
    bytes32 internal zPermPacked;
    bytes32 internal zIndexCommit;
    bytes32 internal ownerPkX;
    bytes32 internal ownerPkY;

    address internal alice = makeAddr("alice");

    uint256 internal constant SOLVE_PI_LEN = 7;

    uint8[]   internal occupiedIdxs;
    uint256[] internal featureIds;
    bytes32[16] internal prevLsh;
    uint8[16] internal zPerm;
    bytes[16] internal plaintextBytes;
    bytes32[16] internal stateCommits;
    bytes32[16][16] internal palettes;
    bytes32[16] internal paletteSalts;

    function setUp() public {
        sponge = new Poseidon2YulSponge();
        sponge16 = new Poseidon2YulSponge16();
        st = new TestableShadowToken(address(sponge));
        fn = new TestableFeatureNFT(address(st));
        st.setFeatureNFT(IFeatureNFT(address(fn)));
        st.setYulSponge16(address(sponge16));
        sponge17 = new Poseidon2YulSpongePaletteSalt();
        fn.setPaletteSponge(address(sponge17));
        vS = new SolveShadowVerifier();
        st.setVerifier(st.SLOT_SOLVE_SHADOW(), IVerifier(address(vS)));

        proofSolve = vm.readFileBinary(string.concat(FIX, "/proof.bin"));
        piSolve    = _loadFields(string.concat(FIX, "/public_inputs.bin"), SOLVE_PI_LEN);

        shadowId     = uint256(piSolve[0]);
        zPermPacked  = piSolve[2];
        zIndexCommit = piSolve[3];
        ownerPkX     = piSolve[5];
        ownerPkY     = piSolve[6];

        _loadFromMeta();
        _seedChainState();
        _materializePlaintexts();
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
            prevLsh[i] = j.readBytes32(string.concat(".prev_lsh[", idx, "]"));
            zPerm[i]   = uint8(j.readUint(string.concat(".z_perm[", idx, "]")));
            stateCommits[i] = j.readBytes32(string.concat(".state_commits[", idx, "]"));
        }
        uint256[] memory occ = j.readUintArray(".occupied_idxs");
        require(occ.length == 16, "fixture must have 16 occupied slots");
        occupiedIdxs = new uint8[](16);
        for (uint256 i = 0; i < 16; i++) {
            occupiedIdxs[i] = uint8(occ[i]);
        }
    }

    function _seedChainState() internal {
        uint256[] memory featIds = new uint256[](16);
        bytes32[] memory prevLshArr = new bytes32[](16);
        featureIds = new uint256[](16);
        for (uint256 i = 0; i < 16; i++) {
            uint8 sIdx = occupiedIdxs[i];
            featIds[i] = uint256(keccak256(abi.encode(shadowId, sIdx, "feature_solve")));
            featureIds[i] = featIds[i];
            prevLshArr[i] = prevLsh[sIdx];
        }
        st.seedShadowMultiSlot(shadowId, alice, ownerPkX, ownerPkY, occupiedIdxs, featIds, prevLshArr);
        st.setShadowZIndexCommitForTest(shadowId, zIndexCommit);

        for (uint256 i = 0; i < 16; i++) {
            uint8 sIdx = occupiedIdxs[i];
            (bytes32[16] memory pal, bytes32 salt) = _genPaletteSalt(sIdx);
            for (uint256 c = 0; c < 16; c++) palettes[sIdx][c] = pal[c];
            paletteSalts[sIdx] = salt;
            bytes32 paletteCommit = _computePaletteCommit(pal, salt);
            fn.seedFeature(
                featIds[i], shadowId, sIdx, uint8(i),
                keccak256(abi.encode("origin", shadowId, sIdx)),
                paletteCommit,
                prevLsh[sIdx],
                alice
            );
        }
    }

    function _genPaletteSalt(uint8 sIdx)
        internal view returns (bytes32[16] memory palette, bytes32 salt)
    {
        for (uint256 c = 0; c < 16; c++) {
            palette[c] = bytes32(uint256(
                uint24(uint256(keccak256(abi.encode("color", shadowId, sIdx, c))))
            ));
        }
        salt = keccak256(abi.encode("salt", shadowId, sIdx));
    }

    function _computePaletteCommit(bytes32[16] memory palette, bytes32 salt)
        internal view returns (bytes32 commit)
    {
        bytes memory buf = new bytes(17 * 32);
        for (uint256 i = 0; i < 16; i++) {
            bytes32 v = palette[i];
            assembly { mstore(add(add(buf, 32), mul(i, 32)), v) }
        }
        assembly { mstore(add(add(buf, 32), mul(16, 32)), salt) }
        (bool ok, bytes memory ret) = address(sponge17).staticcall(buf);
        require(ok && ret.length == 32, "sponge17 staticcall failed");
        assembly { commit := mload(add(ret, 32)) }
    }

    function _materializePlaintexts() internal {
        string memory j = vm.readFile(string.concat(FIX, "/plaintexts.json"));
        for (uint256 i = 0; i < 16; i++) {
            string memory idx = vm.toString(i);
            bytes memory buf = new bytes(39 * 32);
            for (uint256 k = 0; k < 39; k++) {
                bytes32 v = j.readBytes32(string.concat(".plaintexts[", idx, "][", vm.toString(k), "]"));
                assembly { mstore(add(add(buf, 32), mul(k, 32)), v) }
            }
            // All 16 occupied -> every plaintext slot must be non-empty.
            plaintextBytes[i] = buf;
        }
    }

    function _buildArgs() internal view returns (ShadowToken.SolveArgs memory args) {
        args.shadowId = shadowId;
        args.proof = proofSolve;
        args.plaintexts = plaintextBytes;
        args.stateCommits = stateCommits;
        args.palettes = palettes;
        args.paletteSalts = paletteSalts;
        args.zPermPacked = zPermPacked;
        args.zPerm = zPerm;
    }

    /// solve with all 16 slots occupied. Auto-extract loop must process
    /// every entry; post-state every slot is EMPTY and every carrier
    /// is uninserted with checkpoint synced to its final_lsh.
    function test_solve_max_occupancy_auto_extracts_all_16_carriers() public {
        ShadowToken.SolveArgs memory args = _buildArgs();

        // Pre-state: 16 occupied + 16 inserted carriers.
        for (uint256 i = 0; i < 16; i++) {
            assertEq(uint256(st.slotOf(shadowId, occupiedIdxs[i]).kind),
                     uint256(ShadowToken.SlotKind.OCCUPIED));
            assertTrue(fn.isInserted(featureIds[i]));
        }

        vm.recordLogs();
        vm.prank(alice);
        st.solve(args);

        // Post-state.
        assertTrue(st.isSolved(shadowId), "solved");
        for (uint256 i = 0; i < 16; i++) {
            uint8 sIdx = occupiedIdxs[i];
            assertEq(uint256(st.slotOf(shadowId, sIdx).kind),
                     uint256(ShadowToken.SlotKind.EMPTY), "slot empty post-solve");
            assertFalse(fn.isInserted(featureIds[i]), "carrier extracted");
            assertEq(fn.liveStateHashCheckpointOf(featureIds[i]), prevLsh[sIdx],
                     "checkpoint synced to final lsh");
        }

        // 16 SlotExtracted events.
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 sigEx = keccak256("SlotExtracted(uint256,uint8,uint256,bytes32)");
        uint256 sawEx = 0;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter != address(st)) continue;
            if (logs[i].topics[0] == sigEx) sawEx++;
        }
        assertEq(sawEx, 16, "16 SlotExtracted (one per carrier)");
    }

    /// Gas pin at high-water mark. solve_demo (4 occupied) ~12.4M;
    /// 16-occupied projects ~18-20M. Budget 22M leaves ~2-4M margin.
    function test_solve_max_occupancy_gas_under_block_budget() public {
        ShadowToken.SolveArgs memory args = _buildArgs();
        vm.prank(alice);
        uint256 gasBefore = gasleft();
        st.solve(args);
        uint256 used = gasBefore - gasleft();
        // reveal-update: 16-occ + per-slot sponge_39 + per-slot sponge_17
        // + per-slot revealPaletteAtSolve. Estimate ~14-16M. Budget 18M.
        assertLt(used, 18_000_000, "max-occupancy solve gas regressed");
    }
}
