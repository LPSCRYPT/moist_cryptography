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

    TestableShadowToken internal st;
    TestableFeatureNFT internal fn;
    SolveShadowVerifier internal vS;
    Poseidon2YulSponge internal sponge;
    Poseidon2YulSponge16 internal sponge16;
    Poseidon2YulSpongePaletteSalt internal sponge17;

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

    uint8[] internal occupiedIdxs;
    uint256[] internal featureIds;
    bytes32[16] internal prevLsh;
    bytes32[16] internal stateCommits; // pre-derivation; for assertions only
    bytes32[16][16] internal palettes; // [slot][color]
    bytes32[16] internal paletteSalts; // per-slot
    bytes[16] internal plaintextBytes;
    uint8[16] internal zPerm;

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
        piSolve = _loadFields(string.concat(FIX, "/public_inputs.bin"), SOLVE_PI_LEN);

        shadowId = uint256(piSolve[0]);
        stateCommitsRoot = piSolve[1];
        zPermPacked = piSolve[2];
        zIndexCommit = piSolve[3];
        lshRoot = piSolve[4];
        ownerPkX = piSolve[5];
        ownerPkY = piSolve[6];

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

    function _writeField(bytes memory data, uint256 fieldIndex, uint256 value) internal pure {
        assembly { mstore(add(add(data, 32), mul(fieldIndex, 32)), value) }
    }

    function _loadFromMeta() internal {
        string memory j = vm.readFile(string.concat(FIX, "/meta.json"));
        for (uint256 i = 0; i < 16; i++) {
            string memory idx = vm.toString(i);
            prevLsh[i] = j.readBytes32(string.concat(".prev_lsh[", idx, "]"));
            stateCommits[i] = j.readBytes32(string.concat(".state_commits[", idx, "]"));
            zPerm[i] = uint8(j.readUint(string.concat(".z_perm[", idx, "]")));
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
                if (occupiedIdxs[q] == i) {
                    isOccupied = true;
                    break;
                }
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
        st.seedShadowMultiSlot(shadowId, alice, ownerPkX, ownerPkY, occupiedIdxs, featIds, prevLshArr);
        // Set zIndexCommit so the solve proof's PI[3] matches chain.
        st.setShadowZIndexCommitForTest(shadowId, zIndexCommit);

        // Each occupied slot gets a deterministic (palette, salt) pair;
        // the resulting paletteCommit is computed via the on-chain Yul
        // sponge_17 (so seed and reveal use byte-identical hashing).
        for (uint256 i = 0; i < occupiedIdxs.length; i++) {
            uint8 sIdx = occupiedIdxs[i];
            uint8 typeIdx = uint8(i);
            bytes32 originFaceId = keccak256(abi.encode("origin", shadowId, sIdx));
            (bytes32[16] memory pal, bytes32 salt) = _genPaletteSalt(sIdx);
            for (uint256 c = 0; c < 16; c++) {
                palettes[sIdx][c] = pal[c];
            }
            paletteSalts[sIdx] = salt;
            bytes32 paletteCommit = _computePaletteCommit(pal, salt);
            fn.seedFeature(featIds[i], shadowId, sIdx, typeIdx, originFaceId, paletteCommit, prevLsh[sIdx], alice);
        }
    }

    /// Generate a deterministic 16-color palette + salt for a slot. Each
    /// color is a 24-bit value seeded from (shadowId, slotIdx, colorIdx).
    function _genPaletteSalt(uint8 sIdx) internal view returns (bytes32[16] memory palette, bytes32 salt) {
        for (uint256 c = 0; c < 16; c++) {
            palette[c] = bytes32(uint256(uint24(uint256(keccak256(abi.encode("color", shadowId, sIdx, c))))));
        }
        salt = bytes32(uint256(keccak256(abi.encode("salt", shadowId, sIdx))) % st.FR_MOD());
    }

    /// Compute paletteCommit by static-calling the same Yul sponge_17 the
    /// contract uses at solve. Guarantees seed-side and reveal-side hashing
    /// agree byte-for-byte.
    function _computePaletteCommit(bytes32[16] memory palette, bytes32 salt) internal view returns (bytes32 commit) {
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

    function _paletteRgb(bytes32[16] memory palette) internal pure returns (bytes memory rgb) {
        rgb = new bytes(48);
        for (uint256 i = 0; i < 16; i++) {
            uint256 c = uint256(palette[i]);
            rgb[i * 3] = bytes1(uint8(c >> 16));
            rgb[i * 3 + 1] = bytes1(uint8(c >> 8));
            rgb[i * 3 + 2] = bytes1(uint8(c));
        }
    }

    function _assertFeatureSolveLog(Vm.Log memory log, bytes32 sigPalette, bytes32 sigFeatureSlot)
        internal
        view
        returns (uint256 paletteSeen, uint256 featureSlotSeen)
    {
        if (log.topics[0] == sigPalette) {
            uint256 featureId = uint256(log.topics[1]);
            (bytes32 emittedCommit, bytes memory emittedRgb) = abi.decode(log.data, (bytes32, bytes));
            for (uint256 q = 0; q < occupiedIdxs.length; q++) {
                if (featureIds[q] == featureId) {
                    uint8 sIdx = occupiedIdxs[q];
                    assertEq(emittedCommit, fn.paletteCommitOf(featureId), "palette commit event");
                    assertEq(emittedRgb, _paletteRgb(palettes[sIdx]), "palette RGB event");
                    return (1, 0);
                }
            }
        } else if (log.topics[0] == sigFeatureSlot) {
            uint256 featureId = uint256(log.topics[1]);
            uint8 emittedSlot = uint8(uint256(log.topics[3]));
            bytes memory emittedPlaintext = abi.decode(log.data, (bytes));
            for (uint256 q = 0; q < occupiedIdxs.length; q++) {
                if (featureIds[q] == featureId) {
                    assertEq(emittedPlaintext, plaintextBytes[emittedSlot], "feature plaintext event");
                    return (0, 1);
                }
            }
        }
    }

    function _buildArgs() internal returns (ShadowToken.SolveArgs memory args) {
        _materializePlaintexts();
        args.shadowId = shadowId;
        args.proof = proofSolve;
        args.plaintexts = plaintextBytes;
        args.zPermPacked = zPermPacked;
        args.zPerm = zPerm;
        args.stateCommits = stateCommits;
        args.palettes = palettes;
        args.paletteSalts = paletteSalts;
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
        uint256 sawPalette = 0;
        uint256 sawFeatureSlot = 0;
        bytes32 sigSolved = keccak256("ShadowSolved(uint256,address,uint64)");
        bytes32 sigExtracted = keccak256("SlotExtracted(uint256,uint8,uint256,bytes32)");
        bytes32 sigPalette = keccak256("FeaturePaletteRevealed(uint256,bytes32,bytes)");
        bytes32 sigFeatureSlot = keccak256("FeatureSlotRevealed(uint256,uint256,uint8,bytes)");
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(st)) {
                if (logs[i].topics[0] == sigSolved) sawSolved = true;
                else if (logs[i].topics[0] == sigExtracted) sawExtracted++;
            } else if (logs[i].emitter == address(fn)) {
                (uint256 paletteSeen, uint256 featureSlotSeen) =
                    _assertFeatureSolveLog(logs[i], sigPalette, sigFeatureSlot);
                sawPalette += paletteSeen;
                sawFeatureSlot += featureSlotSeen;
            }
        }
        assertTrue(sawSolved, "ShadowSolved emitted");
        assertEq(sawExtracted, occupiedIdxs.length, "SlotExtracted per occupied slot");
        assertEq(sawPalette, occupiedIdxs.length, "FeaturePaletteRevealed per occupied slot");
        assertEq(sawFeatureSlot, occupiedIdxs.length, "FeatureSlotRevealed per occupied slot");
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

    /// Envelope-binding cutover (audit H-01): the canonical behavioural-
    /// change marker. Pre-cutover, args.plaintexts was advisory and chain
    /// accepted any plaintext bytes -- the proof bound only stateCommits
    /// via PI[1]. Post-cutover, the contract recomputes sponge_39 of every
    /// occupied plaintext and asserts equality with the corresponding
    /// stateCommit BEFORE any FeatureSlotRevealed event fires.
    function test_solve_reverts_when_plaintext_tampered() public {
        ShadowToken.SolveArgs memory args = _buildArgs();
        uint8 sIdx = occupiedIdxs[0];
        args.plaintexts[sIdx][100] = bytes1(uint8(args.plaintexts[sIdx][100]) ^ 1);
        // Snapshot pre-state so we can prove revert atomicity.
        bool solvedBefore = st.isSolved(args.shadowId);
        vm.prank(alice);
        vm.expectRevert();
        st.solve(args);
        assertEq(st.isSolved(args.shadowId), solvedBefore, "shadow unchanged on tampered-plaintext revert");
    }

    function test_solve_reverts_when_plaintext_field_noncanonical() public {
        ShadowToken.SolveArgs memory args = _buildArgs();
        uint8 sIdx = occupiedIdxs[0];
        uint256 fr = st.FR_MOD();
        _writeField(args.plaintexts[sIdx], 0, fr);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.NonCanonicalField.selector, uint256(0), fr));
        st.solve(args);
        assertFalse(st.isSolved(shadowId), "shadow remains unsolved");
    }

    /// reveal-update: tampering a palette color makes sponge_palette_salt
    /// produce a hash that doesn't match the carrier's stored
    /// paletteCommit. FeatureNFT.revealPaletteAtSolve reverts with
    /// PaletteCommitMismatch BEFORE auto-extract runs.
    function test_solve_reverts_when_palette_tampered() public {
        ShadowToken.SolveArgs memory args = _buildArgs();
        uint8 sIdx = occupiedIdxs[0];
        // Flip one bit in palette[0] of the first occupied slot.
        args.palettes[sIdx][0] = bytes32(uint256(args.palettes[sIdx][0]) ^ 1);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(FeatureNFT.PaletteCommitMismatch.selector, featureIds[0]));
        st.solve(args);
    }

    /// reveal-update: tampering the salt also breaks the commit opening.
    function test_solve_reverts_when_salt_tampered() public {
        ShadowToken.SolveArgs memory args = _buildArgs();
        uint8 sIdx = occupiedIdxs[0];
        args.paletteSalts[sIdx] = bytes32(uint256(args.paletteSalts[sIdx]) ^ 1);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(FeatureNFT.PaletteCommitMismatch.selector, featureIds[0]));
        st.solve(args);
    }

    function test_solve_reverts_when_palette_color_out_of_range() public {
        ShadowToken.SolveArgs memory args = _buildArgs();
        uint8 sIdx = occupiedIdxs[0];
        args.palettes[sIdx][0] = bytes32(uint256(0x01000000));
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(FeatureNFT.PaletteColorOutOfRange.selector, uint256(0), uint256(0x01000000))
        );
        st.solve(args);
        assertFalse(st.isSolved(shadowId), "shadow remains unsolved");
    }

    function test_solve_reverts_when_palette_salt_noncanonical() public {
        ShadowToken.SolveArgs memory args = _buildArgs();
        uint8 sIdx = occupiedIdxs[0];
        uint256 fr = st.FR_MOD();
        args.paletteSalts[sIdx] = bytes32(fr);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(FeatureNFT.NonCanonicalField.selector, uint256(16), fr));
        st.solve(args);
        assertFalse(st.isSolved(shadowId), "shadow remains unsolved");
    }

    // ============== Edge cases the spec called out ==============

    /// `zIndexCommit == 0` is the default storage value when
    /// setZIndexCommit was never called for a shadow. The solve circuit
    /// asserts `sponge_16(z_perm) == z_index_commit` with z_index_commit
    /// fed from the chain (PI[3] = s.zIndexCommit). With s.zIndexCommit=0,
    /// PI[3]=0; the proof's frozen PI[3] = fixture's sponge_16(perm) which
    /// is non-zero (sponge sentinel-pad invariant pinned in
    /// CryptoInvariants). Mismatch -> InvalidProof.
    ///
    /// This pins the property: a shadow MUST have setZIndexCommit called
    /// before solve is possible. Without it, no permutation reveal is
    /// allowed -- not even an identity permutation [0,1,...,15].
    function test_solve_reverts_when_zIndexCommit_unset() public {
        // Re-seed without setting zIndexCommit. Cleanest path: rebuild the
        // chain state minus the setZIndexCommit step. We have a fresh
        // st instance per test, but the existing setUp already calls
        // setShadowZIndexCommitForTest -- so storage-clear it here.
        st.setShadowZIndexCommitForTest(shadowId, bytes32(0));
        assertEq(st.shadowOf(shadowId).zIndexCommit, bytes32(0), "pre: commit cleared");

        ShadowToken.SolveArgs memory args = _buildArgs();
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.solve(args);
    }

    /// Even with the right zPermPacked from the fixture, swapping it for
    /// the identity permutation (encoded packed as 0xfedcba9876543210
    /// = nibbles [0,1,2,...,15] LE) fails verification. Pins that the
    /// proof's PI[2] is rigidly bound -- callers cannot substitute a
    /// different reveal for the one the prover witnessed.
    function test_solve_reverts_when_zPermPacked_tampered() public {
        ShadowToken.SolveArgs memory args = _buildArgs();
        // Identity perm packed: nibble i = i, low-to-high.
        // 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 -> 0xfedcba9876543210
        args.zPermPacked = bytes32(uint256(0xfedcba9876543210));
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.solve(args);
    }

    /// Solve with a zIndexCommit that does not match the proof's witnessed
    /// commit. Any non-zero off-by-one tampering at the chain level (e.g.,
    /// a corrupt commit due to storage poke) MUST fail solve. Pins the
    /// commit-binding invariant.
    function test_solve_reverts_when_zIndexCommit_mismatched() public {
        st.setShadowZIndexCommitForTest(shadowId, bytes32(uint256(zIndexCommit) ^ 1));
        ShadowToken.SolveArgs memory args = _buildArgs();
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.solve(args);
    }

    /// Gas-pin: solve verifies one proof + auto-extracts every occupied
    /// carrier + writes zIndexRevealed. Budget: 14M -- ~13% above current
    /// ~12.4M baseline.
    function test_solve_gas_under_block_budget() public {
        ShadowToken.SolveArgs memory args = _buildArgs();
        vm.prank(alice);
        uint256 gasBefore = gasleft();
        st.solve(args);
        uint256 used = gasBefore - gasleft();
        // v2-gas: ~6M for 4-occ post-sponge-drop. Budget 8M.
        // reveal-update: solve now does on-chain sponge_39 per occupied
        // slot + sponge_17 per occupied slot + per-slot revealPaletteAtSolve.
        // 4-occ baseline: ~9-10M expected. Budget 12M (4M headroom under cap).
        assertLt(used, 12_000_000, "solve gas regressed");
    }
}
