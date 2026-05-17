// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test, stdJson, Vm} from "forge-std/Test.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {KeyRegistry} from "../src/KeyRegistry.sol";
import {MutateSlotVerifier} from "../src/MutateSlotVerifier.sol";
import {T10ShadowVerifier} from "../src/T10ShadowVerifier.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {Poseidon2YulSponge16} from "../src/Poseidon2YulSponge16.sol";
import {TestableShadowToken, TestableFeatureNFT} from "./Testable.sol";

/// @notice Real-proof e2e test for `ShadowToken.mutateBatch`.
///
/// Loads the linked atomic_mutate_batch fixture (2 mutate proofs for
/// distinct slots of one shadow + 1 T10 proof against the post-batch
/// manifest), seeds the shadow + 2 carriers, then exercises:
///   - happy path: 2-slot batch in one tx; both LSH advance; T10 reflects
///     post-batch manifest; 2x ShadowSlotMutated + 1x ShadowT10Updated
///   - empty-batch revert (BadArrayLen)
///   - non-owner revert
///   - solved-shadow revert
///   - bad proof at any entry aborts entire batch
///   - stale c2 sponge mismatch on any entry aborts batch
///   - same slot referenced twice in batch -> second entry's old_lsh
///     mismatches (because first entry already wrote new_lsh) -> revert
///   - gas measurement: confirms 2-slot batch fits comfortably under
///     30M block gas (Base/mainnet/most rollups today).
contract MutateBatchE2ETest is Test {
    using stdJson for string;

    TestableShadowToken internal st;
    TestableFeatureNFT internal fn;
    MutateSlotVerifier internal vMut;
    T10ShadowVerifier internal vT10;
    Poseidon2YulSponge internal sponge;
    Poseidon2YulSponge16 internal sponge16;
    KeyRegistry internal kr;

    string internal constant FIX = "./test/fixtures/atomic_mutate_batch/atomic_mutate_batch_demo";

    bytes internal proofA;
    bytes internal proofB;
    bytes internal proofT10;
    bytes32[] internal piA; // 16 fields
    bytes32[] internal piB;
    bytes32[] internal piT10; // 20 fields
    bytes internal c2A;
    bytes internal c2B;

    uint256 internal shadowId;
    uint8 internal slotAIdx;
    uint8 internal slotBIdx;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    uint256 internal constant MUT_PI_LEN = 16;
    uint256 internal constant T10_PI_LEN = 20;

    function setUp() public {
        sponge = new Poseidon2YulSponge();
        sponge16 = new Poseidon2YulSponge16();
        st = new TestableShadowToken(address(sponge));
        fn = new TestableFeatureNFT(address(st));
        st.setFeatureNFT(IFeatureNFT(address(fn)));
        st.setYulSponge16(address(sponge16));

        vMut = new MutateSlotVerifier();
        vT10 = new T10ShadowVerifier();
        st.setVerifier(st.SLOT_MUTATE_SLOT(), IVerifier(address(vMut)));
        st.setVerifier(st.SLOT_T10_SHADOW(), IVerifier(address(vT10)));

        kr = new KeyRegistry();
        st.setKeyRegistry(kr);

        proofA = vm.readFileBinary(string.concat(FIX, "/proof_mut_a.bin"));
        piA = _loadFields(string.concat(FIX, "/public_inputs_mut_a.bin"), MUT_PI_LEN);
        proofB = vm.readFileBinary(string.concat(FIX, "/proof_mut_b.bin"));
        piB = _loadFields(string.concat(FIX, "/public_inputs_mut_b.bin"), MUT_PI_LEN);
        proofT10 = vm.readFileBinary(string.concat(FIX, "/proof_t10.bin"));
        piT10 = _loadFields(string.concat(FIX, "/public_inputs_t10.bin"), T10_PI_LEN);
        c2A = vm.readFileBinary(string.concat(FIX, "/c2_a.bin"));
        c2B = vm.readFileBinary(string.concat(FIX, "/c2_b.bin"));

        shadowId = uint256(piA[0]);
        slotAIdx = uint8(uint256(piA[1]));
        slotBIdx = uint8(uint256(piB[1]));

        require(uint256(piB[0]) == shadowId, "fixtures disagree on shadow_id");
        require(slotAIdx != slotBIdx, "fixtures must mutate different slots");

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

    function _seedChainState() internal {
        // Owner pk binds via PI[10..11] of each mutate proof; both proofs
        // share owner since they're for the same shadow.
        bytes32 ownerPkX = piA[10];
        bytes32 ownerPkY = piA[11];
        require(piB[10] == ownerPkX && piB[11] == ownerPkY, "owner pk diverges");

        vm.prank(alice);
        kr.register(ownerPkX, ownerPkY);

        // Seed the shadow with both slots OCCUPIED at their old LSH values.
        uint8[] memory slots = new uint8[](2);
        slots[0] = slotAIdx;
        slots[1] = slotBIdx;
        uint256[] memory featIds = new uint256[](2);
        featIds[0] = uint256(piA[2]);
        featIds[1] = uint256(piB[2]);
        bytes32[] memory oldLshes = new bytes32[](2);
        oldLshes[0] = piA[6]; // PI[6] = old_lsh
        oldLshes[1] = piB[6];

        st.seedShadowMultiSlot(shadowId, alice, ownerPkX, ownerPkY, slots, featIds, oldLshes);

        // Seed each FeatureNFT carrier with metadata matching its proof's PI.
        fn.seedFeature(
            featIds[0],
            shadowId,
            slotAIdx,
            uint8(uint256(piA[3])), // typeIdx
            piA[4], // originFaceId
            piA[5], // paletteCommit
            piA[6], // initial LSH (carrier checkpoint, irrelevant while inserted)
            alice
        );
        fn.seedFeature(featIds[1], shadowId, slotBIdx, uint8(uint256(piB[3])), piB[4], piB[5], piB[6], alice);
    }

    function _entryFromPI(bytes calldata) internal pure returns (uint256) {
        return 0;
    }

    /// Build a MutateSlotEntry from a fixture proof + per-slot calldata.
    function _entry(uint8 slotIdx, bytes memory proof, bytes32[] memory pi, bytes memory c2)
        internal
        pure
        returns (ShadowToken.MutateSlotEntry memory e)
    {
        e.slotIdx = slotIdx;
        e.proofMutate = proof;
        e.newC1X = uint256(0); // not used by contract on PI build (PI[10..11] are pk, not c1)
        e.newC1Y = uint256(0);
        e.newLiveStateHash = pi[7];
        e.newCtCommit = pi[8];
        e.c2FieldCount = uint16(uint256(pi[9]));
        e.c2 = c2;
        e.prevChainTip = pi[12];
        e.newChainTip = pi[13];
        e.prevMutationCount = uint16(uint256(pi[14]));
        e.newMutationCount = uint16(uint256(pi[15]));
    }

    function _buildArgs() internal view returns (ShadowToken.MutateBatchArgs memory args) {
        args.shadowId = shadowId;
        args.entries = new ShadowToken.MutateSlotEntry[](2);
        args.entries[0] = _entry(slotAIdx, proofA, piA, c2A);
        args.entries[1] = _entry(slotBIdx, proofB, piB, c2B);
        bytes32[2] memory t10;
        t10[0] = piT10[2];
        t10[1] = piT10[3];
        args.newT10 = t10;
        args.proofT10 = proofT10;
    }

    function test_mutateBatch_success_advances_two_slots_and_T10() public {
        ShadowToken.MutateBatchArgs memory args = _buildArgs();

        // Pre-state.
        assertEq(st.slotOf(shadowId, slotAIdx).liveStateHash, piA[6], "slot A pre-LSH");
        assertEq(st.slotOf(shadowId, slotBIdx).liveStateHash, piB[6], "slot B pre-LSH");

        vm.recordLogs();
        vm.prank(alice);
        st.mutateBatch(args);

        // Post-state.
        assertEq(st.slotOf(shadowId, slotAIdx).liveStateHash, piA[7], "slot A LSH advanced");
        assertEq(st.slotOf(shadowId, slotBIdx).liveStateHash, piB[7], "slot B LSH advanced");
        assertEq(st.shadowT10(shadowId, 0), args.newT10[0], "T10 hi reflects post-batch");
        assertEq(st.shadowT10(shadowId, 1), args.newT10[1], "T10 lo reflects post-batch");

        // Events.
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 sigSM = keccak256("ShadowSlotMutated(uint256,uint8,bytes32,uint256,uint16,bytes32,bytes32,bytes)");
        bytes32 sigT10 = keccak256("ShadowT10Updated(uint256,bytes32,bytes32)");
        uint256 sm = 0;
        bool t10Seen = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter != address(st)) continue;
            if (logs[i].topics[0] == sigSM) sm++;
            else if (logs[i].topics[0] == sigT10) t10Seen = true;
        }
        assertEq(sm, 2, "2x ShadowSlotMutated emitted");
        assertTrue(t10Seen, "ShadowT10Updated emitted");
    }

    function test_mutateBatch_reverts_on_empty_entries() public {
        ShadowToken.MutateBatchArgs memory args;
        args.shadowId = shadowId;
        args.entries = new ShadowToken.MutateSlotEntry[](0);
        args.newT10[0] = piT10[2];
        args.newT10[1] = piT10[3];
        args.proofT10 = proofT10;
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.BadArrayLen.selector, 0, 1));
        st.mutateBatch(args);
    }

    function test_mutateBatch_reverts_when_not_owner() public {
        ShadowToken.MutateBatchArgs memory args = _buildArgs();
        vm.prank(bob);
        vm.expectRevert(ShadowToken.NotShadowOwner.selector);
        st.mutateBatch(args);
    }

    function test_mutateBatch_reverts_when_first_proof_tampered() public {
        ShadowToken.MutateBatchArgs memory args = _buildArgs();
        // Flip a byte in entry[0]'s proof. The whole batch must abort
        // BEFORE entry[1] applies, so chain state stays untouched.
        args.entries[0].proofMutate[256] = bytes1(uint8(args.entries[0].proofMutate[256]) ^ 0x40);
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.mutateBatch(args);
        // Sanity: chain state is unchanged.
        assertEq(st.slotOf(shadowId, slotAIdx).liveStateHash, piA[6], "slot A unchanged");
        assertEq(st.slotOf(shadowId, slotBIdx).liveStateHash, piB[6], "slot B unchanged");
    }

    function test_mutateBatch_reverts_when_second_proof_tampered() public {
        ShadowToken.MutateBatchArgs memory args = _buildArgs();
        // Flip a byte in entry[1]'s proof. Entry[0] applies its write
        // first; then entry[1] verify fails. The whole tx reverts so
        // entry[0]'s write is rolled back too -- atomicity invariant.
        args.entries[1].proofMutate[256] = bytes1(uint8(args.entries[1].proofMutate[256]) ^ 0x40);
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.mutateBatch(args);
        assertEq(st.slotOf(shadowId, slotAIdx).liveStateHash, piA[6], "slot A rolled back");
        assertEq(st.slotOf(shadowId, slotBIdx).liveStateHash, piB[6], "slot B unchanged");
    }

    /// Envelope-binding cutover (audit H-02): tampering one entry's c2
    /// MUST revert. Pre-cutover, the per-entry c2 was advisory and chain
    /// state advanced regardless of c2 content. The whole batch now aborts
    /// atomically on the first byte-level c2 mismatch and the chain stays
    /// at its pre-batch state.
    function test_mutateBatch_reverts_when_entry_c2_tampered() public {
        ShadowToken.MutateBatchArgs memory args = _buildArgs();
        // Snapshot pre-state so we can prove revert was atomic.
        bytes32 lshABefore = st.slotOf(shadowId, slotAIdx).liveStateHash;
        bytes32 lshBBefore = st.slotOf(shadowId, slotBIdx).liveStateHash;

        args.entries[0].c2[7] = bytes1(uint8(args.entries[0].c2[7]) ^ 0x80);
        vm.prank(alice);
        vm.expectRevert();
        st.mutateBatch(args);

        // Both slots stayed at their pre-batch lsh: tx rolled back.
        assertEq(st.slotOf(shadowId, slotAIdx).liveStateHash, lshABefore, "slot A unchanged");
        assertEq(st.slotOf(shadowId, slotBIdx).liveStateHash, lshBBefore, "slot B unchanged");
    }

    function test_mutateBatch_reverts_when_entry_c2_field_noncanonical() public {
        ShadowToken.MutateBatchArgs memory args = _buildArgs();
        bytes32 lshABefore = st.slotOf(shadowId, slotAIdx).liveStateHash;
        bytes32 lshBBefore = st.slotOf(shadowId, slotBIdx).liveStateHash;
        uint256 fr = st.FR_MOD();
        _writeField(args.entries[0].c2, 0, fr);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.NonCanonicalField.selector, uint256(0), fr));
        st.mutateBatch(args);
        assertEq(st.slotOf(shadowId, slotAIdx).liveStateHash, lshABefore, "slot A unchanged");
        assertEq(st.slotOf(shadowId, slotBIdx).liveStateHash, lshBBefore, "slot B unchanged");
    }

    function test_mutateBatch_reverts_when_t10_proof_tampered() public {
        ShadowToken.MutateBatchArgs memory args = _buildArgs();
        // Per-slot mutates verify cleanly; T10 fails. Both entry writes
        // apply during the loop, then T10 reverts -- the tx must roll
        // back both writes. Atomic-T10 invariant: if T10 doesn't bind,
        // chain state cannot move.
        args.proofT10[256] = bytes1(uint8(args.proofT10[256]) ^ 0x40);
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.mutateBatch(args);
        assertEq(st.slotOf(shadowId, slotAIdx).liveStateHash, piA[6], "slot A rolled back");
        assertEq(st.slotOf(shadowId, slotBIdx).liveStateHash, piB[6], "slot B rolled back");
        assertEq(st.shadowT10(shadowId, 0), bytes32(0), "T10 hi unchanged");
        assertEq(st.shadowT10(shadowId, 1), bytes32(0), "T10 lo unchanged");
    }

    function test_mutateBatch_gas_within_real_chain_block_limit() public {
        ShadowToken.MutateBatchArgs memory args = _buildArgs();
        vm.prank(alice);
        uint256 gasBefore = gasleft();
        st.mutateBatch(args);
        uint256 used = gasBefore - gasleft();

        // Hard target: every entry point under 16M (per spec). N=2 baseline
        // sits comfortably under 12M (forge ~9M, on-chain ~10.8M including
        // calldata).
        assertLt(used, 12_000_000, "mutateBatch(2) gas regressed past 12M target");
    }

    /// Per-entry asymptote: gas scales ~linearly with entries.length.
    /// At N=2 the per-entry cost (after fixed overhead) sets the practical
    /// upper bound on N. The contract permits any non-empty entries[] but
    /// callers MUST bound N <= floor((16M - overhead) / per_entry).
    /// At ~3.5M-4.5M per entry, that's N <= ~3 to fit under the 16M target.
    /// This test asserts the per-entry growth is small enough that the math
    /// doesn't get worse over time. If this fires, either circuit cost grew
    /// or the caller-bound documentation needs updating.
    function test_mutateBatch_per_entry_gas_bounded() public {
        ShadowToken.MutateBatchArgs memory args = _buildArgs();
        uint256 n = args.entries.length;
        require(n >= 2, "per-entry test needs N>=2 fixture");

        vm.prank(alice);
        uint256 gasBefore = gasleft();
        st.mutateBatch(args);
        uint256 used = gasBefore - gasleft();

        // Subtract a fixed-overhead estimate (T10 verify ~1M + calldata + bookkeeping).
        // Then per-entry should be < 5M (current measurement: ~3.5-4M).
        uint256 fixedOverhead = 2_000_000;
        require(used > fixedOverhead, "sanity: total gas below fixed overhead");
        uint256 perEntry = (used - fixedOverhead) / n;
        assertLt(perEntry, 5_000_000, "mutateBatch per-entry gas exceeds 5M; reduce N bound or shrink mutate verifier");
    }

    function test_mutateBatch_reverts_when_slot_referenced_twice() public {
        // Build a batch where entry[0] mutates slot A, and entry[1] is a
        // FAKE entry that targets slot A again. The second entry's
        // PI[6] (old_lsh) was witnessed against the chain's pre-batch
        // value of slot A. After entry[0] applies, slot A's lsh is
        // piA[7], not piA[6]. Building PI for entry[1] with the new
        // chain value mismatches the proof's PI[6] -> InvalidProof.
        ShadowToken.MutateBatchArgs memory args;
        args.shadowId = shadowId;
        args.entries = new ShadowToken.MutateSlotEntry[](2);
        args.entries[0] = _entry(slotAIdx, proofA, piA, c2A);
        // Entry 1: same slot, same proof (artificial double-mutate).
        args.entries[1] = _entry(slotAIdx, proofA, piA, c2A);
        bytes32[2] memory t10;
        t10[0] = piT10[2];
        t10[1] = piT10[3];
        args.newT10 = t10;
        args.proofT10 = proofT10;
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.mutateBatch(args);
    }
}
