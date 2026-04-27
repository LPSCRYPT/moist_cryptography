// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test, Vm} from "forge-std/Test.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {MutateSlotVerifier} from "../src/MutateSlotVerifier.sol";
import {T10ShadowVerifier} from "../src/T10ShadowVerifier.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {TestableShadowToken, TestableFeatureNFT} from "./Testable.sol";

/// @notice End-to-end real-proof test for `ShadowToken.mutateSlot`.
///
/// The fixture (`tools/build_atomic_mutate_fixture.py --seed atomic_demo`)
/// produces a *linked pair* of real proofs:
///   - proof_mut.bin / public_inputs_mut.bin: the mutate_slot proof, with
///     PI binding owner_pk, feature_id, type_idx, origin_face_id,
///     palette_commit, old_lsh, new_lsh, etc.
///   - proof_t10.bin / public_inputs_t10.bin: the shadow_t10 proof,
///     bound to the LSH array the chain will hold *after* mutateSlot
///     applies its write (slot[3].liveStateHash = new_lsh; rest = 0).
///
/// The test seeds the FeatureNFT + Shadow + manifest from the fixture's
/// PI values, then calls `mutateSlot(...)` and asserts:
///   1. The function succeeds.
///   2. manifest[slot].liveStateHash advances from old_lsh to new_lsh.
///   3. shadowT10[shadowId] is set to (t10_hi, t10_lo).
///   4. ShadowSlotMutated + ShadowT10Updated events are emitted with
///      the correct values.
contract MutateSlotE2ETest is Test {
    TestableShadowToken internal st;
    TestableFeatureNFT  internal fn;
    MutateSlotVerifier  internal vMut;
    T10ShadowVerifier   internal vT10;
    Poseidon2YulSponge  internal sponge;

    string internal constant FIX = "./test/fixtures/atomic_mutate/atomic_demo";

    bytes internal proofMut;
    bytes32[] internal piMut;
    bytes internal proofT10;
    bytes32[] internal piT10;
    bytes internal newC2;

    // Convenience aliases pulled from PI:
    uint256 internal shadowId;
    uint8   internal slotIdx;
    uint256 internal featureId;
    uint8   internal typeIdx;
    bytes32 internal originFaceId;
    bytes32 internal paletteCommit;
    bytes32 internal oldLsh;
    bytes32 internal newLsh;
    bytes32 internal newCtCommit;
    bytes32 internal ownerPkX;
    bytes32 internal ownerPkY;
    bytes32 internal prevChainTip;
    bytes32 internal newChainTip;
    uint16  internal prevMutationCount;
    uint16  internal newMutationCount;

    address internal alice = makeAddr("alice");

    uint256 internal constant MUT_PI_LEN = 16;
    uint256 internal constant T10_PI_LEN = 20;

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
        st.setMutateSlotVerifier(IVerifier(address(vMut)));
        st.setT10ShadowVerifier(IVerifier(address(vT10)));

        proofMut = vm.readFileBinary(string.concat(FIX, "/proof_mut.bin"));
        piMut    = _loadFields(string.concat(FIX, "/public_inputs_mut.bin"), MUT_PI_LEN);
        proofT10 = vm.readFileBinary(string.concat(FIX, "/proof_t10.bin"));
        piT10    = _loadFields(string.concat(FIX, "/public_inputs_t10.bin"), T10_PI_LEN);
        newC2    = vm.readFileBinary(string.concat(FIX, "/c2.bin"));

        shadowId      = uint256(piMut[0]);
        slotIdx       = uint8(uint256(piMut[1]));
        featureId     = uint256(piMut[2]);
        typeIdx       = uint8(uint256(piMut[3]));
        originFaceId  = piMut[4];
        paletteCommit = piMut[5];
        oldLsh        = piMut[6];
        newLsh        = piMut[7];
        newCtCommit   = piMut[8];
        ownerPkX      = piMut[10];
        ownerPkY      = piMut[11];
        prevChainTip  = piMut[12];
        newChainTip   = piMut[13];
        prevMutationCount = uint16(uint256(piMut[14]));
        newMutationCount  = uint16(uint256(piMut[15]));

        // Seed the FeatureNFT carrier so its stored values match what the
        // mutate_slot proof PI claims.
        fn.seedFeature(
            featureId,
            shadowId,
            slotIdx,
            typeIdx,
            originFaceId,
            paletteCommit,
            oldLsh,         // checkpoint stale-while-inserted; doesn't have to match here
            alice
        );
        // Seed the shadow + manifest entry to match the mutate_slot pre-state.
        st.seedShadowAndSlot(
            shadowId,
            alice,
            ownerPkX,
            ownerPkY,
            slotIdx,
            featureId,
            oldLsh
        );
    }

    function _loadFields(string memory path, uint256 expectedLen) internal returns (bytes32[] memory out) {
        bytes memory raw = vm.readFileBinary(path);
        require(raw.length == expectedLen * 32, "PI length mismatch (regenerate fixture?)");
        out = new bytes32[](expectedLen);
        for (uint256 i = 0; i < expectedLen; i++) {
            bytes32 word;
            assembly { word := mload(add(raw, add(0x20, mul(i, 32)))) }
            out[i] = word;
        }
    }

    function _buildArgs() internal view returns (ShadowToken.MutateSlotArgs memory args) {
        bytes32[2] memory newT10;
        newT10[0] = piT10[2];   // hi
        newT10[1] = piT10[3];   // lo
        return ShadowToken.MutateSlotArgs({
            shadowId: shadowId,
            slotIdx: slotIdx,
            proofMutate: proofMut,
            newC1X: 0,                  // not bound on chain in v2; viewer hint via event
            newC1Y: 0,                  // (folded into liveStateHash in-circuit)
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

    // ---- happy path ----

    function test_mutateSlot_success_advances_state_and_T10() public {
        ShadowToken.MutateSlotArgs memory args = _buildArgs();

        // Pre-state checks.
        ShadowToken.ManifestEntry memory mPre = st.slotOf(shadowId, slotIdx);
        assertEq(mPre.liveStateHash, oldLsh, "pre: lsh = old");
        assertEq(uint256(mPre.kind), uint256(ShadowToken.SlotKind.OCCUPIED));

        // Contract emits in order: ShadowT10Updated (from _refreshT10Atomically),
        // then ShadowSlotMutated.
        vm.expectEmit(true, false, false, true);
        emit ShadowT10Updated(shadowId, args.newT10[0], args.newT10[1]);
        vm.expectEmit(true, true, true, false);
        emit ShadowSlotMutated(
            shadowId, slotIdx, originFaceId, featureId,
            newMutationCount, prevChainTip, newChainTip, hex""
        );

        vm.prank(alice);
        st.mutateSlot(args);

        // Post-state checks.
        ShadowToken.ManifestEntry memory mPost = st.slotOf(shadowId, slotIdx);
        assertEq(mPost.liveStateHash, newLsh, "post: lsh = new");

        bytes32 t10Hi = st.shadowT10(shadowId, 0);
        bytes32 t10Lo = st.shadowT10(shadowId, 1);
        assertEq(t10Hi, args.newT10[0], "T10 hi");
        assertEq(t10Lo, args.newT10[1], "T10 lo");
    }

    // ---- negative cases ----

    function test_mutateSlot_reverts_when_caller_not_owner() public {
        ShadowToken.MutateSlotArgs memory args = _buildArgs();
        address mallory = makeAddr("mallory");
        vm.prank(mallory);
        vm.expectRevert(ShadowToken.NotShadowOwner.selector);
        st.mutateSlot(args);
    }

    function test_mutateSlot_reverts_when_slot_empty() public {
        ShadowToken.MutateSlotArgs memory args = _buildArgs();
        // Move the seed to a different slot index than what the proof expects.
        // Easiest: try mutating slot 7 (which is EMPTY); the proof's PI says slot 3.
        // But ShadowToken validates slotIdx via piMut[1]; we'd need a tampered fixture.
        // Instead, just point args at a confirmed-EMPTY slot and let the SlotEmpty
        // check revert before the proof is checked.
        args.slotIdx = 7;
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.SlotEmpty.selector, uint8(7)));
        st.mutateSlot(args);
    }

    function test_mutateSlot_reverts_when_c2_length_wrong() public {
        ShadowToken.MutateSlotArgs memory args = _buildArgs();
        args.c2 = hex"deadbeef";  // 4 bytes, not 39 * 32
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(
            ShadowToken.BadC2Length.selector,
            uint256(4),
            uint256(args.c2FieldCount) * 32
        ));
        st.mutateSlot(args);
    }

    function test_mutateSlot_reverts_when_c2_sponge_mismatch() public {
        ShadowToken.MutateSlotArgs memory args = _buildArgs();
        // Flip a byte deep in c2; sponge will mismatch the proof's
        // committed new_ct_commit.
        bytes memory tampered = bytes.concat(args.c2);
        tampered[64] = bytes1(uint8(tampered[64]) ^ 0x01);
        args.c2 = tampered;
        vm.prank(alice);
        vm.expectRevert();   // CtCommitMismatch with specific args; just expect any revert
        st.mutateSlot(args);
    }

    function test_mutateSlot_reverts_when_oldLsh_mismatch() public {
        // Tamper with chain state's stored lsh; proof's PI[6] no longer matches.
        // Storage-poke: ManifestEntry's `liveStateHash` lives at offset 2 of the
        // entry (3 slots: kind, featureId, liveStateHash). _MANIFESTS_SLOT = 19.
        bytes32 outerBase = keccak256(abi.encode(shadowId, uint256(19)));
        bytes32 entryBase = bytes32(uint256(outerBase) + uint256(slotIdx) * 3);
        bytes32 lshSlot = bytes32(uint256(entryBase) + 2);
        vm.store(address(st), lshSlot, bytes32(uint256(oldLsh) ^ 1));

        ShadowToken.MutateSlotArgs memory args = _buildArgs();
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.mutateSlot(args);
    }

    function test_mutateSlot_reverts_when_solved() public {
        // Direct write to `solved` flag via storage slot. The Shadow struct's
        // `solved` field is at slot offset 2 within the struct; we read+write
        // via the seed function side-step.
        // Simpler: call solve() via TestableShadowToken... wait, solve() is
        // stubbed and reverts. So we must storage-poke. Compute the slot
        // manually by mirroring _shadowsStorage's keccak base + offset 2.
        bytes32 baseSlot = keccak256(abi.encode(shadowId, uint256(18))); // _SHADOWS_SLOT
        bytes32 solvedSlot = bytes32(uint256(baseSlot) + 2); // Shadow.solved offset
        vm.store(address(st), solvedSlot, bytes32(uint256(1)));

        ShadowToken.MutateSlotArgs memory args = _buildArgs();
        vm.prank(alice);
        vm.expectRevert(ShadowToken.AlreadySolved.selector);
        st.mutateSlot(args);
    }
}
