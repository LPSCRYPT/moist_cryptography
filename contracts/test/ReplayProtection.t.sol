// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test, stdJson} from "forge-std/Test.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {KeyRegistry} from "../src/KeyRegistry.sol";
import {MutateSlotVerifier} from "../src/MutateSlotVerifier.sol";
import {T10ShadowVerifier} from "../src/T10ShadowVerifier.sol";
import {TransferShadowVerifier} from "../src/TransferShadowVerifier.sol";
import {ZIndexCommitVerifier} from "../src/ZIndexCommitVerifier.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {Poseidon2YulSponge16} from "../src/Poseidon2YulSponge16.sol";
import {TestableShadowToken, TestableFeatureNFT} from "./Testable.sol";

/// @notice Replay-protection coverage for every state-changing v2 op.
///
/// Each state-changing entry-point in v2 must be one of:
///   (a) chain-state-bound: a successful call advances chain state such that
///       a second call with identical args fails proof verification or trips
///       a state-shape revert. The proof's PI[6]=oldLsh, PI[12]=prevChainTip,
///       PI[14]=prevMutationCount carry the old chain state; storage carries
///       the *new* chain state after the first call. The contract rebuilds PI
///       from storage, so the proof's frozen claim about pre-state no longer
///       matches and the verifier rejects.
///   (b) explicitly-anti-replay: stores a nullifier (mintedOrigins) or a
///       monotone flag (solved) and reverts on second call.
///   (c) idempotent-by-design: the proof binds only the new commit, not the
///       chain's old state. Re-submission is a no-op refresh. Documented.
///
/// Coverage matrix:
///   - mintShadow      : (b)  [already covered in MintShadow.t.sol via
///                              AlreadyMinted]
///   - solve           : (b)  [already covered in SolveShadow.t.sol via
///                              AlreadySolved]
///   - mutateSlot      : (a)  -> ReplayMutateSlotTest below
///   - extractSlot     : (a)  -> ReplayExtractSlotTest below
///   - transferShadow  : (a)  -> ReplayTransferShadowTest below
///   - insertFeature   : (a)  -> ReplayInsertFeatureTest below
///   - setZIndexCommit : (c)  -> ReplaySetZIndexCommitTest below
///                              (intentionally idempotent; documents this)

// ============================================================================
// 1. mutateSlot: chain advances; second call's proof PI[6] (oldLsh)
//    no longer matches storage's lsh -> InvalidProof.
// ============================================================================

contract ReplayMutateSlotTest is Test {
    TestableShadowToken internal st;
    TestableFeatureNFT  internal fn;
    MutateSlotVerifier  internal vMut;
    T10ShadowVerifier   internal vT10;
    Poseidon2YulSponge  internal sponge;

    string internal constant FIX = "./test/fixtures/atomic_mutate/atomic_demo";

    address internal alice = makeAddr("alice");
    ShadowToken.MutateSlotArgs internal args;

    function setUp() public {
        sponge = new Poseidon2YulSponge();
        st = new TestableShadowToken(address(sponge));
        fn = new TestableFeatureNFT(address(st));
        st.setFeatureNFT(IFeatureNFT(address(fn)));
        vMut = new MutateSlotVerifier();
        vT10 = new T10ShadowVerifier();
        st.setVerifier(st.SLOT_MUTATE_SLOT(), IVerifier(address(vMut)));
        st.setVerifier(st.SLOT_T10_SHADOW(), IVerifier(address(vT10)));

        _seedAndBuildArgs();
    }

    /// Split out of setUp to keep stack depth manageable. Loads fixture
    /// PI/proof bytes, seeds chain to pre-mutate state, builds `args`.
    function _seedAndBuildArgs() internal {
        bytes memory proofMut = vm.readFileBinary(string.concat(FIX, "/proof_mut.bin"));
        bytes32[] memory piMut = _loadFields(string.concat(FIX, "/public_inputs_mut.bin"), 16);
        bytes memory proofT10 = vm.readFileBinary(string.concat(FIX, "/proof_t10.bin"));
        bytes32[] memory piT10 = _loadFields(string.concat(FIX, "/public_inputs_t10.bin"), 20);
        bytes memory newC2    = vm.readFileBinary(string.concat(FIX, "/c2.bin"));

        fn.seedFeature(
            uint256(piMut[2]), uint256(piMut[0]), uint8(uint256(piMut[1])),
            uint8(uint256(piMut[3])),
            piMut[4], piMut[5], piMut[6], alice
        );
        st.seedShadowAndSlot(
            uint256(piMut[0]), alice, piMut[10], piMut[11],
            uint8(uint256(piMut[1])), uint256(piMut[2]), piMut[6]
        );

        bytes32[2] memory newT10;
        newT10[0] = piT10[2];
        newT10[1] = piT10[3];
        args = ShadowToken.MutateSlotArgs({
            shadowId: uint256(piMut[0]),
            slotIdx:  uint8(uint256(piMut[1])),
            proofMutate: proofMut,
            newC1X: 0, newC1Y: 0,
            newLiveStateHash: piMut[7],
            newCtCommit:      piMut[8],
            c2FieldCount: uint16(newC2.length / 32),
            c2: newC2,
            prevChainTip: piMut[12],
            newChainTip:  piMut[13],
            prevMutationCount: uint16(uint256(piMut[14])),
            newMutationCount:  uint16(uint256(piMut[15])),
            newT10: newT10,
            proofT10: proofT10
        });
    }

    /// First call succeeds (chain at oldLsh); second identical call reverts
    /// because storage lsh has advanced to newLsh, so contract-built PI[6]
    /// no longer matches the proof's frozen claim. Verifier rejects.
    function test_replay_mutateSlot_reverts_after_chain_advance() public {
        vm.prank(alice);
        st.mutateSlot(args);

        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.mutateSlot(args);
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
}

// ============================================================================
// 2. extractSlot: first call zeros the slot; second call hits SlotEmpty
//    before any T10 work. Proofless body, but slot-kind guard catches replay.
// ============================================================================

contract ReplayExtractSlotTest is Test {
    using stdJson for string;

    TestableShadowToken internal st;
    TestableFeatureNFT  internal fn;
    T10ShadowVerifier   internal vT10;
    Poseidon2YulSponge  internal sponge;

    string internal constant FIX = "./test/fixtures/atomic_extract/extract_demo";

    address internal alice = makeAddr("alice");
    uint256 internal shadowId;
    uint8   internal slotIdx;
    bytes32[2] internal newT10;
    bytes internal proofT10;

    function setUp() public {
        sponge = new Poseidon2YulSponge();
        st = new TestableShadowToken(address(sponge));
        fn = new TestableFeatureNFT(address(st));
        st.setFeatureNFT(IFeatureNFT(address(fn)));
        vT10 = new T10ShadowVerifier();
        st.setVerifier(st.SLOT_T10_SHADOW(), IVerifier(address(vT10)));

        proofT10 = vm.readFileBinary(string.concat(FIX, "/proof_t10.bin"));

        string memory meta = vm.readFile(string.concat(FIX, "/meta.json"));
        shadowId           = vm.parseJsonUint(meta, ".shadow_id");
        slotIdx            = uint8(vm.parseJsonUint(meta, ".slot_idx"));
        uint256 featureId  = vm.parseJsonUint(meta, ".feature_id");
        uint8   typeIdx    = uint8(vm.parseJsonUint(meta, ".type_idx"));
        bytes32 originFaceId  = vm.parseJsonBytes32(meta, ".origin_face_id");
        bytes32 paletteCommit = vm.parseJsonBytes32(meta, ".palette_commit");
        bytes32 lshPre        = vm.parseJsonBytes32(meta, ".lsh_pre");
        newT10[0]             = vm.parseJsonBytes32(meta, ".t10_hi");
        newT10[1]             = vm.parseJsonBytes32(meta, ".t10_lo");

        fn.seedFeature(featureId, shadowId, slotIdx, typeIdx, originFaceId, paletteCommit, lshPre, alice);
        st.seedShadowAndSlot(
            shadowId, alice,
            bytes32(uint256(0xaa)), bytes32(uint256(0xbb)),
            slotIdx, featureId, lshPre
        );
    }

    /// First extract empties slot; second call sees kind == EMPTY and
    /// reverts with SlotEmpty(slotIdx). Proves the slot-kind guard
    /// short-circuits before the T10 proof would re-verify against
    /// the now-stale (post-extract) manifest hash.
    function test_replay_extractSlot_reverts_with_SlotEmpty() public {
        vm.prank(alice);
        st.extractSlot(shadowId, slotIdx, newT10, proofT10);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.SlotEmpty.selector, slotIdx));
        st.extractSlot(shadowId, slotIdx, newT10, proofT10);
    }
}

// ============================================================================
// 3. transferShadow: first call rotates ERC-721 owner alice -> bob and
//    cycles the carrier ownership. Second call by alice fails the
//    NotShadowOwner guard. Even if alice were still owner, the proof's
//    PI[5..6] (prev_owner_pk) would mismatch the new ecdhPub state.
// ============================================================================

contract ReplayTransferShadowTest is Test {
    using stdJson for string;

    TestableShadowToken    internal st;
    TestableFeatureNFT     internal fn;
    TransferShadowVerifier internal vT;
    T10ShadowVerifier      internal vT10;
    Poseidon2YulSponge     internal sponge;
    Poseidon2YulSponge16   internal sponge16;
    KeyRegistry            internal kr;

    string internal constant FIX = "./test/fixtures/atomic_transfer/atomic_transfer_demo";

    address internal alice = makeAddr("alice");
    address internal bob   = makeAddr("bob");

    uint8[]    internal occupiedIdxs;
    uint256[]  internal featureIds;
    ShadowToken.TransferShadowArgs internal args;

    // Storage-resident per-slot arrays so the setup helpers don't blow
    // the stack-too-deep budget. Solidity local stack is 16 vars.
    uint256 internal _shadowId;
    bytes32[16] internal _newLsh;
    bytes32[16] internal _newCt;
    uint256[16] internal _newC1X;
    uint256[16] internal _newC1Y;
    bytes32[16] internal _newChainTip;
    uint16[16]  internal _newCount;
    bytes[]     internal _c2s;          // 16 entries; bytes is variable-length
    bytes32     internal _t10Hi;
    bytes32     internal _t10Lo;
    bytes       internal _proofTransfer;
    bytes       internal _proofT10;

    function setUp() public {
        _deployStack();
        _loadProofsAndPi();
        _seedKeyRegistryAndShadow();
        _loadPerSlotMeta();
        _loadPerSlotC2();
        _buildArgs();
    }

    function _deployStack() internal {
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
    }

    function _loadProofsAndPi() internal {
        _proofTransfer = vm.readFileBinary(string.concat(FIX, "/proof_transfer.bin"));
        bytes32[] memory piTransfer = _loadFields(string.concat(FIX, "/public_inputs_transfer.bin"), 8);
        _proofT10 = vm.readFileBinary(string.concat(FIX, "/proof_t10.bin"));
        bytes32[] memory piT10 = _loadFields(string.concat(FIX, "/public_inputs_t10.bin"), 20);
        _shadowId = uint256(piTransfer[0]);
        _t10Hi = piT10[2];
        _t10Lo = piT10[3];
        // Stash prev/recipient pks via storage slots reused below.
        _stashedRecipientPkX = piTransfer[1];
        _stashedRecipientPkY = piTransfer[2];
        _stashedPrevOwnerPkX = piTransfer[5];
        _stashedPrevOwnerPkY = piTransfer[6];
    }

    bytes32 internal _stashedRecipientPkX;
    bytes32 internal _stashedRecipientPkY;
    bytes32 internal _stashedPrevOwnerPkX;
    bytes32 internal _stashedPrevOwnerPkY;

    function _seedKeyRegistryAndShadow() internal {
        vm.prank(alice);
        kr.register(_stashedPrevOwnerPkX, _stashedPrevOwnerPkY);
        vm.prank(bob);
        kr.register(_stashedRecipientPkX, _stashedRecipientPkY);
    }

    function _loadPerSlotMeta() internal {
        string memory j = vm.readFile(string.concat(FIX, "/meta.json"));
        for (uint256 i = 0; i < 16; i++) {
            string memory idx = vm.toString(i);
            _newLsh[i]      = j.readBytes32(string.concat(".new_lsh[", idx, "]"));
            _newCt[i]       = j.readBytes32(string.concat(".new_ct_commit[", idx, "]"));
            _newC1X[i]      = uint256(j.readBytes32(string.concat(".new_c1_x[", idx, "]")));
            _newC1Y[i]      = uint256(j.readBytes32(string.concat(".new_c1_y[", idx, "]")));
            _newChainTip[i] = j.readBytes32(string.concat(".new_chain_tip[", idx, "]"));
            _newCount[i]    = uint16(j.readUint(string.concat(".new_mutation_count[", idx, "]")));
        }
        uint256[] memory occ = j.readUintArray(".occupied_idxs");
        occupiedIdxs = new uint8[](occ.length);
        bytes32[] memory prevLshArr = new bytes32[](occ.length);
        uint256[] memory featIds = new uint256[](occ.length);
        featureIds = new uint256[](occ.length);
        for (uint256 i = 0; i < occ.length; i++) {
            occupiedIdxs[i] = uint8(occ[i]);
            string memory sIdxStr = vm.toString(uint256(occupiedIdxs[i]));
            prevLshArr[i] = j.readBytes32(string.concat(".prev_lsh[", sIdxStr, "]"));
            featIds[i]   = uint256(keccak256(abi.encode(_shadowId, occupiedIdxs[i], "feature")));
            featureIds[i]= featIds[i];
        }
        st.seedShadowMultiSlot(
            _shadowId, alice,
            _stashedPrevOwnerPkX, _stashedPrevOwnerPkY,
            occupiedIdxs, featIds, prevLshArr
        );
        for (uint256 i = 0; i < occupiedIdxs.length; i++) {
            uint8 sIdx = occupiedIdxs[i];
            fn.seedFeature(
                featIds[i], _shadowId, sIdx, uint8(i),
                keccak256(abi.encode("origin", _shadowId, sIdx)),
                keccak256(abi.encode("palette", _shadowId, sIdx)),
                prevLshArr[i],
                alice
            );
        }
    }

    function _loadPerSlotC2() internal {
        string memory j = vm.readFile(string.concat(FIX, "/meta.json"));
        _c2s = new bytes[](16);
        for (uint256 i = 0; i < occupiedIdxs.length; i++) {
            string memory sIdxStr = vm.toString(uint256(occupiedIdxs[i]));
            bytes memory buf = new bytes(39 * 32);
            for (uint256 k = 0; k < 39; k++) {
                bytes32 v = j.readBytes32(string.concat(".c2_per_slot.", sIdxStr, "[", vm.toString(k), "]"));
                assembly { mstore(add(add(buf, 32), mul(k, 32)), v) }
            }
            _c2s[occupiedIdxs[i]] = buf;
        }
    }

    function _buildArgs() internal {
        bytes32[2] memory t10;
        t10[0] = _t10Hi;
        t10[1] = _t10Lo;
        args.shadowId = _shadowId;
        args.to = bob;
        args.proof = _proofTransfer;
        args.newLiveStateHashes = _newLsh;
        args.newChainTips = _newChainTip;
        args.newC1Xs = _newC1X;
        args.newC1Ys = _newC1Y;
        args.newCtCommits = _newCt;
        args.newMutationCounts = _newCount;
        args.c2s = _c2s;
        args.newT10 = t10;
        args.proofT10 = _proofT10;
    }

    /// First transfer rotates owner alice -> bob. Replay attempt by alice
    /// is rejected at the NotShadowOwner guard before any proof work.
    function test_replay_transferShadow_reverts_NotShadowOwner_after_rotation() public {
        vm.prank(alice);
        st.transferShadow(args);

        vm.prank(alice);
        vm.expectRevert(ShadowToken.NotShadowOwner.selector);
        st.transferShadow(args);
    }

    /// Even if bob (current owner) tries to replay alice's proof, the
    /// proof's prev_owner_pk PI fields claim alice was the prev owner --
    /// but on-chain ecdhPub now holds bob's pk. The chain-built PI mismatches
    /// the proof, verifier rejects.
    function test_replay_transferShadow_reverts_when_bob_replays_alices_proof() public {
        vm.prank(alice);
        st.transferShadow(args);

        vm.prank(bob);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.transferShadow(args);
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
}

// ============================================================================
// 4. insertFeature: first call binds carrier into slot. Second call hits
//    `if (fn.isInserted(args.featureId)) revert FeatureAlreadyInserted(...)`
//    before proof work. Single-host invariant guard.
// ============================================================================

contract ReplayInsertFeatureTest is Test {
    TestableShadowToken internal st;
    TestableFeatureNFT  internal fn;
    MutateSlotVerifier  internal vMut;
    T10ShadowVerifier   internal vT10;
    Poseidon2YulSponge  internal sponge;

    string internal constant FIX = "./test/fixtures/atomic_mutate/atomic_demo";

    address internal alice = makeAddr("alice");
    uint256 internal constant SOURCE_SHADOW = 0xDEADBEEF;
    uint8   internal constant SOURCE_SLOT   = 9;

    ShadowToken.InsertFeatureArgs internal args;
    uint256 internal featureId;

    function setUp() public {
        sponge = new Poseidon2YulSponge();
        st = new TestableShadowToken(address(sponge));
        fn = new TestableFeatureNFT(address(st));
        st.setFeatureNFT(IFeatureNFT(address(fn)));
        vMut = new MutateSlotVerifier();
        vT10 = new T10ShadowVerifier();
        st.setVerifier(st.SLOT_MUTATE_SLOT(), IVerifier(address(vMut)));
        st.setVerifier(st.SLOT_T10_SHADOW(), IVerifier(address(vT10)));

        bytes memory proofMut = vm.readFileBinary(string.concat(FIX, "/proof_mut.bin"));
        bytes32[] memory piMut = _loadFields(string.concat(FIX, "/public_inputs_mut.bin"), 16);
        bytes memory proofT10 = vm.readFileBinary(string.concat(FIX, "/proof_t10.bin"));
        bytes32[] memory piT10 = _loadFields(string.concat(FIX, "/public_inputs_t10.bin"), 20);
        bytes memory newC2    = vm.readFileBinary(string.concat(FIX, "/c2.bin"));

        uint256 shadowId      = uint256(piMut[0]);
        uint8   slotIdx       = uint8(uint256(piMut[1]));
                featureId     = uint256(piMut[2]);
        bytes32 originFaceId  = piMut[4];
        bytes32 paletteCommit = piMut[5];
        bytes32 oldLsh        = piMut[6];
        bytes32 ownerPkX      = piMut[10];
        bytes32 ownerPkY      = piMut[11];

        fn.seedFeature(
            featureId, SOURCE_SHADOW, SOURCE_SLOT,
            uint8(uint256(piMut[3])),
            originFaceId, paletteCommit, oldLsh, alice
        );
        // Detach: matches a post-extract carrier.
        vm.prank(address(st));
        fn.extractFromShadow(featureId, SOURCE_SHADOW, SOURCE_SLOT, oldLsh);

        st.seedShadowOnly(shadowId, alice, ownerPkX, ownerPkY);

        bytes32[2] memory newT10;
        newT10[0] = piT10[2]; newT10[1] = piT10[3];

        args = ShadowToken.InsertFeatureArgs({
            shadowId: shadowId,
            slotIdx:  slotIdx,
            featureId: featureId,
            proofInsert: proofMut,
            newC1X: 0, newC1Y: 0,
            newLiveStateHash: piMut[7],
            newCtCommit:      piMut[8],
            c2FieldCount: uint16(newC2.length / 32),
            c2: newC2,
            prevChainTip: piMut[12],
            newChainTip:  piMut[13],
            prevMutationCount: uint16(uint256(piMut[14])),
            newMutationCount:  uint16(uint256(piMut[15])),
            newT10: newT10,
            proofT10: proofT10
        });
    }

    /// First insertFeature call binds carrier as inserted. Second call
    /// trips `if (fn.isInserted(featureId))` -> FeatureAlreadyInserted.
    /// Defends single-host invariant: a carrier cannot be inserted into
    /// two shadows at once nor inserted twice into the same shadow.
    function test_replay_insertFeature_reverts_FeatureAlreadyInserted() public {
        vm.prank(alice);
        st.insertFeature(args);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(
            ShadowToken.FeatureAlreadyInserted.selector, featureId
        ));
        st.insertFeature(args);
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
}

// ============================================================================
// 5. setZIndexCommit: idempotent-by-design.
//    The zindex_commit circuit binds only (shadowId, newCommit). It does
//    NOT bind the chain's existing zIndexCommit. Re-submitting the same
//    args is therefore a valid no-op refresh: T10 still matches because
//    the manifest hasn't changed; zIndexCommit is overwritten with itself.
//
//    This test pins that property explicitly. If we ever decide
//    setZIndexCommit needs anti-replay (e.g. via prev-commit binding),
//    this test will fail and force the reviewer to update both.
// ============================================================================

contract ReplaySetZIndexCommitTest is Test {
    using stdJson for string;

    TestableShadowToken  internal st;
    TestableFeatureNFT   internal fn;
    ZIndexCommitVerifier internal vZ;
    T10ShadowVerifier    internal vT10;
    Poseidon2YulSponge   internal sponge;

    string internal constant FIX = "./test/fixtures/atomic_zindex/zidx_atomic_demo";

    address internal alice = makeAddr("alice");
    ShadowToken.SetZIndexCommitArgs internal args;
    uint256 internal shadowId;
    bytes32 internal newZCommit;

    function setUp() public {
        sponge = new Poseidon2YulSponge();
        st = new TestableShadowToken(address(sponge));
        fn = new TestableFeatureNFT(address(st));
        st.setFeatureNFT(IFeatureNFT(address(fn)));
        vZ = new ZIndexCommitVerifier();
        vT10 = new T10ShadowVerifier();
        st.setVerifier(st.SLOT_ZINDEX_COMMIT(), IVerifier(address(vZ)));
        st.setVerifier(st.SLOT_T10_SHADOW(), IVerifier(address(vT10)));

        bytes memory proofZ   = vm.readFileBinary(string.concat(FIX, "/proof_z.bin"));
        bytes memory proofT10 = vm.readFileBinary(string.concat(FIX, "/proof_t10.bin"));

        string memory meta = vm.readFile(string.concat(FIX, "/meta.json"));
        shadowId          = vm.parseJsonUint(meta, ".shadow_id");
        uint8 slotIdx     = uint8(vm.parseJsonUint(meta, ".slot_idx"));
        bytes32 lshHeld   = vm.parseJsonBytes32(meta, ".lsh_held");
        newZCommit        = vm.parseJsonBytes32(meta, ".z_commit");
        bytes32[2] memory t10;
        t10[0] = vm.parseJsonBytes32(meta, ".t10_hi");
        t10[1] = vm.parseJsonBytes32(meta, ".t10_lo");

        st.seedShadowAndSlot(
            shadowId, alice,
            bytes32(uint256(0xaa)), bytes32(uint256(0xbb)),
            slotIdx, 0xfeed, lshHeld
        );

        args = ShadowToken.SetZIndexCommitArgs({
            shadowId: shadowId,
            newCommit: newZCommit,
            proofZ: proofZ,
            newT10: t10,
            proofT10: proofT10
        });
    }

    /// Replay is intentionally idempotent. The zindex_commit circuit binds
    /// only (shadowId, newCommit), so re-submission re-verifies trivially
    /// and overwrites zIndexCommit with the same value. T10 also re-verifies
    /// because the manifest hash is unchanged between calls.
    ///
    /// This is by-design (zIndexCommit can be updated pre-solve without
    /// chain-state binding). If someone later adds a prev-commit binding
    /// to harden against speculative-commit games, this test must be
    /// updated to expect a revert -- and the reviewer will see the
    /// behavior change explicitly.
    function test_setZIndexCommit_replay_is_idempotent_by_design() public {
        vm.prank(alice);
        st.setZIndexCommit(args);
        bytes32 zPost1 = st.shadowOf(shadowId).zIndexCommit;
        assertEq(zPost1, newZCommit, "first: commit set");

        // Second identical call must succeed (no anti-replay state).
        vm.prank(alice);
        st.setZIndexCommit(args);
        bytes32 zPost2 = st.shadowOf(shadowId).zIndexCommit;
        assertEq(zPost2, newZCommit, "second: commit same value (idempotent)");
    }

    /// Once shadow is solved, even idempotent zindex updates are blocked
    /// by AlreadySolved. Pins that solved is the actual finality boundary.
    function test_setZIndexCommit_post_solve_reverts_AlreadySolved() public {
        vm.prank(alice);
        st.setZIndexCommit(args);

        // Mark solved via test harness (no real solve proof needed for this
        // assertion; the AlreadySolved guard fires before any proof work).
        st.setShadowSolvedForTest(shadowId, 0x0123456789abcdef, bytes32(uint256(1)), bytes32(uint256(2)));

        vm.prank(alice);
        vm.expectRevert(ShadowToken.AlreadySolved.selector);
        st.setZIndexCommit(args);
    }
}
