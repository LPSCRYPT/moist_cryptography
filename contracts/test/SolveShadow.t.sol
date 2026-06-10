// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test, Vm} from "forge-std/Test.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {TestableShadowToken} from "./Testable.sol";

/// @dev Unit-test verifier double for incremental feature reveal state-machine
///      tests. It checks the contract-provided PI/proof hash but does not perform
///      cryptographic verification. Real `SolveShadowVerifier` + `T10ShadowVerifier`
///      integration coverage lives in `SolveShadowRealProof.t.sol`; broad generated
///      verifier acceptance/rejection lives in `GeneratedVerifierMatrix.t.sol` and
///      `ProofFuzz.t.sol`.
contract ExpectedFeatureRevealVerifier is IVerifier {
    mapping(uint8 => bytes32[9]) internal expectedPi;
    mapping(uint8 => bytes32) internal expectedProofHash;
    bool internal result = true;

    function setExpected(uint8 slotIdx, bytes32[9] memory pi, bytes memory proof) external {
        expectedPi[slotIdx] = pi;
        expectedProofHash[slotIdx] = keccak256(proof);
    }

    function setResult(bool result_) external {
        result = result_;
    }

    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool) {
        if (!result || publicInputs.length != 9) return false;
        uint8 slotIdx = uint8(uint256(publicInputs[1]));
        if (keccak256(proof) != expectedProofHash[slotIdx]) return false;
        bytes32[9] storage pi = expectedPi[slotIdx];
        for (uint256 i = 0; i < 9; i++) {
            if (publicInputs[i] != pi[i]) return false;
        }
        return true;
    }
}

/// @dev Unit-test T10 verifier double. It keeps reveal behavior tests focused on
///      state transitions and PI assembly. Real T10 proof coverage lives in
///      `GeneratedVerifierMatrix.t.sol`, `T10ShadowVerifier.t.sol`, and
///      `SolveShadowRealProof.t.sol`.
contract AlwaysOkT10Verifier is IVerifier {
    function verify(bytes calldata, bytes32[] calldata publicInputs) external pure returns (bool) {
        return publicInputs.length == 20;
    }
}

/// @dev Minimal `IFeatureNFT` double for reveal behavior tests. It records and
///      emits the feature reveal effects needed by `ShadowToken` tests. Real
///      feature implementation coverage lives in `FeatureNFT.t.sol`; real reveal
///      integration with palette opening lives in `SolveShadowRealProof.t.sol`.
contract RevealFeatureNFT is IFeatureNFT {
    struct FeatureState {
        address owner;
        uint256 hostShadowId;
        uint8 hostSlotIdx;
        bytes32 originFaceId;
        bytes32 paletteCommit;
        bytes32 liveStateHash;
        bool inserted;
        bool paletteRevealed;
    }

    event FeaturePaletteRevealed(uint256 indexed featureId, bytes32 paletteCommit, bytes paletteRGB);
    event FeatureSlotRevealed(uint256 indexed featureId, uint256 indexed shadowId, uint8 indexed slotIdx, bytes plaintext);

    mapping(uint256 => FeatureState) internal features;

    function seed(
        uint256 featureId,
        address owner,
        uint256 hostShadowId,
        uint8 hostSlotIdx,
        bytes32 originFaceId,
        bytes32 paletteCommit,
        bytes32 lsh
    ) external {
        features[featureId] = FeatureState(owner, hostShadowId, hostSlotIdx, originFaceId, paletteCommit, lsh, true, false);
    }

    function mintAtShadowMint(uint256, uint8, uint8, bytes32, PaletteAtMint calldata, bytes32, address)
        external
        pure
        returns (uint256)
    {
        revert("unused");
    }

    function extractFromShadow(uint256 featureId, uint256, uint8, bytes32 finalLiveStateHash) external {
        features[featureId].liveStateHash = finalLiveStateHash;
        features[featureId].inserted = false;
    }

    function insertIntoShadow(uint256, uint256, uint8) external pure {
        revert("unused");
    }

    function rotateInsertedOwner(uint256 featureId, uint256, address to) external {
        features[featureId].owner = to;
    }

    function revealInsertedFeature(
        uint256 featureId,
        uint256 shadowId,
        uint8 slotIdx,
        bytes32[16] calldata,
        bytes32,
        bytes calldata plaintext
    ) external {
        FeatureState storage f = features[featureId];
        require(f.inserted, "not inserted");
        require(!f.paletteRevealed, "already revealed");
        f.paletteRevealed = true;
        emit FeaturePaletteRevealed(featureId, f.paletteCommit, new bytes(48));
        emit FeatureSlotRevealed(featureId, shadowId, slotIdx, plaintext);
    }

    function ownerOfFeature(uint256 featureId) external view returns (address) { return features[featureId].owner; }
    function typeIdxOf(uint256) external pure returns (uint8) { return 0; }
    function originFaceIdOf(uint256 featureId) external view returns (bytes32) { return features[featureId].originFaceId; }
    function paletteCommitOf(uint256 featureId) external view returns (bytes32) { return features[featureId].paletteCommit; }
    function liveStateHashCheckpointOf(uint256 featureId) external view returns (bytes32) { return features[featureId].liveStateHash; }
    function isInserted(uint256 featureId) external view returns (bool) { return features[featureId].inserted; }
    function hostShadowIdOf(uint256 featureId) external view returns (uint256) { return features[featureId].hostShadowId; }
    function hostSlotIdxOf(uint256 featureId) external view returns (uint8) { return features[featureId].hostSlotIdx; }
    function paletteRevealedOf(uint256 featureId) external view returns (bool) { return features[featureId].paletteRevealed; }
}

contract IncrementalFeatureRevealTest is Test {
    TestableShadowToken internal st;
    Poseidon2YulSponge internal sponge;
    RevealFeatureNFT internal fn;
    ExpectedFeatureRevealVerifier internal verifier;
    AlwaysOkT10Verifier internal t10Verifier;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    uint256 internal constant SHADOW_ID = 4242;
    bytes32 internal constant OWNER_PK_X = bytes32(uint256(11));
    bytes32 internal constant OWNER_PK_Y = bytes32(uint256(12));
    uint256 internal constant FEATURE_0 = 100;
    uint256 internal constant FEATURE_7 = 107;
    bytes32 internal constant LSH_0 = bytes32(uint256(333));
    bytes32 internal constant LSH_7 = bytes32(uint256(777));
    bytes32 internal constant PALETTE_COMMIT_0 = bytes32(uint256(700));
    bytes32 internal constant PALETTE_COMMIT_7 = bytes32(uint256(707));

    function setUp() public {
        sponge = new Poseidon2YulSponge();
        st = new TestableShadowToken(address(sponge));
        fn = new RevealFeatureNFT();
        verifier = new ExpectedFeatureRevealVerifier();
        t10Verifier = new AlwaysOkT10Verifier();
        st.setFeatureNFT(IFeatureNFT(address(fn)));
        st.setVerifier(3, IVerifier(address(t10Verifier)));
        st.setVerifier(6, IVerifier(address(verifier)));
        _seedShadow();
        _expectReveal(0, FEATURE_0, LSH_0, PALETTE_COMMIT_0, _proof(0), _plaintext(0), 3);
        _expectReveal(7, FEATURE_7, LSH_7, PALETTE_COMMIT_7, _proof(7), _plaintext(7), 9);
    }

    function test_revealSlot_reveals_one_slot_without_global_solve_session() public {
        vm.recordLogs();
        _revealAs(alice, _revealArgs(0, _proof(0), _plaintext(0), 3));

        ShadowToken.ManifestEntry memory m = st.slotOf(SHADOW_ID, 0);
        assertEq(uint256(m.kind), uint256(ShadowToken.SlotKind.REVEALED), "slot revealed");
        assertTrue(fn.paletteRevealedOf(FEATURE_0), "palette revealed");

        (,, bool solved,) = st.shadowHeaderOf(SHADOW_ID);
        assertFalse(solved, "one hidden slot remains");

        bytes32 sigSlot = keccak256("FeatureSlotRevealed(uint256,uint256,uint8,bytes)");
        bytes32 sigShadow = keccak256("ShadowSlotRevealed(uint256,uint8,uint256,uint8)");
        uint256 sawFeatureSlot;
        uint256 sawShadowSlot;
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == sigSlot) sawFeatureSlot++;
            if (logs[i].topics[0] == sigShadow) sawShadowSlot++;
        }
        assertEq(sawFeatureSlot, 1, "one feature reveal event");
        assertEq(sawShadowSlot, 1, "one shadow reveal event");
    }

    function test_revealSlots_batches_and_sets_solved_when_no_hidden_slots_remain() public {
        ShadowToken.RevealSlotArgs[] memory reveals = new ShadowToken.RevealSlotArgs[](2);
        reveals[0] = _revealArgs(0, _proof(0), _plaintext(0), 3);
        reveals[1] = _revealArgs(7, _proof(7), _plaintext(7), 9);
        vm.prank(alice);
        st.revealSlots(SHADOW_ID, reveals);

        (,, bool solved,) = st.shadowHeaderOf(SHADOW_ID);
        assertTrue(solved, "fully revealed");
        assertEq(uint256(st.slotOf(SHADOW_ID, 0).kind), uint256(ShadowToken.SlotKind.REVEALED), "slot0 revealed");
        assertEq(uint256(st.slotOf(SHADOW_ID, 7).kind), uint256(ShadowToken.SlotKind.REVEALED), "slot7 revealed");
    }

    function test_revealSlot_reverts_when_not_owner() public {
        vm.expectRevert(ShadowToken.NotShadowOwner.selector);
        _revealAs(bob, _revealArgs(0, _proof(0), _plaintext(0), 3));
    }

    function test_revealSlot_reverts_for_empty_slot() public {
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.SlotEmpty.selector, 1));
        _revealAs(alice, _revealArgs(1, _proof(1), _plaintext(1), 1));
    }

    function test_revealSlot_reverts_for_already_revealed_slot() public {
        _revealAs(alice, _revealArgs(0, _proof(0), _plaintext(0), 3));
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.SlotRevealed.selector, 0));
        _revealAs(alice, _revealArgs(0, _proof(0), _plaintext(0), 3));
    }

    function test_revealSlot_reverts_when_plaintext_not_proof_bound() public {
        bytes memory tampered = _plaintext(0);
        tampered[31] = 0x01;
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        _revealAs(alice, _revealArgs(0, _proof(0), tampered, 3));
    }

    function test_revealed_slot_rejects_mutate_and_extract() public {
        _revealAs(alice, _revealArgs(0, _proof(0), _plaintext(0), 3));

        ShadowToken.MutateSlotArgs memory mutateArgs;
        mutateArgs.shadowId = SHADOW_ID;
        mutateArgs.slotIdx = 0;
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.SlotRevealed.selector, 0));
        st.mutateSlot(mutateArgs);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.SlotRevealed.selector, 0));
        st.extractSlot(SHADOW_ID, 0, [bytes32(0), bytes32(0)], hex"");
    }

    function _seedShadow() internal {
        uint8[] memory slots = new uint8[](2);
        slots[0] = 0;
        slots[1] = 7;
        uint256[] memory featureIds = new uint256[](2);
        featureIds[0] = FEATURE_0;
        featureIds[1] = FEATURE_7;
        bytes32[] memory lshs = new bytes32[](2);
        lshs[0] = LSH_0;
        lshs[1] = LSH_7;
        st.seedShadowMultiSlot(SHADOW_ID, alice, OWNER_PK_X, OWNER_PK_Y, slots, featureIds, lshs);
        fn.seed(FEATURE_0, alice, SHADOW_ID, 0, bytes32(uint256(1000)), PALETTE_COMMIT_0, LSH_0);
        fn.seed(FEATURE_7, alice, SHADOW_ID, 7, bytes32(uint256(1007)), PALETTE_COMMIT_7, LSH_7);
    }

    function _expectReveal(
        uint8 slotIdx,
        uint256 featureId,
        bytes32 lsh,
        bytes32 paletteCommit,
        bytes memory proof,
        bytes memory plaintext,
        uint8 rank
    ) internal {
        bytes32[9] memory pi;
        pi[0] = bytes32(SHADOW_ID);
        pi[1] = bytes32(uint256(slotIdx));
        pi[2] = bytes32(featureId);
        pi[3] = lsh;
        pi[4] = _sponge(plaintext);
        pi[5] = paletteCommit;
        pi[6] = OWNER_PK_X;
        pi[7] = OWNER_PK_Y;
        pi[8] = bytes32(uint256(rank));
        verifier.setExpected(slotIdx, pi, proof);
    }

    function _revealAs(address who, ShadowToken.RevealSlotArgs memory args) internal {
        ShadowToken.RevealSlotArgs[] memory reveals = new ShadowToken.RevealSlotArgs[](1);
        reveals[0] = args;
        vm.prank(who);
        st.revealSlots(SHADOW_ID, reveals);
    }

    function _revealArgs(
        uint8 slotIdx,
        bytes memory proof,
        bytes memory plaintext,
        uint8 rank
    ) internal pure returns (ShadowToken.RevealSlotArgs memory args) {
        args.slotIdx = slotIdx;
        args.proof = proof;
        args.plaintext = plaintext;
        args.paletteSalt = bytes32(uint256(1));
        args.revealedRank = rank;
        args.newT10 = [bytes32(uint256(1)), bytes32(uint256(2))];
        args.proofT10 = hex"10";
    }

    function _proof(uint8 slotIdx) internal pure returns (bytes memory proof) {
        proof = abi.encodePacked(bytes1(slotIdx + 1));
    }

    function _plaintext(uint8 slotIdx) internal pure returns (bytes memory plaintext) {
        plaintext = new bytes(39 * 32);
        plaintext[31] = bytes1(slotIdx);
    }

    function _sponge(bytes memory data) internal view returns (bytes32 digest) {
        (bool ok, bytes memory ret) = address(sponge).staticcall(data);
        require(ok && ret.length == 32, "sponge failed");
        digest = abi.decode(ret, (bytes32));
    }
}
