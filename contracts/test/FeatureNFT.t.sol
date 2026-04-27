// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";

/// @notice v2 FeatureNFT carrier contract tests.
///
/// The test contract impersonates `ShadowToken` by passing its own
/// address as `shadowTokenAddr` to the FeatureNFT ctor. This is a test
/// fixture, not a mock: the privileged surface really requires
/// `msg.sender == shadowToken`, and we exercise it from that exact
/// address. ZK proof verification is not under test here (no
/// transferFeatureVerifier is set; tests that don't depend on the
/// proof path leave it unset).
contract FeatureNFTv2Test is Test {
    FeatureNFT internal fn;

    address internal owner = makeAddr("owner");
    address internal stranger = makeAddr("stranger");

    uint256 internal constant SHADOW_A = 0x1111;
    uint256 internal constant SHADOW_B = 0x2222;

    bytes32 internal constant ORIGIN_FACE = bytes32(uint256(0xface));
    bytes32 internal constant PALETTE_COMMIT = bytes32(uint256(0xabcd));
    bytes32 internal constant LSH_INIT = bytes32(uint256(0xdead));
    bytes32 internal constant LSH_FINAL = bytes32(uint256(0xbeef));

    function setUp() public {
        fn = new FeatureNFT(address(this));
    }

    // ---- mintAtShadowMint ----

    function test_mintAtShadowMint_writesAllImmutableFields() public {
        uint256 fid = fn.mintAtShadowMint(
            SHADOW_A, 3, 7, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );

        assertEq(fn.ownerOfFeature(fid), owner, "owner");
        assertEq(fn.typeIdxOf(fid), 7, "typeIdx");
        assertEq(fn.originFaceIdOf(fid), ORIGIN_FACE, "originFaceId");
        assertEq(fn.paletteCommitOf(fid), PALETTE_COMMIT, "paletteCommit");
        assertEq(fn.liveStateHashCheckpointOf(fid), LSH_INIT, "checkpoint == init");
        assertTrue(fn.isInserted(fid), "isInserted true at mint");
        assertEq(fn.hostShadowIdOf(fid), SHADOW_A, "hostShadowId");
        assertEq(fn.hostSlotIdxOf(fid), 3, "hostSlotIdx");

        FeatureNFT.Feature memory f = fn.featureOf(fid);
        assertGt(f.mintedAt, 0, "mintedAt set");
    }

    function test_mintAtShadowMint_revertsForNonShadowToken() public {
        vm.prank(stranger);
        vm.expectRevert(FeatureNFT.NotShadowToken.selector);
        fn.mintAtShadowMint(
            SHADOW_A, 0, 0, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );
    }

    function test_mintCounter_increments_andDistinctIds() public {
        uint256 a = fn.mintAtShadowMint(
            SHADOW_A, 0, 0, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );
        uint256 b = fn.mintAtShadowMint(
            SHADOW_A, 1, 1, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );
        assertTrue(a != b, "distinct featureIds");
        assertEq(fn.mintCounter(), 2, "mintCounter == 2");
    }

    // ---- extractFromShadow ----

    function test_extractFromShadow_syncsCheckpoint_clearsHost() public {
        uint256 fid = fn.mintAtShadowMint(
            SHADOW_A, 5, 2, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );

        fn.extractFromShadow(fid, SHADOW_A, 5, LSH_FINAL);

        assertFalse(fn.isInserted(fid), "isInserted cleared");
        assertEq(fn.hostShadowIdOf(fid), 0, "hostShadowId cleared");
        assertEq(fn.hostSlotIdxOf(fid), 0, "hostSlotIdx cleared");
        assertEq(fn.liveStateHashCheckpointOf(fid), LSH_FINAL, "checkpoint synced to final");
        // Immutables survive.
        assertEq(fn.typeIdxOf(fid), 2, "typeIdx preserved");
        assertEq(fn.originFaceIdOf(fid), ORIGIN_FACE, "originFaceId preserved");
        assertEq(fn.paletteCommitOf(fid), PALETTE_COMMIT, "paletteCommit preserved");
    }

    function test_extractFromShadow_revertsWrongHostShadow() public {
        uint256 fid = fn.mintAtShadowMint(
            SHADOW_A, 0, 0, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );
        vm.expectRevert(abi.encodeWithSelector(FeatureNFT.WrongHost.selector, fid));
        fn.extractFromShadow(fid, SHADOW_B, 0, LSH_FINAL);
    }

    function test_extractFromShadow_revertsWrongHostSlot() public {
        uint256 fid = fn.mintAtShadowMint(
            SHADOW_A, 0, 0, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );
        vm.expectRevert(abi.encodeWithSelector(FeatureNFT.WrongHost.selector, fid));
        fn.extractFromShadow(fid, SHADOW_A, 1, LSH_FINAL);
    }

    function test_extractFromShadow_revertsWhenNotInserted() public {
        uint256 fid = fn.mintAtShadowMint(
            SHADOW_A, 0, 0, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );
        fn.extractFromShadow(fid, SHADOW_A, 0, LSH_FINAL);

        vm.expectRevert(abi.encodeWithSelector(FeatureNFT.NotInserted.selector, fid));
        fn.extractFromShadow(fid, SHADOW_A, 0, LSH_FINAL);
    }

    function test_extractFromShadow_revertsForNonShadowToken() public {
        uint256 fid = fn.mintAtShadowMint(
            SHADOW_A, 0, 0, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );
        vm.prank(stranger);
        vm.expectRevert(FeatureNFT.NotShadowToken.selector);
        fn.extractFromShadow(fid, SHADOW_A, 0, LSH_FINAL);
    }

    // ---- insertIntoShadow ----

    function test_insertIntoShadow_setsHost_marksInserted() public {
        uint256 fid = fn.mintAtShadowMint(
            SHADOW_A, 0, 0, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );
        fn.extractFromShadow(fid, SHADOW_A, 0, LSH_FINAL);

        fn.insertIntoShadow(fid, SHADOW_B, 9);

        assertTrue(fn.isInserted(fid), "isInserted re-set");
        assertEq(fn.hostShadowIdOf(fid), SHADOW_B, "hostShadowId moved");
        assertEq(fn.hostSlotIdxOf(fid), 9, "hostSlotIdx moved");
        // checkpoint stays as the post-extract value (slot's liveStateHash is
        // authoritative while inserted).
        assertEq(fn.liveStateHashCheckpointOf(fid), LSH_FINAL, "checkpoint stays stale");
    }

    function test_insertIntoShadow_revertsWhenAlreadyInserted_singleHostInvariant() public {
        uint256 fid = fn.mintAtShadowMint(
            SHADOW_A, 0, 0, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );
        // Still inserted in SHADOW_A; trying to bind into SHADOW_B must revert.
        vm.expectRevert(abi.encodeWithSelector(FeatureNFT.AlreadyInserted.selector, fid));
        fn.insertIntoShadow(fid, SHADOW_B, 9);
    }

    function test_insertIntoShadow_revertsForNonShadowToken() public {
        uint256 fid = fn.mintAtShadowMint(
            SHADOW_A, 0, 0, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );
        fn.extractFromShadow(fid, SHADOW_A, 0, LSH_FINAL);

        vm.prank(stranger);
        vm.expectRevert(FeatureNFT.NotShadowToken.selector);
        fn.insertIntoShadow(fid, SHADOW_B, 9);
    }

    // ---- ERC-721 transfer lockdown ----

    function test_transferFrom_revertsWhileInserted_custodyLock() public {
        uint256 fid = fn.mintAtShadowMint(
            SHADOW_A, 0, 0, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(FeatureNFT.CustodyLocked.selector, fid));
        fn.transferFrom(owner, stranger, fid);
    }

    function test_transferFrom_revertsWhenHeld_TransferGated() public {
        uint256 fid = fn.mintAtShadowMint(
            SHADOW_A, 0, 0, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );
        fn.extractFromShadow(fid, SHADOW_A, 0, LSH_FINAL);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(FeatureNFT.TransferGated.selector, fid));
        fn.transferFrom(owner, stranger, fid);
    }

    function test_safeTransferFrom_revertsWhileInserted() public {
        uint256 fid = fn.mintAtShadowMint(
            SHADOW_A, 0, 0, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(FeatureNFT.CustodyLocked.selector, fid));
        fn.safeTransferFrom(owner, stranger, fid, "");
    }

    function test_safeTransferFrom_revertsWhenHeld_TransferGated() public {
        uint256 fid = fn.mintAtShadowMint(
            SHADOW_A, 0, 0, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );
        fn.extractFromShadow(fid, SHADOW_A, 0, LSH_FINAL);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(FeatureNFT.TransferGated.selector, fid));
        fn.safeTransferFrom(owner, stranger, fid, "");
    }

    function test_safeTransferFrom_threeArg_revertsLikewise() public {
        // OZ 5.x routes the 3-arg `safeTransferFrom(from, to, id)` to the 4-arg
        // virtual override; both must end at the same lockdown.
        uint256 fid = fn.mintAtShadowMint(
            SHADOW_A, 0, 0, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(FeatureNFT.CustodyLocked.selector, fid));
        fn.safeTransferFrom(owner, stranger, fid);
    }

    // ---- transferFeature ----

    function test_transferFeature_revertsWhileInserted() public {
        uint256 fid = fn.mintAtShadowMint(
            SHADOW_A, 0, 0, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );
        bytes memory proof = hex"";
        bytes32[] memory pi = new bytes32[](8);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(FeatureNFT.CustodyLocked.selector, fid));
        fn.transferFeature(fid, stranger, proof, pi);
    }

    function test_transferFeature_revertsWhenNotOwner() public {
        uint256 fid = fn.mintAtShadowMint(
            SHADOW_A, 0, 0, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );
        fn.extractFromShadow(fid, SHADOW_A, 0, LSH_FINAL);

        bytes memory proof = hex"";
        bytes32[] memory pi = new bytes32[](8);
        vm.prank(stranger);
        vm.expectRevert(FeatureNFT.NotFeatureOwner.selector);
        fn.transferFeature(fid, stranger, proof, pi);
    }

    function test_transferFeature_revertsWhenVerifierUnset() public {
        uint256 fid = fn.mintAtShadowMint(
            SHADOW_A, 0, 0, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );
        fn.extractFromShadow(fid, SHADOW_A, 0, LSH_FINAL);

        bytes memory proof = hex"";
        bytes32[] memory pi = new bytes32[](8);
        vm.prank(owner);
        vm.expectRevert(FeatureNFT.VerifierNotSet.selector);
        fn.transferFeature(fid, stranger, proof, pi);
    }

    function test_transferFeature_revertsBadPILen() public {
        uint256 fid = fn.mintAtShadowMint(
            SHADOW_A, 0, 0, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );
        fn.extractFromShadow(fid, SHADOW_A, 0, LSH_FINAL);

        bytes memory proof = hex"";
        bytes32[] memory pi = new bytes32[](7); // wrong length
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(FeatureNFT.BadPILen.selector, 7, 8));
        fn.transferFeature(fid, stranger, proof, pi);
    }

    // ---- end-to-end lifecycle: mint -> extract -> insert different shadow ----

    function test_lifecycle_mintExtractInsert_preservesImmutables() public {
        uint256 fid = fn.mintAtShadowMint(
            SHADOW_A, 4, 6, ORIGIN_FACE,
            IFeatureNFT.PaletteAtMint({commit: PALETTE_COMMIT, saltCt: bytes32(0), saltC1X: bytes32(0), saltC1Y: bytes32(0)}),
            LSH_INIT,
            owner
        );
        bytes32 lshA = fn.liveStateHashCheckpointOf(fid);

        fn.extractFromShadow(fid, SHADOW_A, 4, LSH_FINAL);
        assertEq(fn.liveStateHashCheckpointOf(fid), LSH_FINAL, "synced on extract");
        assertTrue(lshA != fn.liveStateHashCheckpointOf(fid), "checkpoint advanced");

        fn.insertIntoShadow(fid, SHADOW_B, 12);
        assertEq(fn.hostShadowIdOf(fid), SHADOW_B);
        assertEq(fn.hostSlotIdxOf(fid), 12);

        // Immutables travel.
        assertEq(fn.typeIdxOf(fid), 6);
        assertEq(fn.originFaceIdOf(fid), ORIGIN_FACE);
        assertEq(fn.paletteCommitOf(fid), PALETTE_COMMIT);
    }
}
