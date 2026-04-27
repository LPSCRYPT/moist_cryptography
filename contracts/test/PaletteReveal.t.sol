// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {TestableFeatureNFT} from "./Testable.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {PaletteRevealV2Verifier} from "../src/PaletteRevealV2Verifier.sol";

/// @notice Real-proof tests for FeatureNFT.revealPalette.
///
/// Fixture: contracts/test/fixtures/onchain_palette_reveal/palette_reveal_demo
///   built by `python3 tools/build_palette_reveal_fixture.py
///                  --seed palette_reveal_demo`.
///
/// Setup pattern: deploy `TestableFeatureNFT`, install the
/// `PaletteRevealV2Verifier`, seed a fixture-pinned `featureId` with the
/// fixture's `paletteCommit`, then call `revealPalette`. The seedFeature
/// path bypasses the privileged-mint flow on purpose -- we want to isolate
/// reveal semantics from mint plumbing.
contract PaletteRevealTest is Test {
    using stdJson for string;

    string internal constant FIX = "./test/fixtures/onchain_palette_reveal/palette_reveal_demo";

    TestableFeatureNFT internal fn;
    PaletteRevealV2Verifier internal vReveal;

    address internal owner = makeAddr("palette_owner");
    address internal stranger = makeAddr("stranger");

    uint256 internal featureId;
    bytes32 internal paletteCommit;
    bytes32[] internal pi;
    bytes internal proof;
    bytes32[8] internal palettePacked;

    bytes32 internal constant DUMMY_HOST_SHADOW = bytes32(uint256(0xdadababa));
    bytes32 internal constant DUMMY_ORIGIN_FACE = bytes32(uint256(0xface));
    bytes32 internal constant DUMMY_LSH         = bytes32(uint256(0xdead));

    uint256 internal constant PALETTE_REVEAL_PI_LEN = 10;

    function setUp() public {
        fn = new TestableFeatureNFT(address(this));
        vReveal = new PaletteRevealV2Verifier();
        fn.setPaletteRevealVerifier(IVerifier(address(vReveal)));

        proof = vm.readFileBinary(string.concat(FIX, "/proof.bin"));
        pi = _loadFields(string.concat(FIX, "/public_inputs.bin"), PALETTE_REVEAL_PI_LEN);

        // PI[0] = featureId, PI[1] = paletteCommit, PI[2..10] = packed palette.
        featureId     = uint256(pi[0]);
        paletteCommit = pi[1];
        for (uint256 i = 0; i < 8; i++) {
            palettePacked[i] = pi[2 + i];
        }

        // Seed the carrier with the fixture's featureId + paletteCommit.
        // host fields can be anything; revealPalette doesn't touch them.
        fn.seedFeature(
            featureId,
            uint256(DUMMY_HOST_SHADOW),
            0,            // hostSlotIdx
            0,            // typeIdx
            DUMMY_ORIGIN_FACE,
            paletteCommit,
            DUMMY_LSH,
            owner
        );
    }

    function _loadFields(string memory path, uint256 expectedLen)
        internal returns (bytes32[] memory out)
    {
        bytes memory raw = vm.readFileBinary(path);
        require(raw.length == expectedLen * 32, "PI length mismatch");
        out = new bytes32[](expectedLen);
        for (uint256 i = 0; i < expectedLen; i++) {
            bytes32 word;
            assembly { word := mload(add(raw, add(0x20, mul(i, 32)))) }
            out[i] = word;
        }
    }

    /// Convert a packed Field carrying two 24-bit colors into the 6 raw
    /// RGB bytes the contract emits. Mirrors the unpack inside `revealPalette`.
    function _expectedRgb() internal view returns (bytes memory rgb) {
        rgb = new bytes(48);
        for (uint256 i = 0; i < 8; i++) {
            uint256 packed = uint256(palettePacked[i]);
            uint256 lo = packed & 0xFFFFFF;
            uint256 hi = (packed >> 24) & 0xFFFFFF;
            rgb[i * 6 + 0] = bytes1(uint8(lo >> 16));
            rgb[i * 6 + 1] = bytes1(uint8(lo >> 8));
            rgb[i * 6 + 2] = bytes1(uint8(lo));
            rgb[i * 6 + 3] = bytes1(uint8(hi >> 16));
            rgb[i * 6 + 4] = bytes1(uint8(hi >> 8));
            rgb[i * 6 + 5] = bytes1(uint8(hi));
        }
    }

    // ---- happy path ----

    function test_revealPalette_success_emits_rgb_and_flips_flag() public {
        // Pre-state: paletteRevealed must be false.
        assertFalse(fn.paletteRevealedOf(featureId), "pre: not revealed");

        bytes memory expected = _expectedRgb();

        // Expect the FeaturePaletteRevealed event with the unpacked RGB.
        vm.expectEmit(true, false, false, true, address(fn));
        emit FeatureNFT.FeaturePaletteRevealed(featureId, paletteCommit, expected);

        vm.prank(owner);
        fn.revealPalette(featureId, proof, pi);

        // Post-state: flag flipped, commit unchanged.
        assertTrue(fn.paletteRevealedOf(featureId), "post: revealed");
        assertEq(fn.paletteCommitOf(featureId), paletteCommit, "commit preserved");
    }

    // ---- revert cases ----

    function test_revealPalette_reverts_for_non_owner() public {
        vm.prank(stranger);
        vm.expectRevert(FeatureNFT.NotFeatureOwner.selector);
        fn.revealPalette(featureId, proof, pi);
    }

    function test_revealPalette_reverts_when_already_revealed() public {
        vm.prank(owner);
        fn.revealPalette(featureId, proof, pi);
        assertTrue(fn.paletteRevealedOf(featureId), "first reveal succeeded");

        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(
                FeatureNFT.PaletteAlreadyRevealed.selector, featureId
            )
        );
        fn.revealPalette(featureId, proof, pi);
    }

    function test_revealPalette_reverts_on_commit_mismatch() public {
        // Build a sibling featureId whose stored commit differs from the
        // proof's PI[1]. The proof is unchanged; only chain storage is wrong.
        uint256 otherFid = featureId ^ uint256(0xdeadbeef);
        // sibling commit -- any value != paletteCommit
        bytes32 wrongCommit = keccak256(abi.encode("not_the_palette"));
        require(wrongCommit != paletteCommit, "test setup: commits collided");
        fn.seedFeature(
            otherFid,
            uint256(DUMMY_HOST_SHADOW),
            1,
            0,
            DUMMY_ORIGIN_FACE,
            wrongCommit,
            DUMMY_LSH,
            owner
        );

        // Build a tampered PI with the sibling featureId in PI[0] but the
        // original paletteCommit in PI[1]. Chain reads stored commit
        // (wrongCommit) and revertsInvalidProof on the mismatch -- before
        // ever calling the verifier.
        bytes32[] memory piTampered = new bytes32[](pi.length);
        for (uint256 i = 0; i < pi.length; i++) piTampered[i] = pi[i];
        piTampered[0] = bytes32(otherFid);

        vm.prank(owner);
        vm.expectRevert(FeatureNFT.InvalidProof.selector);
        fn.revealPalette(otherFid, proof, piTampered);
    }
}
