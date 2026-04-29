// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test, stdJson} from "forge-std/Test.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {KeyRegistry} from "../src/KeyRegistry.sol";
import {TransferFeatureV2Verifier} from "../src/TransferFeatureV2Verifier.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {Poseidon2YulSponge16} from "../src/Poseidon2YulSponge16.sol";
import {TestableShadowToken, TestableFeatureNFT} from "./Testable.sol";

/// @notice Real-proof e2e test for `FeatureNFT.transferFeature` (V2).
///
/// Loads the on-chain `transfer_feature_v2_a_slot0_p5` fixture (the
/// canonical pipeline-#5 slot-0 carrier rotation), reproduces the
/// post-extract carrier state in test storage, registers the recipient
/// pk in KeyRegistry, then calls transferFeature and:
///   - asserts the call succeeds (verifier accepts proof + PI)
///   - asserts the carrier's owner rotated from sender to recipient
///   - asserts the carrier's liveStateHashCheckpoint advanced to PI[4]
///   - measures gas under a 5M ceiling
///
/// This closes the only entry-point gap in the gas-regression matrix:
/// transferFeature V2 was previously covered only by direct on-chain
/// measurement (D7 = 3,687,290 gas).
contract TransferFeatureV2GasTest is Test {
    using stdJson for string;

    TestableShadowToken       internal st;
    TestableFeatureNFT        internal fn;
    TransferFeatureV2Verifier internal vTF;
    KeyRegistry               internal kr;
    Poseidon2YulSponge        internal sponge;
    Poseidon2YulSponge16      internal sponge16;

    string internal constant FIX =
        "./test/fixtures/onchain_transfer_feature_v2/transfer_feature_v2_a_slot0_p5";

    bytes internal proof;
    bytes32[] internal pi;

    uint256 internal featureId;
    uint256 internal shadowIdAtMint;
    uint8   internal slotAtMint;
    uint8   internal typeIdx;
    bytes32 internal originFaceId;
    bytes32 internal paletteCommit;
    bytes32 internal oldLsh;
    bytes32 internal newLsh;
    bytes32 internal recipientPkX;
    bytes32 internal recipientPkY;
    address internal recipient;
    address internal alice = makeAddr("alice");

    uint256 internal constant TF_PI_LEN = 8;

    function setUp() public {
        sponge   = new Poseidon2YulSponge();
        sponge16 = new Poseidon2YulSponge16();
        st = new TestableShadowToken(address(sponge));
        fn = new TestableFeatureNFT(address(st));
        st.setFeatureNFT(IFeatureNFT(address(fn)));
        st.setYulSponge16(address(sponge16));

        vTF = new TransferFeatureV2Verifier();
        fn.setTransferFeatureVerifier(IVerifier(address(vTF)));

        kr = new KeyRegistry();
        fn.setKeyRegistry(kr);

        // Load proof + PI from fixture.
        proof = vm.readFileBinary(string.concat(FIX, "/proof.bin"));
        pi    = _loadFields(string.concat(FIX, "/public_inputs.bin"), TF_PI_LEN);

        // Read the binding values from meta.json (these are what the
        // contract will check pi against, so they MUST match the fixture).
        string memory j = vm.readFile(string.concat(FIX, "/meta.json"));
        featureId      = uint256(j.readBytes32(".feature_id"));
        shadowIdAtMint = uint256(j.readBytes32(".shadow_id_at_mint"));
        slotAtMint     = uint8(j.readUint(".slot_at_mint"));
        typeIdx        = uint8(j.readUint(".type_idx"));
        originFaceId   = j.readBytes32(".origin_face_id");
        paletteCommit  = j.readBytes32(".palette_commit");
        oldLsh         = j.readBytes32(".old_lsh");
        newLsh         = j.readBytes32(".new_lsh");
        recipientPkX   = j.readBytes32(".to_pk_x");
        recipientPkY   = j.readBytes32(".to_pk_y");
        recipient      = j.readAddress(".to_addr");

        // Sanity: PI fields the contract validates must match meta.
        require(uint256(pi[0]) == featureId,             "pi[0] != featureId");
        require(pi[1] == recipientPkX,                   "pi[1] != recipientPkX");
        require(pi[2] == recipientPkY,                   "pi[2] != recipientPkY");
        require(pi[3] == oldLsh,                         "pi[3] != oldLsh");
        require(pi[4] == newLsh,                         "pi[4] != newLsh");
        require(pi[5] == paletteCommit,                  "pi[5] != paletteCommit");
        require(uint256(pi[6]) == uint256(typeIdx),      "pi[6] != typeIdx");
        require(pi[7] == originFaceId,                   "pi[7] != originFaceId");

        // Seed: feature was inserted in shadowIdAtMint, then extracted to
        // standalone state owned by alice (post-extract carrier).
        fn.seedFeature(
            featureId,
            shadowIdAtMint,
            slotAtMint,
            typeIdx,
            originFaceId,
            paletteCommit,
            oldLsh,
            alice
        );
        // Flip isInserted=false + sync checkpoint via the ShadowToken-only gate.
        vm.prank(address(st));
        fn.extractFromShadow(featureId, shadowIdAtMint, slotAtMint, oldLsh);

        // Register recipient pk so _requirePkMatches passes.
        vm.prank(recipient);
        kr.register(recipientPkX, recipientPkY);
    }

    function _loadFields(string memory path, uint256 expectedLen)
        internal
        view
        returns (bytes32[] memory out)
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

    function test_transferFeature_v2_succeeds_against_real_verifier() public {
        // Pre-state.
        assertEq(fn.ownerOf(featureId), alice, "alice owns pre-transfer");
        assertEq(fn.liveStateHashCheckpointOf(featureId), oldLsh, "checkpoint = oldLsh pre");
        assertFalse(fn.isInserted(featureId), "carrier is standalone pre");

        vm.prank(alice);
        fn.transferFeature(featureId, recipient, proof, pi);

        // Post-state.
        assertEq(fn.ownerOf(featureId), recipient, "recipient owns post-transfer");
        assertEq(fn.liveStateHashCheckpointOf(featureId), newLsh, "checkpoint = newLsh post");
        // Identity immutables unchanged.
        assertEq(fn.originFaceIdOf(featureId), originFaceId, "originFaceId immutable");
        assertEq(fn.paletteCommitOf(featureId), paletteCommit, "paletteCommit immutable");
        assertEq(uint256(fn.typeIdxOf(featureId)), uint256(typeIdx), "typeIdx immutable");
    }

    /// Gas regression: transferFeature V2 is a single ZK verify (8-PI
    /// transfer_feature_v2 circuit) + an ERC-721 owner write + a checkpoint
    /// SSTORE + KR pubkey lookup. On-chain observed: 3,687,290 gas (D7,
    /// pipeline #5, tx 0x13305fc7..., block 40,831,068). Cap at 5M.
    function test_transferFeature_v2_gas_under_block_budget() public {
        vm.prank(alice);
        uint256 gasBefore = gasleft();
        fn.transferFeature(featureId, recipient, proof, pi);
        uint256 used = gasBefore - gasleft();
        assertLt(used, 5_000_000, "transferFeature V2 gas regressed past 5M");
    }
}
