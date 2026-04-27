// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test, stdJson} from "forge-std/Test.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {ZIndexCommitVerifier} from "../src/ZIndexCommitVerifier.sol";
import {T10ShadowVerifier} from "../src/T10ShadowVerifier.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {TestableShadowToken, TestableFeatureNFT} from "./Testable.sol";

/// @notice E2E real-proof test for `ShadowToken.setZIndexCommit`.
///
/// Verifies the bundled (zindex_commit, shadow_t10) atomic refresh:
/// the chain's `zIndexCommit[shadowId]` advances and `shadowT10` rolls
/// to the new (hi, lo) bound by the T10 proof against the new zCommit.
contract SetZIndexCommitE2ETest is Test {
    using stdJson for string;

    TestableShadowToken    internal st;
    TestableFeatureNFT     internal fn;
    ZIndexCommitVerifier   internal vZ;
    T10ShadowVerifier      internal vT10;
    Poseidon2YulSponge     internal sponge;

    string internal constant FIX = "./test/fixtures/atomic_zindex/zidx_atomic_demo";

    bytes internal proofZ;
    bytes32[] internal piZ;
    bytes internal proofT10;
    bytes32[] internal piT10;

    uint256 internal shadowId;
    uint8   internal slotIdx;
    bytes32 internal lshHeld;
    bytes32 internal newZCommit;
    bytes32[2] internal newT10;

    address internal alice = makeAddr("alice");

    uint256 internal constant Z_PI_LEN = 2;
    uint256 internal constant T10_PI_LEN = 20;

    event ShadowZIndexCommitSet(uint256 indexed shadowId, bytes32 newCommit);
    event ShadowT10Updated(uint256 indexed shadowId, bytes32 hi, bytes32 lo);

    function setUp() public {
        sponge = new Poseidon2YulSponge();
        st = new TestableShadowToken(address(sponge));
        fn = new TestableFeatureNFT(address(st));
        st.setFeatureNFT(IFeatureNFT(address(fn)));
        vZ = new ZIndexCommitVerifier();
        vT10 = new T10ShadowVerifier();
        st.setZIndexCommitVerifier(IVerifier(address(vZ)));
        st.setT10ShadowVerifier(IVerifier(address(vT10)));

        proofZ   = vm.readFileBinary(string.concat(FIX, "/proof_z.bin"));
        piZ      = _loadFields(string.concat(FIX, "/public_inputs_z.bin"), Z_PI_LEN);
        proofT10 = vm.readFileBinary(string.concat(FIX, "/proof_t10.bin"));
        piT10    = _loadFields(string.concat(FIX, "/public_inputs_t10.bin"), T10_PI_LEN);

        string memory meta = vm.readFile(string.concat(FIX, "/meta.json"));
        shadowId   = vm.parseJsonUint(meta, ".shadow_id");
        slotIdx    = uint8(vm.parseJsonUint(meta, ".slot_idx"));
        lshHeld    = vm.parseJsonBytes32(meta, ".lsh_held");
        newZCommit = vm.parseJsonBytes32(meta, ".z_commit");
        newT10[0]  = vm.parseJsonBytes32(meta, ".t10_hi");
        newT10[1]  = vm.parseJsonBytes32(meta, ".t10_lo");

        // Seed: shadow with one OCCUPIED slot at lshHeld; default
        // zIndexCommit = 0. (No FeatureNFT seed needed; T10 only reads LSH.)
        st.seedShadowAndSlot(
            shadowId, alice,
            bytes32(uint256(0xaa)),
            bytes32(uint256(0xbb)),
            slotIdx, 0xfeed, lshHeld
        );
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

    function _buildArgs() internal view returns (ShadowToken.SetZIndexCommitArgs memory args) {
        return ShadowToken.SetZIndexCommitArgs({
            shadowId: shadowId,
            newCommit: newZCommit,
            proofZ: proofZ,
            newT10: newT10,
            proofT10: proofT10
        });
    }

    function test_setZIndexCommit_success() public {
        ShadowToken.SetZIndexCommitArgs memory args = _buildArgs();

        // Pre.
        assertEq(st.shadowOf(shadowId).zIndexCommit, bytes32(0));

        vm.expectEmit(true, false, false, true);
        emit ShadowT10Updated(shadowId, newT10[0], newT10[1]);
        vm.expectEmit(true, false, false, true);
        emit ShadowZIndexCommitSet(shadowId, newZCommit);

        vm.prank(alice);
        st.setZIndexCommit(args);

        // Post.
        assertEq(st.shadowOf(shadowId).zIndexCommit, newZCommit);
        assertEq(st.shadowT10(shadowId, 0), newT10[0]);
        assertEq(st.shadowT10(shadowId, 1), newT10[1]);
    }

    function test_setZIndexCommit_reverts_when_not_owner() public {
        ShadowToken.SetZIndexCommitArgs memory args = _buildArgs();
        address mallory = makeAddr("mallory");
        vm.prank(mallory);
        vm.expectRevert(ShadowToken.NotShadowOwner.selector);
        st.setZIndexCommit(args);
    }

    function test_setZIndexCommit_reverts_when_z_proof_lies() public {
        ShadowToken.SetZIndexCommitArgs memory args = _buildArgs();
        // Flip the commit: proof PI[1] no longer matches args.newCommit.
        args.newCommit = bytes32(uint256(args.newCommit) ^ 1);
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.setZIndexCommit(args);
    }

    function test_setZIndexCommit_reverts_when_T10_lies() public {
        ShadowToken.SetZIndexCommitArgs memory args = _buildArgs();
        // T10 PI binds the NEW zCommit; if we feed wrong T10 hi/lo, the
        // T10 verifier rejects the bundled proof.
        args.newT10[0] = bytes32(uint256(args.newT10[0]) ^ 1);
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.setZIndexCommit(args);
    }
}
