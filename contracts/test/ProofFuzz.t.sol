// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {FaceDiscVerifier} from "../src/FaceDiscVerifier.sol";
import {MintShadowVerifier} from "../src/MintShadowVerifier.sol";
import {T10ShadowVerifier} from "../src/T10ShadowVerifier.sol";
import {MutateSlotVerifier} from "../src/MutateSlotVerifier.sol";
import {SolveShadowVerifier} from "../src/SolveShadowVerifier.sol";
import {TransferShadowVerifier} from "../src/TransferShadowVerifier.sol";
import {TransferFeatureV2Verifier} from "../src/TransferFeatureV2Verifier.sol";
import {ZIndexCommitVerifier} from "../src/ZIndexCommitVerifier.sol";

interface IProofFuzzVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

/// @notice Real-fixture fuzz harness for every active generated proof surface.
/// The fuzzer mutates canonical proof bytes and external public inputs and
/// requires rejection from the real generated verifier. It does not use mocked
/// verifiers and should be run with bounded fuzz counts in CI.
contract ProofFuzz is Test {
    struct Fixture {
        string name;
        IProofFuzzVerifier verifier;
        string proofPath;
        string piPath;
        uint256 piLen;
    }

    function testFuzz_faceDisc_rejects_mutated_proof_and_pi(uint256 proofOffset, uint256 piIndex, bytes32 mask) public {
        _assertMutationsRejected(_faceDisc(), proofOffset, piIndex, mask);
    }

    function testFuzz_mintShadow_rejects_mutated_proof_and_pi(uint256 proofOffset, uint256 piIndex, bytes32 mask)
        public
    {
        _assertMutationsRejected(_mintShadow(), proofOffset, piIndex, mask);
    }

    function testFuzz_t10Shadow_rejects_mutated_proof_and_pi(uint256 proofOffset, uint256 piIndex, bytes32 mask)
        public
    {
        _assertMutationsRejected(_t10Shadow(), proofOffset, piIndex, mask);
    }

    function testFuzz_mutateSlot_rejects_mutated_proof_and_pi(uint256 proofOffset, uint256 piIndex, bytes32 mask)
        public
    {
        _assertMutationsRejected(_mutateSlot(), proofOffset, piIndex, mask);
    }

    function testFuzz_solveShadow_rejects_mutated_proof_and_pi(uint256 proofOffset, uint256 piIndex, bytes32 mask)
        public
    {
        _assertMutationsRejected(_solveShadow(), proofOffset, piIndex, mask);
    }

    function testFuzz_transferShadow_rejects_mutated_proof_and_pi(uint256 proofOffset, uint256 piIndex, bytes32 mask)
        public
    {
        _assertMutationsRejected(_transferShadow(), proofOffset, piIndex, mask);
    }

    function testFuzz_transferFeatureV2_rejects_mutated_proof_and_pi(uint256 proofOffset, uint256 piIndex, bytes32 mask)
        public
    {
        _assertMutationsRejected(_transferFeatureV2(), proofOffset, piIndex, mask);
    }

    function testFuzz_zIndexCommit_rejects_mutated_proof_and_pi(uint256 proofOffset, uint256 piIndex, bytes32 mask)
        public
    {
        _assertMutationsRejected(_zIndexCommit(), proofOffset, piIndex, mask);
    }

    function _faceDisc() internal returns (Fixture memory) {
        return Fixture(
            "FaceDiscVerifier",
            IProofFuzzVerifier(address(new FaceDiscVerifier())),
            "./test/fixtures/face_disc/eve0/proof",
            "./test/fixtures/face_disc/eve0/public_inputs",
            1
        );
    }

    function _mintShadow() internal returns (Fixture memory) {
        return Fixture(
            "MintShadowVerifier",
            IProofFuzzVerifier(address(new MintShadowVerifier())),
            "./test/fixtures/atomic_mint/atomic_mint_demo/proof_mint.bin",
            "./test/fixtures/atomic_mint/atomic_mint_demo/public_inputs_mint.bin",
            9
        );
    }

    function _t10Shadow() internal returns (Fixture memory) {
        return Fixture(
            "T10ShadowVerifier",
            IProofFuzzVerifier(address(new T10ShadowVerifier())),
            "./test/fixtures/shadow_t10/t10_demo/proof.bin",
            "./test/fixtures/shadow_t10/t10_demo/public_inputs.bin",
            20
        );
    }

    function _mutateSlot() internal returns (Fixture memory) {
        return Fixture(
            "MutateSlotVerifier",
            IProofFuzzVerifier(address(new MutateSlotVerifier())),
            "./test/fixtures/mutate_slot/mutate_demo_v2/proof.bin",
            "./test/fixtures/mutate_slot/mutate_demo_v2/public_inputs.bin",
            18
        );
    }

    function _solveShadow() internal returns (Fixture memory) {
        return Fixture(
            "SolveShadowVerifier",
            IProofFuzzVerifier(address(new SolveShadowVerifier())),
            "./test/fixtures/solve_shadow_v2/incremental_reveal_contract/proof.bin",
            "./test/fixtures/solve_shadow_v2/incremental_reveal_contract/public_inputs.bin",
            9
        );
    }

    function _transferShadow() internal returns (Fixture memory) {
        return Fixture(
            "TransferShadowVerifier",
            IProofFuzzVerifier(address(new TransferShadowVerifier())),
            "./test/fixtures/atomic_transfer/atomic_transfer_demo/proof_transfer.bin",
            "./test/fixtures/atomic_transfer/atomic_transfer_demo/public_inputs_transfer.bin",
            11
        );
    }

    function _transferFeatureV2() internal returns (Fixture memory) {
        return Fixture(
            "TransferFeatureV2Verifier",
            IProofFuzzVerifier(address(new TransferFeatureV2Verifier())),
            "./test/fixtures/onchain_transfer_feature_v2/transfer_feature_v2_atomic_mint_demo_slot0/proof.bin",
            "./test/fixtures/onchain_transfer_feature_v2/transfer_feature_v2_atomic_mint_demo_slot0/public_inputs.bin",
            11
        );
    }

    function _zIndexCommit() internal returns (Fixture memory) {
        return Fixture(
            "ZIndexCommitVerifier",
            IProofFuzzVerifier(address(new ZIndexCommitVerifier())),
            "./test/fixtures/zindex_commit/zidx_demo/proof.bin",
            "./test/fixtures/zindex_commit/zidx_demo/public_inputs.bin",
            2
        );
    }

    function _assertMutationsRejected(Fixture memory f, uint256 proofOffset, uint256 piIndex, bytes32 mask)
        internal
        view
    {
        bytes memory proof = vm.readFileBinary(f.proofPath);
        bytes32[] memory pi = _loadFields(f.piPath, f.piLen);
        require(proof.length > 0, "empty proof fixture");
        require(pi.length > 0, "empty PI fixture");
        assertTrue(f.verifier.verify(proof, pi), string.concat(f.name, " rejected canonical fixture"));

        uint256 boundedOffset = bound(proofOffset, 0, proof.length - 1);
        bytes memory mutatedProof = bytes.concat(proof);
        mutatedProof[boundedOffset] = bytes1(uint8(mutatedProof[boundedOffset]) ^ 0x01);
        _assertRejected(f.verifier, mutatedProof, pi, string.concat(f.name, " accepted fuzz-mutated proof"));

        uint256 boundedPiIndex = bound(piIndex, 0, pi.length - 1);
        bytes32 effectiveMask = mask == bytes32(0) ? bytes32(uint256(1)) : mask;
        bytes32[] memory mutatedPi = _copy(pi);
        mutatedPi[boundedPiIndex] = mutatedPi[boundedPiIndex] ^ effectiveMask;
        _assertRejected(f.verifier, proof, mutatedPi, string.concat(f.name, " accepted fuzz-mutated PI"));
    }

    function _loadFields(string memory path, uint256 expectedLen) internal view returns (bytes32[] memory out) {
        bytes memory raw = vm.readFileBinary(path);
        require(raw.length == expectedLen * 32, "PI fixture length mismatch");
        out = new bytes32[](expectedLen);
        for (uint256 i = 0; i < expectedLen; i++) {
            bytes32 word;
            assembly { word := mload(add(raw, add(0x20, mul(i, 32)))) }
            out[i] = word;
        }
    }

    function _copy(bytes32[] memory input) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](input.length);
        for (uint256 i = 0; i < input.length; i++) {
            out[i] = input[i];
        }
    }

    function _assertRejected(
        IProofFuzzVerifier verifier,
        bytes memory proof,
        bytes32[] memory pi,
        string memory message
    ) internal view {
        try verifier.verify(proof, pi) returns (bool ok) {
            assertFalse(ok, message);
        } catch {
            // Malformed proof/PI reverts are valid rejection signals.
        }
    }
}
