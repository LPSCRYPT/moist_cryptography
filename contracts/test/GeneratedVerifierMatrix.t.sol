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

interface IGeneratedVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

/// @notice Uniform real-proof regression matrix for generated UltraHonk verifiers.
///         Each covered verifier must accept its tracked fixture, reject a corrupted
///         proof, and reject a one-bit tamper of every external public input.
contract GeneratedVerifierMatrixTest is Test {
    struct Fixture {
        string name;
        IGeneratedVerifier verifier;
        string proofPath;
        string piPath;
        uint256 piLen;
        uint256 generatedPiLen;
    }

    function test_faceDiscVerifier_fixture_matrix() public {
        _assertFixture(
            Fixture({
                name: "FaceDiscVerifier",
                verifier: IGeneratedVerifier(address(new FaceDiscVerifier())),
                proofPath: "./test/fixtures/face_disc/eve0/proof",
                piPath: "./test/fixtures/face_disc/eve0/public_inputs",
                piLen: 1,
                generatedPiLen: 9
            })
        );
    }

    function test_mintShadowVerifier_fixture_matrix() public {
        _assertFixture(
            Fixture({
                name: "MintShadowVerifier",
                verifier: IGeneratedVerifier(address(new MintShadowVerifier())),
                proofPath: "./test/fixtures/atomic_mint/atomic_mint_demo/proof_mint.bin",
                piPath: "./test/fixtures/atomic_mint/atomic_mint_demo/public_inputs_mint.bin",
                piLen: 7,
                generatedPiLen: 15
            })
        );
    }

    function test_t10ShadowVerifier_fixture_matrix() public {
        _assertFixture(
            Fixture({
                name: "T10ShadowVerifier",
                verifier: IGeneratedVerifier(address(new T10ShadowVerifier())),
                proofPath: "./test/fixtures/shadow_t10/t10_demo/proof.bin",
                piPath: "./test/fixtures/shadow_t10/t10_demo/public_inputs.bin",
                piLen: 20,
                generatedPiLen: 28
            })
        );
    }

    function test_mutateSlotVerifier_fixture_matrix() public {
        _assertFixture(
            Fixture({
                name: "MutateSlotVerifier",
                verifier: IGeneratedVerifier(address(new MutateSlotVerifier())),
                proofPath: "./test/fixtures/mutate_slot/mutate_demo_v2/proof.bin",
                piPath: "./test/fixtures/mutate_slot/mutate_demo_v2/public_inputs.bin",
                piLen: 16,
                generatedPiLen: 24
            })
        );
    }

    function test_solveShadowVerifier_fixture_matrix() public {
        _assertFixture(
            Fixture({
                name: "SolveShadowVerifier",
                verifier: IGeneratedVerifier(address(new SolveShadowVerifier())),
                proofPath: "./test/fixtures/solve_shadow_v2/solve_demo/proof.bin",
                piPath: "./test/fixtures/solve_shadow_v2/solve_demo/public_inputs.bin",
                piLen: 7,
                generatedPiLen: 15
            })
        );
    }

    function test_transferShadowVerifier_fixture_matrix() public {
        _assertFixture(
            Fixture({
                name: "TransferShadowVerifier",
                verifier: IGeneratedVerifier(address(new TransferShadowVerifier())),
                proofPath: "./test/fixtures/atomic_transfer/atomic_transfer_demo/proof_transfer.bin",
                piPath: "./test/fixtures/atomic_transfer/atomic_transfer_demo/public_inputs_transfer.bin",
                piLen: 11,
                generatedPiLen: 19
            })
        );
    }

    function test_transferFeatureV2Verifier_fixture_matrix() public {
        _assertFixture(
            Fixture({
                name: "TransferFeatureV2Verifier",
                verifier: IGeneratedVerifier(address(new TransferFeatureV2Verifier())),
                proofPath: "./test/fixtures/onchain_transfer_feature_v2/transfer_feature_v2_atomic_mint_demo_slot0/proof.bin",
                piPath: "./test/fixtures/onchain_transfer_feature_v2/transfer_feature_v2_atomic_mint_demo_slot0/public_inputs.bin",
                piLen: 11,
                generatedPiLen: 19
            })
        );
    }

    function test_zIndexCommitVerifier_fixture_matrix() public {
        _assertFixture(
            Fixture({
                name: "ZIndexCommitVerifier",
                verifier: IGeneratedVerifier(address(new ZIndexCommitVerifier())),
                proofPath: "./test/fixtures/zindex_commit/zidx_demo/proof.bin",
                piPath: "./test/fixtures/zindex_commit/zidx_demo/public_inputs.bin",
                piLen: 2,
                generatedPiLen: 10
            })
        );
    }

    function _assertFixture(Fixture memory f) internal view {
        assertEq(f.generatedPiLen - 8, f.piLen, string.concat(f.name, " generated/external PI mismatch"));
        bytes memory proof = vm.readFileBinary(f.proofPath);
        bytes32[] memory pi = _loadFields(f.piPath, f.piLen);

        assertTrue(f.verifier.verify(proof, pi), string.concat(f.name, " rejected valid proof"));

        bytes memory corruptedProof = bytes.concat(proof);
        corruptedProof[proof.length / 2] = bytes1(uint8(corruptedProof[proof.length / 2]) ^ 0x01);
        _assertRejected(f.verifier, corruptedProof, pi, string.concat(f.name, " accepted corrupted proof"));

        for (uint256 i = 0; i < pi.length; i++) {
            bytes32[] memory tampered = _copy(pi);
            tampered[i] = bytes32(uint256(tampered[i]) ^ 1);
            _assertRejected(f.verifier, proof, tampered, string.concat(f.name, " accepted tampered PI"));
        }
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
        IGeneratedVerifier verifier,
        bytes memory proof,
        bytes32[] memory pi,
        string memory message
    ) internal view {
        try verifier.verify(proof, pi) returns (bool ok) {
            assertFalse(ok, message);
        } catch {
            // Revert is also an acceptable rejection signal for malformed proof/PI.
        }
    }
}
