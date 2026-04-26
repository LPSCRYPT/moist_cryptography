// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.21;

/// @notice Minimal verifier interface matching bb's generated Honk verifier.
///         Shared by FeatureToken (origin + relay-geom proofs) and
///         AmalgamToken (shadow + solve proofs).
interface IVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs)
        external
        view
        returns (bool);
}
