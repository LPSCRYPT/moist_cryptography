// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/// @notice Subset of ShadowToken that ShadowBridgeL2 needs.
///
/// Mirrors the structs declared inside ShadowToken.sol. Kept as a separate
/// interface so the bridge file doesn't depend on ShadowToken's full source
/// (which transitively pulls in OZ ERC721 + KeyRegistry + verifiers).
interface IShadowToken {
    enum SlotKind { EMPTY, ORIGINAL, INSERTED }

    struct ManifestEntry {
        SlotKind kind;
        uint8 originalTypeIdx;
        uint256 insertedFeatureId;
        uint64 pose;
    }

    struct Shadow {
        bytes32 faceOriginId;
        uint8   color;
        bytes32 ecdhPubX;
        bytes32 ecdhPubY;
        bytes32 c2Commit;
        uint64  origPose0;
        uint64  origPose1;
        uint64  origPose2;
        uint64  origPose3;
        uint64  origPose4;
        uint64  origPose5;
        uint64  origPose6;
        uint64  origPose7;
        uint64  mintIdx;
        uint64  mintedAt;
        bytes32 stateCommitsHash;
    }

    function ownerOf(uint256 tokenId) external view returns (address);
    function transferFrom(address from, address to, uint256 tokenId) external;
    function solved(uint256 tokenId) external view returns (bool);
    function shadowOf(uint256 shadowId) external view returns (Shadow memory);
    function manifestOf(uint256 shadowId) external view returns (ManifestEntry[16] memory);
}
