// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/// @notice Interface that ShadowToken needs from FeatureNFT for the cross-
///         contract `extractSlot` and `freezeFeature` paths.
interface IFeatureNFT {
    /// Mint a new FeatureNFT extracted from `originShadowId`'s slot
    /// `originSlotIdx`. Only ShadowToken may call. Returns the new tokenId.
    function mintFromExtraction(
        uint256 originShadowId,
        uint8 originSlotIdx,
        uint8 featureType,
        uint8 color,
        bytes32 ecdhPubX,
        bytes32 ecdhPubY,
        bytes32 c2Commit,
        uint64 pose,
        address to
    ) external returns (uint256 featureNftId);

    /// Freeze a feature (irreversible). Only ShadowToken may call, used by
    /// `solve` to lock all features bound to a solved shadow.
    function freezeFeature(uint256 featureNftId) external;

    /// Read accessors used by ShadowToken.insertFeature for ownership /
    /// freeze checks.
    function ownerOfFeature(uint256 featureNftId) external view returns (address);
    function isFrozen(uint256 featureNftId) external view returns (bool);
    function colorOf(uint256 featureNftId) external view returns (uint8);
    function featureTypeOf(uint256 featureNftId) external view returns (uint8);
}
