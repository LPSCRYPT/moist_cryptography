// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/// @notice Interface that ShadowToken needs from FeatureNFT in v2.
///
/// In v2 every atom is a FeatureNFT from the moment it exists. ShadowToken
/// drives three privileged transitions on FeatureNFT:
///
///   1. mintAtShadowMint: at shadow-mint, atomically mint 8 carriers and
///      install them into slots 0..7 of the new shadow.
///   2. extractFromShadow: when a slot is extracted, copy the slot's
///      current `liveStateHash` into the carrier's checkpoint and clear
///      `isInserted`. The carrier becomes a held ERC-721.
///   3. insertIntoShadow: when a held carrier is bound into another
///      shadow's EMPTY slot, set the host fields and re-assert custody
///      lock. The slot's new `liveStateHash` is written by ShadowToken
///      using the inserting proof's PI; the carrier's checkpoint is
///      treated as stale until the next extract.
///
/// Custody lock: while `isInserted == true`, plain ERC-721 transferFrom
/// MUST revert and FeatureNFT-level `transferFeature` MUST revert. The
/// only exit is `extractFromShadow`, which the host shadow drives.
interface IFeatureNFT {
    // ---- privileged: only ShadowToken may call ----

    /// @notice Mint a fresh FeatureNFT and immediately install it as
    ///         OCCUPIED in `(hostShadowId, hostSlotIdx)`. Returns the
    ///         newly minted featureId. Reverts if the caller is not the
    ///         registered ShadowToken contract.
    /// @param  hostShadowId           the freshly-minted shadow's id
    /// @param  hostSlotIdx            slot index 0..15 the carrier binds to
    /// @param  typeIdx                landmark type 0..7, immutable
    /// @param  originFaceId           lineage anchor, immutable
    /// @param  paletteCommit          poseidon2 of 16 palette colors, immutable
    /// @param  initialLiveStateHash   slot's `liveStateHash` at mint
    /// @param  to                     recipient address (= shadow minter)
    function mintAtShadowMint(
        uint256 hostShadowId,
        uint8 hostSlotIdx,
        uint8 typeIdx,
        bytes32 originFaceId,
        bytes32 paletteCommit,
        bytes32 initialLiveStateHash,
        address to
    ) external returns (uint256 featureId);

    /// @notice Sync the carrier with the slot's current `liveStateHash`
    ///         and release custody. Called by ShadowToken inside
    ///         `extractSlot`. Reverts if the carrier is not currently
    ///         inserted at `(hostShadowId, hostSlotIdx)`.
    function extractFromShadow(
        uint256 featureId,
        uint256 hostShadowId,
        uint8 hostSlotIdx,
        bytes32 finalLiveStateHash
    ) external;

    /// @notice Re-install a held carrier into a new shadow's EMPTY slot.
    ///         Called by ShadowToken inside `insertFeature`. Reverts if
    ///         the carrier is already inserted (single-host invariant).
    ///         The slot's new `liveStateHash` is bound by the proof and
    ///         written by ShadowToken; the carrier's checkpoint stays
    ///         stale until the next extract.
    function insertIntoShadow(
        uint256 featureId,
        uint256 newHostShadowId,
        uint8 newHostSlotIdx
    ) external;

    // ---- read accessors used by ShadowToken's logic ----

    function ownerOfFeature(uint256 featureId) external view returns (address);
    function typeIdxOf(uint256 featureId) external view returns (uint8);
    function originFaceIdOf(uint256 featureId) external view returns (bytes32);
    function paletteCommitOf(uint256 featureId) external view returns (bytes32);
    function liveStateHashCheckpointOf(uint256 featureId) external view returns (bytes32);
    function isInserted(uint256 featureId) external view returns (bool);
    function hostShadowIdOf(uint256 featureId) external view returns (uint256);
    function hostSlotIdxOf(uint256 featureId) external view returns (uint8);
}
