// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/// @notice Subset of ShadowToken (v2) that ShadowBridgeL2 needs.
///
/// Mirrors the structs declared inside ShadowToken.sol. Kept as a separate
/// interface so the bridge file doesn't depend on ShadowToken's full source
/// (which transitively pulls in OZ ERC721 + KeyRegistry + verifiers).
interface IShadowToken {
    enum SlotKind {
        EMPTY,
        OCCUPIED,
        REVEALED
    }

    struct ManifestEntry {
        SlotKind kind;
        uint256 featureId;
        bytes32 liveStateHash;
        uint16 mutationCount;
        bytes32 chainTip;
    }


    function ownerOf(uint256 tokenId) external view returns (address);
    function transferFrom(address from, address to, uint256 tokenId) external;
    function shadowHeaderOf(uint256 shadowId) external view returns (
        bytes32 ecdhPubX,
        bytes32 ecdhPubY,
        bool solved,
        bytes32 zIndexCommit
    );
    function slotOf(uint256 shadowId, uint8 slotIdx) external view returns (ManifestEntry memory);
    function shadowT10(uint256 shadowId, uint256 i) external view returns (bytes32);
    /// Address of the deployed `Poseidon2YulSponge` wrapper. FeatureNFT uses
    /// this for byte-level c2 binding in `transferFeature` (audit H-02)
    /// without keeping its own copy.
    function yulSponge() external view returns (address);
}
