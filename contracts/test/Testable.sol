// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";

/// @title  TestableFeatureNFT
/// @notice Test-only subclass that bypasses the keccak-derived `featureId`
///         in `mintAtShadowMint` so a Forge test can pin a feature's id to
///         the value present in a real-proof fixture's public inputs.
///
/// Live in `test/` so the production `FeatureNFT` stays clean. The exposed
/// `seedFeature` reuses the same struct + invariant logic as the real
/// privileged path; the only difference is that the feature id is supplied
/// directly instead of derived from a counter.
contract TestableFeatureNFT is FeatureNFT {
    constructor(address shadowTokenAddr) FeatureNFT(shadowTokenAddr) {}

    /// Test-only fixture seed: mint a feature with an explicit `featureId`
    /// matching a proof's PI[feature_id], then bind it to a host shadow as
    /// inserted (so `liveStateHashCheckpoint` is irrelevant until extract).
    /// Open to anyone (test contract); real `mintAtShadowMint` keeps its
    /// ShadowToken-only gate.
    function seedFeature(
        uint256 featureId,
        uint256 hostShadowId,
        uint8 hostSlotIdx,
        uint8 typeIdx,
        bytes32 originFaceId,
        bytes32 paletteCommit,
        bytes32 initialLiveStateHash,
        address to
    ) external {
        Feature storage f = _featuresStorage(featureId);
        f.typeIdx = typeIdx;
        f.originFaceId = originFaceId;
        f.paletteCommit = paletteCommit;
        f.mintedAt = uint64(block.number);
        f.liveStateHashCheckpoint = initialLiveStateHash;
        f.isInserted = true;
        f.hostShadowId = hostShadowId;
        f.hostSlotIdx = hostSlotIdx;
        _mint(to, featureId);
    }

    /// Hook the parent's private storage map. We re-declare the storage
    /// pointer via assembly because OZ's _features mapping is `private`.
    /// Layout: `mapping(uint256 => Feature) private _features` is the 1st
    /// (0-indexed) declared private mapping in `FeatureNFT.sol` after the
    /// inherited slots. The slot id can be probed via `forge inspect storageLayout`.
    /// Instead of probing, we re-declare an identical `_features` mapping at
    /// the same logical position by inheriting and adding a synthetic field
    /// at the same slot via `assembly`. Simpler: expose `_features` by
    /// reading the same key directly.
    ///
    /// Solidity won't let us touch a private mapping in a parent. The
    /// simplest workaround is to make the parent's `_features` `internal`.
    /// We do that in the parent (one-character change). For now, this stub
    /// uses a slot reservation + sstore via assembly to match.
    function _featuresStorage(uint256 featureId) private pure returns (Feature storage f) {
        // Slot of `_features` mapping. Determined empirically via
        // `forge inspect FeatureNFT storageLayout` and pinned here. If the
        // parent storage layout shifts, this constant must be updated.
        uint256 slot = _FEATURES_SLOT;
        bytes32 baseSlot;
        assembly {
            mstore(0x00, featureId)
            mstore(0x20, slot)
            baseSlot := keccak256(0x00, 0x40)
        }
        assembly { f.slot := baseSlot }
    }

    /// Pinned storage slot of `FeatureNFT._features`. Derived from
    /// `forge inspect FeatureNFT storageLayout`. See note above; if upstream
    /// layout shifts this constant must move.
    uint256 private constant _FEATURES_SLOT = 11;
}

/// @title  TestableShadowToken
/// @notice Test-only subclass that exposes synthetic mint state writes so
///         a Forge test can replicate the post-mint storage shape implied
///         by a real-proof fixture, without yet having a real
///         `landmark_regions` v2 proof to drive `mintShadow`.
contract TestableShadowToken is ShadowToken {
    constructor(address yulSpongeAddr) ShadowToken(yulSpongeAddr) {}

    /// Synthetic mint without touching any manifest entry. Used by tests
    /// that need an empty manifest (e.g. insertFeature into a fresh shadow).
    function seedShadowOnly(
        uint256 shadowId,
        address to,
        bytes32 ecdhPubX,
        bytes32 ecdhPubY
    ) external {
        Shadow storage s = _shadowsStorage(shadowId);
        s.ecdhPubX = ecdhPubX;
        s.ecdhPubY = ecdhPubY;
        s.mintIdx = 1;
        s.mintedAt = uint64(block.number);
        _mint(to, shadowId);
    }

    /// Synthetic mint: claim ownership of `shadowId` for `to`, set owner pk,
    /// install slot[slotIdx] as OCCUPIED with `(featureId, lsh)`. Slots
    /// outside `slotIdx` remain EMPTY (default-zero). Test only.
    function seedShadowAndSlot(
        uint256 shadowId,
        address to,
        bytes32 ecdhPubX,
        bytes32 ecdhPubY,
        uint8 slotIdx,
        uint256 featureId,
        bytes32 liveStateHash
    ) external {
        Shadow storage s = _shadowsStorage(shadowId);
        s.ecdhPubX = ecdhPubX;
        s.ecdhPubY = ecdhPubY;
        s.mintIdx = 1;
        s.mintedAt = uint64(block.number);

        ManifestEntry storage m = _manifestStorage(shadowId, slotIdx);
        m.kind = SlotKind.OCCUPIED;
        m.featureId = featureId;
        m.liveStateHash = liveStateHash;

        _mint(to, shadowId);
    }

    /// Synthetic mint with N occupied slots seeded at once. Useful for
    /// transferShadow real-proof tests that require multiple slots populated.
    /// Slots not in `slotIdxs` remain EMPTY (default-zero).
    function seedShadowMultiSlot(
        uint256 shadowId,
        address to,
        bytes32 ecdhPubX,
        bytes32 ecdhPubY,
        uint8[] calldata slotIdxs,
        uint256[] calldata featureIds,
        bytes32[] calldata liveStateHashes
    ) external {
        require(slotIdxs.length == featureIds.length, "len mismatch");
        require(slotIdxs.length == liveStateHashes.length, "len mismatch");
        Shadow storage s = _shadowsStorage(shadowId);
        s.ecdhPubX = ecdhPubX;
        s.ecdhPubY = ecdhPubY;
        s.mintIdx = 1;
        s.mintedAt = uint64(block.number);
        for (uint256 i = 0; i < slotIdxs.length; i++) {
            ManifestEntry storage m = _manifestStorage(shadowId, slotIdxs[i]);
            m.kind = SlotKind.OCCUPIED;
            m.featureId = featureIds[i];
            m.liveStateHash = liveStateHashes[i];
        }
        _mint(to, shadowId);
    }

    /// Test-only setter for a shadow's `zIndexCommit` field. Used by tests
    /// that seed a shadow into a state where setZIndexCommit has been
    /// previously called (e.g. solve real-proof tests).
    function setShadowZIndexCommitForTest(uint256 shadowId, bytes32 commit) external {
        Shadow storage s = _shadowsStorage(shadowId);
        s.zIndexCommit = commit;
    }

    /// Test-only: mark a shadow as solved + write zIndexRevealed +
    /// shadowT10. Used by BridgeShadow tests to simulate a post-solve
    /// chain state without driving the full solve flow (which requires
    /// a real solve_shadow_v2 proof). Spec criterion: bridge MUST work
    /// against v2 storage post-solve.
    function setShadowSolvedForTest(
        uint256 shadowId,
        uint64 zIndexRevealed,
        bytes32 t10Hi,
        bytes32 t10Lo
    ) external {
        Shadow storage s = _shadowsStorage(shadowId);
        s.solved = true;
        s.zIndexRevealed = zIndexRevealed;
        s.zIndexRevealedSet = true;
        shadowT10[shadowId][0] = t10Hi;
        shadowT10[shadowId][1] = t10Lo;
    }

    /// Test-only verifier swap. Routes through ShadowToken's rotation
    /// path (`_writeVerifierSlot`), which bypasses the one-shot setter
    /// lock on `setXyzVerifier`. Used by mint tests to install verifier
    /// slots after the deploy script has already locked them, e.g. to
    /// register a face_disc verifier whose proof was generated against
    /// a real image fixture but pinned post-deploy.
    function setVerifierForTest(uint8 slotId, address newVerifier) external {
        _writeVerifierSlot(slotId, newVerifier);
    }

    /// Pinned storage slot of `ShadowToken._shadows` mapping. Derived from
    /// `forge inspect ShadowToken storageLayout`.
    uint256 private constant _SHADOWS_SLOT = 19;
    /// Pinned storage slot of `ShadowToken._manifests` mapping.
    uint256 private constant _MANIFESTS_SLOT = 20;

    function _shadowsStorage(uint256 shadowId) private pure returns (Shadow storage s) {
        uint256 slot = _SHADOWS_SLOT;
        bytes32 baseSlot;
        assembly {
            mstore(0x00, shadowId)
            mstore(0x20, slot)
            baseSlot := keccak256(0x00, 0x40)
        }
        assembly { s.slot := baseSlot }
    }

    /// Per-shadow manifest is `mapping(uint256 => ManifestEntry[16])`.
    /// Lookup: outerSlot = keccak256(shadowId || _MANIFESTS_SLOT); inner
    /// array element i sits at outerSlot + i * (entry slots), where each
    /// entry occupies 2 storage slots (kind+featureId packed in slot0,
    /// liveStateHash in slot1; though Solidity actually packs `kind` and
    /// `featureId` differently -- see check below).
    function _manifestStorage(uint256 shadowId, uint8 slotIdx)
        private
        pure
        returns (ManifestEntry storage m)
    {
        uint256 mapSlot = _MANIFESTS_SLOT;
        bytes32 outerBase;
        assembly {
            mstore(0x00, shadowId)
            mstore(0x20, mapSlot)
            outerBase := keccak256(0x00, 0x40)
        }
        // ManifestEntry { SlotKind kind; uint256 featureId; bytes32 liveStateHash; }
        // -> 3 storage slots per entry (Solidity does NOT pack uint8 enum + uint256).
        bytes32 entrySlot = bytes32(uint256(outerBase) + uint256(slotIdx) * 3);
        assembly { m.slot := entrySlot }
    }
}
