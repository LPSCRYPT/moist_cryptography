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
/// Live in `test/` so the production `FeatureNFT` stays clean. This is not a
/// verifier mock: it is storage seeding for tests that already have real proof
/// public inputs. Real mint/reveal integration coverage lives in
/// `MintShadow.t.sol` and `SolveShadowRealProof.t.sol`.
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

    /// Hook the parent's private storage map for fixture seeding only.
    /// Production never uses this path; real FeatureNFT writes still go through
    /// `mintAtShadowMint`, `extractFromShadow`, `insertIntoShadow`, and
    /// `revealInsertedFeature`. The pinned slot is checked when storage layout
    /// changes, and real flow tests exercise the production entry points.
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
    uint256 private constant _FEATURES_SLOT = 12;
}

/// @title  TestableShadowToken
/// @notice Test-only subclass that exposes synthetic storage writes for fixture
///         setup. It does not replace proof verification: real generated-verifier
///         coverage lives in `GeneratedVerifierMatrix.t.sol` and flow-specific
///         integration lives in `MintShadow.t.sol`, `SolveShadowRealProof.t.sol`,
///         and transfer proof tests.
contract TestableShadowToken is ShadowToken {
    constructor(address yulSpongeAddr) ShadowToken(yulSpongeAddr) {}

    /// Synthetic mint without touching any manifest entry. Used by tests
    /// that need an empty manifest (e.g. insertFeature into a fresh shadow).
    function seedShadowOnly(uint256 shadowId, address to, bytes32 ecdhPubX, bytes32 ecdhPubY) external {
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
        m.mutationCount = 0;
        m.chainTip = bytes32(0);

        _mint(to, shadowId);
    }

    /// Synthetic mint with N occupied slots seeded at once. Useful for tests
    /// that require multiple bounded features populated. Slots not in `slotIdxs`
    /// remain EMPTY (default-zero).
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
        _seedShadowHeader(shadowId, ecdhPubX, ecdhPubY);
        for (uint256 i = 0; i < slotIdxs.length; i++) {
            _seedManifestEntry(shadowId, slotIdxs[i], featureIds[i], liveStateHashes[i], 0, bytes32(0));
        }
        _mint(to, shadowId);
    }

    function setSlotHistoryForTest(uint256 shadowId, uint8 slotIdx, uint16 mutationCount, bytes32 chainTip) external {
        ManifestEntry storage m = _manifestStorage(shadowId, slotIdx);
        m.mutationCount = mutationCount;
        m.chainTip = chainTip;
    }

    function _seedShadowHeader(uint256 shadowId, bytes32 ecdhPubX, bytes32 ecdhPubY) private {
        Shadow storage s = _shadowsStorage(shadowId);
        s.ecdhPubX = ecdhPubX;
        s.ecdhPubY = ecdhPubY;
        s.mintIdx = 1;
        s.mintedAt = uint64(block.number);
    }

    function _seedManifestEntry(
        uint256 shadowId,
        uint8 slotIdx,
        uint256 featureId,
        bytes32 liveStateHash,
        uint16 mutationCount,
        bytes32 chainTip
    ) private {
        ManifestEntry storage m = _manifestStorage(shadowId, slotIdx);
        m.kind = SlotKind.OCCUPIED;
        m.featureId = featureId;
        m.liveStateHash = liveStateHash;
        m.mutationCount = mutationCount;
        m.chainTip = chainTip;
    }

    /// Test-only setter for a shadow's `zIndexCommit` field. Used by tests
    /// that seed a shadow into a state where setZIndexCommit has been
    /// previously called (e.g. solve real-proof tests).
    function setShadowZIndexCommitForTest(uint256 shadowId, bytes32 commit) external {
        Shadow storage s = _shadowsStorage(shadowId);
        s.zIndexCommit = commit;
    }

    /// Test-only: mark a shadow as fully revealed/solved + write shadowT10.
    /// Used by bridge tests after solve semantics have been separately covered;
    /// bridge messenger wiring is tested in `BridgeWiring.t.sol`, while live-chain
    /// OP messenger caveats are tracked in `docs/SEPOLIA_TEST_MATRIX.md`.
    function setShadowSolvedForTest(uint256 shadowId, bytes32 t10Hi, bytes32 t10Lo) external {
        Shadow storage s = _shadowsStorage(shadowId);
        s.solved = true;
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
    /// `forge inspect ShadowToken storage-layout`. Bumped 20 → 21 when the
    /// phased mint controller pointer was inserted before verifier storage.
    uint256 private constant _SHADOWS_SLOT = 21;
    /// Pinned storage slot of `ShadowToken._manifests` mapping. Bumped 21→22.
    uint256 private constant _MANIFESTS_SLOT = 22;

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
    function _manifestStorage(uint256 shadowId, uint8 slotIdx) private pure returns (ManifestEntry storage m) {
        uint256 mapSlot = _MANIFESTS_SLOT;
        bytes32 outerBase;
        assembly {
            mstore(0x00, shadowId)
            mstore(0x20, mapSlot)
            outerBase := keccak256(0x00, 0x40)
        }
        // ManifestEntry { kind, featureId, liveStateHash, mutationCount, chainTip }
        // -> 5 storage slots per entry (uint256/bytes32 members force slot breaks).
        bytes32 entrySlot = bytes32(uint256(outerBase) + uint256(slotIdx) * 5);
        assembly { m.slot := entrySlot }
    }
}
