// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {KeyRegistry} from "../src/KeyRegistry.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {Poseidon2YulSponge16} from "../src/Poseidon2YulSponge16.sol";
import {TestableShadowToken} from "./Testable.sol";

/// @dev Diagnostic verifier double only. It deliberately removes proof-verifier
///      gas from attribution measurements; do not cite this file as proof-layer
///      coverage. Real generated-verifier coverage lives in
///      `GeneratedVerifierMatrix.t.sol`, with per-flow real-proof integration in
///      files such as `SolveShadowRealProof.t.sol` and `MintShadow.t.sol`.
contract AlwaysOkVerifier is IVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

/// @dev Minimal `IFeatureNFT` test double for gas attribution. It lets this suite
///      toggle feature-side storage/events independently from verifier gas. Real
///      feature custody and palette behavior is covered by `FeatureNFT.t.sol`,
///      `MintShadow.t.sol`, and `SolveShadowRealProof.t.sol`.
contract AttributionFeatureNFT is IFeatureNFT {
    enum Mode {
        Noop,
        StorageOnly,
        StorageAndEvents
    }

    struct FeatureState {
        address owner;
        uint256 hostShadowId;
        uint8 hostSlotIdx;
        bytes32 originFaceId;
        bytes32 paletteCommit;
        bytes32 liveStateHashCheckpoint;
        bool inserted;
        bool paletteRevealed;
    }

    event FeatureExtracted(
        uint256 indexed featureId, uint256 indexed hostShadowId, uint8 indexed hostSlotIdx, bytes32 finalLiveStateHash
    );
    event FeatureInsertedOwnerRotated(uint256 indexed featureId, uint256 indexed expectedHostShadowId, address to);
    event FeaturePaletteRevealed(uint256 indexed featureId, bytes32 paletteCommit, bytes paletteRGB);
    event FeatureSlotRevealed(
        uint256 indexed featureId, uint256 indexed shadowId, uint8 indexed slotIdx, bytes plaintext
    );

    Mode public mode;
    mapping(uint256 => FeatureState) internal features;

    function setMode(Mode next) external {
        mode = next;
    }

    function seed(
        uint256 featureId,
        address owner,
        uint256 hostShadowId,
        uint8 hostSlotIdx,
        bytes32 originFaceId,
        bytes32 paletteCommit,
        bytes32 lsh
    ) external {
        FeatureState storage f = features[featureId];
        f.owner = owner;
        f.hostShadowId = hostShadowId;
        f.hostSlotIdx = hostSlotIdx;
        f.originFaceId = originFaceId;
        f.paletteCommit = paletteCommit;
        f.liveStateHashCheckpoint = lsh;
        f.inserted = true;
        f.paletteRevealed = false;
    }

    function mintAtShadowMint(uint256, uint8, uint8, bytes32, PaletteAtMint calldata, bytes32, address)
        external
        pure
        returns (uint256)
    {
        revert("unused");
    }

    function extractFromShadow(uint256 featureId, uint256 hostShadowId, uint8 hostSlotIdx, bytes32 finalLiveStateHash)
        external
    {
        if (mode == Mode.Noop) return;
        FeatureState storage f = features[featureId];
        f.liveStateHashCheckpoint = finalLiveStateHash;
        f.inserted = false;
        f.hostShadowId = 0;
        f.hostSlotIdx = 0;
        if (mode == Mode.StorageAndEvents) {
            emit FeatureExtracted(featureId, hostShadowId, hostSlotIdx, finalLiveStateHash);
        }
    }

    function insertIntoShadow(uint256, uint256, uint8) external pure {
        revert("unused");
    }

    function rotateInsertedOwner(uint256 featureId, uint256 expectedHostShadowId, address to) external {
        if (mode == Mode.Noop) return;
        FeatureState storage f = features[featureId];
        f.owner = to;
        if (mode == Mode.StorageAndEvents) emit FeatureInsertedOwnerRotated(featureId, expectedHostShadowId, to);
    }

    function revealInsertedFeature(uint256 featureId,
    uint256 shadowId,
    uint8 slotIdx,
    bytes32[10] calldata,
    bytes32,
    bytes calldata plaintext) external { if (mode == Mode.Noop) return;
    FeatureState storage f = features[featureId];
    f.paletteRevealed = true;
    if (mode == Mode.StorageAndEvents) {
        bytes memory rgb = new bytes(30);
        emit FeaturePaletteRevealed(featureId, f.paletteCommit, rgb);
        emit FeatureSlotRevealed(featureId, shadowId, slotIdx, plaintext);
    } }

    function ownerOfFeature(uint256 featureId) external view returns (address) {
        return features[featureId].owner;
    }

    function typeIdxOf(uint256) external pure returns (uint8) {
        return 0;
    }

    function originFaceIdOf(uint256 featureId) external view returns (bytes32) {
        return features[featureId].originFaceId;
    }

    function paletteCommitOf(uint256 featureId) external view returns (bytes32) {
        return features[featureId].paletteCommit;
    }

    function liveStateHashCheckpointOf(uint256 featureId) external view returns (bytes32) {
        return features[featureId].liveStateHashCheckpoint;
    }

    function isInserted(uint256 featureId) external view returns (bool) {
        return features[featureId].inserted;
    }

    function hostShadowIdOf(uint256 featureId) external view returns (uint256) {
        return features[featureId].hostShadowId;
    }

    function hostSlotIdxOf(uint256 featureId) external view returns (uint8) {
        return features[featureId].hostSlotIdx;
    }

    function paletteRevealedOf(uint256 featureId) external view returns (bool) {
        return features[featureId].paletteRevealed;
    }
}

/// @notice Gas-attribution diagnostics with verifier/feature doubles.
/// @dev This suite answers "where does gas go after proof cost is removed?" It is
///      not cryptographic evidence. Use `GeneratedVerifierMatrix.t.sol` and
///      `ProofFuzz.t.sol` for generated-verifier assurance, and flow-specific
///      real-proof tests for integration behavior.
contract GasAttributionTest is Test {
    uint256 internal constant N = 16;
    uint256 internal constant PLAINTEXT_FIELDS = 39;
    uint256 internal constant SHADOW_ID = 0xA77B;

    Poseidon2YulSponge internal sponge;
    Poseidon2YulSponge16 internal sponge16;
    AlwaysOkVerifier internal verifier;
    KeyRegistry internal keyRegistry;
    AttributionFeatureNFT internal feature;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    bytes32 internal ownerPkX = bytes32(uint256(11));
    bytes32 internal ownerPkY = bytes32(uint256(12));
    bytes32 internal recipientPkX = bytes32(uint256(21));
    bytes32 internal recipientPkY = bytes32(uint256(22));

    function setUp() public {
        sponge = new Poseidon2YulSponge();
        sponge16 = new Poseidon2YulSponge16();
        verifier = new AlwaysOkVerifier();
        keyRegistry = new KeyRegistry();
        feature = new AttributionFeatureNFT();

        vm.prank(alice);
        keyRegistry.register(ownerPkX, ownerPkY);
        vm.prank(bob);
        keyRegistry.register(recipientPkX, recipientPkY);
    }

    function test_plain_transfer_featureless_shadow_gas() public {
        TestableShadowToken st = _deployToken(address(feature));
        st.seedShadowOnly(SHADOW_ID, alice, ownerPkX, ownerPkY);

        vm.prank(alice);
        uint256 gasBefore = gasleft();
        st.transferFrom(alice, bob, SHADOW_ID);
        uint256 used = gasBefore - gasleft();
        emit log_named_uint("plain transfer, featureless shadow", used);
    }

    function test_plain_transfer_16_occupied_reverts() public {
        TestableShadowToken st = _deployToken(address(feature));
        _seed16(st);

        vm.prank(alice);
        vm.expectRevert(ShadowToken.TransferGated.selector);
        st.transferFrom(alice, bob, SHADOW_ID);
    }

    function test_incrementalReveal_16_occ_mock_verifier_gas() public {
        TestableShadowToken st = _deployToken(address(feature));
        _seed16(st);
        st.setShadowZIndexCommitForTest(SHADOW_ID, bytes32(uint256(99)));

        uint256 used = _measureIncrementalReveal(st);
        emit log_named_uint("incremental reveal 16 occ, mocked verifier", used);
    }

    function _deployToken(address featureAddr) internal returns (TestableShadowToken st) {
        st = new TestableShadowToken(address(sponge));
        st.setYulSponge16(address(sponge16));
        st.setKeyRegistry(keyRegistry);
        st.setFeatureNFT(IFeatureNFT(featureAddr));
        st.setVerifier(5, verifier);
        st.setVerifier(3, verifier);
        st.setVerifier(6, verifier);
    }

    function _seed16(TestableShadowToken st) internal {
        uint8[] memory slots = new uint8[](N);
        uint256[] memory featureIds = new uint256[](N);
        bytes32[] memory lshs = new bytes32[](N);
        for (uint256 i = 0; i < N; i++) {
            slots[i] = uint8(i);
            featureIds[i] = _featureId(i);
            lshs[i] = bytes32(uint256(1000 + i));
        }
        st.seedShadowMultiSlot(SHADOW_ID, alice, ownerPkX, ownerPkY, slots, featureIds, lshs);
        for (uint256 i = 0; i < N; i++) {
            feature.seed(
                _featureId(i),
                alice,
                SHADOW_ID,
                uint8(i),
                bytes32(uint256(5000 + i)),
                bytes32(uint256(6000 + i)),
                lshs[i]
            );
        }
    }

    function _featureId(uint256 i) internal pure returns (uint256) {
        return 10_000 + i;
    }

    function _zeroPlaintext() internal pure returns (bytes memory plaintext) {
        plaintext = new bytes(PLAINTEXT_FIELDS * 32);
    }

    function _zeroDigest() internal view returns (bytes32 digest) {
        bytes memory plaintext = _zeroPlaintext();
        (bool ok, bytes memory ret) = address(sponge).staticcall(plaintext);
        require(ok && ret.length == 32, "sponge failed");
        digest = abi.decode(ret, (bytes32));
    }


    function _revealArgs(uint8 slotIdx) internal pure returns (ShadowToken.RevealSlotArgs memory args) {
        args.slotIdx = slotIdx;
        args.proof = hex"03";
        args.plaintext = new bytes(PLAINTEXT_FIELDS * 32);
        args.revealedRank = slotIdx;
        args.newT10[0] = bytes32(uint256(7101));
        args.newT10[1] = bytes32(uint256(7102));
        args.proofT10 = hex"04";
    }


    function _measureIncrementalReveal(TestableShadowToken st) internal returns (uint256 used) {
        vm.startPrank(alice);
        uint256 gasBefore = gasleft();
        for (uint8 i = 0; i < N; i++) {
            ShadowToken.ManifestEntry memory m = st.slotOf(SHADOW_ID, i);
            if (m.kind != ShadowToken.SlotKind.OCCUPIED) continue;
            ShadowToken.RevealSlotArgs[] memory reveals = new ShadowToken.RevealSlotArgs[](1);
            reveals[0] = _revealArgs(i);
            st.revealSlots(SHADOW_ID, reveals);
        }
        used = gasBefore - gasleft();
        vm.stopPrank();
    }
}
