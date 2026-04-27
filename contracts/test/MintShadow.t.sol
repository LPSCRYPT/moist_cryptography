// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test, stdJson, Vm} from "forge-std/Test.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {KeyRegistry} from "../src/KeyRegistry.sol";
import {MintShadowVerifier} from "../src/MintShadowVerifier.sol";
import {FaceDiscVerifier} from "../src/FaceDiscVerifier.sol";
import {T10ShadowVerifier} from "../src/T10ShadowVerifier.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {Poseidon2YulSponge16} from "../src/Poseidon2YulSponge16.sol";
import {TestableShadowToken, TestableFeatureNFT} from "./Testable.sol";

/// @notice Real-proof e2e test for `ShadowToken.mintShadow`.
///
/// Loads the linked atomic_mint fixture (8 origin slots + face_disc proof
/// for image alice0 + atomic shadow_t10), then calls mintShadow as alice
/// and asserts:
///   - shadow's ERC-721 minted to alice with deterministic shadowId
///   - 8 FeatureNFT carriers minted into slots 0..7, each owned by alice
///   - 8 manifest entries OCCUPIED with the proof's lsh_init values
///   - shadowT10 reflects the post-mint manifest hash
///   - mintedOrigins[imageCommit] = true (anti-replay armed)
///   - ShadowMinted + 8x ShadowSlotMutated + ShadowT10Updated emitted
///
/// Fixture: contracts/test/fixtures/atomic_mint/atomic_mint_demo (built
/// via tools/build_atomic_mint_fixture.py; ~3s wall-clock end-to-end).
contract MintShadowE2ETest is Test {
    using stdJson for string;

    TestableShadowToken    internal st;
    TestableFeatureNFT     internal fn;
    MintShadowVerifier     internal vMint;
    FaceDiscVerifier       internal vDisc;
    T10ShadowVerifier      internal vT10;
    Poseidon2YulSponge     internal sponge;
    Poseidon2YulSponge16   internal sponge16;
    KeyRegistry            internal kr;

    string internal constant FIX = "./test/fixtures/atomic_mint/atomic_mint_demo";

    bytes internal proofMint;
    bytes internal proofDisc;
    bytes internal proofT10;
    bytes32[] internal piMint;     // 7 fields
    bytes32[] internal piDisc;     // 1 field
    bytes32[] internal piT10;      // 20 fields

    uint256 internal shadowId;
    bytes32 internal imageCommit;
    bytes32 internal ownerPkX;
    bytes32 internal ownerPkY;

    address internal alice = makeAddr("alice");
    address internal bob   = makeAddr("bob");

    uint256 internal constant MINT_PI_LEN = 7;
    uint256 internal constant DISC_PI_LEN = 1;
    uint256 internal constant T10_PI_LEN  = 20;

    /// Cached per-slot fields read from meta.json.
    bytes32[8] internal lshInits;
    bytes32[8] internal chainTips;
    bytes32[8] internal paletteCommits;
    bytes32[8] internal originFaceIds;

    function setUp() public {
        sponge = new Poseidon2YulSponge();
        sponge16 = new Poseidon2YulSponge16();
        st = new TestableShadowToken(address(sponge));
        fn = new TestableFeatureNFT(address(st));
        st.setFeatureNFT(IFeatureNFT(address(fn)));
        st.setYulSponge16(address(sponge16));

        vMint = new MintShadowVerifier();
        vDisc = new FaceDiscVerifier();
        vT10  = new T10ShadowVerifier();
        st.setVerifier(st.SLOT_MINT_SHADOW(), IVerifier(address(vMint)));
        st.setVerifier(st.SLOT_FACE_DISC(), IVerifier(address(vDisc)));
        st.setVerifier(st.SLOT_T10_SHADOW(), IVerifier(address(vT10)));

        kr = new KeyRegistry();
        st.setKeyRegistry(kr);

        // Load proofs.
        proofMint = vm.readFileBinary(string.concat(FIX, "/proof_mint.bin"));
        piMint    = _loadFields(string.concat(FIX, "/public_inputs_mint.bin"), MINT_PI_LEN);
        proofDisc = vm.readFileBinary(string.concat(FIX, "/proof_disc.bin"));
        piDisc    = _loadFields(string.concat(FIX, "/public_inputs_disc.bin"), DISC_PI_LEN);
        proofT10  = vm.readFileBinary(string.concat(FIX, "/proof_t10.bin"));
        piT10     = _loadFields(string.concat(FIX, "/public_inputs_t10.bin"), T10_PI_LEN);

        shadowId    = uint256(piMint[0]);
        imageCommit = piMint[1];
        ownerPkX    = piMint[2];
        ownerPkY    = piMint[3];

        // Sanity: imageCommit pinned in mint PI must match face_disc PI.
        require(piDisc[0] == imageCommit, "imageCommit mismatch fixture");

        _loadFromMeta();

        // Register alice with the prover's owner_pk.
        vm.prank(alice);
        kr.register(ownerPkX, ownerPkY);
    }

    function _loadFields(string memory path, uint256 expectedLen)
        internal returns (bytes32[] memory out)
    {
        bytes memory raw = vm.readFileBinary(path);
        require(raw.length == expectedLen * 32, "PI length mismatch");
        out = new bytes32[](expectedLen);
        for (uint256 i = 0; i < expectedLen; i++) {
            bytes32 word;
            assembly { word := mload(add(raw, add(0x20, mul(i, 32)))) }
            out[i] = word;
        }
    }

    function _loadFromMeta() internal {
        string memory j = vm.readFile(string.concat(FIX, "/meta.json"));
        for (uint256 i = 0; i < 8; i++) {
            string memory idx = vm.toString(i);
            lshInits[i]       = j.readBytes32(string.concat(".lsh_inits[", idx, "]"));
            chainTips[i]      = j.readBytes32(string.concat(".chain_tips[", idx, "]"));
            paletteCommits[i] = j.readBytes32(string.concat(".palette_commits[", idx, "]"));
            originFaceIds[i]  = j.readBytes32(string.concat(".origin_face_ids[", idx, "]"));
        }
    }

    function _buildArgs() internal returns (ShadowToken.MintShadowArgs memory args) {
        args.proofMint   = proofMint;
        args.proofDisc   = proofDisc;
        args.imageCommit = imageCommit;
        args.liveStateHashInits = lshInits;
        args.chainTips          = chainTips;
        args.paletteCommits     = paletteCommits;
        args.originFaceIds      = originFaceIds;

        // Per-slot c2 (39 fields = 1248 bytes), pulled from meta.json.
        bytes[] memory c2s = new bytes[](8);
        string memory j = vm.readFile(string.concat(FIX, "/meta.json"));
        for (uint256 i = 0; i < 8; i++) {
            string memory idx = vm.toString(i);
            bytes memory buf = new bytes(39 * 32);
            for (uint256 k = 0; k < 39; k++) {
                bytes32 v = j.readBytes32(string.concat(
                    ".c2_per_slot[", idx, "][", vm.toString(k), "]"));
                assembly { mstore(add(add(buf, 32), mul(k, 32)), v) }
            }
            c2s[i] = buf;
        }
        args.c2s = c2s;

        bytes32[2] memory t10;
        t10[0] = piT10[2];   // hi
        t10[1] = piT10[3];   // lo
        args.newT10 = t10;
        args.proofT10 = proofT10;
    }

    function test_mintShadow_success_creates_shadow_and_8_carriers() public {
        ShadowToken.MintShadowArgs memory args = _buildArgs();

        // Pre-state: shadow doesn't exist; mintedOrigins clean.
        assertFalse(st.mintedOrigins(imageCommit), "imageCommit not yet minted");

        vm.recordLogs();
        vm.prank(alice);
        uint256 mintedShadowId = st.mintShadow(args);

        // ---- Post-state ----
        assertEq(mintedShadowId, shadowId, "returned shadowId matches PI[0]");
        assertEq(st.ownerOf(shadowId), alice, "shadow ERC-721 to alice");
        assertTrue(st.mintedOrigins(imageCommit), "anti-replay armed");

        ShadowToken.Shadow memory s = st.shadowOf(shadowId);
        assertEq(s.ecdhPubX, ownerPkX, "shadow ecdhPubX seeded");
        assertEq(s.ecdhPubY, ownerPkY, "shadow ecdhPubY seeded");
        assertFalse(s.solved, "fresh shadow not solved");
        assertEq(s.zIndexCommit, bytes32(0), "fresh zIndexCommit zero");
        assertEq(s.mintIdx, 1, "first mint idx = 1");

        // 8 origin slots OCCUPIED with the proof's lsh_init values.
        for (uint8 i = 0; i < 8; i++) {
            ShadowToken.ManifestEntry memory m = st.slotOf(shadowId, i);
            assertEq(uint256(m.kind), uint256(ShadowToken.SlotKind.OCCUPIED),
                     string.concat("slot ", vm.toString(uint256(i)), " OCCUPIED"));
            assertEq(m.liveStateHash, lshInits[i],
                     string.concat("slot ", vm.toString(uint256(i)), " lsh = lsh_init"));
            assertGt(m.featureId, 0, "carrier minted");
            // Cross-check carrier metadata.
            assertEq(fn.ownerOf(m.featureId), alice, "carrier owned by alice");
            assertTrue(fn.isInserted(m.featureId), "carrier inserted");
            assertEq(fn.hostShadowIdOf(m.featureId), shadowId, "carrier host");
            assertEq(fn.hostSlotIdxOf(m.featureId), i, "carrier slot idx");
            assertEq(fn.typeIdxOf(m.featureId), i, "typeIdx = slot idx");
            assertEq(fn.originFaceIdOf(m.featureId), originFaceIds[i],
                     "originFaceId stored");
            assertEq(fn.paletteCommitOf(m.featureId), paletteCommits[i],
                     "paletteCommit stored");
        }

        // Slots 8..15 EMPTY (default-zero values).
        for (uint8 i = 8; i < 16; i++) {
            ShadowToken.ManifestEntry memory m = st.slotOf(shadowId, i);
            assertEq(uint256(m.kind), uint256(ShadowToken.SlotKind.EMPTY),
                     string.concat("slot ", vm.toString(uint256(i)), " EMPTY"));
            assertEq(m.featureId, 0, "EMPTY slot featureId = 0");
            assertEq(m.liveStateHash, bytes32(0), "EMPTY slot lsh = 0");
        }

        // T10 reflects post-mint state.
        assertEq(st.shadowT10(shadowId, 0), args.newT10[0], "T10 hi");
        assertEq(st.shadowT10(shadowId, 1), args.newT10[1], "T10 lo");

        // Events.
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool sawMinted = false;
        bool sawT10 = false;
        uint256 sawSlotMutated = 0;
        bytes32 sigMinted = keccak256("ShadowMinted(uint256,address,uint64,bytes32)");
        bytes32 sigT10    = keccak256("ShadowT10Updated(uint256,bytes32,bytes32)");
        bytes32 sigSM     = keccak256("ShadowSlotMutated(uint256,uint8,bytes32,uint256,uint16,bytes32,bytes32,bytes)");
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter != address(st)) continue;
            if (logs[i].topics[0] == sigMinted) sawMinted = true;
            else if (logs[i].topics[0] == sigT10) sawT10 = true;
            else if (logs[i].topics[0] == sigSM) sawSlotMutated++;
        }
        assertTrue(sawMinted, "ShadowMinted emitted");
        assertTrue(sawT10, "ShadowT10Updated emitted");
        assertEq(sawSlotMutated, 8, "8 ShadowSlotMutated emitted (one per origin slot)");
    }

    function test_mintShadow_reverts_when_already_minted() public {
        ShadowToken.MintShadowArgs memory args = _buildArgs();
        vm.prank(alice);
        st.mintShadow(args);

        // Re-submitting same imageCommit must trip anti-replay.
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.AlreadyMinted.selector, imageCommit));
        st.mintShadow(args);
    }

    function test_mintShadow_reverts_when_mint_proof_tampered() public {
        ShadowToken.MintShadowArgs memory args = _buildArgs();
        // Flip a byte in the middle of the mint proof.
        args.proofMint[256] = bytes1(uint8(args.proofMint[256]) ^ 0x40);
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.mintShadow(args);
    }

    function test_mintShadow_reverts_when_face_disc_tampered() public {
        ShadowToken.MintShadowArgs memory args = _buildArgs();
        // Flip a byte in the middle of the face_disc proof.
        args.proofDisc[256] = bytes1(uint8(args.proofDisc[256]) ^ 0x40);
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.mintShadow(args);
    }

    function test_mintShadow_reverts_when_c2_tampered() public {
        ShadowToken.MintShadowArgs memory args = _buildArgs();
        // Flip a byte in the first c2 slot. Re-spongeing yields a different
        // ct_commits_root, so PI[5] mismatches and the proof verifier rejects.
        // The contract checks the proof first, so we expect InvalidProof.
        args.c2s[0][7] = bytes1(uint8(args.c2s[0][7]) ^ 0x80);
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.mintShadow(args);
    }
}
