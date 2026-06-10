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
import {Poseidon2YulHash2} from "../src/Poseidon2YulHash2.sol";
import {ShadowMintController} from "../src/ShadowMintController.sol";
import {TestableShadowToken, TestableFeatureNFT} from "./Testable.sol";

/// @notice Real-proof e2e test for phased `ShadowToken` mint.
///
/// Loads the linked atomic_mint fixture (8 origin slots + face_disc proof
/// for image alice0 + atomic shadow_t10), then exercises the split flow:
///   1. registerImage(imageCommit, proofDisc)  — face_disc verified once.
///   2. beginMintShadow(args, recipient)       — locks a fixed recipient.
///   3. submitMintCiphertexts(...)             — c2 commitment checks in batches.
///   4. finalizeMintShadow(...)                — installs carriers and T10.
///
/// Asserts:
///   - registeredImages[imageCommit] = true after registerImage
///   - shadow's ERC-721 minted to alice with deterministic shadowId
///   - 8 FeatureNFT carriers minted into slots 0..7, each owned by alice
///   - 8 manifest entries OCCUPIED with the proof's lsh_init values
///   - shadowT10 reflects the post-mint manifest hash
///   - mintedOrigins[imageCommit] = true (anti-replay armed)
///   - ImageRegistered + ShadowMintStarted + 8x MintCiphertextSubmitted + ShadowMinted emitted
///
/// Fixture: contracts/test/fixtures/atomic_mint/atomic_mint_demo (built
/// via tools/build_atomic_mint_fixture.py; ~3s wall-clock end-to-end).
contract MintShadowE2ETest is Test {
    using stdJson for string;

    TestableShadowToken internal st;
    TestableFeatureNFT internal fn;
    MintShadowVerifier internal vMint;
    FaceDiscVerifier internal vDisc;
    T10ShadowVerifier internal vT10;
    Poseidon2YulSponge internal sponge;
    Poseidon2YulSponge16 internal sponge16;
    Poseidon2YulHash2 internal hash2;
    KeyRegistry internal kr;
    ShadowMintController internal mc;

    string internal constant FIX = "./test/fixtures/atomic_mint/atomic_mint_demo";

    bytes internal proofMint;
    bytes internal proofDisc;
    bytes internal proofT10;
    bytes32[] internal piMint; // 7 fields
    bytes32[] internal piDisc; // 1 field
    bytes32[] internal piT10; // 20 fields

    uint256 internal shadowId;
    bytes32 internal imageCommit;
    bytes32 internal ownerPkX;
    bytes32 internal ownerPkY;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    uint256 internal constant MINT_PI_LEN = 7;
    uint256 internal constant DISC_PI_LEN = 1;
    uint256 internal constant T10_PI_LEN = 20;

    /// Cached per-slot fields read from meta.json.
    bytes32[8] internal lshInits;
    bytes32[8] internal chainTips;
    bytes32[8] internal paletteCommits;
    bytes32[8] internal originFaceIds;
    bytes32[8] internal ctCommits; // sponge_39(c2[i]) per slot, from fixture
    bytes32[8] internal paletteSaltCts; // per-slot ECIES salt envelopes (advisory)
    bytes32[8] internal saltC1Xs;
    bytes32[8] internal saltC1Ys;
    bytes[] internal mintC2s;

    function setUp() public {
        sponge = new Poseidon2YulSponge();
        sponge16 = new Poseidon2YulSponge16();
        hash2 = new Poseidon2YulHash2();
        st = new TestableShadowToken(address(sponge));
        fn = new TestableFeatureNFT(address(st));
        st.setFeatureNFT(IFeatureNFT(address(fn)));
        st.setYulSponge16(address(sponge16));
        st.setYulHash2(address(hash2));

        vMint = new MintShadowVerifier();
        vDisc = new FaceDiscVerifier();
        vT10 = new T10ShadowVerifier();
        st.setVerifier(0, IVerifier(address(vMint)));
        st.setVerifier(1, IVerifier(address(vDisc)));
        st.setVerifier(3, IVerifier(address(vT10)));

        kr = new KeyRegistry();
        st.setKeyRegistry(kr);
        mc = new ShadowMintController(st, kr, IVerifier(address(vMint)), address(sponge), address(sponge16), address(hash2));
        st.setMintController(address(mc));

        // Load proofs.
        proofMint = vm.readFileBinary(string.concat(FIX, "/proof_mint.bin"));
        piMint = _loadFields(string.concat(FIX, "/public_inputs_mint.bin"), MINT_PI_LEN);
        proofDisc = vm.readFileBinary(string.concat(FIX, "/proof_disc.bin"));
        piDisc = _loadFields(string.concat(FIX, "/public_inputs_disc.bin"), DISC_PI_LEN);
        proofT10 = vm.readFileBinary(string.concat(FIX, "/proof_t10.bin"));
        piT10 = _loadFields(string.concat(FIX, "/public_inputs_t10.bin"), T10_PI_LEN);

        shadowId = uint256(piMint[0]);
        imageCommit = piMint[1];
        ownerPkX = piMint[2];
        ownerPkY = piMint[3];

        // Sanity: imageCommit pinned in mint PI must match face_disc PI.
        require(piDisc[0] == imageCommit, "imageCommit mismatch fixture");

        _loadFromMeta();
        mintC2s = _loadMintC2s();

        // Register alice with the prover's owner_pk.
        vm.prank(alice);
        kr.register(ownerPkX, ownerPkY);
    }

    /// Helper: register the fixture's imageCommit. Tests that exercise
    /// registerImage failure paths (or want to verify beginMintShadow's
    /// `ImageNotRegistered` gate) do NOT call this.
    function _registerImage() internal {
        st.registerImage(imageCommit, proofDisc);
    }

    function _loadFields(string memory path, uint256 expectedLen) internal returns (bytes32[] memory out) {
        bytes memory raw = vm.readFileBinary(path);
        require(raw.length == expectedLen * 32, "PI length mismatch");
        out = new bytes32[](expectedLen);
        for (uint256 i = 0; i < expectedLen; i++) {
            bytes32 word;
            assembly { word := mload(add(raw, add(0x20, mul(i, 32)))) }
            out[i] = word;
        }
    }

    function _writeField(bytes memory data, uint256 fieldIndex, uint256 value) internal pure {
        assembly { mstore(add(add(data, 32), mul(fieldIndex, 32)), value) }
    }

    function _loadFromMeta() internal {
        string memory j = vm.readFile(string.concat(FIX, "/meta.json"));
        for (uint256 i = 0; i < 8; i++) {
            string memory idx = vm.toString(i);
            lshInits[i] = j.readBytes32(string.concat(".lsh_inits[", idx, "]"));
            chainTips[i] = j.readBytes32(string.concat(".chain_tips[", idx, "]"));
            paletteCommits[i] = j.readBytes32(string.concat(".palette_commits[", idx, "]"));
            originFaceIds[i] = j.readBytes32(string.concat(".origin_face_ids[", idx, "]"));
            ctCommits[i] = j.readBytes32(string.concat(".ct_commits[", idx, "]"));
            paletteSaltCts[i] = j.readBytes32(string.concat(".palette_salt_cts[", idx, "]"));
            saltC1Xs[i] = j.readBytes32(string.concat(".salt_c1_xs[", idx, "]"));
            saltC1Ys[i] = j.readBytes32(string.concat(".salt_c1_ys[", idx, "]"));
        }
    }

    function _buildArgs() internal view returns (ShadowToken.MintShadowArgs memory args) {
        args.proofMint = proofMint;
        args.imageCommit = imageCommit;
        args.liveStateHashInits = lshInits;
        args.chainTips = chainTips;
        args.paletteCommits = paletteCommits;
        args.paletteSaltCts = paletteSaltCts;
        args.saltC1Xs = saltC1Xs;
        args.saltC1Ys = saltC1Ys;
        args.originFaceIds = originFaceIds;
        args.ctCommits = ctCommits;
        bytes32[2] memory t10;
        t10[0] = piT10[2];
        t10[1] = piT10[3];
        args.newT10 = t10;
    }

    function _loadMintC2s() internal returns (bytes[] memory c2s) {
        c2s = new bytes[](8);
        string memory j = vm.readFile(string.concat(FIX, "/meta.json"));
        for (uint256 i = 0; i < 8; i++) {
            string memory idx = vm.toString(i);
            bytes memory buf = new bytes(39 * 32);
            for (uint256 k = 0; k < 39; k++) {
                bytes32 v = j.readBytes32(string.concat(".c2_per_slot[", idx, "][", vm.toString(k), "]"));
                assembly { mstore(add(add(buf, 32), mul(k, 32)), v) }
            }
            c2s[i] = buf;
        }
    }

    function _submitOne(uint256 sid, uint8 slot, bytes memory c2) internal {
        uint8[] memory slots = new uint8[](1);
        bytes[] memory c2s = new bytes[](1);
        slots[0] = slot;
        c2s[0] = c2;
        mc.submitMintCiphertexts(sid, slots, c2s);
    }

    function _submitAll(uint256 sid) internal {
        for (uint8 i = 0; i < 8; i++) {
            _submitOne(sid, i, mintC2s[i]);
        }
    }

    function _slotRange(uint8 start, uint8 count) internal pure returns (uint8[] memory slots) {
        slots = new uint8[](count);
        for (uint8 i = 0; i < count; i++) slots[i] = start + i;
    }

    function _c2Range(uint8 start, uint8 count) internal view returns (bytes[] memory c2s) {
        c2s = new bytes[](count);
        for (uint8 i = 0; i < count; i++) c2s[i] = mintC2s[start + i];
    }

    function _completeMint(address recipient) internal returns (uint256 sid) {
        ShadowToken.MintShadowArgs memory args = _buildArgs();
        vm.prank(alice);
        sid = mc.beginMintShadow(args, recipient);
        _submitAll(sid);
        mc.finalizeMintShadow(sid, proofT10);
    }

    // ============== registerImage ==============

    function test_registerImage_succeeds_and_emits_event() public {
        assertFalse(st.registeredImages(imageCommit), "imageCommit not yet registered");
        vm.recordLogs();
        _registerImage();
        assertTrue(st.registeredImages(imageCommit), "registered after call");

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 sigReg = keccak256("ImageRegistered(bytes32)");
        bool sawReg = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(st) && logs[i].topics[0] == sigReg) {
                assertEq(logs[i].topics[1], imageCommit, "indexed imageCommit matches");
                sawReg = true;
            }
        }
        assertTrue(sawReg, "ImageRegistered emitted");
    }

    function test_registerImage_reverts_when_already_registered() public {
        _registerImage();
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.ImageAlreadyRegistered.selector, imageCommit));
        _registerImage();
    }

    function test_registerImage_reverts_when_proof_tampered() public {
        // Flip a byte in the middle of the face_disc proof.
        proofDisc[256] = bytes1(uint8(proofDisc[256]) ^ 0x40);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.registerImage(imageCommit, proofDisc);
    }

    /// Gas-pin: registerImage is a single-proof tx (face_disc). Local
    /// budget 4M; on-chain extrapolation ~5M. Trivially under 16M.
    function test_registerImage_gas_under_budget() public {
        uint256 gasBefore = gasleft();
        st.registerImage(imageCommit, proofDisc);
        uint256 used = gasBefore - gasleft();
        assertLt(used, 4_000_000, "registerImage gas regressed");
    }

    // ============== phased mint ==============

    function test_phasedMint_success_creates_shadow_and_8_carriers() public {
        _registerImage();
        ShadowToken.MintShadowArgs memory args = _buildArgs();

        assertFalse(st.mintedOrigins(imageCommit), "imageCommit not yet minted");
        assertFalse(mc.pendingOrigins(imageCommit), "imageCommit not yet pending");

        vm.recordLogs();
        vm.prank(alice);
        uint256 mintedShadowId = mc.beginMintShadow(args, alice);
        assertEq(mintedShadowId, shadowId, "begin returned shadowId");
        assertTrue(mc.pendingOrigins(imageCommit), "pending after begin");
        assertEq(mc.pendingMintSubmittedBitmap(shadowId), 0, "no c2 submitted yet");

        _submitAll(shadowId);
        assertEq(mc.pendingMintSubmittedBitmap(shadowId), 0xff, "all c2 submitted");
        mc.finalizeMintShadow(shadowId, proofT10);

        assertEq(st.ownerOf(shadowId), alice, "shadow ERC-721 to fixed recipient");
        assertTrue(st.mintedOrigins(imageCommit), "anti-replay armed");
        assertFalse(mc.pendingOrigins(imageCommit), "pending cleared");

        {
            (bytes32 ecdhPubX, bytes32 ecdhPubY, bool solved, bytes32 zIndexCommit) = st.shadowHeaderOf(shadowId);
            assertEq(ecdhPubX, ownerPkX, "shadow ecdhPubX seeded");
            assertEq(ecdhPubY, ownerPkY, "shadow ecdhPubY seeded");
            assertFalse(solved, "fresh shadow not solved");
            assertEq(zIndexCommit, bytes32(0), "fresh zIndexCommit zero");
        }

        for (uint8 i = 0; i < 8; i++) {
            ShadowToken.ManifestEntry memory m = st.slotOf(shadowId, i);
            assertEq(uint256(m.kind), uint256(ShadowToken.SlotKind.OCCUPIED), "origin slot OCCUPIED");
            assertEq(m.liveStateHash, lshInits[i], "slot lsh = lsh_init");
            assertGt(m.featureId, 0, "carrier minted");
            assertEq(fn.ownerOf(m.featureId), alice, "carrier owned by recipient");
            assertTrue(fn.isInserted(m.featureId), "carrier inserted");
            assertEq(fn.hostShadowIdOf(m.featureId), shadowId, "carrier host");
            assertEq(fn.hostSlotIdxOf(m.featureId), i, "carrier slot idx");
            assertEq(fn.typeIdxOf(m.featureId), i, "typeIdx = slot idx");
            assertEq(fn.originFaceIdOf(m.featureId), originFaceIds[i], "originFaceId stored");
            assertEq(fn.paletteCommitOf(m.featureId), paletteCommits[i], "paletteCommit stored");
        }

        for (uint8 i = 8; i < 16; i++) {
            ShadowToken.ManifestEntry memory m = st.slotOf(shadowId, i);
            assertEq(uint256(m.kind), uint256(ShadowToken.SlotKind.EMPTY), "tail slot EMPTY");
            assertEq(m.featureId, 0, "EMPTY slot featureId = 0");
            assertEq(m.liveStateHash, bytes32(0), "EMPTY slot lsh = 0");
        }

        assertEq(st.shadowT10(shadowId, 0), args.newT10[0], "T10 hi");
        assertEq(st.shadowT10(shadowId, 1), args.newT10[1], "T10 lo");

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool sawStarted = false;
        bool sawMinted = false;
        bool sawT10 = false;
        uint256 sawC2 = 0;
        uint256 sawSlotMutated = 0;
        bytes32 sigStarted = keccak256("ShadowMintStarted(uint256,address,bytes32)");
        bytes32 sigMinted = keccak256("ShadowMinted(uint256,address,uint64,bytes32)");
        bytes32 sigT10 = keccak256("ShadowT10Updated(uint256,bytes32,bytes32)");
        bytes32 sigC2 = keccak256("MintCiphertextSubmitted(uint256,uint8,bytes32,bytes)");
        bytes32 sigSM = keccak256("ShadowSlotMutated(uint256,uint8,bytes32,uint256,uint16,bytes32,bytes32,bytes)");
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(mc)) {
                if (logs[i].topics[0] == sigStarted) sawStarted = true;
                else if (logs[i].topics[0] == sigC2) sawC2++;
            } else if (logs[i].emitter == address(st)) {
                if (logs[i].topics[0] == sigMinted) sawMinted = true;
                else if (logs[i].topics[0] == sigT10) sawT10 = true;
                else if (logs[i].topics[0] == sigSM) sawSlotMutated++;
            }
        }
        assertTrue(sawStarted, "ShadowMintStarted emitted");
        assertTrue(sawMinted, "ShadowMinted emitted");
        assertTrue(sawT10, "ShadowT10Updated emitted");
        assertEq(sawC2, 8, "8 ciphertext events emitted");
        assertEq(sawSlotMutated, 8, "8 slot install events emitted");
    }

    function test_phasedMint_fixes_recipient_at_begin() public {
        _registerImage();
        uint256 sid = mc.beginMintShadow(_buildArgs(), alice);
        _submitAll(sid);
        mc.finalizeMintShadow(sid, proofT10);
        assertEq(st.ownerOf(sid), alice, "finalize caller cannot redirect recipient");
    }

    function test_beginMintShadow_uses_canonical_shadow_id_derivation() public {
        _registerImage();
        vm.prank(alice);
        uint256 minted = mc.beginMintShadow(_buildArgs(), alice);
        uint256 FR_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        assertEq(minted, uint256(imageCommit) % FR_MOD, "= imageCommit % FR_MOD");
    }

    function test_beginMintShadow_reverts_when_image_not_registered() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.ImageNotRegistered.selector, imageCommit));
        mc.beginMintShadow(_buildArgs(), alice);
    }

    function test_beginMintShadow_reverts_when_already_minted() public {
        _registerImage();
        _completeMint(alice);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.AlreadyMinted.selector, imageCommit));
        mc.beginMintShadow(_buildArgs(), alice);
    }

    function test_beginMintShadow_reverts_when_pending_exists() public {
        _registerImage();
        vm.prank(alice);
        mc.beginMintShadow(_buildArgs(), alice);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowMintController.PendingMintExists.selector, imageCommit));
        mc.beginMintShadow(_buildArgs(), alice);
    }

    function test_beginMintShadow_reverts_when_mint_proof_tampered() public {
        _registerImage();
        ShadowToken.MintShadowArgs memory args = _buildArgs();
        args.proofMint[256] = bytes1(uint8(args.proofMint[256]) ^ 0x40);
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        mc.beginMintShadow(args, alice);
    }

    function test_beginMintShadow_reverts_when_ctCommits_tampered() public {
        _registerImage();
        ShadowToken.MintShadowArgs memory args = _buildArgs();
        args.ctCommits[0] = bytes32(uint256(args.ctCommits[0]) ^ 1);
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        mc.beginMintShadow(args, alice);
    }

    function test_beginMintShadow_reverts_when_originFaceIds_tampered() public {
        _registerImage();
        ShadowToken.MintShadowArgs memory args = _buildArgs();
        args.originFaceIds[3] = bytes32(uint256(args.originFaceIds[3]) ^ 1);
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        mc.beginMintShadow(args, alice);
    }

    function test_originFaceId_matches_minted_carrier() public {
        _registerImage();
        uint256 sid = _completeMint(alice);
        ShadowToken.MintShadowArgs memory args = _buildArgs();
        for (uint8 i = 0; i < 8; i++) {
            ShadowToken.ManifestEntry memory m = st.slotOf(sid, i);
            assertEq(fn.originFaceIdOf(m.featureId), args.originFaceIds[i], "derived matches fixture");
        }
    }

    function test_submitMintCiphertexts_reverts_when_c2_tampered() public {
        _registerImage();
        vm.prank(alice);
        uint256 sid = mc.beginMintShadow(_buildArgs(), alice);
        bytes memory bad = mintC2s[0];
        bad[7] = bytes1(uint8(bad[7]) ^ 0x80);
        vm.expectRevert(ShadowMintController.DigestMismatch.selector);
        _submitOne(sid, 0, bad);
        assertFalse(st.mintedOrigins(imageCommit), "mintedOrigins unchanged");
    }

    function test_submitMintCiphertexts_reverts_when_c2_field_noncanonical() public {
        _registerImage();
        vm.prank(alice);
        uint256 sid = mc.beginMintShadow(_buildArgs(), alice);
        bytes memory bad = mintC2s[0];
        uint256 fr = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        _writeField(bad, 0, fr);
        vm.expectRevert(ShadowMintController.NonCanonicalField.selector);
        _submitOne(sid, 0, bad);
        assertFalse(st.mintedOrigins(imageCommit), "mintedOrigins unchanged");
    }

    function test_submitMintCiphertexts_reverts_duplicate_slot() public {
        _registerImage();
        vm.prank(alice);
        uint256 sid = mc.beginMintShadow(_buildArgs(), alice);
        _submitOne(sid, 0, mintC2s[0]);
        vm.expectRevert(abi.encodeWithSelector(ShadowMintController.SlotAlreadySubmitted.selector, 0));
        _submitOne(sid, 0, mintC2s[0]);
    }

    function test_submitMintCiphertexts_accepts_multi_slot_batch() public {
        _registerImage();
        vm.prank(alice);
        uint256 sid = mc.beginMintShadow(_buildArgs(), alice);
        uint8[] memory slots = new uint8[](2);
        bytes[] memory c2s = new bytes[](2);
        slots[0] = 0;
        slots[1] = 1;
        c2s[0] = mintC2s[0];
        c2s[1] = mintC2s[1];
        mc.submitMintCiphertexts(sid, slots, c2s);
        assertEq(mc.pendingMintSubmittedBitmap(sid), 0x03, "two slots submitted");
    }

    function test_shadowToken_rejects_direct_finalize_without_controller() public {
        _registerImage();
        vm.expectRevert(ShadowToken.NotDeployer.selector);
        st.finalizeMintFromController(_buildArgs(), alice, ownerPkX, ownerPkY, proofT10);
    }

    function test_finalizeMintShadow_reverts_until_all_ciphertexts_submitted() public {
        _registerImage();
        vm.prank(alice);
        uint256 sid = mc.beginMintShadow(_buildArgs(), alice);
        _submitOne(sid, 0, mintC2s[0]);
        vm.expectRevert(abi.encodeWithSelector(ShadowMintController.MintIncomplete.selector, uint8(1), uint8(0xff)));
        mc.finalizeMintShadow(sid, proofT10);
    }

    function test_executeMintBatch_registers_begins_and_submits_prefix() public {
        ShadowMintController.MintBatch memory batch;
        batch.doRegisterImage = true;
        batch.imageCommit = imageCommit;
        batch.proofDisc = proofDisc;
        batch.doBeginMint = true;
        batch.mintArgs = _buildArgs();
        batch.recipient = alice;
        batch.submitSlots = _slotRange(0, 4);
        batch.submitC2s = _c2Range(0, 4);

        vm.prank(alice);
        (uint256 sid, uint256 mintedSid) = mc.executeMintBatch(batch);

        assertEq(sid, shadowId, "batch returned derived shadowId");
        assertEq(mintedSid, 0, "not finalized");
        assertTrue(st.registeredImages(imageCommit), "image registered in same tx");
        assertTrue(mc.pendingOrigins(imageCommit), "mint pending");
        assertEq(mc.pendingMintSubmittedBitmap(shadowId), 0x0f, "first four c2 submitted");
        assertFalse(st.mintedOrigins(imageCommit), "not minted before finalize");
    }

    function test_executeMintBatch_two_transactions_can_complete_full_mint() public {
        ShadowMintController.MintBatch memory first;
        first.doRegisterImage = true;
        first.imageCommit = imageCommit;
        first.proofDisc = proofDisc;
        first.doBeginMint = true;
        first.mintArgs = _buildArgs();
        first.recipient = alice;
        first.submitSlots = _slotRange(0, 4);
        first.submitC2s = _c2Range(0, 4);

        vm.prank(alice);
        (uint256 sid,) = mc.executeMintBatch(first);
        assertEq(mc.pendingMintSubmittedBitmap(sid), 0x0f, "first batch submitted");

        ShadowMintController.MintBatch memory second;
        second.shadowId = sid;
        second.submitSlots = _slotRange(4, 4);
        second.submitC2s = _c2Range(4, 4);
        second.doFinalize = true;
        second.proofT10 = proofT10;

        (, uint256 mintedSid) = mc.executeMintBatch(second);

        assertEq(mintedSid, shadowId, "finalized expected shadow");
        assertEq(st.ownerOf(shadowId), alice, "recipient fixed from begin tx");
        assertTrue(st.mintedOrigins(imageCommit), "anti-replay armed");
        assertFalse(mc.pendingOrigins(imageCommit), "pending cleared");
        assertEq(mc.pendingMintSubmittedBitmap(shadowId), 0, "pending session deleted");
    }

    function test_executeMintBatch_reverts_when_register_image_mismatches_mint_args() public {
        ShadowMintController.MintBatch memory batch;
        batch.doRegisterImage = true;
        batch.imageCommit = bytes32(uint256(imageCommit) ^ 1);
        batch.proofDisc = proofDisc;
        batch.doBeginMint = true;
        batch.mintArgs = _buildArgs();
        batch.recipient = alice;

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowMintController.ImageCommitMismatch.selector, batch.imageCommit, imageCommit));
        mc.executeMintBatch(batch);
    }

    function test_executeMintBatch_reverts_when_supplied_shadow_id_mismatches_begin() public {
        _registerImage();
        ShadowMintController.MintBatch memory batch;
        batch.doBeginMint = true;
        batch.mintArgs = _buildArgs();
        batch.recipient = alice;
        batch.shadowId = shadowId + 1;

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowMintController.ShadowIdMismatch.selector, shadowId + 1, shadowId));
        mc.executeMintBatch(batch);
    }

    function test_executeMintBatch_reverts_when_missing_shadow_id_for_followup() public {
        ShadowMintController.MintBatch memory batch;
        batch.doFinalize = true;
        batch.proofT10 = proofT10;

        vm.expectRevert(ShadowMintController.MissingShadowId.selector);
        mc.executeMintBatch(batch);
    }


    function test_phasedMint_gas_steps_under_public_rpc_budget() public {
        _registerImage();
        uint256 gasBefore = gasleft();
        vm.prank(alice);
        uint256 sid = mc.beginMintShadow(_buildArgs(), alice);
        uint256 beginUsed = gasBefore - gasleft();
        assertLt(beginUsed, 8_000_000, "beginMintShadow gas regressed");

        gasBefore = gasleft();
        _submitOne(sid, 0, mintC2s[0]);
        uint256 submitUsed = gasBefore - gasleft();
        assertLt(submitUsed, 3_000_000, "single submit gas regressed");

        for (uint8 i = 1; i < 8; i++) _submitOne(sid, i, mintC2s[i]);
        gasBefore = gasleft();
        mc.finalizeMintShadow(sid, proofT10);
        uint256 finalizeUsed = gasBefore - gasleft();
        assertLt(finalizeUsed, 8_000_000, "finalizeMintShadow gas regressed");
    }
}
