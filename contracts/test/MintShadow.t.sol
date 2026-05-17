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
import {TestableShadowToken, TestableFeatureNFT} from "./Testable.sol";

/// @notice Real-proof e2e test for `ShadowToken.registerImage` + `mintShadow`.
///
/// Loads the linked atomic_mint fixture (8 origin slots + face_disc proof
/// for image alice0 + atomic shadow_t10), then exercises the v2-gas split:
///   1. registerImage(imageCommit, proofDisc)  — face_disc verified once.
///   2. mintShadow(args)                       — gates on registeredImages.
///
/// Asserts:
///   - registeredImages[imageCommit] = true after registerImage
///   - shadow's ERC-721 minted to alice with deterministic shadowId
///   - 8 FeatureNFT carriers minted into slots 0..7, each owned by alice
///   - 8 manifest entries OCCUPIED with the proof's lsh_init values
///   - shadowT10 reflects the post-mint manifest hash
///   - mintedOrigins[imageCommit] = true (anti-replay armed)
///   - ImageRegistered + ShadowMinted + 8x ShadowSlotMutated + ShadowT10Updated emitted
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
        st.setVerifier(st.SLOT_MINT_SHADOW(), IVerifier(address(vMint)));
        st.setVerifier(st.SLOT_FACE_DISC(), IVerifier(address(vDisc)));
        st.setVerifier(st.SLOT_T10_SHADOW(), IVerifier(address(vT10)));

        kr = new KeyRegistry();
        st.setKeyRegistry(kr);

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

        // Register alice with the prover's owner_pk.
        vm.prank(alice);
        kr.register(ownerPkX, ownerPkY);
    }

    /// Helper: register the fixture's imageCommit. Tests that exercise
    /// registerImage failure paths (or want to verify mintShadow's
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

    function _buildArgs() internal returns (ShadowToken.MintShadowArgs memory args) {
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

        // Per-slot c2 (39 fields = 1248 bytes), pulled from meta.json.
        bytes[] memory c2s = new bytes[](8);
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
        args.c2s = c2s;

        bytes32[2] memory t10;
        t10[0] = piT10[2]; // hi
        t10[1] = piT10[3]; // lo
        args.newT10 = t10;
        args.proofT10 = proofT10;
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

    // ============== mintShadow ==============

    function test_mintShadow_success_creates_shadow_and_8_carriers() public {
        _registerImage();
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
            assertEq(
                uint256(m.kind),
                uint256(ShadowToken.SlotKind.OCCUPIED),
                string.concat("slot ", vm.toString(uint256(i)), " OCCUPIED")
            );
            assertEq(m.liveStateHash, lshInits[i], string.concat("slot ", vm.toString(uint256(i)), " lsh = lsh_init"));
            assertGt(m.featureId, 0, "carrier minted");
            // Cross-check carrier metadata.
            assertEq(fn.ownerOf(m.featureId), alice, "carrier owned by alice");
            assertTrue(fn.isInserted(m.featureId), "carrier inserted");
            assertEq(fn.hostShadowIdOf(m.featureId), shadowId, "carrier host");
            assertEq(fn.hostSlotIdxOf(m.featureId), i, "carrier slot idx");
            assertEq(fn.typeIdxOf(m.featureId), i, "typeIdx = slot idx");
            assertEq(fn.originFaceIdOf(m.featureId), originFaceIds[i], "originFaceId stored");
            assertEq(fn.paletteCommitOf(m.featureId), paletteCommits[i], "paletteCommit stored");
        }

        // Slots 8..15 EMPTY (default-zero values).
        for (uint8 i = 8; i < 16; i++) {
            ShadowToken.ManifestEntry memory m = st.slotOf(shadowId, i);
            assertEq(
                uint256(m.kind),
                uint256(ShadowToken.SlotKind.EMPTY),
                string.concat("slot ", vm.toString(uint256(i)), " EMPTY")
            );
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
        bytes32 sigT10 = keccak256("ShadowT10Updated(uint256,bytes32,bytes32)");
        bytes32 sigSM = keccak256("ShadowSlotMutated(uint256,uint8,bytes32,uint256,uint16,bytes32,bytes32,bytes)");
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

    /// Audit M-03: pre-fix, `ShadowToken.shadowIdOf` returned a domain-
    /// separated keccak that did NOT match `mintShadow`'s formula
    /// (`uint256(imageCommit) % FR_MOD`). Indexers/scripts using shadowIdOf
    /// to look up minted tokens got the wrong id. After the fix, the view
    /// helper and the minted token id must agree byte-for-byte.
    function test_shadowIdOf_matches_mintShadow_derivation() public {
        _registerImage();
        ShadowToken.MintShadowArgs memory args = _buildArgs();
        vm.prank(alice);
        uint256 minted = st.mintShadow(args);
        assertEq(minted, st.shadowIdOf(imageCommit), "shadowIdOf == minted id");
        // And the formula matches what mintShadow uses internally.
        uint256 FR_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        assertEq(minted, uint256(imageCommit) % FR_MOD, "= imageCommit % FR_MOD");
    }

    function test_mintShadow_reverts_when_image_not_registered() public {
        // No _registerImage() call. mintShadow MUST refuse.
        ShadowToken.MintShadowArgs memory args = _buildArgs();
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.ImageNotRegistered.selector, imageCommit));
        st.mintShadow(args);
    }

    function test_mintShadow_reverts_when_already_minted() public {
        _registerImage();
        ShadowToken.MintShadowArgs memory args = _buildArgs();
        vm.prank(alice);
        st.mintShadow(args);

        // Re-submitting same imageCommit must trip anti-replay.
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.AlreadyMinted.selector, imageCommit));
        st.mintShadow(args);
    }

    function test_mintShadow_reverts_when_mint_proof_tampered() public {
        _registerImage();
        ShadowToken.MintShadowArgs memory args = _buildArgs();
        // Flip a byte in the middle of the mint proof.
        args.proofMint[256] = bytes1(uint8(args.proofMint[256]) ^ 0x40);
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.mintShadow(args);
    }

    /// c2 calldata is byte-bound on chain. Tampering c2 is tested
    /// separately via DigestMismatch; tampering ctCommits exercises the
    /// proof-bound PI[5] root.
    function test_mintShadow_reverts_when_ctCommits_tampered() public {
        _registerImage();
        ShadowToken.MintShadowArgs memory args = _buildArgs();
        args.ctCommits[0] = bytes32(uint256(args.ctCommits[0]) ^ 1);
        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.mintShadow(args);
    }

    /// Audit H-05 negative: caller-supplied `originFaceIds[i]` must equal
    /// `poseidon2_hash_2(imageCommit, i)` (canonical circuit derivation).
    /// Pre-fix the contract trusted the caller; now the contract recomputes
    /// the expected face id via the Poseidon2 hash_2 Yul wrapper and
    /// reverts on mismatch BEFORE invoking the verifier.
    function test_mintShadow_reverts_when_originFaceIds_tampered() public {
        _registerImage();
        ShadowToken.MintShadowArgs memory args = _buildArgs();
        args.originFaceIds[3] = bytes32(uint256(args.originFaceIds[3]) ^ 1);
        vm.prank(alice);
        // EIP-170 budget consolidation: H-05 originFaceId mismatch reverts
        // with the existing `InvalidProof` selector rather than a dedicated
        // error. The contract has STATICCALL'd Poseidon2YulHash2 already, so
        // the revert IS the proof-bound check firing -- the loss is only the
        // error name's diagnostic payload, not the soundness guarantee.
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.mintShadow(args);
    }

    /// Audit H-05 positive: the `originFaceIdOf` view must agree byte-for-byte
    /// with what `_mintOneAtom` stored. Pre-fix it returned a keccak
    /// placeholder that matched nothing the circuit produced.
    function test_originFaceIdOf_matches_minted_carrier() public {
        _registerImage();
        ShadowToken.MintShadowArgs memory args = _buildArgs();
        vm.prank(alice);
        uint256 sid = st.mintShadow(args);
        for (uint8 i = 0; i < 8; i++) {
            ShadowToken.ManifestEntry memory m = st.slotOf(sid, i);
            bytes32 fnOfi = fn.originFaceIdOf(m.featureId);
            bytes32 stOfi = st.originFaceIdOf(imageCommit, i);
            assertEq(fnOfi, stOfi, "FN.originFaceIdOf(fid) == ST.originFaceIdOf(image, i)");
            assertEq(stOfi, args.originFaceIds[i], "derived matches fixture");
        }
    }

    /// Envelope-binding cutover (audit H-02): tampered c2 in mintShadow
    /// MUST revert. Pre-cutover the per-slot c2 calldata was advisory and
    /// only ctCommits[i] was bound to the proof. The contract now
    /// recomputes sponge_39(args.c2s[i]) and asserts equality with
    /// args.ctCommits[i] before any FN.mintAtShadowMint call.
    function test_mintShadow_reverts_when_c2_tampered() public {
        _registerImage();
        ShadowToken.MintShadowArgs memory args = _buildArgs();
        args.c2s[0][7] = bytes1(uint8(args.c2s[0][7]) ^ 0x80);
        vm.prank(alice);
        vm.expectRevert();
        st.mintShadow(args);
    }

    function test_mintShadow_reverts_when_c2_field_noncanonical() public {
        _registerImage();
        ShadowToken.MintShadowArgs memory args = _buildArgs();
        uint256 fr = st.FR_MOD();
        _writeField(args.c2s[0], 0, fr);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ShadowToken.NonCanonicalField.selector, uint256(0), fr));
        st.mintShadow(args);
        assertFalse(st.mintedOrigins(imageCommit), "mintedOrigins unchanged");
    }

    /// Gas-pin: mintShadow body now performs 8 on-chain sponge_39 c2
    /// re-hashes (audit H-02) + 8 on-chain hash_2 originFaceId binds
    /// (audit H-05). Post-cutover local cost ~14.6M, well under the 16M
    /// block budget. Budget 15.5M leaves regression-detection headroom.
    function test_mintShadow_gas_under_block_budget() public {
        _registerImage();
        ShadowToken.MintShadowArgs memory args = _buildArgs();
        vm.prank(alice);
        uint256 gasBefore = gasleft();
        st.mintShadow(args);
        uint256 used = gasBefore - gasleft();
        assertLt(used, 15_500_000, "mintShadow gas regressed");
    }
}
