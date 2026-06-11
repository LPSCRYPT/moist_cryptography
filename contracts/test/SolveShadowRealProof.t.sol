// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {SolveShadowVerifier} from "../src/SolveShadowVerifier.sol";
import {T10ShadowVerifier} from "../src/T10ShadowVerifier.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {Poseidon2YulSpongePaletteSalt} from "../src/Poseidon2YulSpongePaletteSalt.sol";
import {TestableShadowToken, TestableFeatureNFT} from "./Testable.sol";

/// @notice End-to-end real-proof regression for incremental feature reveal.
///
/// Fixture: tools/build_solve_shadow_v2_fixture.py --seed incremental_reveal_contract
/// produces a linked pair of real proofs:
///   - proof.bin/public_inputs.bin: solve_shadow_v2 single-slot reveal proof.
///   - proof_t10.bin/public_inputs_t10.bin: shadow_t10 refresh after the slot
///     becomes REVEALED and no hidden OCCUPIED slots remain.
///
/// This test intentionally uses the generated Solidity verifiers, not the
/// mock verifier used by unit-level mutation-behavior tests. It also uses the
/// real FeatureNFT palette-opening path, so the revealed palette/salt must open
/// the fixture's paletteCommit through Poseidon2YulSpongePaletteSalt.
contract SolveShadowRealProofTest is Test {
    using stdJson for string;

    string internal constant FIX = "./test/fixtures/solve_shadow_v2/incremental_reveal_contract";
    uint256 internal constant REVEAL_PI_LEN = 9;
    uint256 internal constant T10_PI_LEN = 20;

    TestableShadowToken internal st;
    TestableFeatureNFT internal fn;
    SolveShadowVerifier internal revealVerifier;
    T10ShadowVerifier internal t10Verifier;

    address internal alice = makeAddr("alice");

    bytes internal proofReveal;
    bytes32[] internal piReveal;
    bytes internal proofT10;
    bytes32[] internal piT10;
    bytes internal plaintext;
    bytes32[10] internal palette;
    bytes32 internal paletteSalt;

    uint256 internal shadowId;
    uint8 internal slotIdx;
    uint256 internal featureId;
    bytes32 internal liveStateHash;
    bytes32 internal paletteCommit;
    bytes32 internal ownerPkX;
    bytes32 internal ownerPkY;
    uint8 internal revealedRank;
    bytes32 internal originFaceId;
    uint16 internal prevMutationCount;
    bytes32 internal prevChainTip;

    function setUp() public {
        Poseidon2YulSponge sponge = new Poseidon2YulSponge();
        Poseidon2YulSpongePaletteSalt paletteSponge = new Poseidon2YulSpongePaletteSalt();
        st = new TestableShadowToken(address(sponge));
        fn = new TestableFeatureNFT(address(st));
        fn.setPaletteSponge(address(paletteSponge));

        revealVerifier = new SolveShadowVerifier();
        t10Verifier = new T10ShadowVerifier();
        st.setFeatureNFT(IFeatureNFT(address(fn)));
        st.setVerifier(3, IVerifier(address(t10Verifier)));
        st.setVerifier(6, IVerifier(address(revealVerifier)));

        proofReveal = vm.readFileBinary(string.concat(FIX, "/proof.bin"));
        piReveal = _loadFields(string.concat(FIX, "/public_inputs.bin"), REVEAL_PI_LEN);
        proofT10 = vm.readFileBinary(string.concat(FIX, "/proof_t10.bin"));
        piT10 = _loadFields(string.concat(FIX, "/public_inputs_t10.bin"), T10_PI_LEN);
        plaintext = vm.readFileBinary(string.concat(FIX, "/plaintext.bin"));

        string memory meta = vm.readFile(string.concat(FIX, "/meta.json"));
        for (uint256 i = 0; i < 10; i++) {
            palette[i] = bytes32(meta.readUint(string.concat(".palette[", vm.toString(i), "]")));
        }
        paletteSalt = bytes32(meta.readUint(".palette_salt"));
        originFaceId = bytes32(meta.readUint(".origin_face_id"));
        prevMutationCount = uint16(meta.readUint(".prev_mutation_count"));
        prevChainTip = bytes32(meta.readUint(".prev_chain_tip"));

        shadowId = uint256(piReveal[0]);
        slotIdx = uint8(uint256(piReveal[1]));
        featureId = uint256(piReveal[2]);
        liveStateHash = piReveal[3];
        paletteCommit = piReveal[5];
        ownerPkX = piReveal[6];
        ownerPkY = piReveal[7];
        revealedRank = uint8(uint256(piReveal[8]));

        assertEq(piT10[0], bytes32(shadowId), "linked T10 shadow id");
        assertEq(piT10[1], bytes32(0), "linked T10 z-commit");
        for (uint256 i = 4; i < T10_PI_LEN; i++) {
            assertEq(piT10[i], bytes32(0), "revealed-only hidden manifest is zero");
        }

        fn.seedFeature(featureId, shadowId, slotIdx, 0, originFaceId, paletteCommit, liveStateHash, alice);
        st.seedShadowAndSlot(shadowId, alice, ownerPkX, ownerPkY, slotIdx, featureId, liveStateHash);
        st.setSlotHistoryForTest(shadowId, slotIdx, prevMutationCount, prevChainTip);
    }

    function test_revealSlots_accepts_real_solve_and_t10_proofs() public {
        assertTrue(revealVerifier.verify(proofReveal, piReveal), "real reveal verifier rejects fixture");
        assertTrue(t10Verifier.verify(proofT10, piT10), "real T10 verifier rejects fixture");

        ShadowToken.RevealSlotArgs[] memory reveals = new ShadowToken.RevealSlotArgs[](1);
        reveals[0] = ShadowToken.RevealSlotArgs({
            slotIdx: slotIdx,
            proof: proofReveal,
            plaintext: plaintext,
            palette: palette,
            paletteSalt: paletteSalt,
            revealedRank: revealedRank,
            newT10: [piT10[2], piT10[3]],
            proofT10: proofT10
        });

        vm.prank(alice);
        st.revealSlots(shadowId, reveals);

        ShadowToken.ManifestEntry memory m = st.slotOf(shadowId, slotIdx);
        assertEq(uint256(m.kind), uint256(ShadowToken.SlotKind.REVEALED), "slot kind");
        assertEq(m.featureId, featureId, "feature id remains bound");
        assertEq(m.liveStateHash, liveStateHash, "revealed slot keeps provenance hash");
        assertTrue(fn.paletteRevealedOf(featureId), "feature palette revealed");
        assertEq(st.shadowT10(shadowId, 0), piT10[2], "t10 hi");
        assertEq(st.shadowT10(shadowId, 1), piT10[3], "t10 lo");

        (,, bool solved,) = st.shadowHeaderOf(shadowId);
        assertTrue(solved, "single-slot shadow solved after reveal");
    }

    function test_revealSlots_rejects_tampered_real_reveal_proof() public {
        ShadowToken.RevealSlotArgs[] memory reveals = new ShadowToken.RevealSlotArgs[](1);
        bytes memory tamperedProof = bytes.concat(proofReveal);
        tamperedProof[tamperedProof.length / 2] = bytes1(uint8(tamperedProof[tamperedProof.length / 2]) ^ 0x01);
        reveals[0] = ShadowToken.RevealSlotArgs({
            slotIdx: slotIdx,
            proof: tamperedProof,
            plaintext: plaintext,
            palette: palette,
            paletteSalt: paletteSalt,
            revealedRank: revealedRank,
            newT10: [piT10[2], piT10[3]],
            proofT10: proofT10
        });

        vm.prank(alice);
        vm.expectRevert(ShadowToken.InvalidProof.selector);
        st.revealSlots(shadowId, reveals);
    }

    function _loadFields(string memory path, uint256 expectedLen) internal view returns (bytes32[] memory out) {
        bytes memory raw = vm.readFileBinary(path);
        require(raw.length == expectedLen * 32, "PI length mismatch (regenerate fixture?)");
        out = new bytes32[](expectedLen);
        for (uint256 i = 0; i < expectedLen; i++) {
            bytes32 word;
            assembly { word := mload(add(raw, add(0x20, mul(i, 32)))) }
            out[i] = word;
        }
    }
}
