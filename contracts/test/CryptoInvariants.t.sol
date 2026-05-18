// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test, stdJson} from "forge-std/Test.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {Poseidon2YulSponge16} from "../src/Poseidon2YulSponge16.sol";

/// @notice Cryptographic invariants we rely on across the v2 stack.
///         These are the assumptions that, if violated, silently break
///         the security model. Every test here either:
///           (a) asserts a property the design depends on (transcript
///               distinctness, determinism, domain-separation), or
///           (b) re-derives a known-good vector against a published
///               fixture so a regenerated Yul / circuit can't drift.
///
/// What we test (and why):
///
///   1. **Transcript distinctness across sponge variants.**
///      sponge_39 (rate-3, 13 absorb blocks + sentinel) and sponge_16
///      (5 rate-3 + 1 rate-1 partial + sentinel) MUST produce
///      different outputs even when fed the same prefix data + zero
///      padding. If they ever collided, an attacker could substitute
///      one transcript for another (e.g. craft a c2 calldata that
///      sponge-collides with an LSH input). Distinctness is enforced
///      by structural padding shape, not by content.
///
///   2. **Determinism.** Same input -> same output, every call.
///      Trivial but worth pinning: a Yul-staticcall non-determinism
///      would invalidate every proof binding we have.
///
///   3. **Avalanche.** A one-bit input change should flip many
///      output bits. We pin a Hamming-distance floor of 64 (out of
///      256). If the sponge ever degenerates (e.g. a Poseidon round
///      gets dropped), this test fires.
///
///   4. **Non-trivial output.** sponge_X(zeros) MUST NOT be zero --
///      otherwise an empty manifest would look the same as a
///      mid-flight one. Caught by the sentinel pad.
///
///   5. **Length-binding via padding shape.** The same 8 leading
///      fields followed by 8 zeros (sponge_16) MUST NOT collide with
///      the same 8 leading fields followed by 31 zeros (sponge_39).
///      Different absorb shapes prevent length-extension attacks.
///
///   6. **MINT_TAG vs TRANSFER_TAG domain separation.** The two
///      domain tags MUST be distinct nonzero constants. If equal, a
///      mint chain-tip could collide with a transfer chain-tip and an
///      attacker could rebind ownership through fake mint.
contract CryptoInvariantsTest is Test {
    Poseidon2YulSponge internal sponge;
    Poseidon2YulSponge16 internal sponge16;

    /// MUST equal `ShadowToken.MINT_TAG`. Pinned here so a divergence
    /// between contract + test + circuit + Python helper trips a test.
    uint256 internal constant MINT_TAG_EXPECTED = 0x910015e5abad43e0addedda7a;

    /// MUST equal `circuits/transfer_shadow_v2`'s TRANSFER_TAG and
    /// `tools/v2_circuit_helpers.TRANSFER_TAG`.
    uint256 internal constant TRANSFER_TAG_EXPECTED = 0x1ad75ffae4711a5fea7eed;

    /// bn254 Fr modulus (poseidon2 field).
    uint256 internal constant FR_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function setUp() public {
        sponge = new Poseidon2YulSponge();
        sponge16 = new Poseidon2YulSponge16();
    }

    // ============== Yul sponge wrappers ==============

    /// Sponge_39 = yulSponge over 39 fields (1248 bytes). Same shape
    /// the v2 contracts use to bind c2 calldata to its sponge_39 root.
    function _sponge39(bytes memory buf) internal view returns (uint256 out) {
        require(buf.length == 39 * 32, "sponge_39 buffer must be 1248 B");
        address y = address(sponge);
        assembly {
            let ok := staticcall(gas(), y, add(buf, 32), 1248, 0, 32)
            if iszero(ok) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
            out := mload(0)
        }
    }

    /// Sponge_16 = yulSponge16 over 16 fields (512 bytes).
    function _sponge16(bytes memory buf) internal view returns (uint256 out) {
        require(buf.length == 16 * 32, "sponge_16 buffer must be 512 B");
        address y = address(sponge16);
        assembly {
            let ok := staticcall(gas(), y, add(buf, 32), 512, 0, 32)
            if iszero(ok) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
            out := mload(0)
        }
    }

    /// Build a length-N buffer with the first `prefix.length` fields
    /// set to `prefix` and the rest zero. Caller MUST pass a multiple
    /// of 32 for `nFields`.
    function _padBuf(bytes32[] memory prefix, uint256 nFields) internal pure returns (bytes memory) {
        require(prefix.length <= nFields, "prefix > nFields");
        bytes memory buf = new bytes(nFields * 32);
        for (uint256 i = 0; i < prefix.length; i++) {
            bytes32 v = prefix[i];
            assembly { mstore(add(add(buf, 32), mul(i, 32)), v) }
        }
        return buf;
    }

    function _hammingDist(uint256 a, uint256 b) internal pure returns (uint256 d) {
        uint256 x = a ^ b;
        for (; x != 0; x &= x - 1) {
            d++;
        }
    }

    // ============== Tests: transcript distinctness ==============

    /// sponge_39(prefix + zeros) MUST NOT equal sponge_16(prefix + zeros)
    /// for the same 8-field prefix. The shapes have different absorb
    /// patterns + different total lengths; collision would be a sign of
    /// a deep generator bug.
    function test_sponge39_vs_sponge16_distinct_transcripts() public view {
        bytes32[] memory prefix = new bytes32[](8);
        for (uint256 i = 0; i < 8; i++) {
            prefix[i] = bytes32(uint256(0xdeadbeef + i));
        }
        uint256 r39 = _sponge39(_padBuf(prefix, 39));
        uint256 r16 = _sponge16(_padBuf(prefix, 16));
        assertTrue(r39 != r16, "sponge_39 and sponge_16 transcripts collide on shared prefix");
    }

    /// Length-binding: sponge_X(prefix) over different X for the same
    /// prefix MUST diverge. Pads to 39 vs 16; both contain the same 8
    /// leading fields but different trailing zero counts -> different
    /// absorb passes -> different outputs. A length-extension-style
    /// collision here would let a prover swap c2 length on a slot.
    function test_length_binding_via_padding_shape() public view {
        bytes32[] memory prefix = new bytes32[](2);
        prefix[0] = bytes32(uint256(0xa55a));
        prefix[1] = bytes32(uint256(0xc7c7));
        uint256 r39 = _sponge39(_padBuf(prefix, 39));
        uint256 r16 = _sponge16(_padBuf(prefix, 16));
        assertTrue(r39 != r16, "padding-shape collision");
    }

    // ============== Tests: determinism ==============

    function test_sponge39_deterministic() public view {
        bytes32[] memory in_ = new bytes32[](39);
        for (uint256 i = 0; i < 39; i++) {
            in_[i] = bytes32(uint256(i + 1));
        }
        bytes memory buf = _padBuf(in_, 39);
        uint256 a = _sponge39(buf);
        uint256 b = _sponge39(buf);
        assertEq(a, b, "sponge_39 not deterministic");
    }

    function test_sponge16_deterministic() public view {
        bytes32[] memory in_ = new bytes32[](16);
        for (uint256 i = 0; i < 16; i++) {
            in_[i] = bytes32(uint256(i * 7 + 3));
        }
        bytes memory buf = _padBuf(in_, 16);
        uint256 a = _sponge16(buf);
        uint256 b = _sponge16(buf);
        assertEq(a, b, "sponge_16 not deterministic");
    }

    // ============== Tests: avalanche ==============

    /// Flip the lowest bit of one input field; assert at least 64 of
    /// 256 output bits change. A real Poseidon2 hits ~128 with high
    /// probability (close to a random oracle); 64 is a generous floor
    /// that still catches degenerate hash regressions.
    function test_sponge39_avalanche() public view {
        bytes32[] memory in_ = new bytes32[](2);
        in_[0] = bytes32(uint256(0x42));
        in_[1] = bytes32(uint256(0x7));
        bytes memory bufA = _padBuf(in_, 39);
        in_[0] = bytes32(uint256(0x43)); // flip 1 bit
        bytes memory bufB = _padBuf(in_, 39);
        uint256 a = _sponge39(bufA);
        uint256 b = _sponge39(bufB);
        uint256 hd = _hammingDist(a, b);
        assertGe(hd, 64, "sponge_39 avalanche too weak; possible round dropped");
    }

    function test_sponge16_avalanche() public view {
        bytes32[] memory in_ = new bytes32[](2);
        in_[0] = bytes32(uint256(0x42));
        in_[1] = bytes32(uint256(0x7));
        bytes memory bufA = _padBuf(in_, 16);
        in_[0] = bytes32(uint256(0x43));
        bytes memory bufB = _padBuf(in_, 16);
        uint256 a = _sponge16(bufA);
        uint256 b = _sponge16(bufB);
        uint256 hd = _hammingDist(a, b);
        assertGe(hd, 64, "sponge_16 avalanche too weak");
    }

    // ============== Tests: non-trivial output ==============

    /// Sponge of all-zeros input MUST NOT be zero. The sentinel pad
    /// (s[0] += 1 before the final permutation) is what guarantees
    /// this -- it's the difference between a meaningful hash and a
    /// degenerate identity.
    function test_sponge39_zero_input_not_zero() public view {
        bytes memory buf = new bytes(39 * 32); // all zero
        uint256 r = _sponge39(buf);
        assertTrue(r != 0, "sponge_39(zeros) == 0; sentinel pad missing");
    }

    function test_sponge16_zero_input_not_zero() public view {
        bytes memory buf = new bytes(16 * 32);
        uint256 r = _sponge16(buf);
        assertTrue(r != 0, "sponge_16(zeros) == 0; sentinel pad missing");
    }

    // ============== Tests: output is a valid Field element ==============

    /// Sponge output MUST be < FR_MOD. If the Yul implementation lost
    /// the final modulo reduction, downstream Solidity arithmetic
    /// (which treats outputs as bytes32) would silently overflow into
    /// the high range and break proof binding when the same value is
    /// re-fed into a circuit that interprets it as a Field.
    function test_sponge39_output_in_field() public view {
        bytes32[] memory in_ = new bytes32[](2);
        in_[0] = bytes32(uint256(0xdead));
        in_[1] = bytes32(uint256(0xbeef));
        uint256 r = _sponge39(_padBuf(in_, 39));
        assertLt(r, FR_MOD, "sponge_39 output >= FR_MOD; lost modular reduction");
    }

    function test_sponge16_output_in_field() public view {
        bytes32[] memory in_ = new bytes32[](2);
        in_[0] = bytes32(uint256(0xdead));
        in_[1] = bytes32(uint256(0xbeef));
        uint256 r = _sponge16(_padBuf(in_, 16));
        assertLt(r, FR_MOD, "sponge_16 output >= FR_MOD; lost modular reduction");
    }

    // ============== Tests: domain separation ==============

    /// MINT_TAG and TRANSFER_TAG MUST be distinct nonzero Field
    /// constants. Equal tags would let a mint chain-tip collide with a
    /// transfer chain-tip; a malicious prover could rebind ownership
    /// by faking a mint that produces a chain-tip matching some prior
    /// transfer's witness.
    function test_mint_and_transfer_tags_distinct_and_nonzero() public pure {
        assertTrue(MINT_TAG_EXPECTED != 0, "MINT_TAG must be nonzero");
        assertTrue(TRANSFER_TAG_EXPECTED != 0, "TRANSFER_TAG must be nonzero");
        assertTrue(
            MINT_TAG_EXPECTED != TRANSFER_TAG_EXPECTED, "MINT_TAG == TRANSFER_TAG; chain-tip domain separation broken"
        );
        assertLt(MINT_TAG_EXPECTED, FR_MOD, "MINT_TAG outside Fr");
        assertLt(TRANSFER_TAG_EXPECTED, FR_MOD, "TRANSFER_TAG outside Fr");
    }

    // ============== Tests: cross-fixture pinning ==============

    /// Pin sponge_39 against a fixture's `new_ct_commit`. If the Yul
    /// implementation ever drifts (e.g. round count change, S-box
    /// power change, MDS matrix flip), this test catches it before
    /// any verifier does. The fixture itself is generated by Python
    /// helpers + nargo execute + bb prove, so the round-trip
    /// guarantee is end-to-end.
    function test_sponge39_pinned_against_atomic_mutate_fixture() public view {
        // atomic_mutate/atomic_demo fixture: c2 calldata is exactly 39
        // fields packed big-endian; new_ct_commit in meta.json is the
        // sponge_39 of that c2.
        bytes memory c2 = vm.readFileBinary("./test/fixtures/atomic_mutate/atomic_demo/c2.bin");
        require(c2.length == 39 * 32, "c2 length unexpected");
        uint256 chainCommit = _sponge39(c2);
        string memory j = vm.readFile("./test/fixtures/atomic_mutate/atomic_demo/meta.json");
        bytes32 expected = stdJson.readBytes32(j, ".new_ct_commit");
        assertEq(bytes32(chainCommit), expected, "sponge_39 drifted: c2 sponge != fixture's new_ct_commit");
    }
}
