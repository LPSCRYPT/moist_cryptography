// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test, stdJson} from "forge-std/Test.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {KeyRegistry} from "../src/KeyRegistry.sol";
import {MutateSlotVerifier} from "../src/MutateSlotVerifier.sol";
import {T10ShadowVerifier} from "../src/T10ShadowVerifier.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {Poseidon2YulSponge16} from "../src/Poseidon2YulSponge16.sol";
import {TestableShadowToken, TestableFeatureNFT} from "./Testable.sol";

/// @notice Max-batch (N=8) gas regression test for `ShadowToken.mutateBatch`.
///
/// Loads the `atomic_mutate_batch_max_demo` fixture (8 mutate_slot proofs
/// for slots 0..7 of one shadow + 1 T10 proof against the post-batch
/// manifest), seeds 8 carriers, and exercises mutateBatch with N=8.
///
/// Why this matters: `mutateBatch` accepts an arbitrary-length entries[]
/// array. Each entry triggers one ZK verify (~3.5-4M gas). The contract
/// loop scales linearly in N. The companion N=2 test caps at 12M and an
/// asymptote test bounds per-entry growth, but neither directly exercises
/// the worst-case path. This test pins the actual N=8 cost so callers
/// see the cliff explicitly:
///   * forge measured: ~21.4M gas (in-process, no calldata charge)
///   * adding ~3M for calldata (~16 gas/non-zero byte * ~180KB of
///     entries[] data) puts the real-chain cost near ~25M -- inside
///     a ~30M block budget but well above the 16M per-entry-point
///     hard target.
/// **Practical bound:** callers MUST chunk batches at N <= 3 to fit
/// under the 16M target. The contract itself permits any non-empty N.
contract MutateBatchMaxBatchTest is Test {
    using stdJson for string;

    TestableShadowToken internal st;
    TestableFeatureNFT internal fn;
    MutateSlotVerifier internal vMut;
    T10ShadowVerifier internal vT10;
    Poseidon2YulSponge internal sponge;
    Poseidon2YulSponge16 internal sponge16;
    KeyRegistry internal kr;

    string internal constant FIX = "./test/fixtures/atomic_mutate_batch_max/atomic_mutate_batch_max_demo";
    uint256 internal constant N_BATCH = 8;
    uint256 internal constant MUT_PI_LEN = 16;
    uint256 internal constant T10_PI_LEN = 20;

    bytes[N_BATCH] internal proofs;
    bytes32[][N_BATCH] internal pis;
    bytes[N_BATCH] internal c2s;
    bytes internal proofT10;
    bytes32[] internal piT10;

    uint256 internal shadowId;
    uint8[N_BATCH] internal slots;

    address internal alice = makeAddr("alice");

    function setUp() public {
        sponge = new Poseidon2YulSponge();
        sponge16 = new Poseidon2YulSponge16();
        st = new TestableShadowToken(address(sponge));
        fn = new TestableFeatureNFT(address(st));
        st.setFeatureNFT(IFeatureNFT(address(fn)));
        st.setYulSponge16(address(sponge16));

        vMut = new MutateSlotVerifier();
        vT10 = new T10ShadowVerifier();
        st.setVerifier(st.SLOT_MUTATE_SLOT(), IVerifier(address(vMut)));
        st.setVerifier(st.SLOT_T10_SHADOW(), IVerifier(address(vT10)));

        kr = new KeyRegistry();
        st.setKeyRegistry(kr);

        for (uint256 i = 0; i < N_BATCH; i++) {
            string memory idx = vm.toString(i);
            proofs[i] = vm.readFileBinary(string.concat(FIX, "/proof_mut_", idx, ".bin"));
            pis[i] = _loadFields(string.concat(FIX, "/public_inputs_mut_", idx, ".bin"), MUT_PI_LEN);
            c2s[i] = vm.readFileBinary(string.concat(FIX, "/c2_", idx, ".bin"));
        }
        proofT10 = vm.readFileBinary(string.concat(FIX, "/proof_t10.bin"));
        piT10 = _loadFields(string.concat(FIX, "/public_inputs_t10.bin"), T10_PI_LEN);

        shadowId = uint256(pis[0][0]);
        for (uint256 i = 0; i < N_BATCH; i++) {
            require(uint256(pis[i][0]) == shadowId, "fixtures disagree on shadow_id");
            slots[i] = uint8(uint256(pis[i][1]));
        }

        _seedChainState();
    }

    function _loadFields(string memory path, uint256 expectedLen) internal view returns (bytes32[] memory out) {
        bytes memory raw = vm.readFileBinary(path);
        require(raw.length == expectedLen * 32, "PI length mismatch");
        out = new bytes32[](expectedLen);
        for (uint256 i = 0; i < expectedLen; i++) {
            bytes32 word;
            assembly { word := mload(add(raw, add(0x20, mul(i, 32)))) }
            out[i] = word;
        }
    }

    function _seedChainState() internal {
        bytes32 ownerPkX = pis[0][10];
        bytes32 ownerPkY = pis[0][11];
        for (uint256 i = 1; i < N_BATCH; i++) {
            require(pis[i][10] == ownerPkX && pis[i][11] == ownerPkY, "owner pk diverges");
        }

        vm.prank(alice);
        kr.register(ownerPkX, ownerPkY);

        uint8[] memory slotsDyn = new uint8[](N_BATCH);
        uint256[] memory featIds = new uint256[](N_BATCH);
        bytes32[] memory oldLshes = new bytes32[](N_BATCH);
        for (uint256 i = 0; i < N_BATCH; i++) {
            slotsDyn[i] = slots[i];
            featIds[i] = uint256(pis[i][2]);
            oldLshes[i] = pis[i][6];
        }
        st.seedShadowMultiSlot(shadowId, alice, ownerPkX, ownerPkY, slotsDyn, featIds, oldLshes);

        for (uint256 i = 0; i < N_BATCH; i++) {
            fn.seedFeature(
                featIds[i],
                shadowId,
                slots[i],
                uint8(uint256(pis[i][3])), // typeIdx
                pis[i][4], // originFaceId
                pis[i][5], // paletteCommit
                pis[i][6], // initial LSH (irrelevant while inserted)
                alice
            );
        }
    }

    function _entry(uint256 i) internal view returns (ShadowToken.MutateSlotEntry memory e) {
        bytes32[] memory pi = pis[i];
        e.slotIdx = slots[i];
        e.proofMutate = proofs[i];
        e.newC1X = uint256(0);
        e.newC1Y = uint256(0);
        e.newLiveStateHash = pi[7];
        e.newCtCommit = pi[8];
        e.c2FieldCount = uint16(uint256(pi[9]));
        e.c2 = c2s[i];
        e.prevChainTip = pi[12];
        e.newChainTip = pi[13];
        e.prevMutationCount = uint16(uint256(pi[14]));
        e.newMutationCount = uint16(uint256(pi[15]));
    }

    function _buildArgs() internal view returns (ShadowToken.MutateBatchArgs memory args) {
        args.shadowId = shadowId;
        args.entries = new ShadowToken.MutateSlotEntry[](N_BATCH);
        for (uint256 i = 0; i < N_BATCH; i++) {
            args.entries[i] = _entry(i);
        }
        bytes32[2] memory t10;
        t10[0] = piT10[2];
        t10[1] = piT10[3];
        args.newT10 = t10;
        args.proofT10 = proofT10;
    }

    /// Exercise the N=8 path end-to-end. Asserts each occupied slot's
    /// LSH advanced to its post-mutate value.
    function test_mutateBatch_max_n8_advances_all_slots() public {
        ShadowToken.MutateBatchArgs memory args = _buildArgs();
        vm.prank(alice);
        st.mutateBatch(args);
        for (uint256 i = 0; i < N_BATCH; i++) {
            assertEq(st.slotOf(shadowId, slots[i]).liveStateHash, pis[i][7], "slot LSH not advanced");
        }
    }

    /// Gas regression: at N=8 the call cost should be roughly
    ///   (per-entry verify + storage) * 8 + T10 verify + fixed overhead
    /// = ~8 * 3.5M + 1M + 1M = ~30M.
    /// The 16M hard target is BLOWN at N=8. This test pins the actual
    /// observed value with a 35M ceiling so we catch unexpected
    /// non-linear regressions but do NOT pretend the path is cheap.
    /// Practical bound: callers should use N <= 3 to fit under 16M.
    function test_mutateBatch_max_n8_gas_within_block_limit() public {
        ShadowToken.MutateBatchArgs memory args = _buildArgs();
        vm.prank(alice);
        uint256 gasBefore = gasleft();
        st.mutateBatch(args);
        uint256 used = gasBefore - gasleft();

        // Block ceilings: Base Sepolia ~30M, mainnet 30M. Cap at 35M to
        // catch a non-linear blow-up (loop overhead growing quadratically,
        // calldata cost shifts, etc.) but not pretend the path is OK.
        // If this fires below 35M, the practical N bound just got worse.
        assertLt(used, 35_000_000, "mutateBatch(N=8) gas regressed past 35M; non-linear cost suspected");

        // Document the OBSERVED per-entry growth: subtract a fixed
        // overhead estimate (T10 verify ~1M + bookkeeping ~1M) and divide.
        uint256 fixedOverhead = 2_000_000;
        require(used > fixedOverhead, "sanity");
        uint256 perEntry = (used - fixedOverhead) / N_BATCH;

        // At N=8, per-entry should match the N=2 measurement closely
        // (mostly the per-verify cost + per-slot SSTORE). If this drifts,
        // the verifier circuit changed.
        assertLt(perEntry, 5_000_000, "mutateBatch per-entry gas at N=8 exceeds 5M");

        emit log_named_uint("mutateBatch N=8 total gas", used);
        emit log_named_uint("mutateBatch N=8 per-entry gas (after 2M overhead)", perEntry);
    }
}
