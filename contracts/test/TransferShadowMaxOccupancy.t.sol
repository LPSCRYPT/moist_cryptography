// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test, stdJson, Vm} from "forge-std/Test.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {KeyRegistry} from "../src/KeyRegistry.sol";
import {TransferShadowVerifier} from "../src/TransferShadowVerifier.sol";
import {T10ShadowVerifier} from "../src/T10ShadowVerifier.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {Poseidon2YulSponge16} from "../src/Poseidon2YulSponge16.sol";
import {TestableShadowToken, TestableFeatureNFT} from "./Testable.sol";

/// @notice High-water-mark transferShadow test: ALL 16 slots occupied.
///
/// The canonical TransferShadow.t.sol exercises 4 occupied slots --
/// representative of typical mid-game state. This test loads a separate
/// fixture (`atomic_transfer_max`, n_occupied=16) and stresses the
/// contract's loop bounds + gas profile under maximum slot occupation.
///
/// What this pins:
///   - Contract loop over 16 slots completes correctly (no early
///     termination, no skipped carrier rotation)
///   - Every carrier ERC-721 ownership rotates alice -> bob
///   - shadowT10 reflects the full 16-slot post-transfer LSH array
///   - Gas budget under 30M Ethereum / 60M Base block ceiling
///
/// Gas budget: 22M -- ~16% above projected ~19M baseline (4-slot is
/// ~12.1M, so 16-slot should be roughly 4x the per-slot cost = ~14M
/// loop body + ~5M proof = ~19M total). Tight enough to catch a
/// regression that adds N kilobytes per slot.
contract TransferShadowMaxOccupancyTest is Test {
    using stdJson for string;

    TestableShadowToken    internal st;
    TestableFeatureNFT     internal fn;
    TransferShadowVerifier internal vT;
    T10ShadowVerifier      internal vT10;
    Poseidon2YulSponge     internal sponge;
    Poseidon2YulSponge16   internal sponge16;
    KeyRegistry            internal kr;

    string internal constant FIX = "./test/fixtures/atomic_transfer/atomic_transfer_max";

    address internal alice = makeAddr("alice");
    address internal bob   = makeAddr("bob");

    uint256 internal shadowId;
    uint256[] internal featureIds;       // 16 entries, indexed by slot
    ShadowToken.TransferShadowArgs internal args;

    // Storage-resident per-slot arrays to keep stack shallow.
    bytes32[16] internal _newLsh;
    bytes32[16] internal _newCt;
    uint256[16] internal _newC1X;
    uint256[16] internal _newC1Y;
    bytes32[16] internal _newChainTip;
    uint16[16]  internal _newCount;
    bytes[]     internal _c2s;
    bytes32     internal _t10Hi;
    bytes32     internal _t10Lo;
    bytes       internal _proofTransfer;
    bytes       internal _proofT10;
    bytes32     internal _stashedRecipientPkX;
    bytes32     internal _stashedRecipientPkY;
    bytes32     internal _stashedPrevOwnerPkX;
    bytes32     internal _stashedPrevOwnerPkY;

    function setUp() public {
        _deployStack();
        _loadProofsAndPi();
        _seedKeyRegistryAndShadow();
        _loadPerSlotMeta();
        _loadPerSlotC2();
        _buildArgs();
    }

    function _deployStack() internal {
        sponge = new Poseidon2YulSponge();
        sponge16 = new Poseidon2YulSponge16();
        st = new TestableShadowToken(address(sponge));
        fn = new TestableFeatureNFT(address(st));
        st.setFeatureNFT(IFeatureNFT(address(fn)));
        st.setYulSponge16(address(sponge16));
        vT = new TransferShadowVerifier();
        vT10 = new T10ShadowVerifier();
        st.setVerifier(st.SLOT_TRANSFER_SHADOW(), IVerifier(address(vT)));
        st.setVerifier(st.SLOT_T10_SHADOW(), IVerifier(address(vT10)));
        kr = new KeyRegistry();
        st.setKeyRegistry(kr);
    }

    function _loadProofsAndPi() internal {
        _proofTransfer = vm.readFileBinary(string.concat(FIX, "/proof_transfer.bin"));
        bytes32[] memory piTransfer = _loadFields(string.concat(FIX, "/public_inputs_transfer.bin"), 9);
        _proofT10 = vm.readFileBinary(string.concat(FIX, "/proof_t10.bin"));
        bytes32[] memory piT10 = _loadFields(string.concat(FIX, "/public_inputs_t10.bin"), 20);
        shadowId = uint256(piTransfer[0]);
        _stashedRecipientPkX = piTransfer[1];
        _stashedRecipientPkY = piTransfer[2];
        _stashedPrevOwnerPkX = piTransfer[5];
        _stashedPrevOwnerPkY = piTransfer[6];
        _t10Hi = piT10[2];
        _t10Lo = piT10[3];
    }

    function _seedKeyRegistryAndShadow() internal {
        vm.prank(alice);
        kr.register(_stashedPrevOwnerPkX, _stashedPrevOwnerPkY);
        vm.prank(bob);
        kr.register(_stashedRecipientPkX, _stashedRecipientPkY);
    }

    function _loadPerSlotMeta() internal {
        string memory j = vm.readFile(string.concat(FIX, "/meta.json"));
        for (uint256 i = 0; i < 16; i++) {
            string memory idx = vm.toString(i);
            _newLsh[i]      = j.readBytes32(string.concat(".new_lsh[", idx, "]"));
            _newCt[i]       = j.readBytes32(string.concat(".new_ct_commit[", idx, "]"));
            _newC1X[i]      = uint256(j.readBytes32(string.concat(".new_c1_x[", idx, "]")));
            _newC1Y[i]      = uint256(j.readBytes32(string.concat(".new_c1_y[", idx, "]")));
            _newChainTip[i] = j.readBytes32(string.concat(".new_chain_tip[", idx, "]"));
            _newCount[i]    = uint16(j.readUint(string.concat(".new_mutation_count[", idx, "]")));
        }
        // n_occupied = 16; occupied_idxs is the full [0..15] range.
        uint256[] memory occ = j.readUintArray(".occupied_idxs");
        require(occ.length == 16, "fixture must have 16 occupied slots");
        uint8[] memory occupiedIdxs = new uint8[](16);
        bytes32[] memory prevLshArr = new bytes32[](16);
        uint256[] memory featIds = new uint256[](16);
        featureIds = new uint256[](16);
        for (uint256 i = 0; i < 16; i++) {
            occupiedIdxs[i] = uint8(occ[i]);
            string memory sIdxStr = vm.toString(uint256(occupiedIdxs[i]));
            prevLshArr[i] = j.readBytes32(string.concat(".prev_lsh[", sIdxStr, "]"));
            featIds[i]   = uint256(keccak256(abi.encode(shadowId, occupiedIdxs[i], "feature")));
            featureIds[i]= featIds[i];
        }
        st.seedShadowMultiSlot(
            shadowId, alice, _stashedPrevOwnerPkX, _stashedPrevOwnerPkY,
            occupiedIdxs, featIds, prevLshArr
        );
        for (uint256 i = 0; i < 16; i++) {
            uint8 sIdx = occupiedIdxs[i];
            fn.seedFeature(
                featIds[i], shadowId, sIdx, uint8(i),
                keccak256(abi.encode("origin", shadowId, sIdx)),
                keccak256(abi.encode("palette", shadowId, sIdx)),
                prevLshArr[i],
                alice
            );
        }
    }

    function _loadPerSlotC2() internal {
        string memory j = vm.readFile(string.concat(FIX, "/meta.json"));
        _c2s = new bytes[](16);
        for (uint256 i = 0; i < 16; i++) {
            string memory sIdxStr = vm.toString(i);
            bytes memory buf = new bytes(39 * 32);
            for (uint256 k = 0; k < 39; k++) {
                bytes32 v = j.readBytes32(string.concat(".c2_per_slot.", sIdxStr, "[", vm.toString(k), "]"));
                assembly { mstore(add(add(buf, 32), mul(k, 32)), v) }
            }
            _c2s[i] = buf;
        }
    }

    function _buildArgs() internal {
        bytes32[2] memory t10;
        t10[0] = _t10Hi;
        t10[1] = _t10Lo;
        args.shadowId = shadowId;
        args.to = bob;
        args.proof = _proofTransfer;
        args.newLiveStateHashes = _newLsh;
        args.newChainTips = _newChainTip;
        args.newC1Xs = _newC1X;
        args.newC1Ys = _newC1Y;
        args.newCtCommits = _newCt;
        args.newMutationCounts = _newCount;
        args.c2s = _c2s;
        args.newT10 = t10;
        args.proofT10 = _proofT10;
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

    /// All 16 slots occupied. transferShadow rotates everything in one
    /// tx. Asserts every per-slot invariant the canonical 4-slot test
    /// asserts, but at the loop-bound ceiling.
    function test_transferShadow_max_occupancy_rotates_all_16_slots() public {
        // Pre-state: alice owns shadow + 16 carriers.
        assertEq(st.ownerOf(shadowId), alice);
        for (uint256 i = 0; i < 16; i++) {
            assertEq(uint256(st.slotOf(shadowId, uint8(i)).kind),
                     uint256(ShadowToken.SlotKind.OCCUPIED), "all 16 slots occupied pre");
            assertEq(fn.ownerOf(featureIds[i]), alice);
        }

        vm.recordLogs();
        vm.prank(alice);
        st.transferShadow(args);

        // Post-state: bob owns shadow + all 16 carriers; LSH rotated for each.
        assertEq(st.ownerOf(shadowId), bob, "shadow owner rotated");
        ShadowToken.Shadow memory s = st.shadowOf(shadowId);
        assertEq(s.ecdhPubX, _stashedRecipientPkX, "ecdhPubX rotated");
        assertEq(s.ecdhPubY, _stashedRecipientPkY, "ecdhPubY rotated");

        for (uint256 i = 0; i < 16; i++) {
            assertEq(st.slotOf(shadowId, uint8(i)).liveStateHash, _newLsh[i],
                     "slot LSH advanced");
            assertEq(fn.ownerOf(featureIds[i]), bob, "carrier owner rotated");
            assertTrue(fn.isInserted(featureIds[i]), "carrier still inserted");
            assertEq(fn.hostShadowIdOf(featureIds[i]), shadowId, "host unchanged");
        }
        assertEq(st.shadowT10(shadowId, 0), _t10Hi);
        assertEq(st.shadowT10(shadowId, 1), _t10Lo);

        // 16 ShadowSlotMutated events, one per slot.
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 sigSM = keccak256("ShadowSlotMutated(uint256,uint8,bytes32,uint256,uint16,bytes32,bytes32,bytes)");
        uint256 sawSM = 0;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter != address(st)) continue;
            if (logs[i].topics[0] == sigSM) sawSM++;
        }
        assertEq(sawSM, 16, "16 ShadowSlotMutated emitted (one per occupied slot)");
    }

    /// Gas-pin at the high-water mark. Budget 22M leaves ~3M margin
    /// over the projected ~19M baseline. If a refactor adds material
    /// per-slot cost, this fails before deployment.
    function test_transferShadow_max_occupancy_gas_under_block_budget() public {
        vm.prank(alice);
        uint256 gasBefore = gasleft();
        st.transferShadow(args);
        uint256 used = gasBefore - gasleft();
        // Real-chain block gas: 30M Ethereum / 60M Base. 22M is well under
        // either; pinning at 22M catches a per-slot regression early.
        // Envelope binding (Stage C.7): 16-occ + sponge_39 per slot adds ~10M.
        // Budget 22M leaves headroom (was 11M pre-binding). 16-occupancy
        // transferShadow now exceeds Base Sepolia 16M block budget on chain;
        // production must keep occupancy <= 10 or migrate to a fused
        // sponge_624 wrapper.
        assertLt(used, 22_000_000, "max-occupancy transferShadow gas regressed");
    }
}
