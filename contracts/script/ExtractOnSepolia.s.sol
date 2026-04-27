// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {ShadowToken} from "../src/ShadowToken.sol";

/// Broadcast a single `extractSlot` against the live ShadowToken using
/// a fixture from `tools/build_extract_onchain.py`.
///
/// extractSlot is structurally proofless at the per-slot level (no
/// per-slot ZK; carrier custody is enforced via ownership + single-host
/// invariants). The contract requires only a fresh T10 proof bound to
/// the post-extract manifest.
contract ExtractOnSepolia is Script {
    uint256 internal constant T10_PI_LEN = 20;

    function run() external {
        address stAddr = vm.envAddress("ST_ADDRESS");
        string memory fix = vm.envString("FIX");
        uint256 shadowId = vm.envUint("SHADOW_ID");
        uint8 slotIdx = uint8(vm.envUint("SLOT_IDX"));

        bytes memory proofT10 = vm.readFileBinary(
            string.concat(fix, "/proof_t10.bin"));
        bytes memory rawPiT10 = vm.readFileBinary(
            string.concat(fix, "/public_inputs_t10.bin"));
        require(rawPiT10.length == T10_PI_LEN * 32, "bad T10 PI length");

        bytes32 t10Hi = _word(rawPiT10, 2);
        bytes32 t10Lo = _word(rawPiT10, 3);

        ShadowToken st = ShadowToken(stAddr);

        // Idempotency guard: if slot already EMPTY, nothing to do.
        ShadowToken.ManifestEntry memory m = st.slotOf(shadowId, slotIdx);
        if (m.kind == ShadowToken.SlotKind.EMPTY) {
            console.log("SKIP: slot already EMPTY");
            return;
        }

        console.log("=== extractSlot broadcast ===");
        console.log("ST       :", stAddr);
        console.log("shadowId :");
        console.logBytes32(bytes32(shadowId));
        console.log("slotIdx  :", uint256(slotIdx));
        console.log("featureId being released:");
        console.logBytes32(bytes32(m.featureId));
        console.log("proofT10 :", proofT10.length, "B");

        vm.startBroadcast();
        uint256 fid = st.extractSlot(shadowId, slotIdx, [t10Hi, t10Lo], proofT10);
        vm.stopBroadcast();

        console.log("released featureId:", fid);
    }

    function _word(bytes memory raw, uint256 idx) internal pure returns (bytes32 word) {
        assembly { word := mload(add(raw, add(0x20, mul(idx, 32)))) }
    }
}
