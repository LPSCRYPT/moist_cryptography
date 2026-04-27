// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {ShadowToken} from "../src/ShadowToken.sol";

/// Broadcast a single `setZIndexCommit` against the live ShadowToken,
/// using a fixture from `tools/build_zindex_onchain.py`.
///
/// Idempotency: zindex_commit circuit binds only (shadow_id, new_commit);
/// it does NOT bind chain state, so the proof is replay-safe at the
/// circuit level. The T10 proof, however, binds the LSH array, so a
/// stale fixture against a moved chain state will revert via T10
/// InvalidProof. The script checks this and skips cleanly if the
/// stored zIndexCommit already equals the fixture's value.
contract SetZIndexOnSepolia is Script {
    struct Loaded {
        bytes proofZ;
        bytes proofT10;
        bytes piZ;
        bytes piT10;
    }

    uint256 internal constant Z_PI_LEN = 2;
    uint256 internal constant T10_PI_LEN = 20;

    function run() external {
        address stAddr = vm.envAddress("ST_ADDRESS");
        Loaded memory L = _loadFixture(vm.envString("FIX"));

        ShadowToken.SetZIndexCommitArgs memory args =
            ShadowToken.SetZIndexCommitArgs({
                shadowId: uint256(_word(L.piZ, 0)),
                newCommit: _word(L.piZ, 1),
                proofZ: L.proofZ,
                newT10: [_word(L.piT10, 2), _word(L.piT10, 3)],
                proofT10: L.proofT10
            });

        ShadowToken st = ShadowToken(stAddr);
        ShadowToken.Shadow memory s = st.shadowOf(args.shadowId);
        if (s.zIndexCommit == args.newCommit) {
            console.log("SKIP: zIndexCommit already equals fixture's newCommit");
            console.logBytes32(s.zIndexCommit);
            return;
        }

        console.log("=== setZIndexCommit broadcast ===");
        console.log("ST       :", stAddr);
        console.log("shadowId :");
        console.logBytes32(bytes32(args.shadowId));
        console.log("newCommit:");
        console.logBytes32(args.newCommit);
        console.log("proofZ   :", args.proofZ.length, "B");
        console.log("proofT10 :", args.proofT10.length, "B");

        vm.startBroadcast();
        st.setZIndexCommit(args);
        vm.stopBroadcast();

        console.log("done");
    }

    function _loadFixture(string memory fix) internal returns (Loaded memory L) {
        L.proofZ   = vm.readFileBinary(string.concat(fix, "/proof_z.bin"));
        L.piZ      = vm.readFileBinary(string.concat(fix, "/public_inputs_z.bin"));
        require(L.piZ.length == Z_PI_LEN * 32, "bad Z PI length");
        L.proofT10 = vm.readFileBinary(string.concat(fix, "/proof_t10.bin"));
        L.piT10    = vm.readFileBinary(string.concat(fix, "/public_inputs_t10.bin"));
        require(L.piT10.length == T10_PI_LEN * 32, "bad T10 PI length");
    }

    function _word(bytes memory raw, uint256 idx) internal pure returns (bytes32 word) {
        assembly { word := mload(add(raw, add(0x20, mul(idx, 32)))) }
    }
}
