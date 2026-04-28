// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console, stdJson} from "forge-std/Script.sol";
import {ShadowToken} from "../src/ShadowToken.sol";

/// Broadcast `solve()` against the live ShadowToken using a fixture
/// from `tools/build_solve_onchain.py`. Solve is one-way: after this
/// the shadow is frozen and every remaining occupied carrier is
/// auto-extracted to the deployer's wallet.
contract SolveOnSepolia is Script {
    using stdJson for string;

    uint256 internal constant SOLVE_PI_LEN = 7;
    uint256 internal constant N_SLOTS = 16;
    uint256 internal constant FIELDS_PER_SLOT = 39;

    function run() external {
        address stAddr = vm.envAddress("ST_ADDRESS");
        string memory fix = vm.envString("FIX");

        ShadowToken st = ShadowToken(stAddr);

        bytes memory proofSolve = vm.readFileBinary(
            string.concat(fix, "/proof.bin"));
        bytes memory rawPi = vm.readFileBinary(
            string.concat(fix, "/public_inputs.bin"));
        require(rawPi.length == SOLVE_PI_LEN * 32, "bad solve PI length");

        // PI[0] = shadowId, PI[2] = zPermPacked
        uint256 shadowId = uint256(_word(rawPi, 0));
        bytes32 zPermPacked = _word(rawPi, 2);

        // Idempotency: if already solved, skip.
        ShadowToken.Shadow memory s = st.shadowOf(shadowId);
        if (s.solved) {
            console.log("SKIP: shadow already solved");
            return;
        }

        ShadowToken.SolveArgs memory args = _buildArgs(
            fix, shadowId, proofSolve, zPermPacked, st);

        console.log("=== solve() broadcast ===");
        console.log("ST       :", stAddr);
        console.log("shadowId :");
        console.logBytes32(bytes32(shadowId));
        console.log("zPermPacked:");
        console.logBytes32(zPermPacked);
        console.log("proof    :", args.proof.length, "B");

        vm.startBroadcast();
        st.solve(args);
        vm.stopBroadcast();

        console.log("done");
    }

    function _buildArgs(
        string memory fix,
        uint256 shadowId,
        bytes memory proofSolve,
        bytes32 zPermPacked,
        ShadowToken st
    ) internal view returns (ShadowToken.SolveArgs memory args) {
        args.shadowId = shadowId;
        args.proof = proofSolve;
        args.zPermPacked = zPermPacked;

        // Read per-slot palette + salt + stateCommit from meta.json. EMPTY
        // slots get zeros. stateCommits are caller-supplied (proof binds
        // them via PI[1] = sponge_16(stateCommits)). Palettes + salts are
        // chain-bound via sponge_palette_salt against the carrier's stored
        // paletteCommit.
        string memory meta = vm.readFile(string.concat(fix, "/meta.json"));
        for (uint256 i = 0; i < N_SLOTS; i++) {
            ShadowToken.ManifestEntry memory mEntry =
                st.slotOf(shadowId, uint8(i));
            if (mEntry.kind == ShadowToken.SlotKind.OCCUPIED) {
                args.stateCommits[i] = meta.readBytes32(
                    string.concat(".state_commits[", vm.toString(i), "]"));
                for (uint256 c = 0; c < 16; c++) {
                    args.palettes[i][c] = meta.readBytes32(string.concat(
                        ".palettes[", vm.toString(i), "][", vm.toString(c), "]"));
                }
                args.paletteSalts[i] = meta.readBytes32(
                    string.concat(".palette_salts[", vm.toString(i), "]"));
            }
            // EMPTY slots: stateCommits[i], palettes[i], paletteSalts[i] all zero.
        }

        // z_perm: meta.json's perm is a JSON int array; readUint expects "0x..." or decimal.
        // The fixture writes it as integers, so use stdJson's plain readUint.
        for (uint256 i = 0; i < N_SLOTS; i++) {
            args.zPerm[i] = uint8(meta.readUint(
                string.concat(".z_perm[", vm.toString(i), "]")));
        }

        // plaintexts: from plaintexts.json -- 39 bytes32 per slot, packed BE.
        // For empty (or extracted) slots, contract requires zero-length bytes.
        string memory pjson = vm.readFile(string.concat(fix, "/plaintexts.json"));
        for (uint256 i = 0; i < N_SLOTS; i++) {
            // Determine occupancy from on-chain manifest (post-extract).
            ShadowToken.ManifestEntry memory m = st.slotOf(shadowId, uint8(i));
            if (m.kind == ShadowToken.SlotKind.OCCUPIED) {
                bytes memory buf = new bytes(FIELDS_PER_SLOT * 32);
                for (uint256 k = 0; k < FIELDS_PER_SLOT; k++) {
                    bytes32 v = pjson.readBytes32(string.concat(
                        ".plaintexts[", vm.toString(i), "][", vm.toString(k), "]"));
                    assembly { mstore(add(add(buf, 32), mul(k, 32)), v) }
                }
                args.plaintexts[i] = buf;
            } else {
                args.plaintexts[i] = new bytes(0);
            }
        }
    }

    function _word(bytes memory raw, uint256 idx) internal pure returns (bytes32 word) {
        assembly { word := mload(add(raw, add(0x20, mul(idx, 32)))) }
    }
}
