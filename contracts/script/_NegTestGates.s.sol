// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console, stdJson} from "forge-std/Script.sol";
import {ShadowToken} from "../src/ShadowToken.sol";

/// Simulate (via eth_call, no broadcast) the two negative paths against
/// the live deployed ShadowToken to capture the literal revert selectors:
///
///   (a) mintShadow with an UNREGISTERED imageCommit -> ImageNotRegistered
///   (b) mintShadow with the SAME imageCommit that's already minted ->
///       AlreadyMinted (this also proves the anti-replay armed)
///
/// Run:
///   ST_ADDRESS=0x... FIX=./test/fixtures/atomic_mint/atomic_mint_demo \
///     forge script script/_NegTestGates.s.sol:_NegTestGates \
///         --rpc-url $RPC --sender 0x1b43AFe43afC74bF9D0EBd764787eFD7CCcC2B6F
contract _NegTestGates is Script {
    using stdJson for string;

    bytes private _proofMint;
    bytes32 private _imageCommit;
    bytes32[8] private _lshInits;
    bytes32[8] private _chainTips;
    bytes32[8] private _paletteCommits;
    bytes32[8] private _originFaceIds;
    bytes32[8] private _ctCommits;
    bytes32[8] private _paletteSaltCts;
    bytes32[8] private _saltC1Xs;
    bytes32[8] private _saltC1Ys;
    bytes[] private _c2s;
    bytes32[2] private _t10;
    bytes private _proofT10;

    function _loadFixture(string memory fix) internal {
        _proofMint = vm.readFileBinary(string.concat(fix, "/proof_mint.bin"));
        _proofT10 = vm.readFileBinary(string.concat(fix, "/proof_t10.bin"));
        bytes memory rawPiMint = vm.readFileBinary(string.concat(fix, "/public_inputs_mint.bin"));
        bytes memory rawPiT10 = vm.readFileBinary(string.concat(fix, "/public_inputs_t10.bin"));
        bytes32 piMint1;
        bytes32 piT10_2;
        bytes32 piT10_3;
        assembly {
            piMint1 := mload(add(rawPiMint, add(0x20, mul(1, 32)))) // imageCommit
            piT10_2 := mload(add(rawPiT10, add(0x20, mul(2, 32)))) // t10 hi
            piT10_3 := mload(add(rawPiT10, add(0x20, mul(3, 32)))) // t10 lo
        }
        _imageCommit = piMint1;
        _t10[0] = piT10_2;
        _t10[1] = piT10_3;
        string memory j = vm.readFile(string.concat(fix, "/meta.json"));
        _c2s = new bytes[](8);
        for (uint256 i = 0; i < 8; i++) {
            string memory idx = vm.toString(i);
            _lshInits[i] = j.readBytes32(string.concat(".lsh_inits[", idx, "]"));
            _chainTips[i] = j.readBytes32(string.concat(".chain_tips[", idx, "]"));
            _paletteCommits[i] = j.readBytes32(string.concat(".palette_commits[", idx, "]"));
            _originFaceIds[i] = j.readBytes32(string.concat(".origin_face_ids[", idx, "]"));
            _ctCommits[i] = j.readBytes32(string.concat(".ct_commits[", idx, "]"));
            _paletteSaltCts[i] = j.readBytes32(string.concat(".palette_salt_cts[", idx, "]"));
            _saltC1Xs[i] = j.readBytes32(string.concat(".salt_c1_xs[", idx, "]"));
            _saltC1Ys[i] = j.readBytes32(string.concat(".salt_c1_ys[", idx, "]"));
            bytes memory buf = new bytes(39 * 32);
            for (uint256 k = 0; k < 39; k++) {
                bytes32 v = j.readBytes32(string.concat(".c2_per_slot[", idx, "][", vm.toString(k), "]"));
                assembly { mstore(add(add(buf, 32), mul(k, 32)), v) }
            }
            _c2s[i] = buf;
        }
    }

    function _buildArgs(bytes32 overrideImageCommit) internal view returns (ShadowToken.MintShadowArgs memory args) {
        args.proofMint = _proofMint;
        args.imageCommit = overrideImageCommit;
        args.liveStateHashInits = _lshInits;
        args.chainTips = _chainTips;
        args.paletteCommits = _paletteCommits;
        args.originFaceIds = _originFaceIds;
        args.ctCommits = _ctCommits;
        args.paletteSaltCts = _paletteSaltCts;
        args.saltC1Xs = _saltC1Xs;
        args.saltC1Ys = _saltC1Ys;
        args.c2s = _c2s;
        args.newT10 = _t10;
        args.proofT10 = _proofT10;
    }

    function run() external {
        address stAddr = vm.envAddress("ST_ADDRESS");
        string memory fix = vm.envString("FIX");
        _loadFixture(fix);
        ShadowToken st = ShadowToken(stAddr);

        console.log("=== NEG TEST (a): mint with UNREGISTERED imageCommit ===");
        bytes32 fakeIc = bytes32(uint256(0xdeadbeefcafebabe));
        require(!st.registeredImages(fakeIc), "fake ic accidentally registered");
        require(!st.mintedOrigins(fakeIc), "fake ic accidentally minted");
        try st.mintShadow(_buildArgs(fakeIc)) {
            revert("expected revert, got success");
        } catch (bytes memory err) {
            bytes4 sel;
            assembly { sel := mload(add(err, 0x20)) }
            console.log("revert selector (4 bytes):");
            console.logBytes4(sel);
            require(sel == ShadowToken.ImageNotRegistered.selector, "expected ImageNotRegistered selector");
            console.log("OK: ImageNotRegistered(bytes32) selector matched");
        }

        console.log("");
        console.log("=== NEG TEST (b): mint with ALREADY-MINTED imageCommit ===");
        require(st.mintedOrigins(_imageCommit), "preconditions broken");
        try st.mintShadow(_buildArgs(_imageCommit)) {
            revert("expected revert, got success");
        } catch (bytes memory err) {
            bytes4 sel;
            assembly { sel := mload(add(err, 0x20)) }
            console.log("revert selector (4 bytes):");
            console.logBytes4(sel);
            require(sel == ShadowToken.AlreadyMinted.selector, "expected AlreadyMinted selector");
            console.log("OK: AlreadyMinted(bytes32) selector matched");
        }

        console.log("");
        console.log("=== Both gates armed and reverting with correct selectors ===");
    }
}
