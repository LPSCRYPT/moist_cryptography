// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console, stdJson} from "forge-std/Script.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {KeyRegistry} from "../src/KeyRegistry.sol";

/// @notice Real on-chain registerImage + mint against deployed contracts.
///
/// Reads a v2 atomic_mint fixture, registers the fixture's owner_pk
/// against `msg.sender` in KeyRegistry, registers the fixture's
/// imageCommit (via face_disc proof), then calls `mintShadow`.
/// Produces 1 shadow + 8 carriers in slots 0..7 in the mint tx.
///
/// v2-gas split: face_disc verification moved out of `mintShadow` into
/// a separate `registerImage` tx, so the bundled mint stays under the
/// 16M public-RPC gas-LIMIT ceiling.
///
/// All three steps (key register, image register, mint) are idempotent
/// at the script level: each is skipped if its on-chain state already
/// reflects success. Re-running this script after a partial failure
/// must not revert at any pre-checked step.
///
/// Usage:
///   ST_ADDRESS=0x...  KR_ADDRESS=0x...  FIX=./test/fixtures/atomic_mint/atomic_mint_demo \
///   forge script script/MintOnSepolia.s.sol:MintOnSepolia \
///       --broadcast --rpc-url $BASE_SEPOLIA_RPC --private-key $PRIVATE_KEY
contract MintOnSepolia is Script {
    using stdJson for string;

    // Storage-resident fields to keep the run() stack shallow.
    bytes private _proofMint;
    bytes private _proofDisc;
    bytes private _proofT10;
    bytes32 private _imageCommit;
    bytes32 private _ownerPkX;
    bytes32 private _ownerPkY;
    uint256 private _expectedShadowId;
    bytes32[2] private _t10;
    bytes32[8] private _lshInits;
    bytes32[8] private _chainTips;
    bytes32[8] private _paletteCommits;
    bytes32[8] private _originFaceIds;
    bytes32[8] private _ctCommits;
    bytes32[8] private _paletteSaltCts;
    bytes32[8] private _saltC1Xs;
    bytes32[8] private _saltC1Ys;
    bytes[] private _c2s;

    function run() external {
        address stAddr = vm.envAddress("ST_ADDRESS");
        address krAddr = vm.envAddress("KR_ADDRESS");
        string memory fix = vm.envString("FIX");

        _loadFixture(fix);

        console.log("=== Sepolia register + mint ===");
        console.log("expected shadowId:");
        console.logBytes32(bytes32(_expectedShadowId));
        console.log("imageCommit:");
        console.logBytes32(_imageCommit);

        ShadowToken st = ShadowToken(stAddr);
        KeyRegistry kr = KeyRegistry(krAddr);

        vm.startBroadcast();
        // Step 1: idempotent key registration.
        if (!kr.isRegistered(msg.sender)) {
            kr.register(_ownerPkX, _ownerPkY);
            console.log("KeyRegistry.register: tx broadcast");
        } else {
            (bytes32 hadX, bytes32 hadY) = kr.pkOf(msg.sender);
            require(hadX == _ownerPkX && hadY == _ownerPkY, "deployer already registered with a different pk");
            console.log("KeyRegistry.register: skipped (already registered)");
        }

        // Step 2: idempotent image registration. The face_disc verifier
        // proves imageCommit derives from a real face image. Anyone can
        // call this (proof itself is the credential); we check on-chain
        // before broadcasting to avoid wasting gas on a known-failure tx.
        if (!st.registeredImages(_imageCommit)) {
            st.registerImage(_imageCommit, _proofDisc);
            console.log("ShadowToken.registerImage: tx broadcast");
        } else {
            console.log("ShadowToken.registerImage: skipped (already registered)");
        }

        // Step 3: idempotent mint. mintedOrigins[imageCommit] enforces
        // anti-replay; if a previous run succeeded, skip.
        uint256 shadowId;
        if (!st.mintedOrigins(_imageCommit)) {
            shadowId = st.mintShadow(_buildArgs());
            console.log("ShadowToken.mintShadow: tx broadcast");
        } else {
            shadowId = _expectedShadowId;
            console.log("ShadowToken.mintShadow: skipped (already minted)");
        }
        vm.stopBroadcast();

        require(shadowId == _expectedShadowId, "shadowId mismatch");

        console.log("=== Mint state confirmed ===");
        console.log("shadowId:");
        console.logBytes32(bytes32(shadowId));
        console.log("owner of shadow:");
        console.log(st.ownerOf(shadowId));
    }

    function _loadFixture(string memory fix) internal {
        _proofMint = vm.readFileBinary(string.concat(fix, "/proof_mint.bin"));
        bytes32[] memory piMint = _loadFields(string.concat(fix, "/public_inputs_mint.bin"), 7);
        _proofDisc = vm.readFileBinary(string.concat(fix, "/proof_disc.bin"));
        bytes32[] memory piDisc = _loadFields(string.concat(fix, "/public_inputs_disc.bin"), 1);
        _proofT10 = vm.readFileBinary(string.concat(fix, "/proof_t10.bin"));
        bytes32[] memory piT10 = _loadFields(string.concat(fix, "/public_inputs_t10.bin"), 20);

        require(piDisc[0] == piMint[1], "imageCommit mismatch fixture");

        _expectedShadowId = uint256(piMint[0]);
        _imageCommit = piMint[1];
        _ownerPkX = piMint[2];
        _ownerPkY = piMint[3];
        _t10[0] = piT10[2];
        _t10[1] = piT10[3];

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

    function _buildArgs() internal view returns (ShadowToken.MintShadowArgs memory args) {
        args.proofMint = _proofMint;
        args.imageCommit = _imageCommit;
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
}
