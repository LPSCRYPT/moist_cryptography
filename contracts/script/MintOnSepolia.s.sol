// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console, stdJson} from "forge-std/Script.sol";
import {ShadowToken}   from "../src/ShadowToken.sol";
import {KeyRegistry}   from "../src/KeyRegistry.sol";

/// @notice Real on-chain mint against deployed contracts.
///
/// Reads a v2 atomic_mint fixture, registers the fixture's owner_pk
/// against `msg.sender` in KeyRegistry, then calls `mintShadow`.
/// Produces 1 shadow + 8 carriers in slots 0..7 in a single tx.
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
    bytes[]   private _c2s;

    function run() external {
        address stAddr = vm.envAddress("ST_ADDRESS");
        address krAddr = vm.envAddress("KR_ADDRESS");
        string memory fix = vm.envString("FIX");

        _loadFixture(fix);

        console.log("=== Sepolia mint ===");
        console.log("expected shadowId:");
        console.logBytes32(bytes32(_expectedShadowId));
        console.log("imageCommit:");
        console.logBytes32(_imageCommit);

        ShadowToken st = ShadowToken(stAddr);
        KeyRegistry kr = KeyRegistry(krAddr);

        vm.startBroadcast();
        // Idempotent: register only if msg.sender has no pk yet.
        // (Re-running this script after a partial failure must not revert here.)
        if (!kr.isRegistered(msg.sender)) {
            kr.register(_ownerPkX, _ownerPkY);
        } else {
            (bytes32 hadX, bytes32 hadY) = kr.pkOf(msg.sender);
            require(hadX == _ownerPkX && hadY == _ownerPkY,
                "deployer already registered with a different pk");
        }
        uint256 shadowId = st.mintShadow(_buildArgs());
        vm.stopBroadcast();

        require(shadowId == _expectedShadowId, "shadowId mismatch");

        console.log("=== Mint succeeded ===");
        console.log("returned shadowId:");
        console.logBytes32(bytes32(shadowId));
        console.log("owner of shadow:");
        console.log(st.ownerOf(shadowId));
    }

    function _loadFixture(string memory fix) internal {
        _proofMint = vm.readFileBinary(string.concat(fix, "/proof_mint.bin"));
        bytes32[] memory piMint = _loadFields(string.concat(fix, "/public_inputs_mint.bin"), 7);
        _proofDisc = vm.readFileBinary(string.concat(fix, "/proof_disc.bin"));
        bytes32[] memory piDisc = _loadFields(string.concat(fix, "/public_inputs_disc.bin"), 1);
        _proofT10  = vm.readFileBinary(string.concat(fix, "/proof_t10.bin"));
        bytes32[] memory piT10 = _loadFields(string.concat(fix, "/public_inputs_t10.bin"), 20);

        require(piDisc[0] == piMint[1], "imageCommit mismatch fixture");

        _expectedShadowId = uint256(piMint[0]);
        _imageCommit      = piMint[1];
        _ownerPkX         = piMint[2];
        _ownerPkY         = piMint[3];
        _t10[0]           = piT10[2];
        _t10[1]           = piT10[3];

        string memory j = vm.readFile(string.concat(fix, "/meta.json"));
        _c2s = new bytes[](8);
        for (uint256 i = 0; i < 8; i++) {
            string memory idx = vm.toString(i);
            _lshInits[i]       = j.readBytes32(string.concat(".lsh_inits[", idx, "]"));
            _chainTips[i]      = j.readBytes32(string.concat(".chain_tips[", idx, "]"));
            _paletteCommits[i] = j.readBytes32(string.concat(".palette_commits[", idx, "]"));
            _originFaceIds[i]  = j.readBytes32(string.concat(".origin_face_ids[", idx, "]"));
            _ctCommits[i]      = j.readBytes32(string.concat(".ct_commits[", idx, "]"));

            bytes memory buf = new bytes(39 * 32);
            for (uint256 k = 0; k < 39; k++) {
                bytes32 v = j.readBytes32(string.concat(
                    ".c2_per_slot[", idx, "][", vm.toString(k), "]"));
                assembly { mstore(add(add(buf, 32), mul(k, 32)), v) }
            }
            _c2s[i] = buf;
        }
    }

    function _buildArgs() internal view returns (ShadowToken.MintShadowArgs memory args) {
        args.proofMint   = _proofMint;
        args.proofDisc   = _proofDisc;
        args.imageCommit = _imageCommit;
        args.liveStateHashInits = _lshInits;
        args.chainTips          = _chainTips;
        args.paletteCommits     = _paletteCommits;
        args.originFaceIds      = _originFaceIds;
        args.ctCommits          = _ctCommits;
        args.c2s                = _c2s;
        args.newT10   = _t10;
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
