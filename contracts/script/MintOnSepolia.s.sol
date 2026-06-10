// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console, stdJson} from "forge-std/Script.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {KeyRegistry} from "../src/KeyRegistry.sol";
import {ShadowMintController} from "../src/ShadowMintController.sol";

/// @notice Real on-chain registerImage + mint against deployed contracts.
///
/// Reads a v2 atomic_mint fixture, registers the fixture's owner_pk
/// against `msg.sender` in KeyRegistry, registers the fixture's
/// imageCommit (via face_disc proof), then executes modular phased mint through
/// ShadowMintController in gas-sized ordered batches.
///
/// The recipient is fixed at beginMintShadow and finalize installs the
/// fully loaded 8-carrier Shadow NFT at that address.
///
/// All three steps (key register, image register, mint) are idempotent
/// at the script level: each is skipped if its on-chain state already
/// reflects success. Re-running this script after a partial failure
/// must not revert at any pre-checked step.
///
/// Usage:
///   ST_ADDRESS=0x...  KR_ADDRESS=0x... MC_ADDRESS=0x... FIX=./test/fixtures/atomic_mint/atomic_mint_demo \
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
    bytes32[8] private _c1Xs;
    bytes32[8] private _c1Ys;
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
        address mcAddr = vm.envAddress("MC_ADDRESS");
        string memory fix = vm.envString("FIX");
        uint256 beginSubmitCount = vm.envOr("BEGIN_SUBMIT_COUNT", uint256(0));
        uint256 submitChunkSize = vm.envOr("SUBMIT_CHUNK_SIZE", uint256(1));
        require(beginSubmitCount <= 8, "BEGIN_SUBMIT_COUNT > 8");
        require(submitChunkSize > 0 && submitChunkSize <= 8, "bad SUBMIT_CHUNK_SIZE");

        _loadFixture(fix);

        console.log("=== Sepolia register + mint ===");
        console.log("expected shadowId:");
        console.logBytes32(bytes32(_expectedShadowId));
        console.log("imageCommit:");
        console.logBytes32(_imageCommit);

        ShadowToken st = ShadowToken(stAddr);
        KeyRegistry kr = KeyRegistry(krAddr);
        ShadowMintController mc = ShadowMintController(mcAddr);

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

        // Step 2: modular phased mint. The first batch can register, begin,
        // and submit a configurable prefix of ciphertexts; follow-up batches
        // submit bounded chunks and finalize only once the last missing slot is
        // included. This keeps both EVM gas and Base calldata fees controllable.
        uint256 shadowId = _expectedShadowId;
        if (!st.mintedOrigins(_imageCommit)) {
            bool pending = mc.pendingOrigins(_imageCommit);
            if (!pending) {
                ShadowMintController.MintBatch memory first;
                if (!st.registeredImages(_imageCommit)) {
                    first.doRegisterImage = true;
                    first.imageCommit = _imageCommit;
                    first.proofDisc = _proofDisc;
                }
                first.doBeginMint = true;
                first.mintArgs = _buildArgs();
                first.recipient = msg.sender;
                (first.submitSlots, first.submitC2s) = _missingSlotBatch(0, 8, 0, beginSubmitCount);
                (shadowId,) = mc.executeMintBatch(first);
                console.log(beginSubmitCount == 0
                    ? "ShadowMintController.executeMintBatch: register/begin tx broadcast"
                    : "ShadowMintController.executeMintBatch: register/begin/prefix tx broadcast");
            } else {
                console.log("ShadowMintController.beginMintShadow: skipped (pending mint exists)");
            }

            while (true) {
                uint8 bitmap = mc.pendingMintSubmittedBitmap(shadowId);
                if (bitmap == 0xff) {
                    ShadowMintController.MintBatch memory finalOnly;
                    finalOnly.shadowId = shadowId;
                    finalOnly.doFinalize = true;
                    finalOnly.proofT10 = _proofT10;
                    (, shadowId) = mc.executeMintBatch(finalOnly);
                    console.log("ShadowMintController.executeMintBatch: finalize tx broadcast");
                    break;
                }

                ShadowMintController.MintBatch memory next;
                next.shadowId = shadowId;
                (next.submitSlots, next.submitC2s) = _missingSlotBatch(0, 8, bitmap, submitChunkSize);
                uint8 nextBitmap = _bitmapAfter(bitmap, next.submitSlots);
                next.doFinalize = nextBitmap == 0xff;
                if (next.doFinalize) next.proofT10 = _proofT10;
                (, uint256 mintedShadowId) = mc.executeMintBatch(next);
                console.log("ShadowMintController.executeMintBatch: submit chunk tx broadcast");
                if (next.doFinalize) {
                    shadowId = mintedShadowId;
                    break;
                }
            }
        } else {
            shadowId = _expectedShadowId;
            console.log("ShadowToken phased mint: skipped (already minted)");
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
        bytes32[] memory piMint = _loadFields(string.concat(fix, "/public_inputs_mint.bin"), 9);
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
            _c1Xs[i] = j.readBytes32(string.concat(".c1_xs[", idx, "]"));
            _c1Ys[i] = j.readBytes32(string.concat(".c1_ys[", idx, "]"));
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

    function _missingSlotBatch(uint8 start, uint8 count, uint8 bitmap, uint256 maxOut)
        internal
        view
        returns (uint8[] memory slots, bytes[] memory c2s)
    {
        uint256 n = 0;
        for (uint8 i = 0; i < count && n < maxOut; i++) {
            uint8 slot = start + i;
            if ((bitmap & (uint8(1) << slot)) == 0) n++;
        }
        slots = new uint8[](n);
        c2s = new bytes[](n);
        uint256 out = 0;
        for (uint8 i = 0; i < count && out < n; i++) {
            uint8 slot = start + i;
            if ((bitmap & (uint8(1) << slot)) != 0) continue;
            slots[out] = slot;
            c2s[out] = _c2s[slot];
            out++;
        }
    }

    function _bitmapAfter(uint8 bitmap, uint8[] memory slots) internal pure returns (uint8 out) {
        out = bitmap;
        for (uint256 i = 0; i < slots.length; i++) out |= uint8(1) << slots[i];
    }


    function _buildArgs() internal view returns (ShadowToken.MintShadowArgs memory args) {
        args.proofMint = _proofMint;
        args.imageCommit = _imageCommit;
        args.liveStateHashInits = _lshInits;
        args.chainTips = _chainTips;
        args.c1Xs = _c1Xs;
        args.c1Ys = _c1Ys;
        args.paletteCommits = _paletteCommits;
        args.originFaceIds = _originFaceIds;
        args.ctCommits = _ctCommits;
        args.paletteSaltCts = _paletteSaltCts;
        args.saltC1Xs = _saltC1Xs;
        args.saltC1Ys = _saltC1Ys;
        args.newT10 = _t10;
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
