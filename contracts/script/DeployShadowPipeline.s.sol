// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";

import {IVerifier} from "../src/IVerifier.sol";
import {KeyRegistry} from "../src/KeyRegistry.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {MintShadowVerifier} from "../src/MintShadowVerifier.sol";
import {TransferShadowVerifier} from "../src/TransferShadowVerifier.sol";
import {ExtractSlotVerifier} from "../src/ExtractSlotVerifier.sol";
import {TransferFeatureVerifier} from "../src/TransferFeatureVerifier.sol";
import {SolveShadowVerifier} from "../src/SolveShadowVerifier.sol";
import {T10ShadowVerifier} from "../src/T10ShadowVerifier.sol";
import {FaceDiscVerifier} from "../src/FaceDiscVerifier.sol";

/// @notice Deploys the full phase-2 stack: Yul sponge + KeyRegistry +
///         ShadowToken + FeatureNFT + 6 verifiers. Wires all back-references.
contract DeployShadowPipeline is Script {
    function run() external {
        vm.startBroadcast();

        Poseidon2YulSponge sponge = new Poseidon2YulSponge();
        console.log("Poseidon2YulSponge:", address(sponge));

        KeyRegistry kr = new KeyRegistry();
        console.log("KeyRegistry:", address(kr));

        ShadowToken st = new ShadowToken(address(sponge));
        console.log("ShadowToken:", address(st));

        FeatureNFT fn = new FeatureNFT(address(st), address(sponge));
        console.log("FeatureNFT:", address(fn));

        st.setFeatureNFT(fn);

        IVerifier mintShadowV = IVerifier(address(new MintShadowVerifier()));
        console.log("MintShadowVerifier:", address(mintShadowV));
        st.setMintShadowVerifier(mintShadowV);

        IVerifier transferShadowV = IVerifier(address(new TransferShadowVerifier()));
        console.log("TransferShadowVerifier:", address(transferShadowV));
        st.setTransferShadowVerifier(transferShadowV);

        IVerifier extractSlotV = IVerifier(address(new ExtractSlotVerifier()));
        console.log("ExtractSlotVerifier:", address(extractSlotV));
        st.setExtractSlotVerifier(extractSlotV);

        IVerifier transferFeatureV = IVerifier(address(new TransferFeatureVerifier()));
        console.log("TransferFeatureVerifier:", address(transferFeatureV));
        fn.setTransferFeatureVerifier(transferFeatureV);

        IVerifier solveShadowV = IVerifier(address(new SolveShadowVerifier()));
        console.log("SolveShadowVerifier:", address(solveShadowV));
        st.setSolveShadowVerifier(solveShadowV);

        IVerifier t10ShadowV = IVerifier(address(new T10ShadowVerifier()));
        console.log("T10ShadowVerifier:", address(t10ShadowV));
        st.setT10ShadowVerifier(t10ShadowV);

        IVerifier faceDiscV = IVerifier(address(new FaceDiscVerifier()));
        console.log("FaceDiscVerifier:", address(faceDiscV));
        st.setFaceDiscVerifier(faceDiscV);

        // KeyRegistry left unwired (permissive mode for dev). For production:
        //   st.setKeyRegistry(kr);
        //   fn.setKeyRegistry(kr);
        kr;  // suppress unused warning

        vm.stopBroadcast();
    }
}
