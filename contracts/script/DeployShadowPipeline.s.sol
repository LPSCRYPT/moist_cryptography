// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";

import {IVerifier} from "../src/IVerifier.sol";
import {KeyRegistry} from "../src/KeyRegistry.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {MintShadowVerifier} from "../src/MintShadowVerifier.sol";
import {FaceDiscVerifier} from "../src/FaceDiscVerifier.sol";

/// @notice Deploys the v2 phase-2 stack: Yul sponge + KeyRegistry +
///         ShadowToken + FeatureNFT + the verifiers that already exist
///         in v2 form.
///
///         Verifiers wired here:
///           - MintShadowVerifier  (will be regenerated for v2 PI shape)
///           - FaceDiscVerifier    (unchanged from v1; the disc circuit
///                                  is explicitly out of scope per refactor non-goal)
///
///         Verifiers NOT wired here (introduced as their circuits land):
///           - MutateSlotVerifier        (Phase 4)
///           - T10ShadowVerifier         (Phase 4)
///           - ZIndexCommitVerifier      (Phase 8)
///           - TransferShadowVerifier    (Phase 7)
///           - SolveShadowVerifier       (Phase 9)
///           - TransferFeatureVerifier   (Phase 7-ish, on FeatureNFT)
///
///         The bare contracts will revert any privileged call until the
///         corresponding verifier is set, by design.
contract DeployShadowPipeline is Script {
    function run() external {
        vm.startBroadcast();

        Poseidon2YulSponge sponge = new Poseidon2YulSponge();
        console.log("Poseidon2YulSponge:", address(sponge));

        KeyRegistry kr = new KeyRegistry();
        console.log("KeyRegistry:", address(kr));

        ShadowToken st = new ShadowToken(address(sponge));
        console.log("ShadowToken:", address(st));

        FeatureNFT fn = new FeatureNFT(address(st));
        console.log("FeatureNFT:", address(fn));

        st.setFeatureNFT(fn);

        IVerifier mintShadowV = IVerifier(address(new MintShadowVerifier()));
        console.log("MintShadowVerifier:", address(mintShadowV));
        st.setMintShadowVerifier(mintShadowV);

        IVerifier faceDiscV = IVerifier(address(new FaceDiscVerifier()));
        console.log("FaceDiscVerifier:", address(faceDiscV));
        st.setFaceDiscVerifier(faceDiscV);

        // KeyRegistry left unwired (permissive mode for dev).
        kr;

        vm.stopBroadcast();
    }
}
