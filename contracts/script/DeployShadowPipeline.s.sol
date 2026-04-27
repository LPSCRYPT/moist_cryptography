// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {Poseidon2YulSponge}   from "../src/Poseidon2YulSponge.sol";
import {Poseidon2YulSponge16} from "../src/Poseidon2YulSponge16.sol";

import {IVerifier}    from "../src/IVerifier.sol";
import {KeyRegistry}  from "../src/KeyRegistry.sol";
import {ShadowToken}  from "../src/ShadowToken.sol";
import {FeatureNFT}   from "../src/FeatureNFT.sol";

import {MintShadowVerifier}     from "../src/MintShadowVerifier.sol";
import {FaceDiscVerifier}       from "../src/FaceDiscVerifier.sol";
import {MutateSlotVerifier}     from "../src/MutateSlotVerifier.sol";
import {T10ShadowVerifier}      from "../src/T10ShadowVerifier.sol";
import {ZIndexCommitVerifier}   from "../src/ZIndexCommitVerifier.sol";
import {TransferShadowVerifier} from "../src/TransferShadowVerifier.sol";
import {SolveShadowVerifier}    from "../src/SolveShadowVerifier.sol";

/// @notice Deploys the v2 shadow pipeline end-to-end:
///         - 2 Yul sponge contracts (sponge_39 and sponge_16)
///         - KeyRegistry
///         - ShadowToken + FeatureNFT (cross-wired)
///         - 7 Honk verifiers, each one-shot wired into ShadowToken
///
///         Every privileged surface on ShadowToken is reachable after
///         this script returns. The one-shot setters lock immediately
///         post-wire; rotation thereafter goes through the
///         `_writeVerifierSlot` admin path.
///
///         Verifier sizes (v2 measured via `forge build --sizes`):
///           |Verifier|Bytes|Headroom|
///           |---|---|---|
///           |MintShadowVerifier      |24,340|236|
///           |FaceDiscVerifier        |24,341|235|
///           |MutateSlotVerifier      |24,340|236|
///           |T10ShadowVerifier       |24,338|238|
///           |ZIndexCommitVerifier    |24,340|236|
///           |TransferShadowVerifier  |24,339|237|
///           |SolveShadowVerifier     |24,340|236|
///
///         All under EIP-170's 24,576-byte runtime cap.
///
///         Usage:
///           forge script script/DeployShadowPipeline.s.sol \
///             --broadcast \
///             --rpc-url $BASE_SEPOLIA_RPC \
///             --private-key $PRIVATE_KEY
contract DeployShadowPipeline is Script {
    function run() external {
        vm.startBroadcast();

        // ---- 1. Yul sponges ----
        Poseidon2YulSponge   sponge   = new Poseidon2YulSponge();
        Poseidon2YulSponge16 sponge16 = new Poseidon2YulSponge16();
        console.log("Poseidon2YulSponge   :", address(sponge));
        console.log("Poseidon2YulSponge16 :", address(sponge16));

        // ---- 2. KeyRegistry ----
        KeyRegistry kr = new KeyRegistry();
        console.log("KeyRegistry          :", address(kr));

        // ---- 3. ShadowToken + FeatureNFT (cross-wired) ----
        ShadowToken st = new ShadowToken(address(sponge));
        console.log("ShadowToken          :", address(st));

        FeatureNFT fn = new FeatureNFT(address(st));
        console.log("FeatureNFT           :", address(fn));

        st.setFeatureNFT(fn);
        st.setYulSponge16(address(sponge16));
        st.setKeyRegistry(kr);

        // ---- 4. Verifiers (deploy + one-shot wire) ----
        IVerifier mintV = IVerifier(address(new MintShadowVerifier()));
        console.log("MintShadowVerifier   :", address(mintV));
        st.setMintShadowVerifier(mintV);

        IVerifier discV = IVerifier(address(new FaceDiscVerifier()));
        console.log("FaceDiscVerifier     :", address(discV));
        st.setFaceDiscVerifier(discV);

        IVerifier mutateV = IVerifier(address(new MutateSlotVerifier()));
        console.log("MutateSlotVerifier   :", address(mutateV));
        st.setMutateSlotVerifier(mutateV);

        IVerifier t10V = IVerifier(address(new T10ShadowVerifier()));
        console.log("T10ShadowVerifier    :", address(t10V));
        st.setT10ShadowVerifier(t10V);

        IVerifier zV = IVerifier(address(new ZIndexCommitVerifier()));
        console.log("ZIndexCommitVerifier :", address(zV));
        st.setZIndexCommitVerifier(zV);

        IVerifier transferV = IVerifier(address(new TransferShadowVerifier()));
        console.log("TransferShadowVerifier:", address(transferV));
        st.setTransferShadowVerifier(transferV);

        IVerifier solveV = IVerifier(address(new SolveShadowVerifier()));
        console.log("SolveShadowVerifier  :", address(solveV));
        st.setSolveShadowVerifier(solveV);

        vm.stopBroadcast();
    }
}
