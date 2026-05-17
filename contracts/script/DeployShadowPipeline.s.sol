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
import {TransferFeatureV2Verifier} from "../src/TransferFeatureV2Verifier.sol";
import {Poseidon2YulSpongePaletteSalt} from "../src/Poseidon2YulSpongePaletteSalt.sol";

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
        // Wire FN's KR too. Pre-audit deploy script omitted this; FeatureNFT
        // has its own KR pointer separate from ShadowToken's, so without this
        // line `FeatureNFT.transferFeature` would silently skip recipient-pk
        // enforcement (M-01 in /audit/). Both calls are one-shot.
        fn.setKeyRegistry(kr);

        // ---- 4. Verifiers (deploy + one-shot wire) ----
        IVerifier mintV = IVerifier(address(new MintShadowVerifier()));
        console.log("MintShadowVerifier   :", address(mintV));
        st.setVerifier(st.SLOT_MINT_SHADOW(), mintV);

        IVerifier discV = IVerifier(address(new FaceDiscVerifier()));
        console.log("FaceDiscVerifier     :", address(discV));
        st.setVerifier(st.SLOT_FACE_DISC(), discV);

        IVerifier mutateV = IVerifier(address(new MutateSlotVerifier()));
        console.log("MutateSlotVerifier   :", address(mutateV));
        st.setVerifier(st.SLOT_MUTATE_SLOT(), mutateV);

        IVerifier t10V = IVerifier(address(new T10ShadowVerifier()));
        console.log("T10ShadowVerifier    :", address(t10V));
        st.setVerifier(st.SLOT_T10_SHADOW(), t10V);

        IVerifier zV = IVerifier(address(new ZIndexCommitVerifier()));
        console.log("ZIndexCommitVerifier :", address(zV));
        st.setVerifier(st.SLOT_ZINDEX_COMMIT(), zV);

        IVerifier transferV = IVerifier(address(new TransferShadowVerifier()));
        console.log("TransferShadowVerifier:", address(transferV));
        st.setVerifier(st.SLOT_TRANSFER_SHADOW(), transferV);

        IVerifier solveV = IVerifier(address(new SolveShadowVerifier()));
        console.log("SolveShadowVerifier  :", address(solveV));
        st.setVerifier(st.SLOT_SOLVE_SHADOW(), solveV);

        // ---- 5. FeatureNFT-side verifiers ----
        IVerifier transferFeatureV = IVerifier(address(new TransferFeatureV2Verifier()));
        console.log("TransferFeatureV2Verifier:", address(transferFeatureV));
        fn.setTransferFeatureVerifier(transferFeatureV);

        // FeatureNFT-side palette commitment opening at solve time uses an
        // on-chain Yul Poseidon2 sponge-17 (palette[16] + salt). No ZK
        // verifier needed; soundness comes from the chain-stored
        // paletteCommit + Poseidon2 collision-resistance.
        Poseidon2YulSpongePaletteSalt paletteSponge = new Poseidon2YulSpongePaletteSalt();
        console.log("Poseidon2YulSpongePaletteSalt:", address(paletteSponge));
        fn.setPaletteSponge(address(paletteSponge));

        vm.stopBroadcast();
    }
}
