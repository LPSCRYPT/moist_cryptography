// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";

import {Poseidon2YulSponge} from "../src/Poseidon2YulSponge.sol";
import {Poseidon2YulSponge16} from "../src/Poseidon2YulSponge16.sol";
import {KeyRegistry} from "../src/KeyRegistry.sol";
import {ShadowToken} from "../src/ShadowToken.sol";
import {FeatureNFT} from "../src/FeatureNFT.sol";
import {MintShadowVerifier} from "../src/MintShadowVerifier.sol";
import {FaceDiscVerifier} from "../src/FaceDiscVerifier.sol";
import {MutateSlotVerifier} from "../src/MutateSlotVerifier.sol";
import {T10ShadowVerifier} from "../src/T10ShadowVerifier.sol";
import {ZIndexCommitVerifier} from "../src/ZIndexCommitVerifier.sol";
import {TransferShadowVerifier} from "../src/TransferShadowVerifier.sol";
import {SolveShadowVerifier} from "../src/SolveShadowVerifier.sol";
import {IShadowToken} from "../src/IShadowToken.sol";
import {IFeatureNFT} from "../src/IFeatureNFT.sol";
import {ShadowBridgeL2} from "../src/ShadowBridgeL2.sol";
import {ShadowMirrorL1} from "../src/ShadowMirrorL1.sol";

/// @notice Enforces real-chain deployment limits at test-time so size
///         regressions cannot silently land. Local `forge script` and
///         `forge test` do NOT enforce these by default -- they only
///         bite at actual `CREATE`/`CREATE2` on a live EVM. This test
///         is the guardrail: it deploys each contract via `new` and
///         asserts `extcodesize` <= EIP-170 (24,576 B). If any deploy
///         silently lands code over the limit, this test fires and
///         we know to fix it before broadcast.
///
/// Limits enforced:
///   - EIP-170 (Spurious Dragon, all post-2017 EVMs): runtime bytecode
///     of any deployed contract MUST be <= 24,576 bytes. Real CREATE
///     reverts at deploy time when this is violated; Foundry's local
///     simulation does NOT.
///   - Honk verifier headroom floor: each Honk verifier is generated
///     to live close to EIP-170. We pin the minimum acceptable headroom
///     so a regenerated verifier that grew silently still trips a test.
contract RealChainLimitsTest is Test {
    uint256 internal constant EIP_170_LIMIT = 24_576;

    /// Honk verifiers run very close to EIP-170 (~24,338-24,341 today).
    /// We pin a generous floor so verifier-generator changes that ate
    /// most of the headroom but stayed legal still trip a CI test.
    uint256 internal constant HONK_HEADROOM_MIN = 100;

    function _sizeOf(address a) internal view returns (uint256 sz) {
        assembly { sz := extcodesize(a) }
    }

    function _assertUnderEip170(string memory name, address a) internal view {
        uint256 sz = _sizeOf(a);
        assertLe(
            sz,
            EIP_170_LIMIT,
            string.concat(
                "EIP-170 violation: ",
                name,
                " runtime bytecode = ",
                vm.toString(sz),
                " B > 24,576 B cap (real CREATE would revert)"
            )
        );
    }

    function _assertVerifierHeadroom(string memory name, address a) internal view {
        uint256 sz = _sizeOf(a);
        assertLe(sz, EIP_170_LIMIT, string.concat("EIP-170: ", name));
        uint256 headroom = EIP_170_LIMIT - sz;
        assertGe(
            headroom,
            HONK_HEADROOM_MIN,
            string.concat(
                "Honk verifier ",
                name,
                " headroom = ",
                vm.toString(headroom),
                " B is under HONK_HEADROOM_MIN = ",
                vm.toString(HONK_HEADROOM_MIN),
                " B; investigate before regenerating"
            )
        );
    }

    // ============== Core stack ==============

    function test_eip170_Poseidon2YulSponge() public {
        Poseidon2YulSponge x = new Poseidon2YulSponge();
        _assertUnderEip170("Poseidon2YulSponge", address(x));
    }

    function test_eip170_Poseidon2YulSponge16() public {
        Poseidon2YulSponge16 x = new Poseidon2YulSponge16();
        _assertUnderEip170("Poseidon2YulSponge16", address(x));
    }

    function test_eip170_KeyRegistry() public {
        KeyRegistry x = new KeyRegistry();
        _assertUnderEip170("KeyRegistry", address(x));
    }

    function test_eip170_ShadowToken() public {
        Poseidon2YulSponge sponge = new Poseidon2YulSponge();
        ShadowToken x = new ShadowToken(address(sponge));
        _assertUnderEip170("ShadowToken", address(x));
    }

    function test_eip170_FeatureNFT() public {
        Poseidon2YulSponge sponge = new Poseidon2YulSponge();
        ShadowToken st = new ShadowToken(address(sponge));
        FeatureNFT x = new FeatureNFT(address(st));
        _assertUnderEip170("FeatureNFT", address(x));
    }

    // ============== Honk verifiers ==============

    function test_eip170_MintShadowVerifier() public {
        _assertVerifierHeadroom("MintShadowVerifier", address(new MintShadowVerifier()));
    }

    function test_eip170_FaceDiscVerifier() public {
        _assertVerifierHeadroom("FaceDiscVerifier", address(new FaceDiscVerifier()));
    }

    function test_eip170_MutateSlotVerifier() public {
        _assertVerifierHeadroom("MutateSlotVerifier", address(new MutateSlotVerifier()));
    }

    function test_eip170_T10ShadowVerifier() public {
        _assertVerifierHeadroom("T10ShadowVerifier", address(new T10ShadowVerifier()));
    }

    function test_eip170_ZIndexCommitVerifier() public {
        _assertVerifierHeadroom("ZIndexCommitVerifier", address(new ZIndexCommitVerifier()));
    }

    function test_eip170_TransferShadowVerifier() public {
        _assertVerifierHeadroom("TransferShadowVerifier", address(new TransferShadowVerifier()));
    }

    function test_eip170_SolveShadowVerifier() public {
        _assertVerifierHeadroom("SolveShadowVerifier", address(new SolveShadowVerifier()));
    }

    // ============== Bridge ==============

    function test_eip170_ShadowBridgeL2() public {
        Poseidon2YulSponge sponge = new Poseidon2YulSponge();
        ShadowToken st = new ShadowToken(address(sponge));
        FeatureNFT fn = new FeatureNFT(address(st));
        ShadowBridgeL2 x = new ShadowBridgeL2(IShadowToken(address(st)), IFeatureNFT(address(fn)));
        _assertUnderEip170("ShadowBridgeL2", address(x));
    }

    function test_eip170_ShadowMirrorL1() public {
        // ShadowMirrorL1 expects an L1 messenger address; for the size
        // check the address need not be a real messenger.
        ShadowMirrorL1 x = new ShadowMirrorL1(address(0xCAFE));
        _assertUnderEip170("ShadowMirrorL1", address(x));
    }
}
