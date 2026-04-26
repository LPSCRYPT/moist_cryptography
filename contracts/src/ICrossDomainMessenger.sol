// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/// @notice Subset of the OP Stack CrossDomainMessenger interface that
///         ShadowBridgeL2 / ShadowMirrorL1 actually use.
///
/// Live deployments:
///   - L2CrossDomainMessenger predeploy on every OP Stack chain:
///       0x4200000000000000000000000000000000000007
///   - L1CrossDomainMessenger proxy for Base on Ethereum Sepolia:
///       0xC34855F4De64F1840e5686e64278da901e261f20
///
/// `sendMessage` queues a cross-domain call. Settlement timing:
///   - L2 -> L1: ~7 days (challenge period; Base Sepolia testnet may finalize
///     faster but we budget for the worst case).
///   - L1 -> L2: ~1 minute.
///
/// `xDomainMessageSender()` is the trust anchor on the receiving side: it
/// returns the address that called `sendMessage` on the opposite chain. Both
/// our bridge endpoints gate calls on `(msg.sender == messenger &&
/// messenger.xDomainMessageSender() == counterpart)`.
interface ICrossDomainMessenger {
    function sendMessage(
        address target,
        bytes calldata message,
        uint32 minGasLimit
    ) external;

    function xDomainMessageSender() external view returns (address);
}
