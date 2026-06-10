// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";

/// Broadcast a pre-encoded incremental reveal call.
///
/// Per-slot reveal includes proof, plaintext, palette, salt, rank, and T10
/// refresh calldata. Fixture tooling should ABI-encode either `revealSlot` or
/// `revealSlots` and pass it as REVEAL_CALLDATA.
contract SolveOnSepolia is Script {
    function run() external {
        address stAddr = vm.envAddress("ST_ADDRESS");
        bytes memory callData = vm.envBytes("REVEAL_CALLDATA");

        console.log("=== incremental reveal broadcast ===");
        console.log("ST       :", stAddr);
        console.log("calldata :", callData.length, "bytes");

        vm.startBroadcast();
        (bool ok, bytes memory ret) = stAddr.call(callData);
        vm.stopBroadcast();
        if (!ok) {
            assembly { revert(add(ret, 32), mload(ret)) }
        }

        console.log("done");
    }
}
