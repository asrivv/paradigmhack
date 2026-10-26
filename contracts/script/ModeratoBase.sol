// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { Script } from "forge-std/Script.sol";

/// @dev Shared constants for the Tempo Moderato deployment scripts.
abstract contract ModeratoBase is Script {
    uint256 internal constant CHAIN_ID = 42431;
    /// pathUSD, Moderato's default fee and settlement stablecoin (docs.tempo.xyz faucet page).
    address internal constant PATH_USD = 0x20C0000000000000000000000000000000000000;
    string internal constant DEPLOYMENT_FILE = "../deployments/moderato.json";

    // DEMO SETTINGS, not production ones. A 30-second challenge window is far too short for
    // watchers on a real network; it exists so the demo's fixture epoch finalizes in about two
    // minutes. They must match offchain/moderato/src/main.rs, which certifies the close.
    uint64 internal constant ADMISSION_DELAY = 60;
    uint64 internal constant CHALLENGE_DURATION = 30;
    uint64 internal constant DEPOSIT_INCLUSION_TIMEOUT = 300;
    uint64 internal constant MINIMUM_WITHDRAWAL_NOTICE = 120;
    uint64 internal constant MAXIMUM_WITHDRAWAL_NOTICE = 3600;
    uint64 internal constant MAX_DESTINATION_BYTES = 256;
    uint64 internal constant MAX_DEPOSIT_IDS = 1024;

    function _key() internal view returns (uint256) {
        return vm.envUint("PRIVATE_KEY");
    }

    function _settlement() internal view returns (address) {
        return vm.parseJsonAddress(vm.readFile(DEPLOYMENT_FILE), ".settlement.address");
    }
}
