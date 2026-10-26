// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

// Test harness. It adds two test-only entry points and changes no production behaviour:
// 1. `exposedInstallPayouts` installs a finalized payout head for scenario tests that need more
//    payout outputs than the single fixture epoch has.
// 2. `exposedPredecessor` finds a claimed-range predecessor by walking the list.

import { BajillionClaims } from "../../src/BajillionClaims.sol";
import { BajillionSettlement } from "../../src/BajillionSettlement.sol";

contract SettlementHarness is BajillionSettlement {
    constructor(DeploymentArgs memory d) BajillionSettlement(d) { }

    /// @dev Install a finalized payout head and its reserve, then record the trailing commit as
    /// `finalize` does (settlement.rs:1616-1620).
    function exposedInstallPayouts(bytes32 root, uint64 operations, uint64 floor, uint64 reserve) external {
        finalizedPayouts = LogHead(root, operations, floor);
        claimableBalance += reserve;
        require(BajillionClaims.insertCommit(claimState, operations - 1), "commit insert");
    }

    /// @dev The predecessor-or-containing range start for `index`, found by walking the list.
    function exposedPredecessor(uint64 index) external view returns (uint64) {
        return BajillionClaims.predecessorOf(claimState, index);
    }
}
