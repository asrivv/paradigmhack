// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

// TEMPORARY. Withdrawal batches are empty in this pass (Ed25519 has no EVM precompile), so a real
// close never carries payout outputs. This harness installs a synthetic finalized payout head and
// reserve so claim paths can be tested. Remove once withdrawals and crate fixtures land.

import { BajillionSettlement } from "../../src/BajillionSettlement.sol";

contract SettlementHarness is BajillionSettlement {
    constructor(DeploymentArgs memory d) BajillionSettlement(d) { }

    /// @dev Install a finalized payout head and its reserve, then record the trailing commit as
    /// `finalize` does (settlement.rs:1616-1620).
    function exposedInstallPayouts(bytes32 root, uint64 operations, uint64 floor, uint64 reserve) external {
        finalizedPayouts = LogHead(root, operations, floor);
        claimableBalance += reserve;
        uint64 commitIndex = operations - 1;
        (bool ok, uint64 start, uint64 end,, ClaimedRange memory succ, uint64 afterStart) =
            _planClaim(commitIndex, claimedTail);
        require(ok, "commit insert");
        _applyClaim(commitIndex, claimedTail, afterStart, start, end, succ);
    }

    /// @dev The predecessor-or-containing range start for `index`, found by walking the list.
    function exposedPredecessor(uint64 index) external view returns (uint64 predecessor) {
        uint64 cursor = claimedHead;
        while (cursor != 0 && cursor <= index) {
            predecessor = cursor;
            cursor = claimed[cursor].next;
        }
    }
}
