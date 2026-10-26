// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { BajillionWithdrawals as Withdrawals } from "./BajillionWithdrawals.sol";
import { EPOCH_RING_SIZE, Epoch, INBOX_RING_SIZE, Run } from "./BajillionTypes.sol";

/// @title Liveness deadlines for BajillionSettlement
/// @notice `expired_reason` from `SettlementChain` (clearing/src/bajillion/settlement.rs:769-836 at
/// commonwarexyz/monorepo dd6d60cb44fb3dc05cee1efa06d957ce30df1340): the earliest missed deposit,
/// withdrawal or registration deadline, with upstream's tie-breaks. A linked library reading the
/// settlement contract's storage by DELEGATECALL, to keep the contract under EIP-170.
library BajillionLiveness {
    /// @dev `BajillionSettlement.FaultKind` values (`HardFaultReason` tags plus one).
    uint8 internal constant NONE = 0;
    uint8 internal constant EXPIRED_DEPOSIT = 2;
    uint8 internal constant EXPIRED_WITHDRAWAL = 3;
    uint8 internal constant EXPIRED_REGISTRATION = 4;

    /// @notice The clock and the contract's pipeline and run-ring positions.
    struct Clock {
        uint64 now_;
        uint64 runHead;
        uint64 runTail;
        uint64 expectedEpoch;
        uint64 admittedEnd;
        uint64 registeredEnd;
    }

    /// @return kind A `FaultKind` value, `NONE` when nothing has expired.
    /// @return expiredAt The missed deadline.
    /// @return detail The account for an expired deposit or withdrawal, the anchor for an expired
    /// registration.
    /// @return epoch The expired registration's epoch, else zero.
    function expiredReason(
        mapping(uint256 => Run) storage runs,
        mapping(uint256 => Epoch) storage epochs,
        Withdrawals.State storage w,
        Clock memory c
    ) external view returns (uint8 kind, uint64 expiredAt, bytes32 detail, uint64 epoch) {
        // Every deposit shares one timeout, so the front run holds the earliest deadline.
        Run storage front = runs[c.runHead % INBOX_RING_SIZE];
        bool depositExpired = c.runHead < c.runTail && c.now_ >= front.deadline;

        // Withdrawal attribution wins when both intake obligations expire together.
        (uint64 wDeadline, bytes32 wAccount) = Withdrawals.earliestDeadline(w, epochs, c.expectedEpoch, c.admittedEnd);
        if (wDeadline != 0 && c.now_ >= wDeadline && (!depositExpired || wDeadline <= front.deadline)) {
            (kind, expiredAt, detail) = (EXPIRED_WITHDRAWAL, wDeadline, wAccount);
        } else if (depositExpired) {
            (kind, expiredAt, detail) = (EXPIRED_DEPOSIT, front.deadline, front.account);
        }

        // A live frontier is always promoted; the zero check only guards a stale ring record.
        Epoch storage frontier = epochs[c.admittedEnd % EPOCH_RING_SIZE];
        uint64 admission = frontier.admissionDeadline;
        if (c.registeredEnd > c.admittedEnd && admission != 0 && c.now_ > admission) {
            // At a shared first-fault instant the registration reason wins (settlement.rs:827-835).
            // A later timestamp was observed, so `admission + 1` does not overflow.
            if (kind == NONE || admission + 1 <= expiredAt) {
                return (EXPIRED_REGISTRATION, admission, frontier.anchor, c.admittedEnd);
            }
        }
    }
}
