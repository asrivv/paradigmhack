// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

// Storage types shared by BajillionSettlement and the linked libraries that operate on its
// storage (BajillionChallenge, BajillionRecovery).

/// @dev Capacity of the epoch ring: registered plus admitted-but-unfinalized epochs. The crate
/// bounds neither (settlement.rs:235-239); a fixed ring keeps storage reusable.
uint256 constant EPOCH_RING_SIZE = 64;

/// @dev Capacity of the inbox ring. At most `INBOX_RING_SIZE - 1` deposits may be unpulled.
uint256 constant INBOX_RING_SIZE = 1024;

/// @dev `Epoch.status` values. Zero is an empty ring record.
uint8 constant BATCH_REGISTERED = 1;
uint8 constant BATCH_PENDING = 2;
uint8 constant BATCH_CHALLENGED = 3;
uint8 constant BATCH_INVALIDATED = 4;

/// @notice One registered or admitted epoch.
/// @dev Epochs live in a ring of `EPOCH_RING` records keyed by `epoch % EPOCH_RING`. Tempo
/// charges 250,000 gas for each storage slot that goes from zero to nonzero, so a record that
/// is overwritten in place costs about 3,000 per slot after the ring's first lap. Records are
/// never cleared, for the same reason; `status` and the deadlines are rewritten on reuse.
/// Fields are packed so that each slot is written by one step of the lifecycle.
struct Epoch {
    // Registration (EpochContext, transition.rs:492-499). The deployment, operator and
    // committee are immutable per deployment and are not stored per epoch.
    bytes32 anchor;
    bytes32 depositRoot;
    bytes32 withdrawalRoot;
    uint64[8] limits; // CloseLimits (transition.rs:356-365), two slots.
    uint64 epoch; // Guards against reading a stale ring record.
    uint64 floorActivity; // Floors captured pos registration (settlement.rs:1776-1781).
    uint64 floorPayouts;
    uint64 depositTotal;
    // Promotion (settlement.rs:1418-1440). Zero admission deadline means not yet promoted;
    // a promoted deadline is at least `admissionDelay > 0`.
    uint64 admissionDeadline;
    uint64 challengeDeadline;
    // Admission (settlement.rs:1523-1540).
    uint64 withdrawalTotal;
    uint8 status;
    uint8 challengeKind; // ChallengeKind tag (settlement.rs:2227-2233) when status is CHALLENGED.
    bytes32 batchId;
    bytes32 successorRoot;
    bytes32 activityRoot;
    bytes32 payoutRoot;
    uint64 activityOperations;
    uint64 activityFloor;
    uint64 payoutOperations;
    uint64 payoutFloor;
    uint64 rowsStart;
    uint64 rowsEnd;
    uint64 successorLiability;
    // keccak256 of the predecessor `Heads`, compared at finalization (settlement.rs:1647-1649).
    bytes32 predecessorLogs;
    // `earliest_withdrawal` of the registered batch (settlement.rs:431-439): its smallest
    // `(deadline, account)`, or zero deadline when the batch is empty. Deadlines are positive.
    uint64 withdrawalDeadline;
    bytes32 withdrawalAccount;
}

/// @notice `LogHead` (logs.rs:168-176). Two slots.
struct LogHead {
    bytes32 root;
    uint64 operations;
    uint64 floor;
}

/// @dev The settlement-visible prefix the next frontier binds (settlement.rs:895-907, 1749-1770).
struct Head {
    bytes32 stateRoot;
    LogHead activity;
    LogHead payouts;
    uint64 rowsStart;
    uint64 rowsEnd;
    uint64 liability;
}

/// @notice One run of unpulled deposits sharing an inclusion deadline (settlement.rs:280-287).
struct Run {
    uint64 end;
    uint64 deadline;
    bytes32 account;
}
