//! Stable status codes for every outcome the oracle reports.
//!
//! [`TABLE`] is the single definition. The Solidity port must return the same number for the
//! same failure, so codes are append-only: never renumber or reuse one. The README's status
//! table is checked against this table by a test.
//!
//! Wrapped errors (`Boundary`, `Transition`, `Challenge`, `State`, `Commitment`, `Proof`) map to
//! one code per top-level variant regardless of their inner cause.

use commonware_clearing::bajillion::settlement::{ClaimError, SettlementError};

/// The operation succeeded.
pub const OK: u16 = 0;
/// The op's `args` are not the canonical encoding its kind requires, so nothing was called.
pub const MALFORMED_ARGS: u16 = 1001;
/// The op's `kind` is not one of the nine defined kinds.
pub const UNKNOWN_KIND: u16 = 1002;
/// `advanceTime` would overflow the 64-bit clock.
pub const CLOCK_OVERFLOW: u16 = 1003;
/// The input violates a documented caller precondition (upstream panics instead of returning
/// an error). The whole call is discarded, including any time it observed.
pub const PRECONDITION: u16 = 1004;

/// Every status code and its name, in code order.
pub const TABLE: &[(u16, &str)] = &[
    (OK, "Ok"),
    (1, "SettlementError::Deployment"),
    (2, "SettlementError::OperatorMismatch"),
    (3, "SettlementError::EpochSequence"),
    (4, "SettlementError::StateAncestry"),
    (5, "SettlementError::CommitteeMismatch"),
    (6, "SettlementError::BoundaryRoot"),
    (7, "SettlementError::DepositWitness"),
    (8, "SettlementError::WithdrawalWitness"),
    (9, "SettlementError::IntakeRange"),
    (10, "SettlementError::IntakeOverflow"),
    (11, "SettlementError::ClaimAlreadyConsumed"),
    (12, "SettlementError::ZeroDeposit"),
    (13, "SettlementError::DuplicateDeposit"),
    (14, "SettlementError::PendingDepositUnavailable"),
    (15, "SettlementError::DepositCapacity"),
    (16, "SettlementError::DepositDeadlineOverflow"),
    (17, "SettlementError::IneligibleDestination"),
    (18, "SettlementError::DestinationTooLarge"),
    (19, "SettlementError::WithdrawalOpening"),
    (20, "SettlementError::WithdrawalBalance"),
    (21, "SettlementError::DuplicateWithdrawal"),
    (22, "SettlementError::DuplicateWithdrawalAuthorization"),
    (23, "SettlementError::WithdrawalDeadlineTooSoon"),
    (24, "SettlementError::WithdrawalDeadlineTooLate"),
    (25, "SettlementError::WithdrawalNoticeOrder"),
    (26, "SettlementError::DeadlineNotReached"),
    (27, "SettlementError::OperatorHardFaulted"),
    (28, "SettlementError::OperatorNotHardFaulted"),
    (29, "SettlementError::HardFaultAlreadySettled"),
    (30, "SettlementError::HardFaultSettlementNotStarted"),
    (31, "SettlementError::CustodyArithmetic"),
    (32, "SettlementError::CustodyMismatch"),
    (33, "SettlementError::NoRegisteredEpoch"),
    (34, "SettlementError::EpochDeadlineOverflow"),
    (35, "SettlementError::InvalidCertificate"),
    (36, "SettlementError::NoPendingBatch"),
    (37, "SettlementError::AlreadyChallenged"),
    (38, "SettlementError::BatchInvalidated"),
    (39, "SettlementError::PreFaultBatchPending"),
    (40, "SettlementError::ChallengeWindowOpen"),
    (41, "SettlementError::EpochOverflow"),
    (42, "SettlementError::Boundary"),
    (43, "SettlementError::Transition"),
    (44, "SettlementError::Challenge"),
    (45, "SettlementError::State"),
    (46, "SettlementError::Commitment"),
    (101, "ClaimError::Unavailable"),
    (102, "ClaimError::Reserve"),
    (103, "ClaimError::Proof"),
    (MALFORMED_ARGS, "Oracle::MalformedArgs"),
    (UNKNOWN_KIND, "Oracle::UnknownKind"),
    (CLOCK_OVERFLOW, "Oracle::ClockOverflow"),
    (PRECONDITION, "Oracle::Precondition"),
];

fn code(name: &str) -> u16 {
    TABLE
        .iter()
        .find(|(_, entry)| *entry == name)
        .map(|(code, _)| *code)
        .expect("every reported name is in the status table")
}

/// The status code of a settlement failure.
pub fn settlement(error: &SettlementError) -> u16 {
    // Exhaustive on purpose: a variant added upstream must fail to compile here, not silently
    // share another variant's code.
    code(match error {
        SettlementError::Deployment => "SettlementError::Deployment",
        SettlementError::OperatorMismatch => "SettlementError::OperatorMismatch",
        SettlementError::EpochSequence => "SettlementError::EpochSequence",
        SettlementError::StateAncestry => "SettlementError::StateAncestry",
        SettlementError::CommitteeMismatch => "SettlementError::CommitteeMismatch",
        SettlementError::BoundaryRoot => "SettlementError::BoundaryRoot",
        SettlementError::DepositWitness => "SettlementError::DepositWitness",
        SettlementError::WithdrawalWitness => "SettlementError::WithdrawalWitness",
        SettlementError::IntakeRange => "SettlementError::IntakeRange",
        SettlementError::IntakeOverflow => "SettlementError::IntakeOverflow",
        SettlementError::ClaimAlreadyConsumed => "SettlementError::ClaimAlreadyConsumed",
        SettlementError::ZeroDeposit => "SettlementError::ZeroDeposit",
        SettlementError::DuplicateDeposit => "SettlementError::DuplicateDeposit",
        SettlementError::PendingDepositUnavailable => "SettlementError::PendingDepositUnavailable",
        SettlementError::DepositCapacity => "SettlementError::DepositCapacity",
        SettlementError::DepositDeadlineOverflow => "SettlementError::DepositDeadlineOverflow",
        SettlementError::IneligibleDestination => "SettlementError::IneligibleDestination",
        SettlementError::DestinationTooLarge => "SettlementError::DestinationTooLarge",
        SettlementError::WithdrawalOpening => "SettlementError::WithdrawalOpening",
        SettlementError::WithdrawalBalance => "SettlementError::WithdrawalBalance",
        SettlementError::DuplicateWithdrawal => "SettlementError::DuplicateWithdrawal",
        SettlementError::DuplicateWithdrawalAuthorization => {
            "SettlementError::DuplicateWithdrawalAuthorization"
        }
        SettlementError::WithdrawalDeadlineTooSoon => "SettlementError::WithdrawalDeadlineTooSoon",
        SettlementError::WithdrawalDeadlineTooLate => "SettlementError::WithdrawalDeadlineTooLate",
        SettlementError::WithdrawalNoticeOrder => "SettlementError::WithdrawalNoticeOrder",
        SettlementError::DeadlineNotReached => "SettlementError::DeadlineNotReached",
        SettlementError::OperatorHardFaulted => "SettlementError::OperatorHardFaulted",
        SettlementError::OperatorNotHardFaulted => "SettlementError::OperatorNotHardFaulted",
        SettlementError::HardFaultAlreadySettled => "SettlementError::HardFaultAlreadySettled",
        SettlementError::HardFaultSettlementNotStarted => {
            "SettlementError::HardFaultSettlementNotStarted"
        }
        SettlementError::CustodyArithmetic => "SettlementError::CustodyArithmetic",
        SettlementError::CustodyMismatch => "SettlementError::CustodyMismatch",
        SettlementError::NoRegisteredEpoch => "SettlementError::NoRegisteredEpoch",
        SettlementError::EpochDeadlineOverflow => "SettlementError::EpochDeadlineOverflow",
        SettlementError::InvalidCertificate => "SettlementError::InvalidCertificate",
        SettlementError::NoPendingBatch => "SettlementError::NoPendingBatch",
        SettlementError::AlreadyChallenged => "SettlementError::AlreadyChallenged",
        SettlementError::BatchInvalidated => "SettlementError::BatchInvalidated",
        SettlementError::PreFaultBatchPending => "SettlementError::PreFaultBatchPending",
        SettlementError::ChallengeWindowOpen => "SettlementError::ChallengeWindowOpen",
        SettlementError::EpochOverflow => "SettlementError::EpochOverflow",
        SettlementError::Boundary(_) => "SettlementError::Boundary",
        SettlementError::Transition(_) => "SettlementError::Transition",
        SettlementError::Challenge(_) => "SettlementError::Challenge",
        SettlementError::State(_) => "SettlementError::State",
        SettlementError::Commitment(_) => "SettlementError::Commitment",
    })
}

/// The status code of a payout claim failure.
pub fn claim(error: &ClaimError) -> u16 {
    code(match error {
        ClaimError::Unavailable => "ClaimError::Unavailable",
        ClaimError::Reserve => "ClaimError::Reserve",
        ClaimError::Proof(_) => "ClaimError::Proof",
    })
}

/// The name of a status code, for diagnostics.
pub fn name(status: u16) -> Option<&'static str> {
    TABLE
        .iter()
        .find(|(code, _)| *code == status)
        .map(|(_, name)| *name)
}
