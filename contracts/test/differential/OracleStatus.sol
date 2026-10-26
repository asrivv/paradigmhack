// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { BajillionSettlement as S } from "../../src/BajillionSettlement.sol";

/// @notice The single map from BajillionSettlement outcomes onto the differential oracle's
/// status table (offchain/oracle/src/status.rs, `TABLE`). The oracle reports one code per
/// top-level `SettlementError` or `ClaimError` variant, so every `Transition*` error shares 43
/// and every `Challenge*` error shares 44. Decode failures are 1001 on both sides: the oracle
/// rejects args that do not decode as crate values before calling settlement, and the contract
/// rejects the same bytes with an `*Encoding` error before changing state.
/// @dev Embedding errors with no oracle counterpart map to `EMBEDDING`, and anything else
/// (a panic, a bare revert) maps to `UNMAPPED`. Neither code is in the oracle's table, so either
/// one always surfaces as a mismatch.
library OracleStatus {
    uint16 internal constant OK = 0;
    uint16 internal constant MALFORMED_ARGS = 1001;
    uint16 internal constant PRECONDITION = 1004;
    uint16 internal constant EMBEDDING = 2000;
    uint16 internal constant UNMAPPED = 2001;

    /// @notice A status the contract returned after committing the liveness fence.
    function fromStatus(S.Status status) internal pure returns (uint16) {
        if (status == S.Status.Ok) return OK;
        if (status == S.Status.OperatorHardFaulted) return 27;
        if (status == S.Status.NoPendingBatch) return 36;
        if (status == S.Status.BatchInvalidated) return 38;
        if (status == S.Status.ChallengeWindowOpen) return 40;
        if (status == S.Status.StateAncestry) return 4;
        if (status == S.Status.EpochOverflow) return 41;
        if (status == S.Status.CustodyArithmetic) return 31;
        // `Status.Rejected` carries its error in the `Rejected(bytes4)` event; callers pass that
        // selector to `fromSelector`.
        return UNMAPPED;
    }

    /// @notice A custom error, either reverted or carried by a `Rejected` event.
    function fromSelector(bytes4 s) internal pure returns (uint16) {
        // SettlementError variants, numbered in declaration order (settlement.rs:3159-3314).
        if (s == S.Deployment.selector) return 1;
        if (s == S.OperatorMismatch.selector) return 2;
        if (s == S.EpochSequence.selector) return 3;
        if (s == S.StateAncestry.selector) return 4;
        if (s == S.CommitteeMismatch.selector) return 5;
        if (s == S.BoundaryRoot.selector) return 6;
        if (s == S.IntakeRange.selector) return 9;
        if (s == S.IntakeOverflow.selector) return 10;
        if (s == S.ZeroDeposit.selector) return 12;
        if (s == S.DepositCapacity.selector) return 15;
        if (s == S.DepositDeadlineOverflow.selector) return 16;
        if (s == S.WithdrawalWitness.selector) return 8;
        if (s == S.IneligibleDestination.selector) return 17;
        if (s == S.DestinationTooLarge.selector) return 18;
        if (s == S.WithdrawalOpening.selector) return 19;
        if (s == S.WithdrawalBalance.selector) return 20;
        if (s == S.DuplicateWithdrawal.selector) return 21;
        if (s == S.DuplicateWithdrawalAuthorization.selector) return 22;
        if (s == S.WithdrawalDeadlineTooSoon.selector) return 23;
        if (s == S.WithdrawalDeadlineTooLate.selector) return 24;
        if (s == S.WithdrawalNoticeOrder.selector) return 25;
        if (s == S.DeadlineNotReached.selector) return 26;
        if (s == S.OperatorHardFaulted.selector) return 27;
        if (s == S.CustodyArithmetic.selector) return 31;
        if (s == S.NoRegisteredEpoch.selector) return 33;
        if (s == S.EpochDeadlineOverflow.selector) return 34;
        if (s == S.InvalidCertificate.selector) return 35;
        if (s == S.NoPendingBatch.selector) return 36;
        if (s == S.AlreadyChallenged.selector) return 37;
        if (s == S.BatchInvalidated.selector) return 38;
        if (s == S.ChallengeWindowOpen.selector) return 40;
        if (s == S.EpochOverflow.selector) return 41;
        // SettlementError::Transition(_).
        if (
            s == S.TransitionEpochAnchor.selector || s == S.TransitionHeaderRoot.selector
                || s == S.TransitionBoundaryRoot.selector || s == S.TransitionCloseLimit.selector
                || s == S.TransitionLogRange.selector || s == S.TransitionWithdrawalOutputRoot.selector
                || s == S.TransitionLiabilityEquation.selector || s == S.TransitionLiabilityOverflow.selector
        ) return 43;
        // SettlementError::Boundary(_) and SettlementError::State(_).
        if (s == S.BoundaryWrongContext.selector || s == S.BoundaryInvalidSignature.selector) return 42;
        if (s == S.StateProof.selector) return 45;
        // SettlementError::Challenge(_).
        if (
            s == S.ChallengeExpired.selector || s == S.ChallengeTooLarge.selector || s == S.ChallengeHeaderRoot.selector
                || s == S.ChallengeCodec.selector || s == S.ChallengeKindUnsupported.selector
                || s == S.ChallengeLookupOrder.selector || s == S.ChallengeActivity.selector
                || s == S.ChallengeInvalidPayerSignature.selector || s == S.ChallengeInvalidOperatorSignature.selector
        ) return 44;
        // ClaimError variants.
        if (s == S.ClaimUnavailable.selector) return 101;
        if (s == S.ClaimReserve.selector) return 102;
        if (s == S.ClaimProof.selector) return 103;
        // Arguments that do not decode as crate values. `DepositBatchEncoding` also stands for
        // `Commitment(TooManyValues)`, which needs more than 2^24 records and cannot occur here.
        if (
            s == S.ContextEncoding.selector || s == S.RootsEncoding.selector || s == S.ClaimEncoding.selector
                || s == S.DepositBatchEncoding.selector || s == S.WithdrawalEncoding.selector
                || s == S.StateOpeningEncoding.selector
        ) return MALFORMED_ARGS;
        // Upstream panics when a deposit batch credits an account more than its unpulled
        // deposits (settlement.rs:1304-1307); the oracle reports the panic as 1004.
        if (s == S.DepositAggregate.selector) return PRECONDITION;
        // Embedding checks: point hints, committee calldata, fixed capacities, asset transfer,
        // and the pending-list position hint.
        if (
            s == S.CommitteeKeys.selector || s == S.PipelineFull.selector || s == S.InboxFull.selector
                || s == S.TransferFailed.selector || s == S.WithdrawalOrder.selector
        ) return EMBEDDING;
        return UNMAPPED;
    }
}
