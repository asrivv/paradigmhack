// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { LibQMDBCurrent } from "commonware/qmdb/LibQMDBCurrent.sol";
import { Ed25519Verifier } from "./verify/LibEd25519.sol";
import { StateVerifier, WithdrawalCodec as W } from "./verify/WithdrawalVerifiers.sol";
import { BajillionWithdrawals as Withdrawals } from "./BajillionWithdrawals.sol";
import { AdmissionVerifier } from "./verify/BajillionVerifiers.sol";
import { BATCH_PENDING, EPOCH_RING_SIZE, Epoch } from "./BajillionTypes.sol";

/// @title Terminal settlement for BajillionSettlement
/// @notice A linked library holding the terminal-claims half of `SettlementChain`
/// (clearing/src/bajillion/settlement.rs:1796-2082 at commonwarexyz/monorepo
/// dd6d60cb44fb3dc05cee1efa06d957ce30df1340): the frozen state root, per-account consumption,
/// and `claim_hard_fault`. Its external functions run by DELEGATECALL on a `State` in the
/// settlement contract's storage. It exists to keep BajillionSettlement under EIP-170.
/// @dev Clearing accounts are Ed25519 keys, not Tempo addresses, so amounts upstream returns
/// "directly to the account" (deposit refunds and state residuals) are credited here and swept by
/// the account's own signature (`sweep`). A signed withdrawal's output already names a 20-byte
/// destination and is paid there. Errors share names and selectors with BajillionSettlement's.
library BajillionRecovery {
    struct State {
        /// `hard_fault_claims.is_some()` and `fault_settled` (settlement.rs:685-686).
        bool started;
        bool settled;
        /// The admitted unfinalized closes drained at `begin_hard_fault_settlement`:
        /// `[drainFrom, drainTo)`. Their deposits are refundable and their withdrawals route.
        uint64 drainFrom;
        uint64 drainTo;
        /// `HardFaultClaims` (settlement.rs:567-578).
        uint64 stateLiability;
        uint64 remainingStateLiability;
        uint64 depositTotal;
        uint64 custody;
        bytes32 frozenRoot;
        mapping(bytes32 => bool) depositClaimed;
        mapping(bytes32 => bool) accountClaimed;
        /// Amounts released to a clearing account, awaiting its signed sweep.
        mapping(bytes32 => uint64) credit;
        mapping(bytes32 => uint64) sweepNonce;
    }

    /// @notice One `claim_hard_fault` release (settlement.rs:166-177).
    struct Release {
        bytes32 account;
        uint64 balance;
        uint64 withdrawn;
        address destination;
        uint64 residual;
    }

    /// @notice The settlement contract's custody ledger, read by these functions; the caller
    /// writes back the changes they return.
    struct Ledger {
        bool faulted;
        uint64 expectedEpoch;
        uint64 admittedEnd;
        uint64 pendingDepositTotal;
        uint64 unfinalizedDepositTotal;
        uint64 currentLiability;
        uint64 custodyBalance;
        bytes32 currentStateRoot;
    }

    error OperatorNotHardFaulted();
    error PreFaultBatchPending();
    error CustodyMismatch();
    error PendingDepositUnavailable();
    error HardFaultAlreadySettled();
    error HardFaultSettlementNotStarted();
    error ClaimAlreadyConsumed();
    error WithdrawalWitness();
    error StateProof();
    error CustodyArithmetic();
    error StateOpeningEncoding();
    error RecoveryWitness();
    error RecoverySignature();
    error NothingToRecover();

    /// @dev Proof digests accepted in a state opening, as for `queueWithdrawal`.
    uint256 internal constant MAX_STATE_DIGESTS = 256;
    /// @dev `union_unique(namespace, ...)` prefix of the sweep authorization: varint(32).
    bytes internal constant SWEEP_PREFIX = "\x20_PARADIGMHACK_BAJILLION_RECOVERY";

    /// @notice `begin_hard_fault_settlement` (settlement.rs:1876-1986): freeze the finalized root
    /// and drain the admitted pipeline `[expectedEpoch, admittedEnd)`, whose deposits become
    /// refundable and whose withdrawals route at `claimState`. Idempotent once started.
    /// @return startedNow True when this call started settlement; the caller then empties the
    /// pipeline and registrations.
    /// @return settledNow True when nothing remains to claim; the caller zeroes liability and custody.
    function begin(State storage s, mapping(uint256 => Epoch) storage epochs, Ledger memory l)
        external
        returns (bool startedNow, bool settledNow)
    {
        if (!l.faulted) revert OperatorNotHardFaulted();
        if (s.settled) revert HardFaultAlreadySettled();
        if (s.started) return (false, false);
        if (l.expectedEpoch < l.admittedEnd && epochs[l.expectedEpoch % EPOCH_RING_SIZE].status == BATCH_PENDING) {
            revert PreFaultBatchPending();
        }
        // Unadmitted deposits already include those pulled by the dropped registrations.
        uint256 total = l.pendingDepositTotal;
        for (uint64 e = l.expectedEpoch; e < l.admittedEnd; ++e) {
            total += epochs[e % EPOCH_RING_SIZE].depositTotal;
        }
        if (total > type(uint64).max) revert CustodyArithmetic();
        if (total != l.unfinalizedDepositTotal) revert CustodyMismatch();
        if (uint256(l.currentLiability) + total != l.custodyBalance) revert CustodyMismatch();

        s.started = true;
        s.frozenRoot = l.currentStateRoot;
        s.stateLiability = l.currentLiability;
        s.remainingStateLiability = l.currentLiability;
        // forge-lint: disable-next-line(unsafe-typecast) bounded by the check above
        s.depositTotal = uint64(total);
        s.custody = l.custodyBalance;
        s.drainFrom = l.expectedEpoch;
        s.drainTo = l.admittedEnd;
        return (true, _finish(s, l.unfinalizedDepositTotal));
    }

    /// @notice `claim_pending_deposit` after time is observed (settlement.rs:1796-1874): refund
    /// every unadmitted deposit of `account` once, crediting it for `sweep`.
    /// @param batches After settlement starts, the admitted `DepositBatch` of each drained close in
    /// order, checked against its registered root. Empty before.
    /// @return err A custom-error selector, or zero on success; the caller reverts or returns the
    /// fenced status.
    /// @return amount The refund.
    /// @return unpulled The part of `amount` that was in `pendingDeposits`.
    /// @return settledNow As for `begin`.
    function refund(
        State storage s,
        mapping(uint256 => Epoch) storage epochs,
        mapping(bytes32 => uint64) storage pendingDeposits,
        bytes32 account,
        bytes[] calldata batches,
        Ledger memory l
    ) external returns (bytes4 err, uint64 amount, uint64 unpulled, bool settledNow) {
        if (s.settled) return (HardFaultAlreadySettled.selector, 0, 0, false);
        unpulled = pendingDeposits[account];
        uint256 total = unpulled;
        if (s.started) {
            if (s.depositClaimed[account]) return (PendingDepositUnavailable.selector, 0, 0, false);
            bytes32[] memory roots = new bytes32[](s.drainTo - s.drainFrom);
            for (uint256 i; i < roots.length; ++i) {
                roots[i] = epochs[(s.drainFrom + i) % EPOCH_RING_SIZE].depositRoot;
            }
            (bool ok, uint256 drained) = AdmissionVerifier.pipelineDeposit(account, batches, roots);
            if (!ok) return (RecoveryWitness.selector, 0, 0, false);
            total += drained;
        } else if (batches.length != 0) {
            return (RecoveryWitness.selector, 0, 0, false);
        }
        if (total == 0) return (PendingDepositUnavailable.selector, 0, 0, false);
        if (total > l.custodyBalance || total > l.unfinalizedDepositTotal) {
            return (CustodyArithmetic.selector, 0, 0, false);
        }
        // forge-lint: disable-next-line(unsafe-typecast) bounded by custodyBalance
        amount = uint64(total);
        pendingDeposits[account] = 0;
        if (s.started) s.depositClaimed[account] = true;
        s.credit[account] += amount;
        settledNow = _finish(s, l.unfinalizedDepositTotal - amount);
    }

    /// @notice `claim_hard_fault` (settlement.rs:1988-2062), with the account's one withdrawal
    /// request, if any, supplied as a witness and matched against its stored digest.
    /// @param faulted Whether the deployment is hard-faulted.
    /// @param opening The crate's `StateOpening` at the frozen root. Decoded first, as the crate
    /// decodes it before the call.
    /// @param request The account's chain-queued or drained-close request, verbatim; empty when
    /// it has none.
    function claimState(
        State storage s,
        Withdrawals.State storage w,
        bool faulted,
        uint64 unfinalizedDepositTotal,
        bytes calldata opening,
        bytes calldata request,
        uint64 maxDestinationBytes
    ) external returns (Release memory r, bool settledNow) {
        (bool ok, bytes32 account, uint64 balance, bytes32 nextKey, LibQMDBCurrent.Proof memory proof) =
            StateVerifier.decode(opening, MAX_STATE_DIGESTS);
        if (!ok || !Ed25519Verifier.isStrictKey(account)) revert StateOpeningEncoding();
        if (!faulted) revert OperatorNotHardFaulted();
        if (s.settled) revert HardFaultAlreadySettled();
        if (!s.started) revert HardFaultSettlementNotStarted();
        if (s.accountClaimed[account]) revert ClaimAlreadyConsumed();
        if (!StateVerifier.verify(s.frozenRoot, account, balance, nextKey, proof)) revert StateProof();

        // The account's withdrawal: chain-queued, or carried by one drained close. Two is a
        // witness inconsistency (settlement.rs:2011-2019).
        bytes32 expected;
        uint256 found;
        Withdrawals.Pending storage p = w.pending[account];
        if (p.deadline != 0) {
            expected = p.digest;
            ++found;
        }
        bool carried;
        for (uint64 e = s.drainFrom; e < s.drainTo; ++e) {
            bytes32 record = w.carried[e][account];
            if (record == 0) continue;
            if (++found > 1) revert WithdrawalWitness();
            expected = record;
            carried = true;
        }

        r.account = account;
        r.balance = balance;
        if (found == 0) {
            if (request.length != 0) revert RecoveryWitness();
        } else {
            (bool decoded, W.Request memory q) = W.decodeRequest(request, maxDestinationBytes);
            bytes32 digest = keccak256(request);
            if (!decoded || (carried ? Withdrawals.carriedRecord(digest, q.deadline) : digest) != expected) {
                revert RecoveryWitness();
            }
            // All-or-nothing coverage at the frozen root (settlement.rs:2020-2031).
            if (q.action == W.CLOSE) r.withdrawn = balance;
            else if (q.amount <= balance) r.withdrawn = q.amount;
            // Intake admitted only 20-byte destinations.
            r.destination = address(bytes20(request[q.destination:q.destination + 20]));
        }
        r.residual = balance - r.withdrawn;
        if (s.remainingStateLiability < balance) revert CustodyArithmetic();
        s.remainingStateLiability -= balance;
        s.accountClaimed[account] = true;
        s.credit[account] += r.residual;
        settledNow = _finish(s, unfinalizedDepositTotal);
    }

    /// @dev `finish_hard_fault_if_drained` (settlement.rs:2064-2082): settled once no state
    /// liability and no unfinalized deposit remains.
    function _finish(State storage s, uint64 unfinalizedDepositTotal) private returns (bool) {
        if (!s.started || s.remainingStateLiability != 0 || unfinalizedDepositTotal != 0) return false;
        s.started = false;
        s.settled = true;
        return true;
    }

    /// @notice Pay an account's credited recovery to `recipient`, authorized by the account's
    /// Ed25519 signature over `union_unique("_PARADIGMHACK_BAJILLION_RECOVERY", deployment ||
    /// recipient || u64 nonce)`. Our addition: upstream returns these amounts to the account and
    /// leaves the asset adapter to the embedding.
    function sweep(State storage s, bytes32 deployment, bytes32 account, address recipient, bytes calldata signature)
        external
        returns (uint64 amount)
    {
        amount = s.credit[account];
        if (amount == 0) revert NothingToRecover();
        uint64 nonce = s.sweepNonce[account];
        bytes memory message = abi.encodePacked(SWEEP_PREFIX, deployment, recipient, nonce);
        if (!Ed25519Verifier.isStrictKey(account) || !Ed25519Verifier.verify(account, signature, message)) {
            revert RecoverySignature();
        }
        s.sweepNonce[account] = nonce + 1;
        s.credit[account] = 0;
    }
}
