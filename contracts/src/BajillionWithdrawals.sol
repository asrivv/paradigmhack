// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { LibQMDBCurrent } from "commonware/qmdb/LibQMDBCurrent.sol";
import { Ed25519Verifier } from "./verify/LibEd25519.sol";
import { StateVerifier, WithdrawalCodec as W } from "./verify/WithdrawalVerifiers.sol";
import { LibClearingCodec as Codec } from "./verify/LibClearingCodec.sol";
import { EPOCH_RING_SIZE, Epoch } from "./BajillionTypes.sol";

/// @title Withdrawal bookkeeping for BajillionSettlement
/// @notice A linked library holding the withdrawal half of `SettlementChain`
/// (clearing/src/bajillion/settlement.rs at commonwarexyz/monorepo
/// dd6d60cb44fb3dc05cee1efa06d957ce30df1340): chain-queued requests, replay protection, the
/// intake battery, and the withdrawal checks of registration and admission. Its external
/// functions run by DELEGATECALL on a `State` that lives in the settlement contract's storage, so
/// the deployment keeps one address and one storage. It exists to keep BajillionSettlement under
/// EIP-170.
/// @dev Errors share their names, and so their selectors, with BajillionSettlement's.
library BajillionWithdrawals {
    /// @notice A chain-queued withdrawal awaiting admission (settlement.rs:289-296), one per
    /// account, in a list sorted by `(deadline, account bytes)` like `pending_withdrawal_deadlines`
    /// (settlement.rs:675-676).
    /// @dev `carriedBy` is the carrying epoch plus one. The request is carried while that epoch is
    /// still a live registration, `[admittedEnd, registeredEnd)`, so a hard fault, which drops
    /// every registration, uncarries it without a write (settlement.rs:855-857).
    struct Pending {
        uint64 index;
        uint64 deadline;
        uint64 carriedBy;
        bytes32 digest;
        bytes32 prev;
        bytes32 next;
    }

    struct State {
        /// Chain-queued requests by account. Account zero is not a strict key, so it marks an
        /// absent link.
        mapping(bytes32 => Pending) pending;
        bytes32 head;
        /// Replay protection (settlement.rs:660-661): an id stays consumed until its deadline.
        /// Upstream prunes ids whose deadline is `<= now` whenever it observes time, and its only
        /// reader is the intake check, which always runs after an observation at the same `now`.
        /// So "consumed while `deadline > now`" is the same predicate without the pruning writes.
        mapping(bytes32 => uint64) replayExpiry;
        /// An account's request in an epoch's registered batch, or zero: the high 192 bits of
        /// the request's keccak256 digest above its u64 deadline (see `carriedRecord`). Terminal
        /// claims match a supplied request against the digest. Epoch numbers are never
        /// registered twice, so entries need no clearing.
        mapping(uint64 => mapping(bytes32 => bytes32)) carried;
    }

    /// @notice Deployment parameters the intake battery reads.
    struct Config {
        bytes32 deployment;
        uint64 minimumNotice;
        uint64 maximumNotice;
        uint64 maxDestinationBytes;
    }

    /// @notice The epoch pipeline: admitted unfinalized closes are `[expectedEpoch, admittedEnd)`
    /// and live registrations `[admittedEnd, registeredEnd)`.
    struct Window {
        uint64 expectedEpoch;
        uint64 admittedEnd;
        uint64 registeredEnd;
    }

    error EpochOverflow();
    error WithdrawalWitness();
    error DestinationTooLarge();
    error IneligibleDestination();
    error WithdrawalOpening();
    error WithdrawalBalance();
    error DuplicateWithdrawal();
    error DuplicateWithdrawalAuthorization();
    error WithdrawalDeadlineTooSoon();
    error WithdrawalDeadlineTooLate();
    error BoundaryWrongContext();
    error BoundaryInvalidSignature();
    error StateProof();
    error WithdrawalEncoding();
    error StateOpeningEncoding();
    error WithdrawalOrder();

    /// @dev `WITHDRAWAL_SIGNATURE_NAMESPACE` (boundary.rs:20) framed by `union_unique`: varint(40).
    bytes internal constant SIGNATURE_PREFIX = "\x28_COMMONWARE_CLEARING_BOUNDARY_WITHDRAWAL";
    /// @dev Proof digests accepted in a state opening; the crate leaves the bound to the embedding.
    uint256 internal constant MAX_STATE_DIGESTS = 256;

    // ---------------------------------------------------------------------------------------
    // queue_withdrawal (settlement.rs:1129-1188)
    // ---------------------------------------------------------------------------------------

    /// @notice Decode the request and its opening, including the strict-key checks `P::read`
    /// performs. The crate decodes both before the call, so the contract runs this before
    /// observing time, and then `queue` in the same call.
    function decodeQueued(bytes calldata request, bytes calldata opening, uint64 maxDestinationBytes)
        external
        view
        returns (bytes32 account, uint64 deadline)
    {
        (bool ok, W.Request memory r) = W.decodeRequest(request, maxDestinationBytes);
        if (!ok || !Ed25519Verifier.isStrictKey(r.account)) revert WithdrawalEncoding();
        (bool openingOk, bytes32 opened,,,) = StateVerifier.decode(opening, MAX_STATE_DIGESTS);
        if (!openingOk || !Ed25519Verifier.isStrictKey(opened)) revert StateOpeningEncoding();
        return (r.account, r.deadline);
    }

    /// @notice Every `queue_withdrawal` check after time is observed, in upstream order, then the
    /// insertion. The caller has run `decodeQueued` on the same bytes, so the strict-key checks
    /// are not repeated, and it assigns `index` and appends it to the inbox.
    function queue(
        State storage s,
        Config memory c,
        Window memory w,
        uint64 now_,
        bytes32 stateRoot,
        bytes calldata request,
        bytes calldata opening,
        bytes32 predecessor,
        uint64 index
    ) external {
        (, W.Request memory r) = W.decodeRequest(request, c.maxDestinationBytes);
        _ensureEpochAvailable(w, r.action);
        _intake(s, c, now_, request, r);
        if (s.pending[r.account].deadline != 0 || _carriedElsewhere(s, w, r.account)) revert DuplicateWithdrawal();
        (, bytes32 account, uint64 balance, bytes32 nextKey, LibQMDBCurrent.Proof memory proof) =
            StateVerifier.decode(opening, MAX_STATE_DIGESTS);
        if (!StateVerifier.verify(stateRoot, account, balance, nextKey, proof)) revert StateProof();
        if (account != r.account) revert WithdrawalOpening();
        if (r.action == W.AMOUNT && r.amount > balance) revert WithdrawalBalance();
        _insert(s, r.account, r.deadline, predecessor);
        Pending storage p = s.pending[r.account];
        p.index = index;
        p.digest = r.digest;
        s.replayExpiry[r.id] = r.deadline;
    }

    // ---------------------------------------------------------------------------------------
    // register_epoch (settlement.rs:1323-1397) and admit (settlement.rs:1504-1522)
    // ---------------------------------------------------------------------------------------

    /// @notice Decode a `WithdrawalBatch` and return its vector root and request count.
    function boundary(bytes calldata encoded, uint256 maxRecords, uint64 maxDestinationBytes)
        external
        pure
        returns (bytes32 root, uint256 count)
    {
        (bool ok, W.Request[] memory requests, bytes32 batchRoot) =
            W.decodeBatch(encoded, maxRecords, maxDestinationBytes);
        if (!ok) revert WithdrawalEncoding();
        return (batchRoot, requests.length);
    }

    /// @notice The withdrawal checks of `register_epoch`, in order, then the carry bookkeeping:
    /// record the batch for `carried_withdrawal_deadline`, mark the chain-queued requests it
    /// carries verbatim (`mark_carried`, settlement.rs:441-458), drop the requests its extras
    /// supersede, and return `earliest_withdrawal` (settlement.rs:431-439), zero when empty.
    /// @param pulled The authenticated inbox witness for indices from `pulledStart`: 40-byte
    /// `account || amount` entries, amount zero for a chain-queued withdrawal. While operating,
    /// uncarried requests sit at or past `pulled`, so these are every request the pull reaches.
    /// @param latestChallengeDeadline The latest challenge deadline over the pipeline, the
    /// frontier, and the deadline this epoch would receive now.
    function register(
        State storage s,
        Config memory c,
        Window memory w,
        uint64 now_,
        bytes calldata encoded,
        uint256 maxRecords,
        bytes calldata pulled,
        uint64 pulledStart,
        uint64 latestChallengeDeadline
    ) external returns (uint64 earliest, bytes32 earliestAccount) {
        W.Request[] memory requests = _decodeBatch(encoded, maxRecords, c.maxDestinationBytes);
        for (uint256 k; k < pulled.length / 40; ++k) {
            if (Codec.readU64(pulled, k * 40 + 32) != 0) continue;
            bytes32 owed = Codec.readBytes32(pulled, k * 40);
            Pending storage p = s.pending[owed];
            if (p.deadline == 0 || p.index != pulledStart + k || _isCarried(p, w)) continue;
            if (!_batchHas(requests, owed, p.digest)) revert WithdrawalWitness();
        }
        bytes32[] memory superseded = new bytes32[](requests.length);
        uint256 n;
        for (uint256 i; i < requests.length; ++i) {
            W.Request memory r = requests[i];
            Pending storage p = s.pending[r.account];
            if (p.deadline != 0 && p.digest == r.digest) {
                if (_isCarried(p, w)) revert DuplicateWithdrawal();
                continue;
            }
            // A fresh extra runs the decode-time key check and the shared intake battery.
            if (!Ed25519Verifier.isStrictKey(r.account)) revert WithdrawalEncoding();
            _ensureEpochAvailable(w, r.action);
            _intake(s, c, now_, encoded, r);
            if (_carriedElsewhere(s, w, r.account)) revert DuplicateWithdrawal();
            if (p.deadline != 0) superseded[n++] = r.account;
            // Finalization runs one tick past the latest challenge deadline in the prefix, after
            // the expiry sweep, so the request needs a strictly later deadline.
            if (latestChallengeDeadline == type(uint64).max) revert EpochOverflow();
            if (r.deadline <= latestChallengeDeadline + 1) revert WithdrawalDeadlineTooSoon();
        }

        // `w.registeredEnd` is the epoch being registered.
        uint64 epoch = w.registeredEnd;
        for (uint256 i; i < requests.length; ++i) {
            W.Request memory r = requests[i];
            s.carried[epoch][r.account] = carriedRecord(r.digest, r.deadline);
            Pending storage p = s.pending[r.account];
            if (p.deadline != 0 && p.digest == r.digest) p.carriedBy = epoch + 1;
            if (earliest == 0 || _before(r.deadline, r.account, earliest, earliestAccount)) {
                (earliest, earliestAccount) = (r.deadline, r.account);
            }
        }
        for (uint256 i; i < n; ++i) {
            _remove(s, superseded[i]);
        }
    }

    /// @notice The admitted batch retires the chain-queued requests it carries and consumes every
    /// request's replay id until its deadline.
    function retire(State storage s, bytes calldata encoded, uint256 maxRecords, uint64 maxDestinationBytes) external {
        W.Request[] memory requests = _decodeBatch(encoded, maxRecords, maxDestinationBytes);
        for (uint256 i; i < requests.length; ++i) {
            W.Request memory r = requests[i];
            Pending storage p = s.pending[r.account];
            if (p.deadline != 0 && p.digest == r.digest) _remove(s, r.account);
            s.replayExpiry[r.id] = r.deadline;
        }
    }

    // ---------------------------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------------------------

    /// @notice `earliest_withdrawal_deadline` (settlement.rs:756-767): the smallest
    /// `(deadline, account)` over chain-queued requests and the admitted unfinalized closes
    /// `[expectedEpoch, admittedEnd)`. Requests carried only by registrations are not counted, as
    /// upstream. Zero deadline when none.
    function earliestDeadline(
        State storage s,
        mapping(uint256 => Epoch) storage epochs,
        uint64 expectedEpoch,
        uint64 admittedEnd
    ) external view returns (uint64 deadline, bytes32 account) {
        account = s.head;
        if (account != 0) deadline = s.pending[account].deadline;
        for (uint64 e = expectedEpoch; e < admittedEnd; ++e) {
            Epoch storage rec = epochs[e % EPOCH_RING_SIZE];
            uint64 d = rec.withdrawalDeadline;
            if (d != 0 && (deadline == 0 || _before(d, rec.withdrawalAccount, deadline, account))) {
                (deadline, account) = (d, rec.withdrawalAccount);
            }
        }
    }

    /// @notice `unfinalized_withdrawal_deadline` (settlement.rs:1061-1088): the account's
    /// chain-queued request, else one a live registration or an admitted unfinalized close
    /// carries, in that order. Zero when none.
    function unfinalizedDeadline(State storage s, Window memory w, bytes32 account) external view returns (uint64) {
        uint64 d = s.pending[account].deadline;
        if (d != 0) return d;
        // Upstream checks the frontier, then queued registrations, then the pipeline.
        for (uint64 e = w.admittedEnd; e < w.registeredEnd; ++e) {
            d = uint64(uint256(s.carried[e][account]));
            if (d != 0) return d;
        }
        for (uint64 e = w.expectedEpoch; e < w.admittedEnd; ++e) {
            d = uint64(uint256(s.carried[e][account]));
            if (d != 0) return d;
        }
        return 0;
    }

    // ---------------------------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------------------------

    function _decodeBatch(bytes calldata encoded, uint256 maxRecords, uint64 maxDestinationBytes)
        private
        pure
        returns (W.Request[] memory requests)
    {
        bool ok;
        (ok, requests,) = W.decodeBatch(encoded, maxRecords, maxDestinationBytes);
        if (!ok) revert WithdrawalEncoding();
    }

    /// @dev `ensure_withdrawal_epoch_available` (settlement.rs:951-962): an `Amount` needs two
    /// epochs past the next registration, a `Close` one.
    function _ensureEpochAvailable(Window memory w, uint8 action) private pure {
        if (uint256(w.registeredEnd) + (action == W.AMOUNT ? 2 : 1) > type(uint64).max) revert EpochOverflow();
    }

    /// @dev `ensure_withdrawal_intake` (settlement.rs:1090-1127), in its order. `encoded` holds
    /// the request at `r.start`.
    function _intake(State storage s, Config memory c, uint64 now_, bytes calldata encoded, W.Request memory r)
        private
        view
    {
        if (r.destinationLength > c.maxDestinationBytes) revert DestinationTooLarge();
        if (s.replayExpiry[r.id] > now_) revert DuplicateWithdrawalAuthorization();
        // `verify_deployment` (boundary.rs:446-452): context, then signature.
        if (r.deployment != c.deployment) revert BoundaryWrongContext();
        bytes memory message = bytes.concat(SIGNATURE_PREFIX, encoded[r.start + 32:r.end - 64]);
        if (!Ed25519Verifier.verify(r.account, encoded[r.end - 64:r.end], message)) revert BoundaryInvalidSignature();
        // The asset adapter pays one 20-byte Tempo address, so only those are eligible.
        if (r.destinationLength != 20) revert IneligibleDestination();
        uint256 earliest = uint256(now_) + c.minimumNotice;
        if (earliest > type(uint64).max || r.deadline < earliest) revert WithdrawalDeadlineTooSoon();
        uint256 latest = uint256(now_) + c.maximumNotice;
        if (latest > type(uint64).max) latest = type(uint64).max;
        if (r.deadline > latest) revert WithdrawalDeadlineTooLate();
    }

    /// @dev `carried_withdrawal_deadline(account).is_some()` (settlement.rs:1070-1088): live
    /// registrations and pipeline entries are exactly the epochs `[expectedEpoch, registeredEnd)`.
    function _carriedElsewhere(State storage s, Window memory w, bytes32 account) private view returns (bool) {
        for (uint64 e = w.expectedEpoch; e < w.registeredEnd; ++e) {
            if (s.carried[e][account] != 0) return true;
        }
        return false;
    }

    function _isCarried(Pending storage p, Window memory w) private view returns (bool) {
        uint64 by = p.carriedBy;
        return by != 0 && by - 1 >= w.admittedEnd && by - 1 < w.registeredEnd;
    }

    function _batchHas(W.Request[] memory requests, bytes32 account, bytes32 digest) private pure returns (bool) {
        for (uint256 i; i < requests.length; ++i) {
            if (requests[i].account == account) return requests[i].digest == digest;
        }
        return false;
    }

    /// @dev Insert after `predecessor` (zero for the head), checking the order on both sides.
    function _insert(State storage s, bytes32 account, uint64 deadline, bytes32 predecessor) private {
        bytes32 next;
        if (predecessor == 0) {
            next = s.head;
            s.head = account;
        } else {
            Pending storage p = s.pending[predecessor];
            if (p.deadline == 0 || !_before(p.deadline, predecessor, deadline, account)) revert WithdrawalOrder();
            next = p.next;
            p.next = account;
        }
        if (next != 0) {
            Pending storage n = s.pending[next];
            if (!_before(deadline, account, n.deadline, next)) revert WithdrawalOrder();
            n.prev = account;
        }
        s.pending[account] = Pending(0, deadline, 0, 0, predecessor, next);
    }

    function _remove(State storage s, bytes32 account) private {
        Pending storage p = s.pending[account];
        (bytes32 prev, bytes32 next) = (p.prev, p.next);
        if (prev == 0) s.head = next;
        else s.pending[prev].next = next;
        if (next != 0) s.pending[next].prev = prev;
        delete s.pending[account];
    }

    /// @notice The packed `carried` entry for a request: digest high bits, then the deadline. Never
    /// zero, since deadlines are positive.
    function carriedRecord(bytes32 digest, uint64 deadline) internal pure returns (bytes32) {
        return bytes32((uint256(digest) >> 64 << 64) | deadline);
    }

    /// @dev `(deadline, account)` order: deadline first, then account bytes, the derived order of
    /// `(u64, StrictVerifyingKey)` (cryptography/curve25519/src/signing.rs:288-292, 407).
    function _before(uint64 d1, bytes32 a1, uint64 d2, bytes32 a2) internal pure returns (bool) {
        return d1 < d2 || (d1 == d2 && a1 < a2);
    }
}
