// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { PayoutVerifier } from "./verify/BajillionVerifiers.sol";
import { LibClearingCodec as Codec } from "./verify/LibClearingCodec.sol";

/// @title Claimed payout ranges for BajillionSettlement
/// @notice A linked library holding the claimed-range map and `claim_withdrawal` from
/// `SettlementChain` (clearing/src/bajillion/settlement.rs:475-522, 1703-1736 at
/// commonwarexyz/monorepo dd6d60cb44fb3dc05cee1efa06d957ce30df1340). Its external functions run by
/// DELEGATECALL on a `State` in the settlement contract's storage. It exists to keep
/// BajillionSettlement under EIP-170.
/// @dev The crate keeps the ranges in an authenticated ordered map under `(deployment, start)`
/// and has the caller supply both neighbours (settlement.rs:475-483). Here the ranges form a
/// list linked by start, and the caller names only the predecessor, which the library checks in
/// O(1) against its own links. Errors share names and selectors with BajillionSettlement's.
library BajillionClaims {
    /// @notice One claimed range `[start, end)` of payout-log locations, keyed by `start`.
    struct Range {
        uint64 end;
        uint64 next;
    }

    struct State {
        /// Contiguous claims merge into one record, so a fully claimed history occupies one slot,
        /// and a merged successor is deleted (settlement.rs:1703-1709).
        mapping(uint64 => Range) ranges;
        /// Start of the first range, zero when empty; start of the last range.
        uint64 head;
        uint64 tail;
        uint64 count;
    }

    /// @notice The finalized payout log head (logs.rs:168-176).
    struct Head {
        bytes32 root;
        uint64 operations;
        uint64 floor;
    }

    error ClaimUnavailable();
    error ClaimReserve();
    error ClaimProof();
    error ClaimEncoding();
    error IneligibleDestination();

    /// @dev `mmr::Family::MAX_LEAVES` (storage/src/merkle/mmr/mod.rs:110).
    uint64 internal constant MMR_MAX_LEAVES = 1 << 62;

    /// @notice Record a finalized close's trailing Commit location as claimed, in the same
    /// transaction as finalization (settlement.rs:1616-1620). Always extends the last range, since
    /// every range ends at or below the previous payout count.
    function insertCommit(State storage s, uint64 index) external returns (bool ok) {
        (bool planned, uint64 start, uint64 end,, Range memory succ, uint64 afterStart) = _plan(s, index, s.tail);
        if (!planned) return false;
        _apply(s, index, s.tail, afterStart, start, end, succ);
        return true;
    }

    /// @notice Verify and consume one payout under the finalized payout head (`claim_withdrawal`,
    /// settlement.rs:1710-1736). The caller deducts `amount` from the claim reserve and pays it to
    /// `destination`; `index` is the consumed payout-log location.
    /// @param claimable The claim reserve before this claim.
    /// @param predecessor Start of the claimed range immediately before or containing the claimed
    /// location, or zero when no range starts at or before it.
    /// @param encoded The crate's `WithdrawalClaim` encoding (transition.rs:1024-1047).
    function claim(
        State storage s,
        Head memory hd,
        uint64 claimable,
        uint64 predecessor,
        bytes calldata encoded,
        uint256 maxDestinationBytes
    ) external returns (uint64 index, uint64 amount, address destination, uint64 start, uint64 end) {
        bool ok;
        uint256 outputEnd;
        uint256 leaves;
        uint256 inactivePeaks;
        uint256 digestsAt;
        (ok, outputEnd, amount, index, leaves, inactivePeaks, digestsAt) =
            PayoutVerifier.decodeClaim(encoded, maxDestinationBytes);
        if (!ok) revert ClaimEncoding();

        // ClaimedRange::insert and the neighbour bounds (settlement.rs:1716-1724).
        Range memory prior;
        Range memory succ;
        uint64 afterStart;
        (ok, start, end, prior, succ, afterStart) = _plan(s, index, predecessor);
        if (!ok || prior.end > hd.operations || succ.end > hd.operations || end > hd.operations) {
            revert ClaimUnavailable();
        }

        // `WithdrawalClaim::verify` -> `Opening::verify_payout` (transition.rs:1014-1021,
        // logs.rs:399-433), with the checks commonware-sol leaves to the caller: the location is
        // below the trailing commit, the proof covers the whole log, and its inactive peaks match
        // the head's floor.
        if (
            uint256(index) + 1 > uint256(hd.operations) - 1 || leaves != hd.operations
                || inactivePeaks != _inactivePeaks(hd.operations, hd.floor)
                || !PayoutVerifier.verifyPayout(hd.root, encoded, outputEnd, index, leaves, inactivePeaks, digestsAt)
        ) revert ClaimProof();
        if (claimable < amount) revert ClaimReserve();
        // The asset adapter's destination: exactly one 20-byte Tempo address.
        (uint256 length, uint256 pos,) = Codec.readVarint(encoded, 0, 32);
        if (length != 20) revert IneligibleDestination();
        destination = address(bytes20(encoded[pos:pos + 20]));

        _apply(s, index, predecessor, afterStart, start, end, succ);
    }

    /// @notice The start of the claimed range at or before `index`, walking the list. For callers
    /// building a `claim` hint.
    function predecessorOf(State storage s, uint64 index) external view returns (uint64 predecessor) {
        uint64 cursor = s.head;
        while (cursor != 0 && cursor <= index) {
            predecessor = cursor;
            cursor = s.ranges[cursor].next;
        }
    }

    /// @dev Resolve the neighbours of `index` from the list and run `ClaimedRange::insert`
    /// (settlement.rs:501-521) on them. A neighbour with `end == 0` is absent.
    function _plan(State storage s, uint64 index, uint64 predecessor)
        private
        view
        returns (bool ok, uint64 start, uint64 end, Range memory prior, Range memory succ, uint64 afterStart)
    {
        uint64 beforeStart;
        if (predecessor == 0) {
            afterStart = s.head;
            if (afterStart != 0 && afterStart <= index) return (false, 0, 0, prior, succ, 0);
        } else {
            prior = s.ranges[predecessor];
            if (prior.end == 0 || predecessor > index) return (false, 0, 0, prior, succ, 0);
            afterStart = prior.next;
            if (afterStart != 0 && afterStart <= index) return (false, 0, 0, prior, succ, 0);
            beforeStart = predecessor;
        }
        if (afterStart != 0) succ = s.ranges[afterStart];

        // ClaimedRange::insert. Stored ranges are valid by construction, so `is_valid` reduces to
        // the coverage checks.
        if (index == 0 || index >= MMR_MAX_LEAVES) return (false, 0, 0, prior, succ, afterStart);
        if (beforeStart != 0 && prior.end > index) return (false, 0, 0, prior, succ, afterStart);
        uint64 next = index + 1;
        start = beforeStart != 0 && prior.end == index ? beforeStart : index;
        end = afterStart != 0 && afterStart == next ? succ.end : next;
        return (true, start, end, prior, succ, afterStart);
    }

    /// @dev Upsert the merged range and delete a merged successor, keeping the list linked.
    /// `predecessor` and `afterStart` are the neighbours `_plan` resolved (zero when absent).
    function _apply(
        State storage s,
        uint64 index,
        uint64 predecessor,
        uint64 afterStart,
        uint64 start,
        uint64 end,
        Range memory succ
    ) private {
        bool mergeAfter = afterStart != 0 && afterStart == index + 1;
        uint64 next = mergeAfter ? succ.next : afterStart;
        if (predecessor != 0 && start == predecessor) {
            s.ranges[predecessor] = Range(end, next);
        } else {
            s.ranges[start] = Range(end, next);
            ++s.count;
            if (predecessor == 0) s.head = start;
            else s.ranges[predecessor].next = start;
        }
        if (mergeAfter) {
            delete s.ranges[afterStart];
            --s.count;
        }
        if (next == 0) s.tail = start;
    }

    /// @dev `mmr::Family::inactive_peaks` (storage/src/merkle/mod.rs:101-116): the number of
    /// leading peaks, largest first, whose cumulative leaf capacity stays at or below the floor.
    function _inactivePeaks(uint64 leaves, uint64 floor) private pure returns (uint256 count) {
        uint256 sum;
        for (uint256 i; i < 64; ++i) {
            uint256 capacity = uint256(1) << (63 - i);
            if (leaves & capacity == 0) continue;
            sum += capacity;
            if (sum > floor) break;
            ++count;
        }
    }
}
