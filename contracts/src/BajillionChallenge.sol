// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { LibMerkle } from "commonware/merkle/LibMerkle.sol";
import { LibQMDBCommon } from "commonware/qmdb/LibQMDBCommon.sol";
import { LibClearingCodec as Codec } from "./verify/LibClearingCodec.sol";
import { Ed25519Verifier } from "./verify/LibEd25519.sol";
import { BATCH_CHALLENGED, BATCH_INVALIDATED, EPOCH_RING_SIZE, Epoch } from "./BajillionTypes.sol";

/// @title Bajillion challenge adjudication
/// @notice A port of `challenge::adjudicate` and `challenge::decode_bounded` from Commonware's
/// commonware-clearing (clearing/src/bajillion/challenge.rs pos commonwarexyz/monorepo
/// dd6d60cb44fb3dc05cee1efa06d957ce30df1340). Deployed as a linked library so the settlement
/// contract stays under the EIP-170 code size limit.
///
/// Errors are returned as the selector of the settlement contract's custom error rather than
/// reverted, because the caller may already have committed the liveness fence and must then
/// return a status instead of reverting (settlement.rs:3-12). A zero selector means success.
///
/// Scope: `HigherAckDebit` and `AckFork` are adjudicated. `HigherAckEntry` decodes as a kind but is
/// rejected with `ChallengeKindUnsupported` until its edge-vector proofs are ported.
library BajillionChallenge {
    // ChallengeKind (challenge.rs:595-603), with the settlement codec tags of settlement.rs:2227-2233.
    uint8 internal constant HIGHER_ACK_DEBIT = 0;
    uint8 internal constant HIGHER_ACK_ENTRY = 1;
    uint8 internal constant ACK_FORK = 2;

    /// @dev `AckWitness` encoding (challenge.rs:121-143): payer(32) seq(8) debit(8) send_root(32)
    /// predecessor(32) payer_signature(64) operator_signature(64).
    uint256 internal constant ACK_WITNESS_SIZE = 240;
    /// @dev `AccountChange` encoding (state.rs:274-299): account(32) debit(8) seq(8) send_root(32).
    uint256 internal constant ACCOUNT_CHANGE_SIZE = 80;
    /// @dev `Opening` decodes pos most `MAX_PROOF_DIGESTS_PER_ELEMENT * 2` digests (logs.rs:450-455).
    uint256 internal constant MAX_OPENING_DIGESTS = 244;
    uint64 internal constant MMR_MAX_LEAVES = 1 << 62;

    bytes internal constant VECTOR_SEND_NAMESPACE = "_COMMONWARE_CLEARING_VECTOR_SEND"; // payment.rs:29
    bytes internal constant VECTOR_ACK_NAMESPACE = "_COMMONWARE_CLEARING_VECTOR_ACK"; // payment.rs:31

    // Error selectors, matching the custom errors declared by BajillionSettlement.
    error ChallengeCodec();
    error ChallengeKindUnsupported();
    error ChallengeLookupOrder();
    error ChallengeActivity();
    error ChallengeInvalidPayerSignature();
    error ChallengeInvalidOperatorSignature();
    error ChallengeHeaderRoot();
    error ChallengeTooLarge();
    error ChallengeExpired();
    error NoPendingBatch();
    error AlreadyChallenged();
    error BatchInvalidated();

    /// @notice What `challenge` needs from the settlement contract besides the evidence.
    struct Call {
        bytes32 batchId;
        bytes32 operator;
        uint64 now_;
        uint64 expectedEpoch;
        uint64 admittedEnd;
        uint64 maxBytes;
    }

    bytes internal constant HEADER_ROOT_NAMESPACE = "_COMMONWARE_CLEARING_HEADER_ROOT"; // transition.rs:38
    bytes internal constant BATCH_ID_NAMESPACE = "_COMMONWARE_CLEARING_BATCH_ID"; // transition.rs:36
    bytes internal constant EPOCH_ANCHOR_NAMESPACE = "_COMMONWARE_CLEARING_EPOCH_ANCHOR"; // transition.rs:40
    uint256 internal constant MAX_VECTOR_LENGTH = 1 << 24;

    /// @notice The payment context and certified activity range a challenge is judged against.
    /// `rangeValid` is false when `RootBundle::activity_range` failed for the target; upstream maps
    /// that failure to `LookupOrder` pos the point the range is first needed (challenge.rs:684-688).
    struct Target {
        bytes32 anchor;
        uint64 epoch;
        bytes32 operator;
        bool rangeValid;
        uint64 rangeStart;
        uint64 rangeEnd;
        bytes32 headRoot;
        uint64 headOperations;
        uint64 headFloor;
    }

    // -------------------------------------------------------------------------------------------
    // Entry point
    // -------------------------------------------------------------------------------------------

    /// @notice `challenge_encoded` after time is observed (settlement.rs:1559-1614), on the
    /// settlement contract's epoch ring: the outer byte bound, the structural decode, the target
    /// among admitted closes `[expectedEpoch, admittedEnd)`, its status and inclusive deadline, then
    /// adjudication. A proven challenge marks the target challenged and every later admitted close
    /// invalidated (settlement.rs:1604-1609); the caller records `invalid_from` and the hard fault.
    /// @return err A custom-error selector, or zero.
    /// @return proven Whether a contradiction was proven.
    /// @return kind The proven `ChallengeKind` tag.
    /// @return epoch The target's epoch.
    function challenge(
        mapping(uint256 => Epoch) storage epochs,
        Call memory c,
        bytes calldata context,
        bytes calldata roots,
        uint64 withdrawalTotal,
        bytes calldata encoded
    ) external returns (bytes4 err, bool proven, uint8 kind, uint64 epoch) {
        if (encoded.length > c.maxBytes) return (ChallengeTooLarge.selector, false, 0, 0);
        err = decode(encoded);
        if (err != bytes4(0)) return (err, false, 0, 0);
        epoch = c.expectedEpoch;
        while (epoch < c.admittedEnd && epochs[epoch % EPOCH_RING_SIZE].batchId != c.batchId) {
            ++epoch;
        }
        if (epoch == c.admittedEnd) return (NoPendingBatch.selector, false, 0, 0);
        Epoch storage rec = epochs[epoch % EPOCH_RING_SIZE];
        if (rec.status == BATCH_CHALLENGED) return (AlreadyChallenged.selector, false, 0, 0);
        if (rec.status == BATCH_INVALIDATED) return (BatchInvalidated.selector, false, 0, 0);
        if (c.now_ > rec.challengeDeadline) return (ChallengeExpired.selector, false, 0, 0);
        (err, proven, kind) = adjudicate(c.batchId, c.operator, context, roots, withdrawalTotal, encoded);
        if (err != bytes4(0) || !proven) return (err, false, 0, epoch);
        rec.status = BATCH_CHALLENGED;
        rec.challengeKind = kind;
        for (uint64 e = epoch + 1; e < c.admittedEnd; ++e) {
            epochs[e % EPOCH_RING_SIZE].status = BATCH_INVALIDATED;
        }
    }

    // -------------------------------------------------------------------------------------------
    // Decoding
    // -------------------------------------------------------------------------------------------

    /// @notice Structural decode of one challenge, as `Challenge::decode` does inside
    /// `decode_bounded` (challenge.rs:851-861): exact length, valid tags and option flags, opening
    /// bounds, and strict payer keys (`StrictVerifyingKey::read`, signing.rs:457-470). Every length
    /// is bounded before it is read. The caller checks the outer byte bound first.
    function decode(bytes calldata encoded) public view returns (bytes4 err) {
        if (encoded.length == 0) return ChallengeCodec.selector;
        uint8 tag = uint8(encoded[0]);
        uint256 pos = 1;
        bool ok;
        if (tag == 1) {
            (ok, pos) = _ackWitness(encoded, pos);
            if (!ok) return ChallengeCodec.selector;
            (ok, pos) = _accountLookup(encoded, pos);
            if (!ok) return ChallengeCodec.selector;
        } else if (tag == 2) {
            // HigherAckEntry: the EntryWitness and HigherEntryLookup codecs are not ported yet.
            return ChallengeKindUnsupported.selector;
        } else if (tag == 3) {
            (ok, pos) = _ackWitness(encoded, pos);
            if (!ok) return ChallengeCodec.selector;
            (ok, pos) = _ackWitness(encoded, pos);
            if (!ok) return ChallengeCodec.selector;
        } else {
            return ChallengeCodec.selector;
        }
        if (pos != encoded.length) return ChallengeCodec.selector;
        return bytes4(0);
    }

    function _ackWitness(bytes calldata encoded, uint256 pos) private view returns (bool ok, uint256 next) {
        if (encoded.length - pos < ACK_WITNESS_SIZE) return (false, 0);
        if (!Ed25519Verifier.isStrictKey(Codec.readBytes32(encoded, pos))) return (false, 0);
        return (true, pos + ACK_WITNESS_SIZE);
    }

    /// @dev `AccountLookup` (challenge.rs:383-395): `1 || ChangeOpening` or `2 || ChangeAbsence`.
    function _accountLookup(bytes calldata encoded, uint256 pos) private view returns (bool ok, uint256 next) {
        if (pos >= encoded.length) return (false, 0);
        uint8 tag = uint8(encoded[pos++]);
        if (tag == 1) {
            if (encoded.length - pos < 48) return (false, 0);
            return _opening(encoded, pos + 48);
        }
        if (tag != 2) return (false, 0);
        // ChangeAbsence (challenge.rs:296-302): Option<AccountChange> twice, then Option<Opening>.
        for (uint256 i; i < 2; ++i) {
            (ok, pos) = _optionFlag(encoded, pos);
            if (ok) {
                if (encoded.length - pos < ACCOUNT_CHANGE_SIZE) return (false, 0);
                // AccountChange::read decodes the account as a StrictVerifyingKey.
                if (!Ed25519Verifier.isStrictKey(Codec.readBytes32(encoded, pos))) return (false, 0);
                pos += ACCOUNT_CHANGE_SIZE;
            } else if (pos == 0) {
                return (false, 0);
            }
        }
        (ok, pos) = _optionFlag(encoded, pos);
        if (pos == 0) return (false, 0);
        if (ok) return _opening(encoded, pos);
        return (true, pos);
    }

    /// @dev `Option` flag: one byte, 0 or 1 (codec/src/types/primitives.rs:254-261). Returns
    /// `(isSome, next)`, with `next == 0` on a malformed flag.
    function _optionFlag(bytes calldata encoded, uint256 pos) private pure returns (bool some, uint256 next) {
        if (pos >= encoded.length) return (false, 0);
        uint8 flag = uint8(encoded[pos]);
        if (flag > 1) return (false, 0);
        return (flag == 1, pos + 1);
    }

    /// @dev `Opening` (logs.rs:435-456): u64 start (a valid MMR index), then `mmr::Proof`
    /// (varint leaves, varint inactive peaks, varint count, count digests, count <= 244).
    function _opening(bytes calldata encoded, uint256 pos) private pure returns (bool ok, uint256 next) {
        if (encoded.length - pos < 8) return (false, 0);
        if (Codec.readU64(encoded, pos) >= MMR_MAX_LEAVES) return (false, 0);
        pos += 8;
        uint256 value;
        (, pos, ok) = Codec.readVarint(encoded, pos, 64);
        if (!ok) return (false, 0);
        (, pos, ok) = Codec.readVarint(encoded, pos, 64);
        if (!ok) return (false, 0);
        (value, pos, ok) = Codec.readVarint(encoded, pos, 32);
        if (!ok || value > MAX_OPENING_DIGESTS || encoded.length - pos < value * 32) return (false, 0);
        return (true, pos + value * 32);
    }

    // -------------------------------------------------------------------------------------------
    // Adjudication (challenge.rs:624-728)
    // -------------------------------------------------------------------------------------------

    function _headerMatches(bytes32 batchId, bytes calldata context, bytes calldata roots, uint64 withdrawalTotal)
        private
        pure
        returns (bool)
    {
        // EpochContext offsets: anchor 0, epoch 32, operator 40, deployment 72, deposit root 104,
        // withdrawal root 136, limits 168, committee 232 (transition.rs:690-699, 533-544).
        bytes32 anchor = sha256(
            abi.encodePacked(
                EPOCH_ANCHOR_NAMESPACE,
                context[72:104],
                context[104:136],
                context[136:168],
                context[32:40],
                context[40:72],
                context[168:232],
                context[232:264]
            )
        );
        if (anchor != Codec.readBytes32(context, 0)) return false;
        bytes32 header = sha256(abi.encodePacked(HEADER_ROOT_NAMESPACE, context, roots, withdrawalTotal));
        return sha256(abi.encodePacked(BATCH_ID_NAMESPACE, header)) == batchId;
    }

    /// @dev The payment context and `RootBundle::activity_range` (transition.rs:154-186) of an
    /// authenticated target. CloseContext offsets: predecessor activity head at 296 (operations
    /// 328, floor 336), limits at 168 (max_rows 176, max_total_entries 200), floors at 432.
    function _target(bytes32 operator, bytes calldata context, bytes calldata roots)
        private
        pure
        returns (Target memory t)
    {
        t.anchor = Codec.readBytes32(context, 0);
        t.epoch = Codec.readU64(context, 32);
        t.operator = operator;
        t.headRoot = Codec.readBytes32(roots, 0);
        t.headOperations = Codec.readU64(roots, 32);
        t.headFloor = Codec.readU64(roots, 40);
        uint256 start = Codec.readU64(context, 328);
        uint256 rowCount = Codec.readU64(roots, 48);
        uint256 end = start + rowCount;
        // Upstream's `checked_add` fails on overflow; here `rangeValid` requires
        // `end < headOperations <= 2^62`, so a truncated value is only ever paired with
        // `rangeValid == false`, which is rejected before the range is used.
        // forge-lint: disable-next-line(unsafe-typecast)
        t.rangeStart = uint64(start);
        // forge-lint: disable-next-line(unsafe-typecast)
        t.rangeEnd = uint64(end);
        t.rangeValid = t.headOperations != 0
            && !(t.headOperations > MMR_MAX_LEAVES
                || start == 0
                || end > t.headOperations - 1
                || rowCount > Codec.readU64(context, 176)
                || rowCount > MAX_VECTOR_LENGTH
                || t.headOperations - 1 - end > Codec.readU64(context, 200)
                || (rowCount == 0 && end != t.headOperations - 1)
                || t.headFloor != Codec.readU64(context, 432)
                || t.headFloor < Codec.readU64(context, 336)
                || t.headFloor >= start);
    }

    /// @notice Adjudicate an already decoded challenge against the close whose batch id is
    /// `batchId`, given its `CloseContext` and `RootBundle` encodings. Returns an error selector, or
    /// zero with `proven` and the proven `kind`; `proven == false` is `Verdict::NoContradiction`.
    /// @dev The settlement contract stores only the batch id, so `Header::verify`
    /// (transition.rs:320-328), which upstream runs first in `adjudicate` (challenge.rs:631-633),
    /// authenticates the supplied context and roots: the anchor must bind the context's
    /// parameters and `BatchId(Header(context, roots, total))` must equal `batchId`.
    function adjudicate(
        bytes32 batchId,
        bytes32 operator,
        bytes calldata context,
        bytes calldata roots,
        uint64 withdrawalTotal,
        bytes calldata encoded
    ) public view returns (bytes4 err, bool proven, uint8 kind) {
        if (context.length != 448 || roots.length != 184 || !_headerMatches(batchId, context, roots, withdrawalTotal)) {
            return (ChallengeHeaderRoot.selector, false, 0);
        }
        Target memory target = _target(operator, context, roots);
        uint8 tag = uint8(encoded[0]);
        if (tag == 3) return _ackFork(target, encoded);
        if (tag == 1) return _higherAckDebit(target, encoded);
        return (ChallengeKindUnsupported.selector, false, 0);
    }

    /// @dev `Challenge::AckFork` (challenge.rs:713-724). Only the operator countersignatures are
    /// checked: `reconstruct_operator` (challenge.rs:96-119) deliberately skips the payer
    /// signature, because a fork is the operator's fault whoever produced the payer half.
    function _ackFork(Target memory target, bytes calldata encoded)
        private
        view
        returns (bytes4 err, bool proven, uint8 kind)
    {
        bytes calldata left = encoded[1:1 + ACK_WITNESS_SIZE];
        bytes calldata right = encoded[1 + ACK_WITNESS_SIZE:1 + 2 * ACK_WITNESS_SIZE];
        bytes memory leftMessage = _message(target, left);
        if (!Ed25519Verifier.verify(target.operator, left[176:240], _frame(VECTOR_ACK_NAMESPACE, leftMessage))) {
            return (ChallengeInvalidOperatorSignature.selector, false, 0);
        }
        bytes memory rightMessage = _message(target, right);
        if (!Ed25519Verifier.verify(target.operator, right[176:240], _frame(VECTOR_ACK_NAMESPACE, rightMessage))) {
            return (ChallengeInvalidOperatorSignature.selector, false, 0);
        }
        // Same payer and sequence, different (body, predecessor). The bodies share the context, so
        // comparing the full messages compares exactly the fields upstream compares.
        if (
            Codec.readBytes32(left, 0) == Codec.readBytes32(right, 0)
                && Codec.readU64(left, 32) == Codec.readU64(right, 32)
                && keccak256(leftMessage) != keccak256(rightMessage)
        ) return (bytes4(0), true, ACK_FORK);
        return (bytes4(0), false, 0);
    }

    /// @dev `Challenge::HigherAckDebit` (challenge.rs:636-672).
    function _higherAckDebit(Target memory target, bytes calldata encoded)
        private
        view
        returns (bytes4 err, bool proven, uint8 kind)
    {
        bytes calldata ack = encoded[1:1 + ACK_WITNESS_SIZE];
        // `AckWitness::reconstruct` (challenge.rs:64-94): payer signature, then operator.
        bytes memory message = _message(target, ack);
        bytes32 payer = Codec.readBytes32(ack, 0);
        if (!Ed25519Verifier.verify(payer, ack[112:176], _frame(VECTOR_SEND_NAMESPACE, message))) {
            return (ChallengeInvalidPayerSignature.selector, false, 0);
        }
        if (!Ed25519Verifier.verify(target.operator, ack[176:240], _frame(VECTOR_ACK_NAMESPACE, message))) {
            return (ChallengeInvalidOperatorSignature.selector, false, 0);
        }
        if (!target.rangeValid) return (ChallengeLookupOrder.selector, false, 0);

        (bytes4 lookupErr, uint64 terminalDebit, bool present, uint64 terminalSeq, bytes32 sendRoot) =
            _resolveAccount(target, encoded, 1 + ACK_WITNESS_SIZE, payer);
        if (lookupErr != bytes4(0)) return (lookupErr, false, 0);

        uint64 seq = Codec.readU64(ack, 32);
        uint64 debit = Codec.readU64(ack, 40);
        if (debit > terminalDebit) return (bytes4(0), true, HIGHER_ACK_DEBIT);
        // `has_outgoing` is `terminal_debit != 0` (state.rs:177-182); `matches_outgoing` compares
        // the row's terminal body with the acknowledged body (state.rs:190-204). The payer and the
        // context are already equal, so the bodies match iff seq, debit and send root match.
        if (present && terminalDebit != 0) {
            bool matches = seq == terminalSeq && debit == terminalDebit && Codec.readBytes32(ack, 48) == sendRoot;
            if (!matches) {
                if (seq == terminalSeq) return (bytes4(0), true, HIGHER_ACK_DEBIT);
                if (debit == terminalDebit && seq > terminalSeq) return (bytes4(0), true, HIGHER_ACK_DEBIT);
            }
        }
        return (bytes4(0), false, 0);
    }

    /// @dev `AccountLookup::resolve` (challenge.rs:323-345) and `ChangeAbsence::resolve`
    /// (challenge.rs:248-293).
    function _resolveAccount(Target memory target, bytes calldata encoded, uint256 pos, bytes32 account)
        private
        view
        returns (bytes4 err, uint64 terminalDebit, bool present, uint64 terminalSeq, bytes32 sendRoot)
    {
        uint8 tag = uint8(encoded[pos++]);
        if (tag == 1) {
            terminalDebit = Codec.readU64(encoded, pos);
            terminalSeq = Codec.readU64(encoded, pos + 8);
            sendRoot = Codec.readBytes32(encoded, pos + 16);
            uint64 start = Codec.readU64(encoded, pos + 48);
            if (!_contains(target, start, 1)) return (ChallengeLookupOrder.selector, 0, false, 0, 0);
            bytes[] memory rows = new bytes[](1);
            rows[0] = _rowOperation(account, encoded[pos:pos + 48]);
            if (!_verifyActivity(target, encoded, pos + 48, rows)) {
                return (ChallengeActivity.selector, 0, false, 0, 0);
            }
            return (bytes4(0), terminalDebit, true, terminalSeq, sendRoot);
        }
        return (_resolveAbsence(target, encoded, pos, account), 0, false, 0, 0);
    }

    function _resolveAbsence(Target memory target, bytes calldata encoded, uint256 pos, bytes32 account)
        private
        view
        returns (bytes4)
    {
        if (!_contains(target, target.rangeStart, 0)) return ChallengeLookupOrder.selector;
        bool hasPredecessor = encoded[pos] == 0x01;
        bytes calldata predecessor = encoded[0:0];
        if (hasPredecessor) predecessor = encoded[pos + 1:pos + 1 + ACCOUNT_CHANGE_SIZE];
        pos += hasPredecessor ? 1 + ACCOUNT_CHANGE_SIZE : 1;
        bool hasSuccessor = encoded[pos] == 0x01;
        bytes calldata successor = encoded[0:0];
        if (hasSuccessor) successor = encoded[pos + 1:pos + 1 + ACCOUNT_CHANGE_SIZE];
        pos += hasSuccessor ? 1 + ACCOUNT_CHANGE_SIZE : 1;
        bool hasOpening = encoded[pos] == 0x01;
        pos += 1;

        uint64 count = (hasPredecessor ? 1 : 0) + (hasSuccessor ? 1 : 0);
        if (count == 0) {
            return target.rangeStart == target.rangeEnd && !hasOpening ? bytes4(0) : ChallengeLookupOrder.selector;
        }
        if (!hasOpening) return ChallengeLookupOrder.selector;
        uint64 start = Codec.readU64(encoded, pos);
        if (
            !_contains(target, start, count) || (!hasPredecessor && start != target.rangeStart)
                || (!hasSuccessor && start + count != target.rangeEnd)
                || (hasPredecessor && Codec.readBytes32(predecessor, 0) >= account)
                || (hasSuccessor && Codec.readBytes32(successor, 0) <= account)
        ) return ChallengeLookupOrder.selector;
        bytes[] memory rows = new bytes[](count);
        uint256 i;
        if (hasPredecessor) rows[i++] = _rowOperation(Codec.readBytes32(predecessor, 0), predecessor[32:]);
        if (hasSuccessor) rows[i] = _rowOperation(Codec.readBytes32(successor, 0), successor[32:]);
        if (!_verifyActivity(target, encoded, pos, rows)) return ChallengeActivity.selector;
        return bytes4(0);
    }

    /// @dev `ActivityRange::contains` (transition.rs:201-209).
    function _contains(Target memory t, uint64 start, uint64 count) private pure returns (bool) {
        return t.rangeStart > 0 && t.rangeStart <= t.rangeEnd && t.headOperations <= MMR_MAX_LEAVES
            && t.rangeEnd < t.headOperations && t.headFloor < t.headOperations && start >= t.rangeStart
            && uint256(start) + count <= t.rangeEnd;
    }

    /// @dev `Opening::verify_activity` -> `Opening::verify` (logs.rs:381-433) for consecutive rows.
    function _verifyActivity(Target memory t, bytes calldata encoded, uint256 pos, bytes[] memory rows)
        private
        view
        returns (bool)
    {
        uint64 start = Codec.readU64(encoded, pos);
        (uint256 leaves, uint256 next,) = Codec.readVarint(encoded, pos + 8, 64);
        uint256 inactive;
        (inactive, next,) = Codec.readVarint(encoded, next, 64);
        uint256 count;
        (count, next,) = Codec.readVarint(encoded, next, 32);
        if (
            t.headOperations == 0 || t.headFloor >= t.headOperations || start >= MMR_MAX_LEAVES
                || uint256(start) + rows.length > t.headOperations - 1 || leaves != t.headOperations
                || inactive != _inactivePeaks(t.headOperations, t.headFloor)
        ) return false;
        bytes32[] calldata digests;
        assembly ("memory-safe") {
            digests.offset := add(encoded.offset, next)
            digests.length := count
        }
        (bytes32 root, bool valid) = LibQMDBCommon.reconstructRange(
            rows, leaves, start, digests, inactive, LibMerkle.RangeGraft(0, 0, 0, 0), LibMerkle.Family.MMR, address(2)
        );
        return valid && root == t.headRoot;
    }

    /// @dev `mmr::Family::inactive_peaks` (storage/src/merkle/mod.rs:101-116).
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

    /// @dev Keyless `Append(ActivityRecord::Row(row))`: `0x01 || 0x00 || account || value`
    /// (storage/src/qmdb/keyless/operation/variable.rs:15-26, logs.rs:63-75).
    function _rowOperation(bytes32 account, bytes calldata value) private pure returns (bytes memory) {
        return abi.encodePacked(hex"0100", account, value[0:48]);
    }

    /// @dev `VectorSendBody::message` (payment.rs:194-201): `anchor || epoch || payer || seq ||
    /// debit || send_root || predecessor`, with the anchor, epoch and operator from the context.
    function _message(Target memory t, bytes calldata witness) private pure returns (bytes memory) {
        return abi.encodePacked(t.anchor, t.epoch, witness[0:112]);
    }

    /// @dev `union_unique` framing (utils/src/lib.rs:183-192); both namespaces are under 128 bytes.
    function _frame(bytes memory namespace, bytes memory message) private pure returns (bytes memory) {
        return abi.encodePacked(uint8(namespace.length), namespace, message);
    }
}
