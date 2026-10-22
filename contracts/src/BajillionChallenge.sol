// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { LibClearingCodec as Codec } from "./verify/LibClearingCodec.sol";
import { Ed25519Verifier } from "./verify/LibEd25519.sol";

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
/// Scope: `AckFork` is adjudicated. `HigherAckDebit` decodes but is not yet adjudicated, and
/// `HigherAckEntry` is rejected with `ChallengeKindUnsupported` until its edge-vector proofs are
/// ported.
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
        t.rangeStart = uint64(start);
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
