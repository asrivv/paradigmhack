// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { LibBLS12381 as BLS } from "commonware/certificate/LibBLS12381.sol";
import { LibBLS12381Multisig } from "commonware/certificate/LibBLS12381Multisig.sol";
import { LibMerkle } from "commonware/merkle/LibMerkle.sol";
import { LibQMDBCommon } from "commonware/qmdb/LibQMDBCommon.sol";
import { LibBLS12381Point } from "./LibBLS12381Point.sol";
import { LibBLS12381PoP } from "./LibBLS12381PoP.sol";
import { LibClearingCodec as Codec } from "./LibClearingCodec.sol";
import { LibVectorCommitment as Vector } from "./LibVectorCommitment.sol";
import { Epoch, Head } from "../BajillionTypes.sol";

/// @notice Linked-library entry points for the BLS checks BajillionSettlement performs. They live
/// outside the settlement contract so it stays under the EIP-170 code size limit; the checks are
/// unchanged from the inline versions they replace.
library CertificateVerifier {
    bytes internal constant HEADER_NAMESPACE = "_COMMONWARE_CLEARING_HEADER"; // admission/certificate.rs:14

    /// @notice `bls12381::Scheme::verify` (admission/certificate.rs:359-386) on the crate's
    /// certificate bytes: `u64 BE bit count || ceil(n/8) bitmap bytes || 48-byte compressed G1`.
    /// The bit count must equal `n`; `verifyMinSig` checks the bitmap length, unused high bits and
    /// popcount `>= q`. The uncompressed hint must compress to the certificate's signature.
    function verifyCertificate(
        bytes32 header,
        bytes calldata certificate,
        bytes calldata signature,
        BLS.G2Point[] calldata committee,
        uint256 quorum
    ) public view returns (bool) {
        uint256 n = committee.length;
        uint256 bitmapLength = (n + 7) >> 3;
        if (certificate.length != 8 + bitmapLength + 48) return false;
        if (Codec.readU64(certificate, 0) != n) return false;
        if (!LibBLS12381Point.matchesG1(certificate[8 + bitmapLength:], signature)) return false;
        return LibBLS12381Multisig.verifyMinSig(
            signature, certificate[8:8 + bitmapLength], committee, quorum, HEADER_NAMESPACE, abi.encodePacked(header)
        );
    }

    /// @notice Check one committee member's key hint and MinSig proof of possession.
    /// @return keyOk Whether `point` compresses to `key`.
    /// @return popOk Whether `popPoint` compresses to `pop` and proves possession of `point`.
    function verifyValidator(
        bytes memory key,
        BLS.G2Point memory point,
        bytes memory pop,
        bytes memory popPoint,
        bytes memory popNamespace
    ) public view returns (bool keyOk, bool popOk) {
        keyOk = key.length == 96 && LibBLS12381Point.matchesG2(key, point);
        if (!keyOk) return (false, false);
        popOk = LibBLS12381Point.matchesG1(pop, popPoint) && LibBLS12381PoP.verify(popPoint, point, popNamespace, key);
    }
}

/// @notice Linked-library entry point for payout openings, keeping commonware-sol's Merkle
/// reconstruction out of the settlement contract's bytecode.
library PayoutVerifier {
    /// @notice `WithdrawalClaim` decoding (transition.rs:1037-1047): `WithdrawalOutput`
    /// (`varint(len) || destination || u64 amount`), then `Opening` (`u64 start || varint leaves ||
    /// varint inactive_peaks || varint(count) || count * 32`), nothing trailing.
    function decodeClaim(bytes calldata claim, uint256 maxDestinationBytes)
        public
        pure
        returns (
            bool ok,
            uint256 outputEnd,
            uint64 amount,
            uint64 index,
            uint256 leaves,
            uint256 inactivePeaks,
            uint256 digestsAt
        )
    {
        uint256 destinationLength;
        uint256 pos;
        (destinationLength, pos, ok) = Codec.readVarint(claim, 0, 32);
        if (!ok || destinationLength > maxDestinationBytes) return (false, 0, 0, 0, 0, 0, 0);
        outputEnd = pos + destinationLength + 8;
        if (claim.length < outputEnd + 8) return (false, 0, 0, 0, 0, 0, 0);
        amount = Codec.readU64(claim, outputEnd - 8);
        index = Codec.readU64(claim, outputEnd);
        // `Opening::read_cfg` rejects a start that is not a valid MMR index (logs.rs:445-448).
        if (index >= (uint64(1) << 62)) return (false, 0, 0, 0, 0, 0, 0);
        pos = outputEnd + 8;
        (leaves, pos, ok) = Codec.readVarint(claim, pos, 64);
        if (!ok) return (false, 0, 0, 0, 0, 0, 0);
        (inactivePeaks, pos, ok) = Codec.readVarint(claim, pos, 64);
        if (!ok) return (false, 0, 0, 0, 0, 0, 0);
        uint256 count;
        (count, pos, ok) = Codec.readVarint(claim, pos, 32);
        if (!ok || count > 244 || claim.length - pos != count * 32) return (false, 0, 0, 0, 0, 0, 0);
        digestsAt = pos;
        ok = true;
    }

    /// @notice `LibQMDBCommon.verify` with the MMR family and SHA-256 (`address(2)`) over the
    /// operation `0x01 || claim[0:outputEnd]`. LibQMDBKeylessMMR.verify wraps the same function, but
    /// its `Proof calldata` struct cannot point into the crate's `WithdrawalClaim` encoding.
    function verifyPayout(
        bytes32 root,
        bytes calldata claim,
        uint256 outputEnd,
        uint64 index,
        uint256 leaves,
        uint256 inactivePeaks,
        uint256 digestsAt
    ) public view returns (bool) {
        bytes32[] calldata digests;
        uint256 digestCount = (claim.length - digestsAt) >> 5;
        assembly ("memory-safe") {
            digests.offset := add(claim.offset, digestsAt)
            digests.length := digestCount
        }
        return LibQMDBCommon.verify(
            root,
            bytes.concat(hex"01", claim[0:outputEnd]),
            leaves,
            index,
            digests,
            inactivePeaks,
            LibMerkle.Family.MMR,
            address(2)
        );
    }
}

/// @notice Linked-library entry points for admission checks that need no contract state.
library AdmissionVerifier {
    uint64 internal constant MMR_MAX_LEAVES = 1 << 62; // storage/src/merkle/mmr/mod.rs:110
    uint64 internal constant MMB_MAX_LEAVES = 0x4000_0000_0000_001E; // storage/src/merkle/mmb/mod.rs:161
    uint256 internal constant MAX_VECTOR_LENGTH = 1 << 24; // commitment.rs:28

    error TransitionCloseLimit();
    error TransitionLogRange();
    error TransitionWithdrawalOutputRoot();
    error TransitionLiabilityEquation();
    error TransitionLiabilityOverflow();

    /// @notice Inputs to the settlement-visible bounds of `validate_close_amounts`.
    struct CloseBounds {
        uint64 withdrawalTotal;
        uint64 maxRows; // CloseLimits.max_rows
        uint64 maxTotalEntries; // CloseLimits.max_total_entries
        uint64 maxWithdrawalTotal; // CloseLimits.max_withdrawal_total
        uint64 floorActivity;
        uint64 floorPayouts;
        uint64 headActivityOperations;
        uint64 headActivityFloor;
        uint64 headPayoutsOperations;
        uint64 headPayoutsFloor;
        uint64 headLiability;
        uint64 depositTotal;
        uint256 withdrawalCount;
        uint64 changeOperations;
        uint64 changeFloor;
        uint64 rowCount;
        uint64 outputOperations;
        uint64 outputFloor;
        uint64 successorOperations;
        uint64 successorSyncBoundary;
    }

    /// @notice `validate_close_amounts` after the boundary roots (transition.rs:1779-1805),
    /// including `RootBundle::activity_range` (transition.rs:154-186). Returns the selector of the
    /// first failing check, or zero with the successor liability.
    function closeBounds(CloseBounds memory c) public pure returns (bytes4 err, uint64 successorLiability) {
        if (c.withdrawalTotal > c.maxWithdrawalTotal) return (TransitionCloseLimit.selector, 0);
        {
            uint256 start = c.headActivityOperations;
            uint256 end = start + c.rowCount;
            if (c.changeOperations == 0) return (TransitionLogRange.selector, 0);
            uint256 commit = c.changeOperations - 1;
            if (
                c.changeOperations > MMR_MAX_LEAVES || start == 0 || end > commit || c.rowCount > c.maxRows
                    || c.rowCount > MAX_VECTOR_LENGTH || commit - end > c.maxTotalEntries
                    || (c.rowCount == 0 && end != commit) || c.changeFloor != c.floorActivity
                    || c.changeFloor < c.headActivityFloor || c.changeFloor >= start
            ) return (TransitionLogRange.selector, 0);
        }
        {
            // Payout log: one output per registered withdrawal plus the trailing commit.
            uint256 start = c.headPayoutsOperations;
            if (
                start + c.withdrawalCount + 1 != c.outputOperations || c.outputOperations > MMR_MAX_LEAVES
                    || c.outputFloor != c.floorPayouts || c.outputFloor < c.headPayoutsFloor || c.outputFloor >= start
                    || c.successorOperations == 0 || c.successorOperations > MMB_MAX_LEAVES
                    || c.successorSyncBoundary >= c.successorOperations
                    || (c.withdrawalCount == 0 && c.withdrawalTotal != 0)
            ) return (TransitionWithdrawalOutputRoot.selector, 0);
        }
        // `checked_successor_liability` (transition.rs:1842-1851).
        uint256 credited = uint256(c.headLiability) + c.depositTotal;
        if (credited < c.withdrawalTotal) return (TransitionLiabilityEquation.selector, 0);
        uint256 successor = credited - c.withdrawalTotal;
        if (successor > type(uint64).max) return (TransitionLiabilityOverflow.selector, 0);
        // forge-lint: disable-next-line(unsafe-typecast) bounded by the check above
        return (bytes4(0), uint64(successor));
    }

    /// @notice `CloseContext` encoding (transition.rs:870-882): `EpochContext` (transition.rs:690-699)
    /// from the stored registration and the deployment's fixed fields, then the predecessor state
    /// root, log heads, rows and liability from `hd`, both deadlines and the registration floors.
    function closeContext(
        Epoch storage rec,
        uint64 epoch,
        bytes32 operator,
        bytes32 deployment,
        bytes32 committee,
        Head memory hd
    ) public view returns (bytes memory) {
        uint64[8] memory l = rec.limits;
        bytes memory epochContext = abi.encodePacked(
            rec.anchor,
            epoch,
            operator,
            deployment,
            rec.depositRoot,
            rec.withdrawalRoot,
            abi.encodePacked(l[0], l[1], l[2], l[3], l[4], l[5], l[6], l[7]),
            committee
        );
        return bytes.concat(
            epochContext,
            abi.encodePacked(
                hd.stateRoot,
                hd.activity.root,
                hd.activity.operations,
                hd.activity.floor,
                hd.payouts.root,
                hd.payouts.operations,
                hd.payouts.floor
            ),
            abi.encodePacked(
                hd.rowsStart,
                hd.rowsEnd,
                hd.liability,
                rec.admissionDeadline,
                rec.challengeDeadline,
                rec.floorActivity,
                rec.floorPayouts
            )
        );
    }

    /// @notice `DepositBatch` decoding (boundary.rs:172-200): `varint(count) || count * (account ||
    /// u64)`, accounts strictly increasing by bytes, amounts positive, total in u64, nothing
    /// trailing. Returns the offset of the packed records.
    function decodeDeposits(bytes calldata encoded)
        public
        pure
        returns (bool ok, uint256 offset, uint256 count, uint64 total)
    {
        (uint256 n, uint256 pos, bool countOk) = Codec.readVarint(encoded, 0, 32);
        if (!countOk || n > MAX_VECTOR_LENGTH || encoded.length - pos != n * 40) return (false, 0, 0, 0);
        uint256 sum;
        bytes32 previous;
        for (uint256 i; i < n; ++i) {
            bytes32 account = Codec.readBytes32(encoded, pos + i * 40);
            uint64 amount = Codec.readU64(encoded, pos + i * 40 + 32);
            if (amount == 0 || (i > 0 && account <= previous)) return (false, 0, 0, 0);
            sum += amount;
            previous = account;
        }
        if (sum > type(uint64).max) return (false, 0, 0, 0);
        // forge-lint: disable-next-line(unsafe-typecast) bounded by the check above
        return (true, pos, n, uint64(sum));
    }

    /// @notice Replay the inbox chain over `pulled` (40-byte `account || amount` entries) and
    /// check that `records` is exactly the per-account aggregate of its deposits. A zero amount
    /// marks a chain-queued withdrawal, which is skipped here; the withdrawal checks read those
    /// entries from the same witness.
    /// @return ok False when an entry's account has no record or a record's sum differs.
    /// @return chain The chain value after the last entry, for the caller to compare.
    function pulledAggregate(bytes calldata records, uint256 count, bytes calldata pulled, bytes32 chain)
        public
        pure
        returns (bool ok, bytes32)
    {
        uint256 entries = pulled.length / 40;
        if (pulled.length != entries * 40) return (false, chain);
        uint256[] memory sums = new uint256[](count);
        for (uint256 k; k < entries; ++k) {
            bytes32 account = Codec.readBytes32(pulled, k * 40);
            uint64 amount = Codec.readU64(pulled, k * 40 + 32);
            chain = keccak256(abi.encodePacked(chain, account, amount));
            if (amount == 0) continue;
            (bool found, uint256 pos) = _findDeposit(records, count, account);
            if (!found) return (false, chain);
            sums[pos] += amount;
        }
        for (uint256 i; i < count; ++i) {
            if (sums[i] != Codec.readU64(records, i * 40 + 32)) return (false, chain);
        }
        return (true, chain);
    }

    /// @notice An account's deposits in the closes drained at terminal settlement: `batches[i]`
    /// is the `DepositBatch` encoding admitted for the close whose registered deposit root is
    /// `roots[i]`. Upstream keeps these batches (settlement.rs:1912-1928); the contract keeps only
    /// their roots, so a claimant supplies the batches, which admission published.
    /// @return ok False when a batch does not decode or does not match its root.
    function pipelineDeposit(bytes32 account, bytes[] calldata batches, bytes32[] calldata roots)
        public
        pure
        returns (bool ok, uint256 amount)
    {
        if (batches.length != roots.length) return (false, 0);
        for (uint256 i; i < batches.length; ++i) {
            bytes calldata batch = batches[i];
            (bool decoded, uint256 offset, uint256 count,) = decodeDeposits(batch);
            if (!decoded) return (false, 0);
            bytes calldata records = batch[offset:];
            if (Vector.depositRoot(records, count) != roots[i]) return (false, 0);
            (bool found, uint256 pos) = _findDeposit(records, count, account);
            if (found) amount += Codec.readU64(records, pos * 40 + 32);
        }
        return (true, amount);
    }

    /// @dev Binary search a sorted deposit batch (`DepositBatch::record_for`, boundary.rs:140-147).
    function _findDeposit(bytes calldata records, uint256 count, bytes32 account)
        private
        pure
        returns (bool found, uint256 pos)
    {
        uint256 lo;
        uint256 hi = count;
        while (lo < hi) {
            uint256 mid = (lo + hi) >> 1;
            bytes32 key = Codec.readBytes32(records, mid * 40);
            if (key == account) return (true, mid);
            if (key < account) lo = mid + 1;
            else hi = mid;
        }
        return (false, 0);
    }

    /// @notice `DepositBatch::root` (boundary.rs:155-163) over `count` packed 40-byte records.
    function depositRoot(bytes calldata records, uint256 count) public pure returns (bytes32) {
        return Vector.depositRoot(records, count);
    }
}
