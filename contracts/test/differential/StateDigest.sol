// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { BajillionSettlement as S } from "../../src/BajillionSettlement.sol";

/// @notice The differential oracle's observable-state digest (offchain/oracle/README.md, "State
/// digest"), computed from BajillionSettlement's public state. `stateDigest = sha256(preimage)`;
/// integers are big-endian, so `abi.encodePacked` of fixed-width types writes the layout directly.
library StateDigest {
    bytes internal constant TAG = "BAJILLION_ORACLE_STATE_V1";

    // Contract batch statuses (BajillionSettlement.sol: REGISTERED = 1 .. INVALIDATED = 4).
    uint8 private constant PENDING = 2;
    uint8 private constant CHALLENGED = 3;
    uint8 private constant INVALIDATED = 4;

    function digest(S s) internal view returns (bytes32) {
        return sha256(preimage(s));
    }

    function preimage(S s) internal view returns (bytes memory out) {
        uint64 expected = s.expectedEpoch();
        uint64 admitted = s.admittedEnd();
        uint64 registered = s.registeredEnd();
        // `now`, `nextRegistrationEpoch`, `nextAdmissionEpoch`, `expectedEpoch`, `intake`, `pulled`.
        // The two `next*` values cannot overflow here: the contract never admits or registers
        // epoch 2^64 - 1 (`EpochOverflow`).
        out = abi.encodePacked(TAG, uint64(block.timestamp), registered, admitted, expected, s.intake(), s.pulled());
        out = bytes.concat(out, _frontier(s, admitted, registered), _pending(s, expected, admitted));

        (bytes32 aRoot, uint64 aOps, uint64 aFloor) = s.finalizedActivity();
        (bytes32 pRoot, uint64 pOps, uint64 pFloor) = s.finalizedPayouts();
        out = bytes.concat(out, abi.encodePacked(aRoot, aOps, aFloor, pRoot, pOps, pFloor, s.currentStateRoot()));
        out = bytes.concat(out, _claimed(s));

        out = bytes.concat(
            out, abi.encodePacked(s.custodyBalance(), s.claimableBalance(), s.currentLiability()), _fault(s)
        );
    }

    /// @dev The registered epoch awaiting admission. After a hard fault the contract resets
    /// `registeredEnd` to the fence, so a frontier exists exactly when `registeredEnd > admittedEnd`.
    function _frontier(S s, uint64 admitted, uint64 registered) private view returns (bytes memory) {
        if (registered <= admitted) return abi.encodePacked(uint8(0));
        S.EpochView memory rec = s.epochRecord(admitted);
        return abi.encodePacked(uint8(1), admitted, rec.anchor, rec.admissionDeadline, rec.challengeDeadline);
    }

    /// @dev Admitted unfinalized closes, oldest first. Status 0 pending, 1 challenged,
    /// 2 invalidated; the challenge kind is the crate tag plus one (BajillionChallenge stores
    /// `HigherAckDebit = 0`, `HigherAckEntry = 1`, `AckFork = 2`), only while challenged.
    function _pending(S s, uint64 expected, uint64 admitted) private view returns (bytes memory out) {
        out = abi.encodePacked(uint32(admitted - expected));
        for (uint64 e = expected; e < admitted; ++e) {
            S.EpochView memory rec = s.epochRecord(e);
            uint8 code;
            uint8 kind;
            if (rec.status == CHALLENGED) (code, kind) = (1, rec.challengeKind + 1);
            else if (rec.status == INVALIDATED) code = 2;
            else require(rec.status == PENDING, "digest: pipeline record");
            out = bytes.concat(
                out, abi.encodePacked(rec.batchId, code, kind, rec.withdrawalTotal, rec.successorLiability)
            );
        }
    }

    /// @dev Claimed ranges in ascending start order, walked through the contract's linked list.
    function _claimed(S s) private view returns (bytes memory out) {
        (uint64 cursor,, uint64 count) = s.claimedRanges();
        out = abi.encodePacked(uint32(count));
        uint256 walked;
        while (cursor != 0) {
            (uint64 end, uint64 next) = s.claimed(cursor);
            out = bytes.concat(out, abi.encodePacked(cursor, end));
            cursor = next;
            ++walked;
        }
        require(walked == count, "digest: claimed list length");
    }

    /// @dev Fault reason (the contract's `FaultKind` already uses the oracle's numbering),
    /// `expiredAt`, the admission fence, and the earliest receipt-invalidated close.
    function _fault(S s) private view returns (bytes memory) {
        S.FaultKind kind = s.faultKind();
        bool faulted = kind != S.FaultKind.None;
        bytes32 invalid = s.invalidFrom();
        return abi.encodePacked(
            uint8(kind),
            s.faultExpiredAt(),
            faulted ? uint8(1) : uint8(0),
            faulted ? s.admissionFenceEpoch() : uint64(0),
            invalid != bytes32(0) ? uint8(1) : uint8(0),
            invalid
        );
    }
}
