// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

// Test harness. The production contract rejects nonempty withdrawal batches because it cannot yet
// verify their Ed25519 signatures (no EVM precompile). The harness differs from production in
// two places only:
// 1. `_withdrawalBoundary` decodes a nonempty `WithdrawalBatch` and computes its real vector root
//    and count, without verifying the account signatures. This lets the crate fixture epoch, which
//    carries one signed withdrawal, run through the production registration, admission,
//    finalization and claim code. Ed25519 withdrawal verification is the next step.
// 2. `exposedInstallPayouts` installs a finalized payout head for scenario tests that need more
//    payout outputs than the single fixture epoch has.

import { BajillionSettlement } from "../../src/BajillionSettlement.sol";
import { LibClearingCodec as Codec } from "../../src/verify/LibClearingCodec.sol";
import { LibVectorCommitment as Vector } from "../../src/verify/LibVectorCommitment.sol";

contract SettlementHarness is BajillionSettlement {
    constructor(DeploymentArgs memory d) BajillionSettlement(d) { }

    /// @dev `WithdrawalBatch` decoding (boundary.rs:588-615): `varint(count) || count * SignedWithdrawal`,
    /// each `account(32) || deployment(32) || varint(len) || destination || action || u64 deadline ||
    /// signature(64)` with action `0x01 || u64` (Amount) or `0x02` (Close) (boundary.rs:255-263,
    /// 338-343, 475-479). Signatures are NOT verified here.
    function _withdrawalBoundary(bytes calldata encoded) internal view override returns (bytes32 root, uint256 count) {
        (uint256 n, uint256 pos, bool ok) = Codec.readVarint(encoded, 0, 32);
        require(ok, "withdrawal batch count");
        bytes calldata records = encoded[pos:];
        uint256[] memory ends = new uint256[](n);
        uint256 cursor;
        for (uint256 i; i < n; ++i) {
            require(Codec.readBytes32(records, cursor + 32) == deployment, "withdrawal deployment");
            (uint256 length, uint256 next, bool lengthOk) = Codec.readVarint(records, cursor + 64, 32);
            require(lengthOk && length <= maxDestinationBytes, "withdrawal destination");
            cursor = next + length;
            uint8 action = uint8(records[cursor]);
            require(action == 1 || action == 2, "withdrawal action");
            cursor += (action == 1 ? 9 : 1) + 8 + 64;
            ends[i] = cursor;
        }
        require(cursor == records.length, "withdrawal batch length");
        return (Vector.withdrawalRoot(records, ends), n);
    }

    /// @dev Install a finalized payout head and its reserve, then record the trailing commit as
    /// `finalize` does (settlement.rs:1616-1620).
    function exposedInstallPayouts(bytes32 root, uint64 operations, uint64 floor, uint64 reserve) external {
        finalizedPayouts = LogHead(root, operations, floor);
        claimableBalance += reserve;
        uint64 commitIndex = operations - 1;
        (bool ok, uint64 start, uint64 end,, ClaimedRange memory succ, uint64 afterStart) =
            _planClaim(commitIndex, claimedTail);
        require(ok, "commit insert");
        _applyClaim(commitIndex, claimedTail, afterStart, start, end, succ);
    }

    /// @dev The predecessor-or-containing range start for `index`, found by walking the list.
    function exposedPredecessor(uint64 index) external view returns (uint64 predecessor) {
        uint64 cursor = claimedHead;
        while (cursor != 0 && cursor <= index) {
            predecessor = cursor;
            cursor = claimed[cursor].next;
        }
    }
}
