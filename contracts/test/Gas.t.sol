// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { BajillionSettlement } from "../src/BajillionSettlement.sol";
import { PayoutLogFixture } from "./Claims.t.sol";

/// @dev Per-method gas on the standard EVM schedule (local revm). Tempo prices new storage slots
/// at 250,000 gas, so these numbers understate first-write costs there; P2.3 measures on Moderato.
contract GasTest is PayoutLogFixture {
    function test_GasCoreMethods() public {
        bytes32 account = bytes32(uint256(0x0a) << 248);
        token.mint(address(this), 100);
        token.approve(address(settlement), 100);
        settlement.deposit(account, 100);
        vm.snapshotGasLastCall("BajillionSettlement", "deposit_firstForAccount");

        bytes memory batch = abi.encodePacked(uint8(1), account, uint64(100));
        bytes memory ctx = _epochContext(0, batch);
        settlement.registerEpoch(ctx, 1, batch, hex"00", abi.encodePacked(account, uint64(100)));
        vm.snapshotGasLastCall("BajillionSettlement", "registerEpoch_oneDeposit");

        BajillionSettlement.Admission memory a = _admission(batch, 0x03);
        settlement.admit(a);
        vm.snapshotGasLastCall("BajillionSettlement", "admit_n4_q2");

        vm.warp(_challengeDeadline(0) + 1);
        settlement.finalize();
        vm.snapshotGasLastCall("BajillionSettlement", "finalize");

        // The finalized close above already consumed payout location 1 (its commit), so the
        // synthetic log's output there is unclaimable; claim locations 3 then 2.
        _installLog(8, 0);
        bytes memory c = _claimBytes(3);
        uint64 hint = settlement.exposedPredecessor(3);
        settlement.claimWithdrawal(hint, c);
        vm.snapshotGasLastCall("BajillionSettlement", "claimWithdrawal_newRange_10leaves");
        c = _claimBytes(2);
        hint = settlement.exposedPredecessor(2);
        settlement.claimWithdrawal(hint, c);
        vm.snapshotGasLastCall("BajillionSettlement", "claimWithdrawal_mergeBoth_10leaves");
    }
}
