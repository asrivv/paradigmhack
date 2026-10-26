// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { BajillionSettlement } from "../src/BajillionSettlement.sol";
import { MockTIP20 } from "./mocks/MockTIP20.sol";
import { Fixture } from "./utils/Fixture.sol";

/// @notice Invariant 8 on the production contract with crate fixtures: the fixture epoch is
/// admitted, a deposit waits unpulled, and the crate's proven fork challenge hard-faults the
/// deployment. Terminal settlement then freezes the genesis root (nothing finalized) and every
/// account recovers exactly once, through crate-produced `StateOpening`s.
contract RecoveryTest is Test {
    uint256 internal constant BOND = 1_000;
    uint64 internal constant DEPOSIT = 7;

    MockTIP20 internal token;
    BajillionSettlement internal settlement;
    bytes32 internal batchId;
    bytes32 internal a;
    bytes32 internal b;
    bytes internal requestA;
    address internal destination;

    function setUp() public {
        token = new MockTIP20();
        BajillionSettlement.DeploymentArgs memory d = Fixture.deploymentArgs(address(token), BOND);
        uint256 funding = uint256(d.genesis.liability) + BOND + DEPOSIT;
        token.mint(address(this), funding);
        token.approve(vm.computeCreateAddress(address(this), vm.getNonce(address(this))), funding);
        settlement = new BajillionSettlement(d);
        token.approve(address(settlement), DEPOSIT);
        a = Fixture.bytes32At(".scenario.accounts[0].account_key");
        b = Fixture.bytes32At(".scenario.accounts[1].account_key");
        // The fixture batch carries one request: `varint(1) || request`.
        bytes memory batch = Fixture.hexFile("withdrawal_batch");
        requestA = new bytes(batch.length - 1);
        for (uint256 i; i < requestA.length; ++i) {
            requestA[i] = batch[i + 1];
        }
        destination = address(bytes20(Fixture.bytesAt(".scenario.withdrawal.destination")));

        vm.warp(Fixture.uintAt(".scenario.timing.register_at"));
        settlement.registerEpoch(
            Fixture.hexFile("epoch_context"),
            0,
            Fixture.hexFile("deposit_batch"),
            Fixture.hexFile("withdrawal_batch"),
            ""
        );
        vm.warp(Fixture.uintAt(".scenario.timing.admit_at"));
        (, batchId) = settlement.admit(Fixture.admission());
        settlement.deposit(b, DEPOSIT);
        (, BajillionSettlement.Verdict v) = settlement.challenge(
            batchId,
            Fixture.hexFile("close_context"),
            Fixture.hexFile("root_bundle"),
            uint64(Fixture.uintAt(".close.withdrawal_total")),
            Fixture.hexFile("challenge_ack_fork_proven")
        );
        assertEq(uint8(v), uint8(BajillionSettlement.Verdict.ProvenAckFork));
        assertEq(uint8(settlement.faultKind()), uint8(BajillionSettlement.FaultKind.ProvenChallenge));
    }

    function _opening(string memory name) internal view returns (bytes memory) {
        return Fixture.hexFile(string.concat("state_opening_", name, "_genesis"));
    }

    function _credit(bytes32 account) internal view returns (uint64 amount) {
        (amount,) = settlement.recoveredCredit(account);
    }

    /// @dev Held tokens equal active custody, the claim reserve, unswept credits and the bond.
    function _assertSolvent() internal view {
        uint256 credits;
        for (uint256 i; i < 4; ++i) {
            (uint64 amount,) = settlement.recoveredCredit(
                Fixture.bytes32At(string.concat(".scenario.accounts[", vm.toString(i), "].account_key"))
            );
            credits += amount;
        }
        assertEq(
            token.balanceOf(address(settlement)),
            uint256(settlement.custodyBalance()) + settlement.claimableBalance() + credits + BOND,
            "held tokens cover custody, reserve, credits and bond"
        );
    }

    /// @notice Invariant 8: after a hard fault no close is admitted and every account recovers at
    /// most once.
    function test_Inv08_HardFaultTerminal() public {
        // No new work after the fault.
        vm.expectRevert(BajillionSettlement.OperatorHardFaulted.selector);
        settlement.admit(Fixture.admission());
        vm.expectRevert(BajillionSettlement.OperatorHardFaulted.selector);
        settlement.deposit(b, 1);
        // Claims wait for terminal settlement, which waits for nothing pending ahead of it.
        vm.expectRevert(BajillionSettlement.HardFaultSettlementNotStarted.selector);
        settlement.claimHardFault(_opening("a"), requestA);

        // The unpulled deposit refunds once, before settlement starts.
        (BajillionSettlement.Status s, uint64 refunded) = settlement.claimPendingDeposit(b, new bytes[](0));
        assertEq(uint8(s), uint8(BajillionSettlement.Status.Ok));
        assertEq(refunded, DEPOSIT);
        vm.expectRevert(BajillionSettlement.PendingDepositUnavailable.selector);
        settlement.claimPendingDeposit(b, new bytes[](0));
        _assertSolvent();

        // Freeze genesis and drain the challenged close, whose withdrawal routes at claim time.
        settlement.beginHardFaultSettlement();
        (bool started, bool settled, bytes32 frozen, uint64 remaining, uint64 from, uint64 to) = settlement.terminal();
        assertTrue(started && !settled);
        assertEq(frozen, bytes32(Fixture.hexFile("genesis_state_root")));
        assertEq(remaining, 200);
        assertEq(from, 1);
        assertEq(to, 2);
        assertEq(settlement.admittedEnd(), 1, "pipeline drained");
        settlement.beginHardFaultSettlement(); // idempotent

        // Account a: its drained-close withdrawal must be supplied verbatim.
        vm.expectRevert(BajillionSettlement.RecoveryWitness.selector);
        settlement.claimHardFault(_opening("a"), "");
        settlement.claimHardFault(_opening("a"), requestA);
        assertEq(token.balanceOf(destination), 10, "the signed withdrawal pays its destination");
        assertEq(_credit(a), 90, "the rest of a's frozen balance is credited");
        vm.expectRevert(BajillionSettlement.ClaimAlreadyConsumed.selector);
        settlement.claimHardFault(_opening("a"), requestA);
        _assertSolvent();

        settlement.claimHardFault(_opening("b"), "");
        settlement.claimHardFault(_opening("c"), "");
        settlement.claimHardFault(_opening("d"), "");
        assertEq(_credit(b), 40 + DEPOSIT, "b recovers its balance and its refunded deposit");
        (started, settled,, remaining,,) = settlement.terminal();
        assertTrue(settled && !started, "every liability claimed: settled");
        assertEq(remaining, 0);
        assertEq(settlement.custodyBalance(), 0);
        assertEq(settlement.currentLiability(), 0);
        _assertSolvent();

        // Settled: nothing further moves.
        vm.expectRevert(BajillionSettlement.HardFaultAlreadySettled.selector);
        settlement.claimHardFault(_opening("b"), "");
        vm.expectRevert(BajillionSettlement.HardFaultAlreadySettled.selector);
        settlement.claimPendingDeposit(b, new bytes[](0));
        vm.expectRevert(BajillionSettlement.HardFaultAlreadySettled.selector);
        settlement.beginHardFaultSettlement();
        vm.expectRevert(BajillionSettlement.HardFaultAlreadySettled.selector);
        settlement.finalize();
    }

    /// @notice A credit leaves only by the account's own signature, to the recipient it signed,
    /// once. The signature is the crate's (fixture `recovery_sweep_signature`).
    function test_SweepNeedsTheAccountSignature() public {
        settlement.claimPendingDeposit(b, new bytes[](0));
        settlement.beginHardFaultSettlement();
        settlement.claimHardFault(_opening("a"), requestA);
        bytes memory signature = Fixture.hexFile("recovery_sweep_signature");
        address recipient = address(bytes20(Fixture.bytesAt(".scenario.recovery.sweep_recipient")));

        vm.expectRevert(BajillionSettlement.RecoverySignature.selector);
        settlement.sweepRecovered(a, address(0xbad), signature);
        vm.expectRevert(BajillionSettlement.RecoverySignature.selector);
        settlement.sweepRecovered(b, recipient, signature);

        settlement.sweepRecovered(a, recipient, signature);
        assertEq(token.balanceOf(recipient), 90);
        (uint64 amount, uint64 nonce) = settlement.recoveredCredit(a);
        assertEq(amount, 0);
        assertEq(nonce, 1);
        vm.expectRevert(BajillionSettlement.NothingToRecover.selector);
        settlement.sweepRecovered(a, recipient, signature);
        _assertSolvent();
    }
}
