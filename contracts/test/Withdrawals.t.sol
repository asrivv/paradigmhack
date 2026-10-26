// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { BajillionSettlement } from "../src/BajillionSettlement.sol";
import { BajillionWithdrawals } from "../src/BajillionWithdrawals.sol";
import { MockTIP20 } from "./mocks/MockTIP20.sol";
import { Fixture } from "./utils/Fixture.sol";

/// @notice Invariants 5 and 6 on the production contract with the crate fixture epoch, whose
/// registration carries one signed withdrawal (account a, 10 units, deadline 400).
contract WithdrawalsTest is Test {
    uint256 internal constant BOND = 1_000;

    MockTIP20 internal token;
    BajillionSettlement internal settlement;
    bytes internal context;
    bytes internal withdrawals;

    function setUp() public {
        token = new MockTIP20();
        BajillionSettlement.DeploymentArgs memory d = Fixture.deploymentArgs(address(token), BOND);
        uint256 funding = uint256(d.genesis.liability) + BOND;
        token.mint(address(this), funding);
        token.approve(vm.computeCreateAddress(address(this), vm.getNonce(address(this))), funding);
        settlement = new BajillionSettlement(d);
        context = Fixture.hexFile("epoch_context");
        withdrawals = Fixture.hexFile("withdrawal_batch");
    }

    /// @dev Register, admit and finalize the fixture epoch at its recorded times.
    function _settleFixtureEpoch() internal {
        vm.warp(Fixture.uintAt(".scenario.timing.register_at"));
        settlement.registerEpoch(context, 0, Fixture.hexFile("deposit_batch"), withdrawals, "");
        vm.warp(Fixture.uintAt(".scenario.timing.admit_at"));
        settlement.admit(Fixture.admission());
        vm.warp(Fixture.uintAt(".scenario.timing.finalize_at"));
        assertEq(uint8(settlement.finalize()), uint8(BajillionSettlement.Status.Ok));
    }

    /// @dev Tokens held always equal active custody plus the claim reserve plus the bond.
    function _assertSolvent() internal view {
        assertEq(
            token.balanceOf(address(settlement)),
            uint256(settlement.custodyBalance()) + settlement.claimableBalance() + BOND,
            "held tokens cover custody, reserve and bond exactly"
        );
    }

    /// @notice Invariant 5: the reserve never goes negative and total paid never exceeds
    /// finalized withdrawals. Finalization moves exactly the certified withdrawal total from
    /// custody to the reserve; the one payout drains it to zero; a replay, a claim with a raised
    /// amount, and a claim against an empty reserve all fail without paying.
    function test_Inv05_Solvency() public {
        _assertSolvent();
        uint64 custodyBefore = settlement.custodyBalance();
        _settleFixtureEpoch();
        uint64 finalizedWithdrawals = uint64(Fixture.uintAt(".close.withdrawal_total"));
        assertEq(settlement.claimableBalance(), finalizedWithdrawals, "reserve is the certified total");
        assertEq(settlement.custodyBalance(), custodyBefore - finalizedWithdrawals);
        _assertSolvent();

        bytes memory claim = Fixture.hexFile("payout_claim");
        address destination = address(bytes20(Fixture.bytesAt(".payout_claim.destination")));

        // A raised amount changes the authenticated output, so the opening no longer verifies.
        bytes memory raised = bytes.concat(claim);
        raised[1 + 20 + 7] = bytes1(uint8(raised[1 + 20 + 7]) + 1);
        vm.expectRevert(BajillionSettlement.ClaimProof.selector);
        settlement.claimWithdrawal(0, raised);

        settlement.claimWithdrawal(0, claim);
        assertEq(token.balanceOf(destination), finalizedWithdrawals, "paid exactly the finalized withdrawal");
        assertEq(settlement.claimableBalance(), 0);
        _assertSolvent();

        vm.expectRevert(BajillionSettlement.ClaimUnavailable.selector);
        settlement.claimWithdrawal(0, claim);
        assertEq(token.balanceOf(destination), finalizedWithdrawals, "a replay pays nothing");
        _assertSolvent();
    }

    /// @notice Invariant 6: a signed withdrawal retried in a later epoch settles at most once.
    /// Admission consumes its replay id until its deadline, so carrying the same request again in
    /// epoch 2 fails `DuplicateWithdrawalAuthorization`; after the deadline the id is free, but the
    /// request is past its own notice window and fails `WithdrawalDeadlineTooSoon`. Its payout was
    /// claimable once.
    function test_Inv06_SingleSettlementOnRetry() public {
        _settleFixtureEpoch();
        settlement.claimWithdrawal(0, Fixture.hexFile("payout_claim"));
        bytes32 id = sha256(Fixture.hexFile("withdrawal_id_preimage"));
        assertEq(settlement.withdrawalReplayExpiry(id), 400, "admission consumed the id until its deadline");

        bytes memory retry = _epochContext(2, withdrawals);
        uint64 pulled = settlement.pulled();
        vm.expectRevert(BajillionSettlement.DuplicateWithdrawalAuthorization.selector);
        settlement.registerEpoch(retry, pulled, hex"00", withdrawals, "");

        vm.warp(400);
        vm.expectRevert(BajillionSettlement.WithdrawalDeadlineTooSoon.selector);
        settlement.registerEpoch(retry, pulled, hex"00", withdrawals, "");

        vm.expectRevert(BajillionSettlement.ClaimUnavailable.selector);
        settlement.claimWithdrawal(0, Fixture.hexFile("payout_claim"));
    }

    /// @dev The fixture context re-bound to `epoch` and the root of `batch`, anchor recomputed.
    function _epochContext(uint64 epoch, bytes memory batch) internal view returns (bytes memory out) {
        (bytes32 root,) = this.withdrawalRootOf(batch);
        out = bytes.concat(context);
        bytes memory e = abi.encodePacked(epoch);
        for (uint256 i; i < 8; ++i) {
            out[32 + i] = e[i];
        }
        for (uint256 i; i < 32; ++i) {
            out[136 + i] = root[i];
        }
        bytes32 anchor = sha256(
            bytes.concat(
                "_COMMONWARE_CLEARING_EPOCH_ANCHOR",
                _slice(out, 72, 104),
                _slice(out, 104, 136),
                root,
                e,
                _slice(out, 40, 72),
                _slice(out, 168, 264)
            )
        );
        for (uint256 i; i < 32; ++i) {
            out[i] = anchor[i];
        }
    }

    function withdrawalRootOf(bytes calldata batch) external pure returns (bytes32, uint256) {
        return BajillionWithdrawals.boundary(batch, 1024, 256);
    }

    function _slice(bytes memory data, uint256 start, uint256 end) internal pure returns (bytes memory out) {
        out = new bytes(end - start);
        for (uint256 i; i < out.length; ++i) {
            out[i] = data[start + i];
        }
    }
}
