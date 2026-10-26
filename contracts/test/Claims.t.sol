// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";
import { BajillionSettlement } from "../src/BajillionSettlement.sol";
import { SettlementBase } from "./SettlementBase.sol";
import { SettlementHarness } from "./harness/SettlementHarness.sol";
import { ScenarioMMR } from "./utils/ScenarioMMR.sol";
import { MockTIP20 } from "./mocks/MockTIP20.sol";

/// @dev A synthetic finalized payout log from ScenarioMMR.
abstract contract PayoutLogFixture is SettlementBase {
    bytes[] internal ops;
    uint64 internal headFloor;
    uint256 internal outputs;

    function _destination(uint256 loc) internal pure returns (address) {
        return address(uint160(0xd000 + loc));
    }

    function _amount(uint256 loc) internal pure returns (uint64) {
        return uint64(100 + loc);
    }

    /// @dev Append `count` outputs and a trailing commit, then install the head in the harness.
    function _installLog(uint256 count, uint8 floor) internal {
        if (ops.length == 0) ops.push(ScenarioMMR.commit(0));
        uint64 reserve;
        for (uint256 i; i < count; ++i) {
            uint256 loc = ops.length;
            ops.push(ScenarioMMR.appendOutput(_destination(loc), _amount(loc)));
            reserve += _amount(loc);
            ++outputs;
        }
        ops.push(ScenarioMMR.commit(floor));
        headFloor = floor;
        bytes[] memory all = ops;
        uint256 inactive = ScenarioMMR.inactivePeaks(all.length, floor);
        token.mint(address(settlement), reserve);
        settlement.exposedInstallPayouts(ScenarioMMR.root(all, inactive), uint64(all.length), floor, reserve);
    }

    function _claimBytes(uint256 loc) internal view returns (bytes memory) {
        bytes[] memory all = ops;
        uint256 inactive = ScenarioMMR.inactivePeaks(all.length, headFloor);
        return ScenarioMMR.claim(
            _destination(loc), _amount(loc), uint64(loc), all.length, inactive, ScenarioMMR.proof(all, inactive, loc)
        );
    }

    function _claim(uint256 loc) internal returns (uint64 start, uint64 end) {
        bytes memory c = _claimBytes(loc);
        return settlement.claimWithdrawal(settlement.exposedPredecessor(uint64(loc)), c);
    }

    /// @dev Walk the list: ranges are nonempty, sorted, disjoint, maximal (never touching), and
    /// counted correctly. Returns the number of ranges.
    function _checkRanges() internal view returns (uint256 count) {
        (uint64 cursor,,) = settlement.claimedRanges();
        uint64 previousEnd;
        uint64 last;
        while (cursor != 0) {
            (uint64 end, uint64 next) = settlement.claimed(cursor);
            assertGt(cursor, 0, "location zero is never claimed");
            assertLt(cursor, end, "nonempty");
            if (count > 0) assertGt(cursor, previousEnd, "disjoint and not touching");
            previousEnd = end;
            last = cursor;
            cursor = next;
            ++count;
        }
        (, uint64 tail, uint64 stored) = settlement.claimedRanges();
        assertEq(count, stored, "count tracks the list");
        if (count > 0) assertEq(tail, last, "tail is the last range");
    }
}

contract ClaimsTest is PayoutLogFixture {
    uint256 internal constant U = 9;

    function setUp() public override {
        super.setUp();
        _installLog(U, 0);
    }

    /// @dev Every payout index pays at most once in any claim order, including replays with valid
    /// openings and refreshed proofs under a later head.
    function test_Inv03_SinglePayout() public {
        uint256[U] memory order = [uint256(5), 1, 9, 2, 8, 3, 7, 4, 6];
        uint256 paid;
        for (uint256 i; i < U; ++i) {
            uint256 loc = order[i];
            uint256 before = token.balanceOf(_destination(loc));
            _claim(loc);
            assertEq(token.balanceOf(_destination(loc)) - before, _amount(loc));
            paid += _amount(loc);

            // Replay with the same valid opening, under every possible hint.
            bytes memory c = _claimBytes(loc);
            uint64 hint = settlement.exposedPredecessor(uint64(loc));
            vm.expectRevert(BajillionSettlement.ClaimUnavailable.selector);
            settlement.claimWithdrawal(hint, c);
            vm.expectRevert(BajillionSettlement.ClaimUnavailable.selector);
            settlement.claimWithdrawal(0, c);
            vm.expectRevert(BajillionSettlement.ClaimUnavailable.selector);
            settlement.claimWithdrawal(uint64(loc), c);
            _checkRanges();
        }
        assertEq(settlement.claimableBalance(), 0);
        assertEq(token.balanceOf(address(settlement)), BOND, "only the bond remains");

        // A later head re-proves the same locations; they stay consumed.
        _installLog(3, 0);
        for (uint256 loc = 1; loc <= U; ++loc) {
            bytes memory c = _claimBytes(loc);
            uint64 hint = settlement.exposedPredecessor(uint64(loc));
            vm.expectRevert(BajillionSettlement.ClaimUnavailable.selector);
            settlement.claimWithdrawal(hint, c);
        }
        for (uint256 loc = U + 2; loc < U + 5; ++loc) {
            _claim(loc);
            paid += _amount(loc);
        }
        assertEq(settlement.claimableBalance(), 0);
        assertEq(paid, _totalOutputs(), "total paid equals finalized outputs");
    }

    function test_Inv03_RejectsForgedAndUnfinalizedClaims() public {
        // Tampered amount or destination fails the opening.
        bytes memory c = _claimBytes(3);
        c[5] ^= 0x01; // inside the destination
        vm.expectRevert(BajillionSettlement.ClaimProof.selector);
        settlement.claimWithdrawal(0, c);
        c = _claimBytes(3);
        c[28] ^= 0x01; // last byte of the amount
        vm.expectRevert(BajillionSettlement.ClaimProof.selector);
        settlement.claimWithdrawal(0, c);

        // An opening against a head that is not finalized: append an output without installing.
        ops.push(ScenarioMMR.appendOutput(_destination(99), 1));
        ops.push(ScenarioMMR.commit(0));
        bytes memory pending = _claimBytes(ops.length - 2);
        uint64 pendingHint = settlement.exposedPredecessor(uint64(ops.length - 2));
        vm.expectRevert(BajillionSettlement.ClaimUnavailable.selector);
        settlement.claimWithdrawal(pendingHint, pending);
        bytes memory reproved = _claimBytes(2);
        vm.expectRevert(BajillionSettlement.ClaimProof.selector);
        settlement.claimWithdrawal(0, reproved);
        ops.pop();
        ops.pop();

        // The trailing commit and the genesis commit are never payable.
        bytes memory commitClaim = _claimBytes(U + 1);
        bytes memory genesisClaim = _claimBytes(0);
        vm.expectRevert(BajillionSettlement.ClaimUnavailable.selector);
        settlement.claimWithdrawal(uint64(U + 1), commitClaim);
        vm.expectRevert(BajillionSettlement.ClaimUnavailable.selector);
        settlement.claimWithdrawal(0, genesisClaim);

        // Wrong leaf count or inactive-peak boundary.
        bytes32[] memory digests = new bytes32[](0);
        vm.expectRevert(BajillionSettlement.ClaimProof.selector);
        settlement.claimWithdrawal(0, ScenarioMMR.claim(_destination(1), _amount(1), 1, ops.length + 1, 0, digests));
        vm.expectRevert(BajillionSettlement.ClaimProof.selector);
        settlement.claimWithdrawal(0, ScenarioMMR.claim(_destination(1), _amount(1), 1, ops.length, 1, digests));

        // Malformed encodings.
        c = _claimBytes(1);
        vm.expectRevert(BajillionSettlement.ClaimEncoding.selector);
        settlement.claimWithdrawal(0, bytes.concat(c, hex"00"));
        bytes memory longDestination = abi.encodePacked(uint8(65), new bytes(65), uint64(1), uint64(1), hex"0b0000");
        vm.expectRevert(BajillionSettlement.ClaimEncoding.selector);
        settlement.claimWithdrawal(0, longDestination);
    }

    function test_Inv03_RejectsMisleadingHints() public {
        _claim(4);
        _claim(5); // ranges: [4, 6), [10, 11)
        bytes memory c3 = _claimBytes(3);
        bytes memory c7 = _claimBytes(7);
        bytes memory c5 = _claimBytes(5);
        // Hint at a location that starts no range.
        vm.expectRevert(BajillionSettlement.ClaimUnavailable.selector);
        settlement.claimWithdrawal(2, c3);
        // Hint after the index.
        vm.expectRevert(BajillionSettlement.ClaimUnavailable.selector);
        settlement.claimWithdrawal(4, c3);
        // Zero hint while a range starts before the index.
        vm.expectRevert(BajillionSettlement.ClaimUnavailable.selector);
        settlement.claimWithdrawal(0, c7);
        // Hint that skips the range containing the index cannot hide it.
        vm.expectRevert(BajillionSettlement.ClaimUnavailable.selector);
        settlement.claimWithdrawal(0, c5);
        // Correct hints succeed and merge with both neighbours.
        settlement.claimWithdrawal(0, c3);
        (uint64 start, uint64 end) = settlement.claimWithdrawal(3, _claimBytes(6));
        assertEq(start, 3);
        assertEq(end, 7);
        assertEq(_checkRanges(), 2);
    }

    function test_Inv03_ReserveBoundsPayment() public {
        // Drain the reserve accounting below one output with a second, unfunded head.
        SettlementHarness fresh = _deploy(_args());
        bytes[] memory log = new bytes[](3);
        log[0] = ScenarioMMR.commit(0);
        log[1] = ScenarioMMR.appendOutput(_destination(1), 50);
        log[2] = ScenarioMMR.commit(0);
        fresh.exposedInstallPayouts(ScenarioMMR.root(log, 0), 3, 0, 49);
        bytes memory c = ScenarioMMR.claim(_destination(1), 50, 1, 3, 0, ScenarioMMR.proof(log, 0, 1));
        vm.expectRevert(BajillionSettlement.ClaimReserve.selector);
        fresh.claimWithdrawal(0, c);
    }

    /// @dev A nonzero floor makes leading peaks inactive (storage/src/merkle/mod.rs:101-116).
    function test_Inv03_InactivePeaks() public {
        SettlementHarness fresh = _deploy(_args());
        settlement = fresh;
        delete ops;
        outputs = 0;
        _installLog(13, 8); // 15 leaves: peaks 8, 4, 2, 1; floor 8 makes one peak inactive.
        assertEq(ScenarioMMR.inactivePeaks(15, 8), 1);
        for (uint256 loc = 1; loc <= 13; ++loc) {
            _claim(loc);
        }
        assertEq(fresh.claimableBalance(), 0);
        assertEq(_checkRanges(), 1);
    }

    /// @dev Ranges stay disjoint, merge on contact, and number at most U + 1 with U unclaimed
    /// outputs (settlement.rs:475-483).
    function test_Inv04_ClaimedRanges() public {
        assertEq(_checkRanges(), 1, "the trailing commit");
        uint256[U] memory order = [uint256(2), 4, 6, 8, 1, 9, 3, 7, 5];
        for (uint256 i; i < U; ++i) {
            _claim(order[i]);
            uint256 unclaimed = U - (i + 1);
            assertLe(_checkRanges(), unclaimed + 1, "at most U + 1 ranges");
        }
        assertEq(_checkRanges(), 1, "contiguous history is one record");
        (uint64 end,) = settlement.claimed(1);
        assertEq(end, U + 2);
    }

    function testFuzz_Inv03_Inv04_AnyClaimOrder(uint256 seed) public {
        uint256[] memory order = new uint256[](U);
        for (uint256 i; i < U; ++i) {
            order[i] = i + 1;
        }
        for (uint256 i = U; i > 1; --i) {
            uint256 j = uint256(keccak256(abi.encode(seed, i))) % i;
            (order[i - 1], order[j]) = (order[j], order[i - 1]);
        }
        for (uint256 i; i < U; ++i) {
            _claim(order[i]);
            assertLe(_checkRanges(), U - i, "at most U + 1 ranges");
            if (i > 0) {
                bytes memory replay = _claimBytes(order[i - 1]);
                uint64 hint = settlement.exposedPredecessor(uint64(order[i - 1]));
                vm.expectRevert(BajillionSettlement.ClaimUnavailable.selector);
                settlement.claimWithdrawal(hint, replay);
            }
        }
        assertEq(settlement.claimableBalance(), 0);
    }

    function _totalOutputs() internal view returns (uint256 total) {
        for (uint256 loc = 1; loc < ops.length; ++loc) {
            if (ops[loc][0] == 0x01) total += _amount(loc);
        }
    }
}

/// @dev Fuzzes claim order, hints, replays and time against one payout log.
contract ClaimHandler is PayoutLogFixture {
    uint256 internal constant OUTPUTS = 12;
    mapping(uint256 => uint256) public paidCount;
    uint256 public totalPaid;
    uint256 public initialReserve;

    constructor(SettlementHarness s, MockTIP20 t) {
        settlement = s;
        token = t;
        _installLog(OUTPUTS, 0);
        initialReserve = settlement.claimableBalance();
    }

    function claim(uint256 seed, uint8 hintMode) external {
        uint256 loc = 1 + seed % OUTPUTS;
        bytes memory c = _claimBytes(loc);
        uint64 hint = settlement.exposedPredecessor(uint64(loc));
        if (hintMode % 4 == 1) hint = 0;
        else if (hintMode % 4 == 2) hint = uint64(loc);
        else if (hintMode % 4 == 3) hint = uint64(1 + uint256(hintMode) % (OUTPUTS + 1));
        try settlement.claimWithdrawal(hint, c) {
            ++paidCount[loc];
            totalPaid += _amount(loc);
        } catch { }
    }

    function warp(uint32 delta) external {
        vm.warp(block.timestamp + delta);
    }

    function unclaimed() external view returns (uint256 count) {
        for (uint256 loc = 1; loc <= OUTPUTS; ++loc) {
            if (paidCount[loc] == 0) ++count;
        }
    }

    function maxPaid() external view returns (uint256 m) {
        for (uint256 loc = 1; loc <= OUTPUTS; ++loc) {
            if (paidCount[loc] > m) m = paidCount[loc];
        }
    }

    function ranges() external view returns (uint256) {
        return _checkRanges();
    }

    function setUp() public pure override { }
}

contract ClaimInvariants is SettlementBase {
    ClaimHandler internal handler;

    function setUp() public override {
        super.setUp();
        handler = new ClaimHandler(settlement, token);
        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = ClaimHandler.claim.selector;
        selectors[1] = ClaimHandler.warp.selector;
        targetSelector(StdInvariant.FuzzSelector(address(handler), selectors));
        targetContract(address(handler));
    }

    /// @dev Guards against a vacuous run where no claim ever succeeds.
    function afterInvariant() public view {
        assertGt(handler.totalPaid(), 0, "handler paid nothing");
    }

    function invariant_Inv03_EachIndexPaidAtMostOnce() public view {
        assertLe(handler.maxPaid(), 1);
    }

    function invariant_Inv04_RangesDisjointAndBounded() public view {
        assertLe(handler.ranges(), handler.unclaimed() + 1);
    }

    function invariant_Inv05_ReserveNeverNegative() public view {
        assertEq(handler.totalPaid() + settlement.claimableBalance(), handler.initialReserve());
        assertEq(token.balanceOf(address(settlement)), uint256(BOND) + settlement.claimableBalance());
    }
}
