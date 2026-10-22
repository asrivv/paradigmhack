// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { BajillionSettlement } from "../src/BajillionSettlement.sol";
import { SettlementHarness } from "./harness/SettlementHarness.sol";
import { MockTIP20 } from "./mocks/MockTIP20.sol";
import { Fixture } from "./utils/Fixture.sol";
import { LibVectorCommitment } from "../src/verify/LibVectorCommitment.sol";

/// @notice Challenge adjudication against the crate's fixture epoch and challenge files.
/// The fixture epoch carries a signed withdrawal, so it runs on the harness (see Conformance.t.sol).
contract FixtureChallengeTest is Test {
    MockTIP20 internal token;
    SettlementHarness internal settlement;
    bytes32 internal batchId;
    bytes internal context;
    bytes internal roots;
    uint64 internal total;

    function setUp() public {
        token = new MockTIP20();
        BajillionSettlement.DeploymentArgs memory d = Fixture.deploymentArgs(address(token), 1_000);
        uint256 funding = uint256(d.genesis.liability) + d.bond;
        token.mint(address(this), funding);
        token.approve(vm.computeCreateAddress(address(this), vm.getNonce(address(this))), funding);
        settlement = new SettlementHarness(d);
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
        context = Fixture.hexFile("close_context");
        roots = Fixture.hexFile("root_bundle");
        total = uint64(Fixture.uintAt(".close.withdrawal_total"));
    }

    function _challenge(string memory file) internal returns (BajillionSettlement.Status, BajillionSettlement.Verdict) {
        return settlement.challenge(batchId, context, roots, total, Fixture.hexFile(file));
    }

    function _assertUnchallenged() internal view {
        assertEq(settlement.epochRecord(1).status, 2, "still pending");
        assertEq(uint8(settlement.faultKind()), 0, "no fault");
        assertEq(settlement.invalidFrom(), bytes32(0));
    }

    // ---- AckFork (challenge.rs:713-724) -------------------------------------------------------

    function test_AckForkProven() public {
        (BajillionSettlement.Status s, BajillionSettlement.Verdict v) = _challenge("challenge_ack_fork_proven");
        assertEq(uint8(s), uint8(BajillionSettlement.Status.Ok));
        assertEq(uint8(v), uint8(BajillionSettlement.Verdict.ProvenAckFork));
        BajillionSettlement.Epoch memory rec = settlement.epochRecord(1);
        assertEq(rec.status, 3, "challenged");
        assertEq(rec.challengeKind, 2, "AckFork tag");
        assertEq(uint8(settlement.faultKind()), uint8(BajillionSettlement.FaultKind.ProvenChallenge));
        assertEq(settlement.faultDetail(), batchId);
        assertEq(settlement.invalidFrom(), batchId);
        // The challenged close never finalizes, and a second challenge is refused.
        vm.warp(Fixture.uintAt(".scenario.timing.finalize_at"));
        vm.expectRevert(BajillionSettlement.BatchInvalidated.selector);
        settlement.finalize();
        vm.warp(Fixture.uintAt(".scenario.timing.admit_at"));
        bytes memory again = Fixture.hexFile("challenge_ack_fork_proven");
        vm.expectRevert(BajillionSettlement.AlreadyChallenged.selector);
        settlement.challenge(batchId, context, roots, total, again);
    }

    function test_AckForkNoContradiction() public {
        (BajillionSettlement.Status s, BajillionSettlement.Verdict v) =
            _challenge("challenge_ack_fork_no_contradiction");
        assertEq(uint8(s), uint8(BajillionSettlement.Status.Ok));
        assertEq(uint8(v), uint8(BajillionSettlement.Verdict.NoContradiction));
        _assertUnchallenged();
    }

    /// @dev Upstream checks only the operator countersignatures in a fork (challenge.rs:96-119);
    /// an operator signature made under the send namespace fails as InvalidOperatorSignature.
    function test_AckForkWrongOperatorRoleRejected() public {
        bytes memory encoded = Fixture.hexFile("challenge_ack_fork_wrong_operator_role");
        vm.expectRevert(BajillionSettlement.ChallengeInvalidOperatorSignature.selector);
        settlement.challenge(batchId, context, roots, total, encoded);
        _assertUnchallenged();
    }

    /// @dev A fork whose payer halves carry bad signatures is still proven: the payer signature is
    /// not checked for forks (challenge.rs:96-99).
    function test_AckForkIgnoresPayerSignatures() public {
        bytes memory encoded = Fixture.hexFile("challenge_ack_fork_proven");
        encoded[1 + 112] ^= 0x01; // left payer signature
        encoded[1 + 240 + 112] ^= 0x01; // right payer signature
        (, BajillionSettlement.Verdict v) = settlement.challenge(batchId, context, roots, total, encoded);
        assertEq(uint8(v), uint8(BajillionSettlement.Verdict.ProvenAckFork));
    }

    // ---- HigherAckDebit (challenge.rs:636-672) ------------------------------------------------

    function test_HigherAckDebitProven() public {
        (BajillionSettlement.Status s, BajillionSettlement.Verdict v) = _challenge("challenge_higher_ack_debit_proven");
        assertEq(uint8(s), uint8(BajillionSettlement.Status.Ok));
        assertEq(uint8(v), uint8(BajillionSettlement.Verdict.ProvenHigherAckDebit));
        assertEq(settlement.epochRecord(1).status, 3);
        assertEq(settlement.epochRecord(1).challengeKind, 0, "HigherAckDebit tag");
        assertEq(uint8(settlement.faultKind()), uint8(BajillionSettlement.FaultKind.ProvenChallenge));
    }

    function test_HigherAckDebitNoContradiction() public {
        (BajillionSettlement.Status s, BajillionSettlement.Verdict v) =
            _challenge("challenge_higher_ack_debit_no_contradiction");
        assertEq(uint8(s), uint8(BajillionSettlement.Status.Ok));
        assertEq(uint8(v), uint8(BajillionSettlement.Verdict.NoContradiction));
        _assertUnchallenged();
    }

    /// @dev `AckWitness::reconstruct` checks the payer signature under the send namespace first
    /// (challenge.rs:64-94): a payer signature made under the ack namespace is InvalidPayerSignature.
    function test_HigherAckDebitWrongPayerRoleRejected() public {
        bytes memory encoded = Fixture.hexFile("challenge_higher_ack_debit_wrong_payer_role");
        vm.expectRevert(BajillionSettlement.ChallengeInvalidPayerSignature.selector);
        settlement.challenge(batchId, context, roots, total, encoded);
        _assertUnchallenged();
    }

    /// @dev Tampering with the activity opening or the claimed terminal value fails the proof.
    function test_HigherAckDebitRejectsForgedActivityOpening() public {
        bytes memory proven = Fixture.hexFile("challenge_higher_ack_debit_proven");
        // Layout: tag(1) || AckWitness(240) || lookup tag(1) || ChangeValue(48) || Opening.
        bytes memory forged = bytes.concat(proven);
        forged[1 + 240 + 1 + 7] ^= 0x01; // terminal debit in the change value
        vm.expectRevert(BajillionSettlement.ChallengeActivity.selector);
        settlement.challenge(batchId, context, roots, total, forged);
        forged = bytes.concat(proven);
        forged[forged.length - 1] ^= 0x01; // last proof digest
        vm.expectRevert(BajillionSettlement.ChallengeActivity.selector);
        settlement.challenge(batchId, context, roots, total, forged);
        forged = bytes.concat(proven);
        forged[1 + 240 + 1 + 48 + 7] = 0x09; // opening start 9 lies outside the epoch rows [1, 5)
        vm.expectRevert(BajillionSettlement.ChallengeLookupOrder.selector);
        settlement.challenge(batchId, context, roots, total, forged);
        _assertUnchallenged();
    }

    function test_GasFixtureChallenges() public {
        uint256 snap = vm.snapshotState();
        bytes memory fork = Fixture.hexFile("challenge_ack_fork_proven");
        settlement.challenge(batchId, context, roots, total, fork);
        vm.snapshotGasLastCall("Challenges", "challenge_fixture_ackFork_proven");
        vm.revertToState(snap);
        bytes memory debit = Fixture.hexFile("challenge_higher_ack_debit_proven");
        settlement.challenge(batchId, context, roots, total, debit);
        vm.snapshotGasLastCall("Challenges", "challenge_fixture_higherAckDebit_proven");
    }

    // ---- Witness, encoding and timing ---------------------------------------------------------

    function test_RejectsWrongHeaderWitness() public {
        bytes memory encoded = Fixture.hexFile("challenge_ack_fork_proven");
        bytes memory badContext = bytes.concat(context);
        badContext[300] ^= 0x01;
        vm.expectRevert(BajillionSettlement.ChallengeHeaderRoot.selector);
        settlement.challenge(batchId, badContext, roots, total, encoded);
        bytes memory badRoots = bytes.concat(roots);
        badRoots[0] ^= 0x01;
        vm.expectRevert(BajillionSettlement.ChallengeHeaderRoot.selector);
        settlement.challenge(batchId, context, badRoots, total, encoded);
        vm.expectRevert(BajillionSettlement.ChallengeHeaderRoot.selector);
        settlement.challenge(batchId, context, roots, total + 1, encoded);
        vm.expectRevert(BajillionSettlement.NoPendingBatch.selector);
        settlement.challenge(keccak256("other"), context, roots, total, encoded);
        _assertUnchallenged();
    }

    /// @dev Every length is bounded before it is read, and malformed evidence changes no state.
    function test_RejectsMalformedEncodings() public {
        bytes memory fork = Fixture.hexFile("challenge_ack_fork_proven");
        bytes[] memory bad = new bytes[](7);
        bad[0] = "";
        bad[1] = bytes.concat(hex"04", fork); // unknown tag
        bad[2] = _slice(fork, 0, fork.length - 1); // truncated
        bad[3] = bytes.concat(fork, hex"00"); // trailing byte
        bad[4] = bytes.concat(fork);
        for (uint256 j; j < 32; ++j) {
            bad[4][1 + j] = j == 0 ? bytes1(0x01) : bytes1(0x00); // payer key = identity, not strict
        }
        bad[5] = hex"01"; // HigherAckDebit tag with no witness
        bad[6] = hex"03"; // AckFork tag with no witness
        for (uint256 i; i < bad.length; ++i) {
            vm.expectRevert(BajillionSettlement.ChallengeCodec.selector);
            settlement.challenge(batchId, context, roots, total, bad[i]);
        }
        vm.expectRevert(BajillionSettlement.ChallengeKindUnsupported.selector);
        settlement.challenge(batchId, context, roots, total, hex"02");
        bytes memory huge = new bytes(settlement.maxChallengeBytes() + 1);
        vm.expectRevert(BajillionSettlement.ChallengeTooLarge.selector);
        settlement.challenge(batchId, context, roots, total, huge);
        _assertUnchallenged();
    }

    /// @dev Challenges are accepted through the inclusive deadline (settlement.rs:1594-1596).
    function test_ChallengeAfterDeadlineRejected() public {
        bytes memory encoded = Fixture.hexFile("challenge_ack_fork_proven");
        uint256 deadline = Fixture.uintAt(".scenario.timing.challenge_deadline");
        vm.warp(deadline + 1);
        vm.expectRevert(BajillionSettlement.ChallengeExpired.selector);
        settlement.challenge(batchId, context, roots, total, encoded);
        vm.warp(deadline);
        (, BajillionSettlement.Verdict v) = settlement.challenge(batchId, context, roots, total, encoded);
        assertEq(uint8(v), uint8(BajillionSettlement.Verdict.ProvenAckFork));
    }

    /// @dev The fence still holds on the challenge path (Inv07): a call that observes an expiry
    /// commits the fence and returns a status instead of reverting, a proven challenge still
    /// lands after the fault (settlement.rs:1548-1556 observe, then adjudicate), and the first
    /// fault reason is kept.
    function test_ChallengeKeepsFenceSemantics() public {
        // Register epoch 2 right after admission: it becomes the frontier with a 10s deadline,
        // well inside epoch 1's challenge window.
        bytes memory ctx2 = _emptyEpochContext(2);
        settlement.registerEpoch(ctx2, 0, hex"00", hex"00", "");
        uint64 admissionDeadline = settlement.epochRecord(2).admissionDeadline;
        vm.warp(admissionDeadline + 1);

        bytes memory malformed = hex"03";
        vm.expectEmit(address(settlement));
        emit BajillionSettlement.Rejected(BajillionSettlement.ChallengeCodec.selector);
        (BajillionSettlement.Status s, BajillionSettlement.Verdict v) =
            settlement.challenge(batchId, context, roots, total, malformed);
        assertEq(uint8(s), uint8(BajillionSettlement.Status.Rejected));
        assertEq(uint8(v), uint8(BajillionSettlement.Verdict.NoContradiction));
        assertEq(uint8(settlement.faultKind()), uint8(BajillionSettlement.FaultKind.ExpiredRegistration));
        assertEq(settlement.registeredEnd(), 2, "registration dropped");
        assertEq(settlement.epochRecord(1).status, 2, "target untouched");

        (s, v) = _challenge("challenge_ack_fork_proven");
        assertEq(uint8(s), uint8(BajillionSettlement.Status.Ok));
        assertEq(uint8(v), uint8(BajillionSettlement.Verdict.ProvenAckFork));
        assertEq(settlement.epochRecord(1).status, 3);
        assertEq(
            uint8(settlement.faultKind()), uint8(BajillionSettlement.FaultKind.ExpiredRegistration), "first fault kept"
        );
        assertEq(settlement.invalidFrom(), batchId);
    }

    function _emptyEpochContext(uint64 epoch) internal view returns (bytes memory ctx) {
        bytes memory base = Fixture.hexFile("epoch_context");
        bytes memory body = abi.encodePacked(
            epoch,
            _slice(base, 40, 104), // operator, deployment
            _slice(base, 104, 136), // the fixture's deposit batch is empty: reuse its root
            LibVectorCommitment.emptyWithdrawalRoot(),
            _slice(base, 168, 264) // limits, committee
        );
        bytes32 anchor = sha256(
            abi.encodePacked(
                "_COMMONWARE_CLEARING_EPOCH_ANCHOR",
                _slice(base, 72, 104),
                _slice(base, 104, 136),
                LibVectorCommitment.emptyWithdrawalRoot(),
                epoch,
                _slice(base, 40, 72),
                _slice(base, 168, 232),
                _slice(base, 232, 264)
            )
        );
        ctx = abi.encodePacked(anchor, body);
    }

    function _slice(bytes memory b, uint256 from, uint256 to) internal pure returns (bytes memory out) {
        out = new bytes(to - from);
        for (uint256 i; i < out.length; ++i) {
            out[i] = b[from + i];
        }
    }
}
