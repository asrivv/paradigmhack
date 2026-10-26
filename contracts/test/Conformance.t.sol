// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { BajillionSettlement } from "../src/BajillionSettlement.sol";
import { BajillionWithdrawals } from "../src/BajillionWithdrawals.sol";
import { SettlementHarness } from "./harness/SettlementHarness.sol";
import { MockTIP20 } from "./mocks/MockTIP20.sol";
import { Fixture } from "./utils/Fixture.sol";

/// @notice Invariant 9: crate fixtures (test/fixtures/, commonware-clearing at dd6d60cb) are
/// accepted byte for byte and every invalid variant is rejected.
/// @dev The fixture epoch carries one operator-carried signed withdrawal, verified at
/// registration. `SettlementHarness` adds test-only entry points and changes no production path.
contract ConformanceTest is Test {
    uint256 internal constant BOND = 1_000;
    bytes internal constant HEADER_ROOT_NAMESPACE = "_COMMONWARE_CLEARING_HEADER_ROOT";

    MockTIP20 internal token;
    SettlementHarness internal settlement;
    BajillionSettlement.DeploymentArgs internal args;

    function setUp() public {
        token = new MockTIP20();
        BajillionSettlement.DeploymentArgs memory d = Fixture.deploymentArgs(address(token), BOND);
        settlement = SettlementHarness(_deploy(d, true));
    }

    function _deploy(BajillionSettlement.DeploymentArgs memory d, bool harness) internal returns (address) {
        uint256 funding = uint256(d.genesis.liability) + d.bond;
        token.mint(address(this), funding);
        token.approve(vm.computeCreateAddress(address(this), vm.getNonce(address(this))), funding);
        return harness ? address(new SettlementHarness(d)) : address(new BajillionSettlement(d));
    }

    function _register() internal {
        vm.warp(Fixture.uintAt(".scenario.timing.register_at"));
        BajillionSettlement.Status s = settlement.registerEpoch(
            Fixture.hexFile("epoch_context"),
            0,
            Fixture.hexFile("deposit_batch"),
            Fixture.hexFile("withdrawal_batch"),
            ""
        );
        assertEq(uint8(s), uint8(BajillionSettlement.Status.Ok));
    }

    function _admit() internal {
        vm.warp(Fixture.uintAt(".scenario.timing.admit_at"));
        (BajillionSettlement.Status s,) = settlement.admit(Fixture.admission());
        assertEq(uint8(s), uint8(BajillionSettlement.Status.Ok));
    }

    // ---------------------------------------------------------------------------------------
    // Accepted byte for byte
    // ---------------------------------------------------------------------------------------

    function test_Inv09_Conformance() public {
        // Committee: the contract's commitment equals the crate's, over the crate's encoding.
        bytes memory committee = Fixture.hexFile("committee");
        assertEq(
            Fixture.hexFile("committee_commitment_preimage"), bytes.concat("_COMMONWARE_CLEARING_COMMITTEE", committee)
        );
        assertEq(settlement.committeeCommitment(), Fixture.bytes32At(".hashes.committee_commitment.digest"));
        assertEq(settlement.quorum(), Fixture.uintAt(".bls.quorum"));
        assertEq(settlement.currentStateRoot(), bytes32(Fixture.hexFile("genesis_state_root")));

        // Registration binds exactly the crate's CloseContext, including the bootstrap log heads.
        _register();
        bytes memory context = settlement.frontierContext();
        assertEq(context, Fixture.hexFile("close_context"), "CloseContext bytes");
        assertEq(settlement.epochRecord(1).admissionDeadline, Fixture.uintAt(".scenario.timing.admission_deadline"));
        assertEq(settlement.epochRecord(1).challengeDeadline, Fixture.uintAt(".scenario.timing.challenge_deadline"));

        // The header preimage the contract hashes is the crate's.
        BajillionSettlement.Admission memory a = Fixture.admission();
        bytes memory preimage = abi.encodePacked(HEADER_ROOT_NAMESPACE, context, a.roots, a.withdrawalTotal);
        assertEq(preimage, Fixture.hexFile("header_preimage"), "header preimage bytes");
        assertEq(sha256(preimage), a.header);

        // Admission accepts the crate's header, certificate and committee.
        vm.warp(Fixture.uintAt(".scenario.timing.admit_at"));
        (BajillionSettlement.Status s, bytes32 batchId) = settlement.admit(a);
        assertEq(uint8(s), uint8(BajillionSettlement.Status.Ok));
        assertEq(batchId, bytes32(Fixture.hexFile("batch_id")), "batch id");
        assertEq(settlement.head().liability, Fixture.uintAt(".close.successor_liability"));
        assertEq(settlement.head().rowsStart, Fixture.uintAt(".close.activity_range.start"));
        assertEq(settlement.head().rowsEnd, Fixture.uintAt(".close.activity_range.end"));

        // Finalization records the crate's commit location and payout head.
        vm.warp(Fixture.uintAt(".scenario.timing.challenge_deadline"));
        vm.expectRevert(BajillionSettlement.ChallengeWindowOpen.selector);
        settlement.finalize();
        vm.warp(Fixture.uintAt(".scenario.timing.finalize_at"));
        assertEq(uint8(settlement.finalize()), uint8(BajillionSettlement.Status.Ok));
        (bytes32 root, uint64 operations, uint64 floor) = settlement.finalizedPayouts();
        assertEq(root, Fixture.bytes32At(".payout_claim.payout_head.root"));
        assertEq(operations, Fixture.uintAt(".payout_claim.payout_head.operations"));
        assertEq(floor, Fixture.uintAt(".payout_claim.payout_head.floor"));
        uint64 commit = uint64(Fixture.uintAt(".payout_claim.finalized_commit_index"));
        (uint64 commitEnd,) = settlement.claimed(commit);
        assertEq(commitEnd, commit + 1, "trailing commit consumed");
        assertEq(settlement.claimableBalance(), Fixture.uintAt(".close.withdrawal_total"));

        // The crate's payout opening verifies against the crate's payout head and pays once.
        bytes memory claim = Fixture.hexFile("payout_claim");
        assertEq(Fixture.hexFile("payout_opening").length + 29, claim.length);
        (uint64 start, uint64 end) = settlement.claimWithdrawal(0, claim);
        assertEq(start, Fixture.uintAt(".payout_claim.claimed_range_after.start"));
        assertEq(end, Fixture.uintAt(".payout_claim.claimed_range_after.end"));
        address destination = address(bytes20(Fixture.bytesAt(".payout_claim.destination")));
        assertEq(token.balanceOf(destination), Fixture.uintAt(".payout_claim.amount"));
        vm.expectRevert(BajillionSettlement.ClaimUnavailable.selector);
        settlement.claimWithdrawal(0, claim);
        assertEq(settlement.claimableBalance(), 0);
    }

    /// @dev Production verifies the fixture's crate-signed withdrawal at registration (ZIP215
    /// Ed25519) and rejects it once one signature byte changes.
    function test_Inv09_ProductionVerifiesSignedWithdrawal() public {
        bytes memory context = Fixture.hexFile("epoch_context");
        bytes memory deposits = Fixture.hexFile("deposit_batch");
        bytes memory withdrawals = Fixture.hexFile("withdrawal_batch");
        vm.warp(Fixture.uintAt(".scenario.timing.register_at"));

        BajillionSettlement production =
            BajillionSettlement(_deploy(Fixture.deploymentArgs(address(token), BOND), false));
        // A context that binds the tampered batch, with its anchor recomputed, so the request
        // reaches the signature check (a mismatched root fails `BoundaryRoot` first).
        bytes memory tampered = bytes.concat(withdrawals);
        tampered[tampered.length - 1] ^= 0x01;
        (bytes32 root,) = this.withdrawalRootOf(tampered);
        bytes memory rebound = bytes.concat(context);
        for (uint256 i; i < 32; ++i) {
            rebound[136 + i] = root[i];
        }
        bytes32 anchor = sha256(
            bytes.concat(
                "_COMMONWARE_CLEARING_EPOCH_ANCHOR",
                _slice(context, 72, 104),
                _slice(context, 104, 136),
                root,
                _slice(context, 32, 40),
                _slice(context, 40, 72),
                _slice(context, 168, 264)
            )
        );
        for (uint256 i; i < 32; ++i) {
            rebound[i] = anchor[i];
        }
        vm.expectRevert(BajillionSettlement.BoundaryInvalidSignature.selector);
        production.registerEpoch(rebound, 0, deposits, tampered, "");

        assertEq(
            uint8(production.registerEpoch(context, 0, deposits, withdrawals, "")), uint8(BajillionSettlement.Status.Ok)
        );
        assertEq(production.carriedWithdrawalDeadline(1, Fixture.bytes32At(".scenario.accounts[0].account_key")), 400);
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

    // ---------------------------------------------------------------------------------------
    // Every invalid variant rejected
    // ---------------------------------------------------------------------------------------

    function test_Inv09_RejectsMutatedEpochContext() public {
        vm.warp(Fixture.uintAt(".scenario.timing.register_at"));
        bytes memory deposits = Fixture.hexFile("deposit_batch");
        bytes memory withdrawals = Fixture.hexFile("withdrawal_batch");
        // Offset of one byte inside each EpochContext field, and the error its change must raise.
        uint256[8] memory offsets = [uint256(0), 39, 40, 72, 104, 136, 168, 232];
        bytes4[8] memory errors = [
            BajillionSettlement.TransitionEpochAnchor.selector,
            BajillionSettlement.EpochSequence.selector,
            BajillionSettlement.OperatorMismatch.selector,
            BajillionSettlement.Deployment.selector,
            BajillionSettlement.BoundaryRoot.selector,
            BajillionSettlement.BoundaryRoot.selector,
            BajillionSettlement.TransitionEpochAnchor.selector,
            BajillionSettlement.CommitteeMismatch.selector
        ];
        for (uint256 i; i < offsets.length; ++i) {
            bytes memory context = Fixture.hexFile("epoch_context");
            context[offsets[i]] ^= 0x01;
            vm.expectRevert(errors[i]);
            settlement.registerEpoch(context, 0, deposits, withdrawals, "");
        }
        bytes memory valid = Fixture.hexFile("epoch_context");
        bytes memory badWithdrawals = Fixture.hexFile("withdrawal_batch");
        badWithdrawals[badWithdrawals.length - 1] ^= 0x01; // inside the account signature
        vm.expectRevert(BajillionSettlement.BoundaryRoot.selector);
        settlement.registerEpoch(valid, 0, deposits, badWithdrawals, "");
    }

    function test_Inv09_RejectsMutatedHeaderRootsAndTotal() public {
        _register();
        vm.warp(Fixture.uintAt(".scenario.timing.admit_at"));
        BajillionSettlement.Admission memory a = Fixture.admission();
        for (uint256 i; i < 32; ++i) {
            a.header ^= bytes32(uint256(1) << (8 * i));
            vm.expectRevert(BajillionSettlement.TransitionHeaderRoot.selector);
            settlement.admit(a);
            a.header ^= bytes32(uint256(1) << (8 * i));
        }
        for (uint256 i; i < a.roots.length; ++i) {
            a.roots[i] ^= 0x01;
            _expectAdmitRejected(
                a, BajillionSettlement.TransitionHeaderRoot.selector, BajillionSettlement.RootsEncoding.selector
            );
            a.roots[i] ^= 0x01;
        }
        a.withdrawalTotal += 1;
        vm.expectRevert(BajillionSettlement.TransitionHeaderRoot.selector);
        settlement.admit(a);
        a.withdrawalTotal -= 2;
        vm.expectRevert(BajillionSettlement.TransitionHeaderRoot.selector);
        settlement.admit(a);
    }

    function test_Inv09_RejectsMutatedCertificate() public {
        _register();
        vm.warp(Fixture.uintAt(".scenario.timing.admit_at"));
        BajillionSettlement.Admission memory a = Fixture.admission();
        // Every byte of the bit-count prefix, bitmap and compressed signature, and every bitmap bit.
        for (uint256 i; i < a.certificate.length; ++i) {
            uint256 bits = i == 8 ? 8 : 1;
            for (uint256 bit; bit < bits; ++bit) {
                a.certificate[i] ^= bytes1(uint8(1 << bit));
                vm.expectRevert(BajillionSettlement.InvalidCertificate.selector);
                settlement.admit(a);
                a.certificate[i] ^= bytes1(uint8(1 << bit));
            }
        }
        // A flipped hint coordinate is usually not a curve point. commonware-sol's pairing call
        // forwards all gas, and an EIP-2537 precompile error consumes everything it was given, so
        // each such call is capped here to keep the loop within the test gas limit. The call still
        // reverts with InvalidCertificate on the remaining 1/64.
        for (uint256 i; i < a.signature.length; ++i) {
            a.signature[i] ^= 0x01;
            vm.expectRevert(BajillionSettlement.InvalidCertificate.selector);
            settlement.admit{ gas: 10_000_000 }(a);
            a.signature[i] ^= 0x01;
        }
        // Dropping a signer from the bitmap (signers 0, 2, 3 -> 2, 3) keeps quorum but breaks
        // the aggregate.
        a.certificate[8] = 0x0c;
        vm.expectRevert(BajillionSettlement.InvalidCertificate.selector);
        settlement.admit(a);
        a = Fixture.admission();
        (a.committee[0], a.committee[1]) = (a.committee[1], a.committee[0]);
        vm.expectRevert(BajillionSettlement.CommitteeKeys.selector);
        settlement.admit(a);
        a = Fixture.admission();
        a.withdrawals[a.withdrawals.length - 1] ^= 0x01;
        vm.expectRevert(BajillionSettlement.TransitionBoundaryRoot.selector);
        settlement.admit(a);
        // The untouched fixture is still admissible.
        (BajillionSettlement.Status s,) = settlement.admit(Fixture.admission());
        assertEq(uint8(s), uint8(BajillionSettlement.Status.Ok));
    }

    function test_Inv09_RejectsMutatedPayoutClaim() public {
        _register();
        _admit();
        bytes memory claim = Fixture.hexFile("payout_claim");
        // Before finalization the payout head is the bootstrap head: the claim is unavailable.
        vm.expectRevert(BajillionSettlement.ClaimUnavailable.selector);
        settlement.claimWithdrawal(0, claim);
        vm.warp(Fixture.uintAt(".scenario.timing.finalize_at"));
        settlement.finalize();
        for (uint256 i; i < claim.length; ++i) {
            claim[i] ^= 0x01;
            (bool ok,) = address(settlement).call(abi.encodeCall(settlement.claimWithdrawal, (uint64(0), claim)));
            assertFalse(ok, "mutated claim accepted");
            claim[i] ^= 0x01;
        }
        assertEq(settlement.claimableBalance(), Fixture.uintAt(".close.withdrawal_total"), "nothing paid");
        settlement.claimWithdrawal(0, claim);
    }

    function _expectAdmitRejected(BajillionSettlement.Admission memory a, bytes4 one, bytes4 other) internal {
        try settlement.admit(a) {
            revert("mutated admission accepted");
        } catch (bytes memory reason) {
            bytes4 selector = bytes4(reason);
            assertTrue(selector == one || selector == other, "unexpected error");
        }
    }

    function test_GasFixtureAdmission() public {
        _register();
        vm.warp(Fixture.uintAt(".scenario.timing.admit_at"));
        BajillionSettlement.Admission memory a = Fixture.admission();
        settlement.admit(a);
        vm.snapshotGasLastCall("BajillionSettlement", "admit_fixture_n4_signers3_oneWithdrawal");
        vm.warp(Fixture.uintAt(".scenario.timing.finalize_at"));
        settlement.finalize();
        vm.snapshotGasLastCall("BajillionSettlement", "finalize_fixture");
        bytes memory claim = Fixture.hexFile("payout_claim");
        settlement.claimWithdrawal(0, claim);
        vm.snapshotGasLastCall("BajillionSettlement", "claimWithdrawal_fixture_3leaves");
    }
}
