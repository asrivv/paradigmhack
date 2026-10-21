// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { LibBLS12381 as BLS } from "commonware/certificate/LibBLS12381.sol";
import { BajillionSettlement } from "../src/BajillionSettlement.sol";
import { LibBLS12381Point } from "../src/verify/LibBLS12381Point.sol";
import { SettlementBase } from "./SettlementBase.sol";
import { TmpBLS } from "./tmp/TmpBLS.sol";

contract PointWrapper {
    function matchesG1(bytes memory c, bytes memory u) external pure returns (bool) {
        return LibBLS12381Point.matchesG1(c, u);
    }

    function matchesG2(bytes memory c, BLS.G2Point memory p) external pure returns (bool) {
        return LibBLS12381Point.matchesG2(c, p);
    }
}

contract BajillionSettlementTest is SettlementBase {
    // ---------------------------------------------------------------------------------------
    // Invariant 1: ordered finality
    // ---------------------------------------------------------------------------------------

    /// @dev A close finalizes only strictly after its challenge deadline and after every earlier
    /// close (settlement.rs:1621-1701).
    function test_Inv01_OrderedFinality() public {
        assertEq(uint8(_register(0)), uint8(BajillionSettlement.Status.Ok));
        (BajillionSettlement.Status s0, bytes32 id0) = _admit();
        assertEq(uint8(s0), uint8(BajillionSettlement.Status.Ok));
        // Epoch 1 registers after epoch 0 is admitted, so it becomes the frontier at once.
        vm.warp(START + 5);
        _register(1);
        (, bytes32 id1) = _admit();
        assertTrue(id0 != id1);
        uint64 d0 = _challengeDeadline(0);
        uint64 d1 = _challengeDeadline(1);
        assertGt(d1, d0, "later frontier gets a later window");

        // Before and exactly at the inclusive deadline, the window is open.
        vm.warp(d0 - 1);
        vm.expectRevert(BajillionSettlement.ChallengeWindowOpen.selector);
        settlement.finalize();
        vm.warp(d0);
        vm.expectRevert(BajillionSettlement.ChallengeWindowOpen.selector);
        settlement.finalize();

        // One tick later the front finalizes; epoch 1 waits for its own window.
        vm.warp(d0 + 1);
        assertEq(uint8(settlement.finalize()), uint8(BajillionSettlement.Status.Ok));
        assertEq(settlement.expectedEpoch(), 1);
        assertEq(settlement.currentStateRoot(), keccak256(abi.encode("successor", uint64(0))));
        vm.expectRevert(BajillionSettlement.ChallengeWindowOpen.selector);
        settlement.finalize();

        vm.warp(d1 + 1);
        assertEq(uint8(settlement.finalize()), uint8(BajillionSettlement.Status.Ok));
        assertEq(settlement.expectedEpoch(), 2);
        vm.expectRevert(BajillionSettlement.NoPendingBatch.selector);
        settlement.finalize();
    }

    /// @dev Even when a later close's window has passed, only the front can finalize.
    function test_Inv01_FrontBlocksLaterClose() public {
        _register(0);
        _admit();
        _register(1);
        // Epoch 1 is the frontier with deadlines from now; admit it immediately too.
        _admit();
        assertEq(settlement.admittedEnd(), 2);
        vm.warp(_challengeDeadline(1) + 1);
        settlement.finalize();
        assertEq(settlement.expectedEpoch(), 1, "only the front finalized");
        settlement.finalize();
        assertEq(settlement.expectedEpoch(), 2);
    }

    function test_Inv01_RejectsWrongEpochDeploymentOperatorCommittee() public {
        bytes memory ctx = _epochContext(1, hex"00");
        vm.expectRevert(BajillionSettlement.EpochSequence.selector);
        settlement.registerEpoch(ctx, 0, hex"00", hex"00", "");

        ctx = _epochContext(0, hex"00");
        bytes memory bad = bytes.concat(ctx);
        bad[72] ^= 0x01;
        vm.expectRevert(BajillionSettlement.Deployment.selector);
        settlement.registerEpoch(bad, 0, hex"00", hex"00", "");

        bad = bytes.concat(ctx);
        bad[40] ^= 0x01;
        vm.expectRevert(BajillionSettlement.OperatorMismatch.selector);
        settlement.registerEpoch(bad, 0, hex"00", hex"00", "");

        bad = bytes.concat(ctx);
        bad[232] ^= 0x01;
        vm.expectRevert(BajillionSettlement.CommitteeMismatch.selector);
        settlement.registerEpoch(bad, 0, hex"00", hex"00", "");

        bad = bytes.concat(ctx);
        bad[0] ^= 0x01;
        vm.expectRevert(BajillionSettlement.TransitionEpochAnchor.selector);
        settlement.registerEpoch(bad, 0, hex"00", hex"00", "");

        vm.expectRevert(BajillionSettlement.ContextEncoding.selector);
        settlement.registerEpoch(bytes.concat(ctx, hex"00"), 0, hex"00", hex"00", "");

        vm.expectRevert(BajillionSettlement.WithdrawalsUnsupported.selector);
        settlement.registerEpoch(ctx, 0, hex"00", hex"0100", "");

        vm.expectRevert(BajillionSettlement.IntakeRange.selector);
        settlement.registerEpoch(ctx, 1, hex"00", hex"00", "");
    }

    /// @dev A header bound to the wrong predecessor, epoch, deadline or total fails `validate_header`.
    function test_Inv01_RejectsHeaderWithWrongPredecessor() public {
        _register(0);
        BajillionSettlement.Admission memory a = _admission(hex"00", 0x03);

        // Header over a context whose predecessor state root differs.
        bytes memory ctx = settlement.frontierContext();
        ctx[264] ^= 0x01;
        a.header = sha256(abi.encodePacked(HEADER_ROOT_NAMESPACE, ctx, a.roots, a.withdrawalTotal));
        (a.certificate, a.signature) = _certificate(a.header, 0x03);
        vm.expectRevert(BajillionSettlement.TransitionHeaderRoot.selector);
        settlement.admit(a);

        // Header over a context naming another epoch.
        ctx = settlement.frontierContext();
        ctx[39] ^= 0x01;
        a.header = sha256(abi.encodePacked(HEADER_ROOT_NAMESPACE, ctx, a.roots, a.withdrawalTotal));
        (a.certificate, a.signature) = _certificate(a.header, 0x03);
        vm.expectRevert(BajillionSettlement.TransitionHeaderRoot.selector);
        settlement.admit(a);

        // Correct header, different withdrawal total.
        a = _admission(hex"00", 0x03);
        a.withdrawalTotal = 1;
        vm.expectRevert(BajillionSettlement.TransitionHeaderRoot.selector);
        settlement.admit(a);

        // A certified header with a nonzero total and no withdrawals fails the output-root check.
        a = _admission(hex"00", 0x03);
        a.withdrawalTotal = 1;
        a.header = _header(a.roots, 1);
        (a.certificate, a.signature) = _certificate(a.header, 0x03);
        vm.expectRevert(BajillionSettlement.TransitionWithdrawalOutputRoot.selector);
        settlement.admit(a);
    }

    function test_Inv01_RejectsBadCertificates() public {
        _register(0);
        BajillionSettlement.Admission memory good = _admission(hex"00", 0x03);
        BajillionSettlement.Admission memory a;

        // Below quorum (q = 2 for n = 4).
        a = _admission(hex"00", 0x01);
        vm.expectRevert(BajillionSettlement.InvalidCertificate.selector);
        settlement.admit(a);

        // Out-of-range signer bit (bit 4 of a 4-member committee).
        a = _admission(hex"00", 0x03);
        a.certificate[8] = bytes1(uint8(0x13));
        vm.expectRevert(BajillionSettlement.InvalidCertificate.selector);
        settlement.admit(a);

        // Bitmap length prefix that is not n.
        a = _admission(hex"00", 0x03);
        a.certificate[7] = bytes1(uint8(5));
        vm.expectRevert(BajillionSettlement.InvalidCertificate.selector);
        settlement.admit(a);

        // Truncated and extended certificates.
        a = _admission(hex"00", 0x03);
        a.certificate = bytes.concat(a.certificate, hex"00");
        vm.expectRevert(BajillionSettlement.InvalidCertificate.selector);
        settlement.admit(a);

        // A signer counted twice: the aggregate holds signer 0 twice but the bitmap names 0 and 1.
        a = _admission(hex"00", 0x03);
        BLS.G1Point memory s0 = TmpBLS.sign(secretKeys[0], HEADER_NAMESPACE, abi.encodePacked(a.header));
        BLS.G1Point memory doubled = TmpBLS.addG1(s0, s0);
        a.certificate = abi.encodePacked(uint64(N), uint8(0x03), TmpBLS.compressG1(doubled));
        a.signature = TmpBLS.uncompressedG1(doubled);
        vm.expectRevert(BajillionSettlement.InvalidCertificate.selector);
        settlement.admit(a);

        // A hint that does not compress to the certificate's signature.
        a = _admission(hex"00", 0x03);
        (, a.signature) = _certificate(a.header, 0x06);
        vm.expectRevert(BajillionSettlement.InvalidCertificate.selector);
        settlement.admit(a);

        // Wrong committee witness.
        a = _admission(hex"00", 0x03);
        (a.committee[0], a.committee[1]) = (a.committee[1], a.committee[0]);
        vm.expectRevert(BajillionSettlement.CommitteeKeys.selector);
        settlement.admit(a);

        // A certificate for another header.
        a = _admission(hex"00", 0x03);
        (a.certificate, a.signature) = _certificate(keccak256("other"), 0x03);
        vm.expectRevert(BajillionSettlement.InvalidCertificate.selector);
        settlement.admit(a);

        (BajillionSettlement.Status s,) = settlement.admit(good);
        assertEq(uint8(s), uint8(BajillionSettlement.Status.Ok));
        vm.expectRevert(BajillionSettlement.NoRegisteredEpoch.selector);
        settlement.admit(good);
    }

    function test_Inv01_DepositsFlowThroughAdmissionAndFinality() public {
        // Batches order accounts by bytes: alice (0x0a...) sorts before bob (0x0b...).
        bytes32 alice = bytes32(uint256(0x0a11ce) << 232);
        bytes32 bob = bytes32(uint256(0x0b0b) << 240);
        token.mint(address(this), 100);
        token.approve(address(settlement), 100);
        settlement.deposit(bob, 30);
        settlement.deposit(alice, 50);
        settlement.deposit(bob, 20);
        assertEq(settlement.custodyBalance(), 100);

        bytes memory batch = abi.encodePacked(uint8(2), alice, uint64(50), bob, uint64(50));
        bytes memory pulled = abi.encodePacked(bob, uint64(30), alice, uint64(50), bob, uint64(20));
        bytes memory ctx = _epochContext(0, batch);

        // The aggregate must match the pulled deposits exactly.
        bytes memory short = abi.encodePacked(uint8(2), alice, uint64(50), bob, uint64(30));
        vm.expectRevert(BajillionSettlement.BoundaryRoot.selector);
        settlement.registerEpoch(ctx, 3, short, hex"00", pulled);
        bytes memory shortCtx = _epochContext(0, short);
        vm.expectRevert(BajillionSettlement.DepositAggregate.selector);
        settlement.registerEpoch(shortCtx, 3, short, hex"00", pulled);
        bytes memory forged = abi.encodePacked(bob, uint64(30), alice, uint64(50), bob, uint64(19));
        vm.expectRevert(BajillionSettlement.DepositAggregate.selector);
        settlement.registerEpoch(ctx, 3, batch, hex"00", forged);
        bytes memory unsorted = abi.encodePacked(uint8(2), bob, uint64(50), alice, uint64(50));
        vm.expectRevert(BajillionSettlement.DepositBatchEncoding.selector);
        settlement.registerEpoch(ctx, 3, unsorted, hex"00", pulled);

        settlement.registerEpoch(ctx, 3, batch, hex"00", pulled);
        assertEq(settlement.pulled(), 3);
        assertEq(settlement.pendingDeposits(bob), 50, "pulled deposits stay pending until admission");

        BajillionSettlement.Admission memory a = _admission(batch, 0x05);
        a.deposits = hex"00";
        vm.expectRevert(BajillionSettlement.TransitionBoundaryRoot.selector);
        settlement.admit(a);
        settlement.admit(_admission(batch, 0x05));
        assertEq(settlement.pendingDeposits(bob), 0);
        assertEq(settlement.head().liability, 100);

        vm.warp(_challengeDeadline(0) + 1);
        settlement.finalize();
        assertEq(settlement.currentLiability(), 100);
        assertEq(settlement.unfinalizedDepositTotal(), 0);
        assertEq(settlement.custodyBalance(), 100);
    }

    // ---------------------------------------------------------------------------------------
    // Invariant 7: the liveness fence is never reverted
    // ---------------------------------------------------------------------------------------

    function test_Inv07_FaultFenceNotReverted() public {
        _register(0);
        uint64 deadline = _admissionDeadline(0);

        // Admission is allowed through the inclusive deadline; check it without committing.
        vm.warp(deadline);
        uint256 snap = vm.snapshotState();
        (BajillionSettlement.Status ok,) = _admit();
        assertEq(uint8(ok), uint8(BajillionSettlement.Status.Ok));
        vm.revertToState(snap);

        // One tick later admit observes the expiry, commits the fence, and returns a status.
        vm.warp(deadline + 1);
        BajillionSettlement.Admission memory a = _admission(hex"00", 0x03);
        vm.expectEmit(address(settlement));
        emit BajillionSettlement.HardFault(
            BajillionSettlement.FaultKind.ExpiredRegistration, deadline, settlement.epochRecord(0).anchor, 0, 0
        );
        (BajillionSettlement.Status s,) = settlement.admit(a);
        assertEq(uint8(s), uint8(BajillionSettlement.Status.OperatorHardFaulted));
        assertEq(uint8(settlement.faultKind()), uint8(BajillionSettlement.FaultKind.ExpiredRegistration));
        assertEq(settlement.registeredEnd(), 0, "registrations dropped");
        assertEq(settlement.admittedEnd(), 0, "nothing admitted");

        // Later calls see a fault that predates them and revert without state.
        vm.expectRevert(BajillionSettlement.OperatorHardFaulted.selector);
        settlement.admit(a);
        vm.expectRevert(BajillionSettlement.OperatorHardFaulted.selector);
        settlement.deposit(bytes32(uint256(1)), 1);
        bytes memory ctx = _epochContext(0, hex"00");
        vm.expectRevert(BajillionSettlement.OperatorHardFaulted.selector);
        settlement.registerEpoch(ctx, 0, hex"00", hex"00", "");
        vm.expectRevert(BajillionSettlement.OperatorHardFaulted.selector);
        settlement.faultExpired();
    }

    /// @dev finalize keeps the fence when its own operation fails, and the pre-fault prefix still
    /// finalizes afterwards.
    function test_Inv07_FinalizeKeepsFenceAndPrefix() public {
        _register(0);
        _admit();
        _register(1); // Frontier with an admission deadline 10s from now.
        vm.warp(_admissionDeadline(1) + 1); // Epoch 0's window is still open.
        BajillionSettlement.Status s = settlement.finalize();
        assertEq(uint8(s), uint8(BajillionSettlement.Status.ChallengeWindowOpen));
        assertEq(uint8(settlement.faultKind()), uint8(BajillionSettlement.FaultKind.ExpiredRegistration));
        assertEq(settlement.admissionFenceEpoch(), 1);

        vm.warp(_challengeDeadline(0) + 1);
        assertEq(uint8(settlement.finalize()), uint8(BajillionSettlement.Status.Ok));
        assertEq(settlement.expectedEpoch(), 1);
        vm.expectRevert(BajillionSettlement.NoPendingBatch.selector);
        settlement.finalize();
    }

    function test_Inv07_DepositExpiryFencesThroughAnyCall() public {
        token.mint(address(this), 10);
        token.approve(address(settlement), 10);
        settlement.deposit(bytes32(uint256(7)), 10);
        vm.expectRevert(BajillionSettlement.DeadlineNotReached.selector);
        settlement.faultExpired();

        vm.warp(START + DEPOSIT_TIMEOUT - 1);
        vm.expectRevert(BajillionSettlement.NoPendingBatch.selector);
        settlement.finalize();

        // Deposit deadlines fault at `now >= deadline` (settlement.rs:772-776).
        vm.warp(START + DEPOSIT_TIMEOUT);
        assertEq(uint8(settlement.finalize()), uint8(BajillionSettlement.Status.NoPendingBatch));
        assertEq(uint8(settlement.faultKind()), uint8(BajillionSettlement.FaultKind.ExpiredDeposit));
        assertEq(settlement.faultDetail(), bytes32(uint256(7)));
        assertEq(settlement.pendingDeposits(bytes32(uint256(7))), 10, "deposit stays refundable");
    }

    function test_Inv07_FaultExpiredFencesExplicitly() public {
        _register(0);
        vm.warp(_admissionDeadline(0) + 1);
        assertEq(uint8(settlement.faultExpired()), uint8(BajillionSettlement.FaultKind.ExpiredRegistration));
        assertEq(settlement.faultExpiredAt(), _admissionDeadline(0));
    }

    // ---------------------------------------------------------------------------------------
    // Committee registration
    // ---------------------------------------------------------------------------------------

    function test_CommitteeCommitmentMatchesCrateEncoding() public view {
        assertEq(settlement.committeeCommitment(), _committeeCommitment());
        assertEq(settlement.committeeSize(), 4);
        assertEq(settlement.quorum(), 2);
        assertEq(token.balanceOf(address(settlement)), BOND, "bond escrowed");
    }

    function test_RejectsCommitteeWithOneBadProofOfPossession() public {
        SettlementHarnessDeployer deployer = new SettlementHarnessDeployer();
        BajillionSettlement.DeploymentArgs memory d = _args();
        BLS.G1Point memory wrong = TmpBLS.proveKey(secretKeys[1], POP_NAMESPACE, compressedKeys[2]);
        d.committee[2].pop = TmpBLS.compressG1(wrong);
        d.committee[2].popPoint = TmpBLS.uncompressedG1(wrong);
        token.mint(address(this), BOND);
        vm.expectRevert(BajillionSettlement.InvalidProofOfPossession.selector);
        deployer.deploy(d);

        // A proof over another namespace is also rejected.
        d = _args();
        BLS.G1Point memory other = TmpBLS.proveKey(secretKeys[0], "other", compressedKeys[0]);
        d.committee[0].pop = TmpBLS.compressG1(other);
        d.committee[0].popPoint = TmpBLS.uncompressedG1(other);
        vm.expectRevert(BajillionSettlement.InvalidProofOfPossession.selector);
        deployer.deploy(d);
    }

    function test_RejectsMalformedCommittee() public {
        SettlementHarnessDeployer deployer = new SettlementHarnessDeployer();
        BajillionSettlement.DeploymentArgs memory d = _args();
        (d.committee[0], d.committee[1]) = (d.committee[1], d.committee[0]);
        vm.expectRevert(BajillionSettlement.NonCanonicalCommittee.selector);
        deployer.deploy(d);

        d = _args();
        d.committee[1] = d.committee[0];
        vm.expectRevert(BajillionSettlement.DuplicateValidator.selector);
        deployer.deploy(d);

        d = _args();
        d.committee[0].point = points[1];
        vm.expectRevert(BajillionSettlement.CommitteeEncoding.selector);
        deployer.deploy(d);

        d = _args();
        BajillionSettlement.Validator[] memory three = new BajillionSettlement.Validator[](3);
        for (uint256 i; i < 3; ++i) {
            three[i] = d.committee[i];
        }
        d.committee = three;
        vm.expectRevert(BajillionSettlement.InvalidCommitteeSize.selector);
        deployer.deploy(d);
    }

    // ---------------------------------------------------------------------------------------
    // Point compression against the standard BLS12-381 generator encodings
    // ---------------------------------------------------------------------------------------

    function test_PointCompressionKnownVectors() public {
        PointWrapper w = new PointWrapper();
        bytes memory g1 =
            hex"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
        bytes memory g2 =
            hex"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
        BLS.G1Point memory gen1 = TmpBLS.g1Generator();
        BLS.G2Point memory gen2 = TmpBLS.g2Generator();
        assertEq(TmpBLS.compressG1(gen1), g1);
        assertEq(TmpBLS.compressG2(gen2), g2);
        assertTrue(w.matchesG1(g1, TmpBLS.uncompressedG1(gen1)));
        assertTrue(w.matchesG2(g2, gen2));

        // Negated generators set the sign bit (0x20).
        BLS.G1Point memory neg1 = TmpBLS.mulG1(gen1, _groupOrder() - 1);
        bytes memory negG1 = bytes.concat(g1);
        negG1[0] = 0xb7;
        assertEq(TmpBLS.compressG1(neg1), negG1);
        assertTrue(w.matchesG1(negG1, TmpBLS.uncompressedG1(neg1)));
        assertFalse(w.matchesG1(g1, TmpBLS.uncompressedG1(neg1)), "sign bit is bound");

        BLS.G2Point memory neg2 = TmpBLS.mulG2(gen2, _groupOrder() - 1);
        bytes memory negG2 = bytes.concat(g2);
        negG2[0] = 0xb3;
        assertEq(TmpBLS.compressG2(neg2), negG2);
        assertTrue(w.matchesG2(negG2, neg2));
        assertFalse(w.matchesG2(g2, neg2), "sign bit is bound");

        // Infinity and stray flags never match.
        bytes memory inf = bytes.concat(g1);
        inf[0] = bytes1(uint8(inf[0]) | 0x40);
        assertFalse(w.matchesG1(inf, TmpBLS.uncompressedG1(gen1)));
        bytes memory flagged = bytes.concat(g2);
        flagged[48] = bytes1(uint8(flagged[48]) | 0x80);
        assertFalse(w.matchesG2(flagged, gen2));
    }

    function _groupOrder() internal pure returns (uint256) {
        return 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
    }
}

/// @dev Deploys from a fresh address so constructor reverts surface to `expectRevert`.
contract SettlementHarnessDeployer {
    function deploy(BajillionSettlement.DeploymentArgs memory d) external returns (BajillionSettlement) {
        return new BajillionSettlement(d);
    }
}
