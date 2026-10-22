// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { BajillionSettlement } from "../src/BajillionSettlement.sol";
import { SettlementBase } from "./SettlementBase.sol";
import { ScenarioEd25519 } from "./utils/ScenarioEd25519.sol";

/// @notice Multi-epoch challenge scenarios. The crate fixture covers one certified epoch, so these
/// sign with the scenario committee and the scenario operator key (test/utils/, anchored in
/// ScenarioAnchors.t.sol).
abstract contract ScenarioChallengeBase is SettlementBase {
    bytes internal constant VECTOR_SEND_NAMESPACE = "_COMMONWARE_CLEARING_VECTOR_SEND";
    bytes internal constant VECTOR_ACK_NAMESPACE = "_COMMONWARE_CLEARING_VECTOR_ACK";

    struct Admitted {
        bytes32 batchId;
        bytes context;
        bytes roots;
    }

    mapping(uint64 => Admitted) internal admitted;
    ScenarioEd25519.Key internal payerKey;

    function setUp() public virtual override {
        super.setUp();
        payerKey = ScenarioEd25519.fromSeed(keccak256("scenario payer"));
    }

    /// @dev Admit the frontier with `roots`, recording the witness a challenger needs.
    function _admitWith(bytes memory roots) internal returns (bytes32 batchId) {
        uint64 epoch = settlement.admittedEnd();
        bytes memory context = settlement.frontierContext();
        BajillionSettlement.Admission memory a = _admission(hex"00", 0x03);
        a.roots = roots;
        a.header = _header(roots, 0);
        (a.certificate, a.signature) = _certificate(a.header, 0x03);
        (, batchId) = settlement.admit(a);
        admitted[epoch] = Admitted(batchId, context, roots);
    }

    function _admitSynthetic() internal returns (bytes32) {
        return _admitWith(_roots(keccak256(abi.encode("successor", settlement.admittedEnd()))));
    }

    /// @dev `AckWitness` (challenge.rs:121-143) over `VectorSendBody::message` (payment.rs:194-201).
    function _witness(
        uint64 epoch,
        uint64 seq,
        uint64 debit,
        bytes32 sendRoot,
        bytes32 predecessor,
        bytes memory payerNamespace
    ) internal view returns (bytes memory) {
        bytes memory context = admitted[epoch].context;
        bytes32 anchor;
        assembly {
            anchor := mload(add(context, 0x20))
        }
        bytes memory message = abi.encodePacked(anchor, epoch, payerKey.publicKey, seq, debit, sendRoot, predecessor);
        return abi.encodePacked(
            payerKey.publicKey,
            seq,
            debit,
            sendRoot,
            predecessor,
            ScenarioEd25519.signNamespaced(payerKey, payerNamespace, message),
            ScenarioEd25519.signNamespaced(operatorKey, VECTOR_ACK_NAMESPACE, message)
        );
    }

    function _fork(uint64 epoch) internal view returns (bytes memory) {
        return abi.encodePacked(
            hex"03",
            _witness(epoch, 0, 5, keccak256("root a"), bytes32(0), VECTOR_SEND_NAMESPACE),
            _witness(epoch, 0, 6, keccak256("root b"), bytes32(0), VECTOR_SEND_NAMESPACE)
        );
    }

    function _challenge(uint64 epoch, bytes memory encoded)
        internal
        returns (BajillionSettlement.Status, BajillionSettlement.Verdict)
    {
        Admitted storage t = admitted[epoch];
        return settlement.challenge(t.batchId, t.context, t.roots, 0, encoded);
    }
}

contract ScenarioChallengeTest is ScenarioChallengeBase {
    /// @dev A proven challenge invalidates its close and every later pending close, fences the
    /// deployment, and leaves earlier clean closes finalizable (settlement.rs:1604-1612).
    function test_Inv02_CascadeInvalidation() public {
        for (uint64 e; e < 4; ++e) {
            _register(e);
            _admitSynthetic();
        }
        _register(4); // frontier, never admitted
        bytes memory fork = _fork(1);

        (BajillionSettlement.Status s, BajillionSettlement.Verdict v) = _challenge(1, fork);
        assertEq(uint8(s), uint8(BajillionSettlement.Status.Ok));
        assertEq(uint8(v), uint8(BajillionSettlement.Verdict.ProvenAckFork));
        assertEq(settlement.epochRecord(0).status, 2, "earlier close stays pending");
        assertEq(settlement.epochRecord(1).status, 3, "challenged");
        assertEq(settlement.epochRecord(2).status, 4, "descendant invalidated");
        assertEq(settlement.epochRecord(3).status, 4, "descendant invalidated");
        assertEq(settlement.invalidFrom(), admitted[1].batchId);
        assertEq(uint8(settlement.faultKind()), uint8(BajillionSettlement.FaultKind.ProvenChallenge));
        assertEq(settlement.admissionFenceEpoch(), 4);
        assertEq(settlement.registeredEnd(), 4, "the frontier is dropped");

        // Invalidated descendants cannot be challenged again; the challenged one is refused too.
        bytes memory fork2 = _fork(2);
        vm.expectRevert(BajillionSettlement.BatchInvalidated.selector);
        _challenge(2, fork2);
        vm.expectRevert(BajillionSettlement.AlreadyChallenged.selector);
        _challenge(1, fork);

        // No new work after the fault.
        bytes memory ctx = _epochContext(4, hex"00");
        uint64 end = settlement.pulled();
        vm.expectRevert(BajillionSettlement.OperatorHardFaulted.selector);
        settlement.registerEpoch(ctx, end, hex"00", hex"00", "");

        // The clean prefix finalizes; the challenged close blocks everything after it.
        vm.warp(_challengeDeadline(0) + 1);
        assertEq(uint8(settlement.finalize()), uint8(BajillionSettlement.Status.Ok));
        assertEq(settlement.expectedEpoch(), 1);
        vm.warp(_challengeDeadline(3) + 1);
        vm.expectRevert(BajillionSettlement.BatchInvalidated.selector);
        settlement.finalize();
        assertEq(settlement.expectedEpoch(), 1);
    }

    /// @dev The two sides must name one payer and one sequence over different messages.
    function test_AckForkRequiresSamePayerAndSequence() public {
        _register(0);
        _admitSynthetic();
        bytes memory left = _witness(0, 0, 5, keccak256("root a"), bytes32(0), VECTOR_SEND_NAMESPACE);
        bytes memory laterSeq = _witness(0, 1, 6, keccak256("root b"), bytes32(0), VECTOR_SEND_NAMESPACE);
        (, BajillionSettlement.Verdict v) = _challenge(0, abi.encodePacked(hex"03", left, laterSeq));
        assertEq(uint8(v), uint8(BajillionSettlement.Verdict.NoContradiction));
        (, v) = _challenge(0, abi.encodePacked(hex"03", left, left));
        assertEq(uint8(v), uint8(BajillionSettlement.Verdict.NoContradiction));
        // Same body, different predecessor is a fork.
        bytes memory otherPredecessor = _witness(0, 0, 5, keccak256("root a"), keccak256("pred"), VECTOR_SEND_NAMESPACE);
        (, v) = _challenge(0, abi.encodePacked(hex"03", left, otherPredecessor));
        assertEq(uint8(v), uint8(BajillionSettlement.Verdict.ProvenAckFork));
    }

    function test_GasChallengeAckFork() public {
        _register(0);
        _admitSynthetic();
        bytes memory fork = _fork(0);
        Admitted storage t = admitted[0];
        settlement.challenge(t.batchId, t.context, t.roots, 0, fork);
        vm.snapshotGasLastCall("Challenges", "challenge_ackFork_proven");
    }
}
