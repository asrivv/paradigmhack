// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { BajillionSettlement } from "../src/BajillionSettlement.sol";
import { Head } from "../src/BajillionTypes.sol";
import { SettlementBase } from "./SettlementBase.sol";
import { ScenarioEd25519 } from "./utils/ScenarioEd25519.sol";
import { ScenarioMMR } from "./utils/ScenarioMMR.sol";

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

/// @notice HigherAckDebit over a real activity log (rows only, no entries), covering the present
/// branch rules of challenge.rs:649-670 and the ordered absence of challenge.rs:248-293.
contract ScenarioHigherAckDebitTest is ScenarioChallengeBase {
    bytes32[] internal rowKeys; // sorted
    bytes[] internal activity; // native operations of the epoch's activity log
    mapping(bytes32 => bytes) internal rowValue; // account -> 48-byte ChangeValue

    function setUp() public override {
        super.setUp();
    }

    function _key(uint256 i) internal view returns (ScenarioEd25519.Key memory) {
        return ScenarioEd25519.fromSeed(keccak256(abi.encode("account", i)));
    }

    /// @dev Admit epoch 0 with `accounts` as its activity rows (sorted here) and `values` as their
    /// ChangeValues. The log is the bootstrap commit, the rows, then the epoch commit.
    function _admitRows(bytes32[] memory accounts, bytes[] memory values) internal returns (bytes32) {
        for (uint256 i; i < accounts.length; ++i) {
            for (uint256 j = i + 1; j < accounts.length; ++j) {
                if (accounts[j] < accounts[i]) {
                    (accounts[i], accounts[j]) = (accounts[j], accounts[i]);
                    (values[i], values[j]) = (values[j], values[i]);
                }
            }
        }
        delete activity;
        activity.push(hex"000000");
        for (uint256 i; i < accounts.length; ++i) {
            rowKeys.push(accounts[i]);
            rowValue[accounts[i]] = values[i];
            activity.push(abi.encodePacked(hex"0100", accounts[i], values[i]));
        }
        activity.push(hex"000000");
        _register(0);
        Head memory h = settlement.head();
        bytes[] memory ops = activity;
        bytes memory roots = abi.encodePacked(
            _activityRoot(ops),
            uint64(ops.length),
            uint64(0),
            uint64(accounts.length),
            keccak256("payouts"),
            h.payouts.operations + 1,
            uint64(0),
            keccak256("successor"),
            uint64(1),
            uint64(0),
            keccak256("proposal")
        );
        return _admitWith(roots);
    }

    function _activityRoot(bytes[] memory ops) internal pure returns (bytes32) {
        return ScenarioMMRView.root(ops);
    }

    function _value(uint64 debit, uint64 seq, bytes32 sendRoot) internal pure returns (bytes memory) {
        return abi.encodePacked(debit, seq, sendRoot);
    }

    function _opening(uint256 start, uint256 count) internal view returns (bytes memory) {
        bytes[] memory ops = activity;
        bytes32[] memory digests = ScenarioMMRView.rangeProof(ops, start, count);
        return abi.encodePacked(
            uint64(start),
            ScenarioMMRView.varint(ops.length),
            uint8(0),
            ScenarioMMRView.varint(digests.length),
            abi.encodePacked(digests)
        );
    }

    function _present(bytes memory witness, uint256 rowIndex) internal view returns (bytes memory) {
        return abi.encodePacked(hex"01", witness, hex"01", rowValue[rowKeys[rowIndex]], _opening(1 + rowIndex, 1));
    }

    function _row(uint256 rowIndex) internal view returns (bytes memory) {
        return abi.encodePacked(hex"01", rowKeys[rowIndex], rowValue[rowKeys[rowIndex]]);
    }

    function _ack(uint64 seq, uint64 debit, bytes32 sendRoot) internal view returns (bytes memory) {
        return _witness(0, seq, debit, sendRoot, bytes32(0), VECTOR_SEND_NAMESPACE);
    }

    function _verdict(bytes memory encoded) internal returns (BajillionSettlement.Verdict v) {
        uint256 snap = vm.snapshotState();
        (, v) = _challenge(0, encoded);
        vm.revertToState(snap);
    }

    // ---- Present -------------------------------------------------------------------------------

    function _setUpPresent() internal {
        bytes32[] memory accounts = new bytes32[](3);
        bytes[] memory values = new bytes[](3);
        accounts[0] = payerKey.publicKey;
        values[0] = _value(10, 3, keccak256("terminal root"));
        accounts[1] = _key(1).publicKey;
        values[1] = _value(0, 0, keccak256("empty"));
        accounts[2] = _key(2).publicKey;
        values[2] = _value(4, 0, keccak256("other"));
        _admitRows(accounts, values);
    }

    function _payerRow() internal view returns (uint256 i) {
        while (rowKeys[i] != payerKey.publicKey) {
            ++i;
        }
    }

    function test_HigherAckDebitPresentRules() public {
        _setUpPresent();
        uint256 row = _payerRow();
        bytes32 terminalRoot = keccak256("terminal root");
        // Above the public terminal debit.
        assertEq(
            uint8(_verdict(_present(_ack(4, 11, keccak256("x")), row))),
            uint8(BajillionSettlement.Verdict.ProvenHigherAckDebit)
        );
        // The certified terminal body itself.
        assertEq(
            uint8(_verdict(_present(_ack(3, 10, terminalRoot), row))),
            uint8(BajillionSettlement.Verdict.NoContradiction)
        );
        // Same sequence, different body: equivocation against the certified terminal.
        assertEq(
            uint8(_verdict(_present(_ack(3, 9, keccak256("y")), row))),
            uint8(BajillionSettlement.Verdict.ProvenHigherAckDebit)
        );
        // Equal endpoint at a strictly later sequence the close does not carry.
        assertEq(
            uint8(_verdict(_present(_ack(4, 10, keccak256("z")), row))),
            uint8(BajillionSettlement.Verdict.ProvenHigherAckDebit)
        );
        // An earlier retry below the terminal endpoint is not the operator's fault.
        assertEq(
            uint8(_verdict(_present(_ack(2, 8, keccak256("w")), row))),
            uint8(BajillionSettlement.Verdict.NoContradiction)
        );
    }

    function test_HigherAckDebitCreditOnlyRow() public {
        _setUpPresent();
        // Account 1's row has terminal debit 0: has_outgoing is false, so only a positive debit proves.
        ScenarioEd25519.Key memory saved = payerKey;
        payerKey = _key(1);
        uint256 row = _payerRow();
        assertEq(
            uint8(_verdict(_present(_ack(5, 0, keccak256("v")), row))),
            uint8(BajillionSettlement.Verdict.NoContradiction)
        );
        assertEq(
            uint8(_verdict(_present(_ack(0, 1, keccak256("v")), row))),
            uint8(BajillionSettlement.Verdict.ProvenHigherAckDebit)
        );
        payerKey = saved;
    }

    // ---- Absent --------------------------------------------------------------------------------

    /// @dev Rows are accounts 1..4; the payer key is absent and falls somewhere among them.
    function _setUpAbsent() internal returns (uint256 position) {
        bytes32[] memory accounts = new bytes32[](4);
        bytes[] memory values = new bytes[](4);
        for (uint256 i; i < 4; ++i) {
            accounts[i] = _key(i + 1).publicKey;
            values[i] = _value(uint64(i + 1), 0, keccak256(abi.encode("root", i)));
        }
        _admitRows(accounts, values);
        while (position < rowKeys.length && rowKeys[position] < payerKey.publicKey) {
            ++position;
        }
    }

    function _absent(bytes memory witness, uint256 position) internal view returns (bytes memory) {
        bool hasPredecessor = position > 0;
        bool hasSuccessor = position < rowKeys.length;
        uint256 count = (hasPredecessor ? 1 : 0) + (hasSuccessor ? 1 : 0);
        uint256 start = hasPredecessor ? position : 1; // row i lives at location 1 + i
        return abi.encodePacked(
            hex"01",
            witness,
            hex"02",
            hasPredecessor ? _row(position - 1) : bytes(hex"00"),
            hasSuccessor ? _row(position) : bytes(hex"00"),
            hex"01",
            _opening(start, count)
        );
    }

    function test_HigherAckDebitAbsentPayer() public {
        uint256 position = _setUpAbsent();
        assertEq(
            uint8(_verdict(_absent(_ack(0, 1, keccak256("a")), position))),
            uint8(BajillionSettlement.Verdict.ProvenHigherAckDebit)
        );
        assertEq(
            uint8(_verdict(_absent(_ack(0, 0, keccak256("a")), position))),
            uint8(BajillionSettlement.Verdict.NoContradiction)
        );
    }

    /// @dev Two scenario keys that sort strictly above (`above`) or below (`below`) the payer.
    function _keysBeside(bool above) internal view returns (bytes32[] memory keys) {
        keys = new bytes32[](2);
        uint256 found;
        for (uint256 i = 1; found < 2; ++i) {
            bytes32 k = _key(i).publicKey;
            if (above ? k > payerKey.publicKey : k < payerKey.publicKey) keys[found++] = k;
        }
    }

    function _values(uint256 n) internal pure returns (bytes[] memory values) {
        values = new bytes[](n);
        for (uint256 i; i < n; ++i) {
            values[i] = _value(uint64(i + 1), 0, keccak256(abi.encode("root", i)));
        }
    }

    /// @dev The payer sorts before every row: successor only, and the opening must start at the
    /// range start (challenge.rs:270-272).
    function test_HigherAckDebitAbsentBeforeAllRows() public {
        _admitRows(_keysBeside(true), _values(2));
        bytes memory witness = _ack(0, 7, keccak256("a"));
        assertEq(uint8(_verdict(_absent(witness, 0))), uint8(BajillionSettlement.Verdict.ProvenHigherAckDebit));
        bytes memory wrongStart = abi.encodePacked(hex"01", witness, hex"02", hex"00", _row(1), hex"01", _opening(2, 1));
        vm.expectRevert(BajillionSettlement.ChallengeLookupOrder.selector);
        _challenge(0, wrongStart);
    }

    /// @dev The payer sorts after every row: predecessor only, ending at the range end.
    function test_HigherAckDebitAbsentAfterAllRows() public {
        _admitRows(_keysBeside(false), _values(2));
        bytes memory witness = _ack(0, 7, keccak256("a"));
        assertEq(uint8(_verdict(_absent(witness, 2))), uint8(BajillionSettlement.Verdict.ProvenHigherAckDebit));
        bytes memory notLast = abi.encodePacked(hex"01", witness, hex"02", _row(0), hex"00", hex"01", _opening(1, 1));
        vm.expectRevert(BajillionSettlement.ChallengeLookupOrder.selector);
        _challenge(0, notLast);
    }

    /// @dev An epoch with no rows: absence needs no neighbours and no opening (challenge.rs:257-263).
    function test_HigherAckDebitAbsentFromEmptyRange() public {
        _admitRows(new bytes32[](0), new bytes[](0));
        bytes memory witness = _ack(0, 1, keccak256("a"));
        bytes memory bare = abi.encodePacked(hex"01", witness, hex"02", hex"00", hex"00", hex"00");
        assertEq(uint8(_verdict(bare)), uint8(BajillionSettlement.Verdict.ProvenHigherAckDebit));
        bytes memory withOpening =
            abi.encodePacked(hex"01", witness, hex"02", hex"00", hex"00", hex"01", _opening(1, 0));
        vm.expectRevert(BajillionSettlement.ChallengeLookupOrder.selector);
        _challenge(0, withOpening);
    }

    function test_HigherAckDebitAbsenceRejectsBadNeighbours() public {
        uint256 position = _setUpAbsent();
        // Every branch below must run: the payer sorts strictly inside the rows with a row to spare.
        assertGt(position, 0, "payer before all rows");
        assertLt(position + 1, rowKeys.length, "payer too close to the end");
        bytes memory witness = _ack(0, 1, keccak256("a"));
        if (position > 0 && position < rowKeys.length) {
            // Neighbours in the wrong order around the payer.
            bytes memory swapped = abi.encodePacked(
                hex"01", witness, hex"02", _row(position), _row(position - 1), hex"01", _opening(position, 2)
            );
            vm.expectRevert(BajillionSettlement.ChallengeLookupOrder.selector);
            _challenge(0, swapped);
        }
        // Rows that are not adjacent: the opening proves other rows.
        if (position >= 1 && position + 1 < rowKeys.length) {
            bytes memory gap = abi.encodePacked(
                hex"01", witness, hex"02", _row(position - 1), _row(position + 1), hex"01", _opening(position, 2)
            );
            vm.expectRevert(BajillionSettlement.ChallengeActivity.selector);
            _challenge(0, gap);
        }
        // Missing opening for a nonempty neighbour set.
        bytes memory noOpening = abi.encodePacked(
            hex"01",
            witness,
            hex"02",
            position > 0 ? _row(position - 1) : bytes(hex"00"),
            position < rowKeys.length ? _row(position) : bytes(hex"00"),
            hex"00"
        );
        vm.expectRevert(BajillionSettlement.ChallengeLookupOrder.selector);
        _challenge(0, noOpening);
    }

    function test_GasChallengeHigherAckDebitAbsent() public {
        uint256 position = _setUpAbsent();
        bytes memory encoded = _absent(_ack(0, 1, keccak256("a")), position);
        Admitted storage t = admitted[0];
        settlement.challenge(t.batchId, t.context, t.roots, 0, encoded);
        vm.snapshotGasLastCall("Challenges", "challenge_higherAckDebit_absent_twoNeighbours_proven");
    }

    /// @dev Largest structurally valid evidence: an absence lookup with two neighbour rows (three
    /// strict-key decodes, two signature checks) and an opening at the 244-digest bound. Its proof
    /// is wrong, so this measures the rejection path, which still reconstructs the full range.
    function test_GasChallengeWorstCase() public {
        uint256 position = _setUpAbsent();
        bytes32[] memory junk = new bytes32[](244);
        for (uint256 i; i < junk.length; ++i) {
            junk[i] = keccak256(abi.encode(i));
        }
        bytes memory opening = abi.encodePacked(
            uint64(position),
            ScenarioMMR.varint(activity.length),
            uint8(0),
            ScenarioMMR.varint(244),
            abi.encodePacked(junk)
        );
        bytes memory encoded = abi.encodePacked(
            hex"01", _ack(0, 1, keccak256("a")), hex"02", _row(position - 1), _row(position), hex"01", opening
        );
        Admitted storage t = admitted[0];
        uint256 before = gasleft();
        (bool ok,) =
            address(settlement).call(abi.encodeCall(settlement.challenge, (t.batchId, t.context, t.roots, 0, encoded)));
        uint256 used = before - gasleft();
        assertFalse(ok, "junk proof accepted");
        emit log_named_uint("worst-case challenge gas (excluding intrinsic and calldata)", used);
        emit log_named_uint("evidence bytes", encoded.length);
        assertLt(used, 30_000_000, "fits Tempo's per-transaction cap");
    }

    function test_GasChallengeHigherAckDebit() public {
        _setUpPresent();
        bytes memory encoded = _present(_ack(4, 11, keccak256("x")), _payerRow());
        Admitted storage t = admitted[0];
        settlement.challenge(t.batchId, t.context, t.roots, 0, encoded);
        vm.snapshotGasLastCall("Challenges", "challenge_higherAckDebit_present_proven");
    }
}

/// @dev ScenarioMMR helpers bound to a zero floor (no inactive peaks), as in a first epoch.
library ScenarioMMRView {
    function root(bytes[] memory ops) internal pure returns (bytes32) {
        return ScenarioMMR.root(ops, 0);
    }

    function rangeProof(bytes[] memory ops, uint256 start, uint256 count) internal pure returns (bytes32[] memory) {
        return ScenarioMMR.rangeProof(ops, 0, start, count);
    }

    function varint(uint256 value) internal pure returns (bytes memory) {
        return ScenarioMMR.varint(value);
    }
}
