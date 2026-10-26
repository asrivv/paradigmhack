// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { Vm } from "forge-std/Vm.sol";
import { LibBLS12381 as BLS } from "commonware/certificate/LibBLS12381.sol";
import { BajillionSettlement } from "../src/BajillionSettlement.sol";
import { LibClearingCodec as Codec } from "../src/verify/LibClearingCodec.sol";
import { OracleStatus } from "./differential/OracleStatus.sol";
import { StateDigest } from "./differential/StateDigest.sol";
import { SettlementHarness } from "./harness/SettlementHarness.sol";
import { MockTIP20 } from "./mocks/MockTIP20.sol";
import { Fixture } from "./utils/Fixture.sol";
import { G1Decompress } from "./utils/G1Decompress.sol";

/// @notice Invariant 10: BajillionSettlement and the crate's `SettlementChain` agree on every op
/// sequence. Each run generates op kinds from a seed, has the oracle (offchain/oracle, the real
/// `SettlementChain` from commonware-clearing at dd6d60cb) materialize them into crate bytes,
/// replays the same bytes through the contract and through the oracle, and requires identical
/// per-op status codes, identical mutated-on-error flags and an identical state digest.
/// @dev Needs `vm.ffi` and a built oracle: run from contracts/ with
/// `cargo build --release --locked -p bajillion-oracle` (in offchain/) and then
/// `FOUNDRY_PROFILE=differential forge test --match-contract Differential`. The default profile
/// skips every `*_Differential*` test, as upstream sol/foundry.toml does; the known-answer and
/// skip-list tests need no FFI and run in both profiles.
///
/// Both sides run the fixtures deployment (offchain/fixtures, seed 4664) from time 0. The
/// contract's `now` is `block.timestamp`, moved by `advanceTime` through `vm.warp`.
///
/// Embedding witnesses the contract needs and the oracle does not take are built here from what
/// the test has already submitted: the `pulledDeposits` list for `registerEpoch`, the
/// registered deposit batch and the uncompressed committee and signature hints for `admit`, the
/// target's CloseContext and RootBundle for `challenge`, and the claimed-range predecessor for
/// `claimWithdrawal`.
///
/// Ops the generator skips. PENDING: the contract does not support them yet.
///   - queueWithdrawal (kind 1): chain-queued withdrawals are not ported.
///   - registerEpoch with a nonempty withdrawal batch: production rejects it
///     (`WithdrawalsUnsupported`) until Ed25519 withdrawal verification lands.
/// NOT APPLICABLE: the embedding differs from the oracle's by design.
///   - recordDeposit reusing an earlier deposit id: the contract assigns ids from its inbox
///     index, so `DuplicateDeposit` cannot occur (protocol-notes.md section 6).
/// `test_Inv10_SkipList` pins this list.
contract DifferentialTest is Test {
    struct Op {
        uint8 kind;
        bytes args;
    }

    /// @dev Bound context of an admitted close, kept for challenges against it.
    struct Target {
        bytes context;
        bytes roots;
        uint64 withdrawalTotal;
    }

    uint8 internal constant RECORD_DEPOSIT = 0;
    uint8 internal constant QUEUE_WITHDRAWAL = 1;
    uint8 internal constant REGISTER_EPOCH = 2;
    uint8 internal constant ADMIT = 3;
    uint8 internal constant CHALLENGE = 4;
    uint8 internal constant FINALIZE = 5;
    uint8 internal constant CLAIM_WITHDRAWAL = 6;
    uint8 internal constant FAULT_EXPIRED = 7;
    uint8 internal constant ADVANCE_TIME = 8;

    string internal constant ORACLE = "../offchain/target/release/bajillion-oracle";

    /// @dev The README's genesis state vector (offchain/oracle/README.md, "Test vector").
    bytes internal constant GENESIS_PREIMAGE =
        hex"42414a494c4c494f4e5f4f5241434c455f53544154455f56310000000000000000000000000000000100000000000000010000000000000001000000000000000000000000000000000000000000550b70a7c0fd428441985a82b1e8b1e9d64fb376d4d2b451f25d368fdff437d100000000000000010000000000000000550b70a7c0fd428441985a82b1e8b1e9d64fb376d4d2b451f25d368fdff437d1000000000000000100000000000000006d68250818907071bbe9eea0db384fe1d96aaa6fad1227dbd1d8875f84ae23e70000000000000000000000c8000000000000000000000000000000c8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    bytes32 internal constant GENESIS_DIGEST = 0x5cf6f6c247c1f0f401825bf6c145f66ad6b40952e49af543850d1bc6f6b90f73;

    MockTIP20 internal token;
    BajillionSettlement internal settlement;
    BLS.G2Point[] internal committee;

    /// @dev Every accepted deposit as `account || amount`, by inbox index.
    bytes[] internal inbox;
    mapping(uint64 => bytes) internal registeredDeposits;
    mapping(uint64 => bytes) internal registeredWithdrawals;
    mapping(bytes32 => Target) internal targets;
    /// @dev The target an in-flight admission would create, committed only if it succeeds.
    bytes32 internal admittingId;
    Target internal admitting;

    function setUp() public {
        vm.warp(0);
        token = new MockTIP20();
        token.mint(address(this), type(uint128).max);
        settlement = _deploy(false);
        BLS.G2Point[] memory points = Fixture.committeePoints();
        for (uint256 i; i < points.length; ++i) {
            committee.push(points[i]);
        }
    }

    function _deploy(bool harness) internal returns (BajillionSettlement s) {
        BajillionSettlement.DeploymentArgs memory d = Fixture.deploymentArgs(address(token), 0);
        token.approve(vm.computeCreateAddress(address(this), vm.getNonce(address(this))), d.genesis.liability);
        s = harness ? new SettlementHarness(d) : new BajillionSettlement(d);
        token.approve(address(s), type(uint256).max);
    }

    // ---------------------------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------------------------

    /// @notice The Solidity digest reproduces the README's genesis vector byte for byte.
    function test_Inv10_GenesisDigestKnownAnswer() public view {
        assertEq(StateDigest.preimage(settlement), GENESIS_PREIMAGE, "genesis preimage");
        assertEq(StateDigest.digest(settlement), GENESIS_DIGEST, "genesis digest");
    }

    /// @notice The generator's skip list is exactly the documented one.
    function test_Inv10_SkipList() public pure {
        string[3] memory expected = [
            "PENDING queueWithdrawal",
            "PENDING registerEpoch with a nonempty withdrawal batch",
            "NOT APPLICABLE recordDeposit reusing a deposit id"
        ];
        string[] memory skips = skipList();
        assertEq(skips.length, expected.length, "skip list length");
        for (uint256 i; i < expected.length; ++i) {
            assertEq(skips[i], expected[i]);
        }

        // The generator never emits queueWithdrawal.
        for (uint64 seed; seed < 64; ++seed) {
            Op[] memory ops = generate(seed);
            for (uint256 i; i < ops.length; ++i) {
                assertTrue(ops[i].kind != QUEUE_WITHDRAWAL, "generated queueWithdrawal");
                assertTrue(ops[i].kind <= ADVANCE_TIME, "generated an unknown kind");
            }
        }

        // The filter drops exactly the skipped materializations.
        Op[] memory sample = new Op[](6);
        sample[0] = Op(REGISTER_EPOCH, abi.encode(bytes(""), uint64(0), hex"00", hex"00"));
        sample[1] = Op(REGISTER_EPOCH, abi.encode(bytes(""), uint64(0), hex"00", hex"0100"));
        sample[2] = Op(RECORD_DEPOSIT, abi.encode(bytes32(uint256(1)), bytes32(uint256(2)), uint64(3)));
        sample[3] = Op(RECORD_DEPOSIT, abi.encode(bytes32(uint256(1)), bytes32(uint256(4)), uint64(5)));
        sample[4] = Op(QUEUE_WITHDRAWAL, abi.encode(bytes(""), bytes("")));
        sample[5] = Op(FINALIZE, "");
        Op[] memory kept = filter(sample);
        assertEq(kept.length, 3, "kept count");
        assertEq(kept[0].args, sample[0].args);
        assertEq(kept[1].args, sample[2].args);
        assertEq(kept[2].kind, FINALIZE);
    }

    /// @notice Random op sequences. Fuzz runs come from the differential profile.
    function testFuzz_Differential_Inv10(uint64 seed) public {
        _differential(seed, generate(seed));
    }

    /// @notice A scripted lifecycle on the production contract: deposits, registration,
    /// admission, the challenge window, finalization, a second epoch, a challenge and an expiry.
    /// Several seeds, and at least one success of each lifecycle step across them.
    function test_Differential_Inv10_Lifecycle() public {
        uint8[19] memory script = [
            RECORD_DEPOSIT,
            RECORD_DEPOSIT,
            ADVANCE_TIME,
            REGISTER_EPOCH,
            ADVANCE_TIME,
            ADMIT,
            ADVANCE_TIME,
            ADVANCE_TIME,
            ADVANCE_TIME,
            FINALIZE,
            CLAIM_WITHDRAWAL,
            RECORD_DEPOSIT,
            REGISTER_EPOCH,
            ADMIT,
            CHALLENGE,
            ADVANCE_TIME,
            FINALIZE,
            ADVANCE_TIME,
            FAULT_EXPIRED
        ];
        Op[] memory ops = new Op[](script.length);
        for (uint256 i; i < script.length; ++i) {
            ops[i].kind = script[i];
        }
        bool[9] memory succeeded;
        for (uint64 seed; seed < 16; ++seed) {
            uint256 snapshot = vm.snapshotState();
            (Op[] memory applied, uint16[] memory statuses) = _differential(seed, ops);
            for (uint256 i; i < applied.length; ++i) {
                if (statuses[i] == OracleStatus.OK) succeeded[applied[i].kind] = true;
            }
            // Restores the contract, the token and this test's ledgers.
            vm.revertToState(snapshot);
            vm.warp(0);
        }
        assertTrue(succeeded[RECORD_DEPOSIT], "no deposit succeeded");
        assertTrue(succeeded[REGISTER_EPOCH], "no registration succeeded");
        assertTrue(succeeded[ADMIT], "no admission succeeded");
        assertTrue(succeeded[FINALIZE], "no finalization succeeded");
        assertTrue(succeeded[CHALLENGE], "no challenge succeeded");
    }

    /// @notice The crate fixture epoch as concrete ops, ending in a paid claim and a replayed
    /// claim. Its registration carries one signed withdrawal, so the contract side is
    /// `SettlementHarness`, which differs from production only in computing that batch's root
    /// without checking the Ed25519 signature; the oracle checks it.
    function test_Differential_Inv10_FixtureClaim() public {
        settlement = _deploy(true);
        Op[] memory ops = new Op[](8);
        ops[0] = Op(ADVANCE_TIME, abi.encode(uint64(Fixture.uintAt(".scenario.timing.register_at"))));
        ops[1] = Op(
            REGISTER_EPOCH,
            abi.encode(
                Fixture.hexFile("epoch_context"),
                uint64(0),
                Fixture.hexFile("deposit_batch"),
                Fixture.hexFile("withdrawal_batch")
            )
        );
        ops[2] = Op(ADVANCE_TIME, abi.encode(uint64(Fixture.uintAt(".scenario.timing.admit_at") - 100)));
        BajillionSettlement.Admission memory a = Fixture.admission();
        ops[3] = Op(ADMIT, abi.encode(a.header, a.roots, a.withdrawalTotal, a.certificate));
        ops[4] = Op(ADVANCE_TIME, abi.encode(uint64(Fixture.uintAt(".scenario.timing.finalize_at") - 105)));
        ops[5] = Op(FINALIZE, "");
        ops[6] = Op(CLAIM_WITHDRAWAL, abi.encode(Fixture.hexFile("payout_claim")));
        ops[7] = Op(CLAIM_WITHDRAWAL, abi.encode(Fixture.hexFile("payout_claim")));
        uint16[] memory statuses = _compare(0, ops);
        for (uint256 i; i < 7; ++i) {
            assertEq(statuses[i], OracleStatus.OK, "fixture lifecycle step failed");
        }
        assertEq(statuses[7], 101, "replayed claim must be ClaimError::Unavailable");
    }

    // ---------------------------------------------------------------------------------------
    // Generator
    // ---------------------------------------------------------------------------------------

    /// @notice What the generator skips, and why. Pinned by `test_Inv10_SkipList`.
    function skipList() public pure returns (string[] memory skips) {
        skips = new string[](3);
        skips[0] = "PENDING queueWithdrawal";
        skips[1] = "PENDING registerEpoch with a nonempty withdrawal batch";
        skips[2] = "NOT APPLICABLE recordDeposit reusing a deposit id";
    }

    /// @notice Seed-chosen op kinds with empty args, for the oracle to materialize. Weights
    /// favour the lifecycle ops and time, so sequences reach admission and finalization.
    function generate(uint64 seed) public pure returns (Op[] memory ops) {
        uint256 length = 16 + uint256(keccak256(abi.encode(seed, "length"))) % 48;
        ops = new Op[](length);
        for (uint256 i; i < length; ++i) {
            uint256 r = uint256(keccak256(abi.encode(seed, i))) % 100;
            uint8 kind;
            if (r < 16) kind = RECORD_DEPOSIT;
            else if (r < 30) kind = REGISTER_EPOCH;
            else if (r < 46) kind = ADMIT;
            else if (r < 56) kind = CHALLENGE;
            else if (r < 68) kind = FINALIZE;
            else if (r < 74) kind = CLAIM_WITHDRAWAL;
            else if (r < 78) kind = FAULT_EXPIRED;
            else kind = ADVANCE_TIME;
            ops[i].kind = kind;
        }
    }

    /// @notice Drop the skipped ops from a materialized sequence.
    function filter(Op[] memory ops) public pure returns (Op[] memory kept) {
        kept = new Op[](ops.length);
        bytes32[] memory ids = new bytes32[](ops.length);
        uint256 idCount;
        uint256 n;
        for (uint256 i; i < ops.length; ++i) {
            Op memory op = ops[i];
            if (op.kind == QUEUE_WITHDRAWAL) continue;
            if (op.kind == REGISTER_EPOCH) {
                (,,, bytes memory withdrawals) = abi.decode(op.args, (bytes, uint64, bytes, bytes));
                if (withdrawals.length != 1 || withdrawals[0] != 0x00) continue;
            }
            if (op.kind == RECORD_DEPOSIT) {
                (bytes32 id,,) = abi.decode(op.args, (bytes32, bytes32, uint64));
                bool reused;
                for (uint256 j; j < idCount; ++j) {
                    if (ids[j] == id) reused = true;
                }
                if (reused) continue;
                ids[idCount++] = id;
            }
            kept[n++] = op;
        }
        assembly ("memory-safe") {
            mstore(kept, n)
        }
    }

    // ---------------------------------------------------------------------------------------
    // Differential driver
    // ---------------------------------------------------------------------------------------

    /// @dev Materialize, filter, then compare. Returns the applied ops and the oracle statuses.
    function _differential(uint64 seed, Op[] memory ops) internal returns (Op[] memory applied, uint16[] memory) {
        applied = filter(_materialize(seed, ops));
        return (applied, _compare(seed, applied));
    }

    /// @dev Apply `ops` (all args concrete) through the oracle and the contract and require
    /// identical statuses, fence flags and final digest.
    function _compare(uint64 seed, Op[] memory ops) internal returns (uint16[] memory statuses) {
        bool[] memory mutated;
        bytes32 expected;
        (statuses, mutated, expected) = _oracleApply(seed, ops);
        assertEq(statuses.length, ops.length, "oracle status count");
        for (uint256 i; i < ops.length; ++i) {
            (uint16 status, bool fenced) = _apply(ops[i]);
            string memory where =
                string.concat("seed ", vm.toString(seed), " op ", vm.toString(i), " kind ", vm.toString(ops[i].kind));
            assertEq(status, statuses[i], string.concat(where, ": status"));
            assertEq(fenced, mutated[i], string.concat(where, ": mutatedOnError"));
        }
        assertEq(StateDigest.digest(settlement), expected, string.concat("seed ", vm.toString(seed), ": digest"));
    }

    function _materialize(uint64 seed, Op[] memory ops) internal returns (Op[] memory) {
        return abi.decode(vm.ffi(_command("materialize", seed, ops)), (Op[]));
    }

    function _oracleApply(uint64 seed, Op[] memory ops) internal returns (uint16[] memory, bool[] memory, bytes32) {
        return abi.decode(vm.ffi(_command("apply", seed, ops)), (uint16[], bool[], bytes32));
    }

    function _command(string memory verb, uint64 seed, Op[] memory ops) internal pure returns (string[] memory cmd) {
        cmd = new string[](3);
        cmd[0] = ORACLE;
        cmd[1] = verb;
        cmd[2] = vm.toString(abi.encode(seed, ops));
    }

    // ---------------------------------------------------------------------------------------
    // Contract side
    // ---------------------------------------------------------------------------------------

    /// @dev Run one op against the contract. `mutatedOnError` is true exactly when the op failed
    /// without reverting: the contract returns a non-Ok status only after committing the fence,
    /// and a revert discards every write.
    function _apply(Op memory op) internal returns (uint16 status, bool mutatedOnError) {
        if (op.kind == ADVANCE_TIME) return (_advance(op.args), false);
        vm.recordLogs();
        (bool ok, bytes memory ret) = _call(op);
        if (!ok) return (_revertCode(ret), false);
        status = _returnedCode(op.kind, ret);
        if (status == OracleStatus.OK) _record(op);
        return (status, status != OracleStatus.OK);
    }

    function _call(Op memory op) internal returns (bool ok, bytes memory ret) {
        address s = address(settlement);
        if (op.kind == RECORD_DEPOSIT) {
            (, bytes32 account, uint64 amount) = abi.decode(op.args, (bytes32, bytes32, uint64));
            return s.call(abi.encodeCall(BajillionSettlement.deposit, (account, amount)));
        }
        if (op.kind == REGISTER_EPOCH) {
            (bytes memory context, uint64 end, bytes memory deposits, bytes memory withdrawals) =
                abi.decode(op.args, (bytes, uint64, bytes, bytes));
            return s.call(
                abi.encodeCall(
                    BajillionSettlement.registerEpoch, (context, end, deposits, withdrawals, _pulledDeposits(end))
                )
            );
        }
        if (op.kind == ADMIT) return s.call(abi.encodeCall(BajillionSettlement.admit, (_admission(op.args))));
        if (op.kind == CHALLENGE) {
            (bytes32 batchId, bytes memory evidence) = abi.decode(op.args, (bytes32, bytes));
            Target memory t = targets[batchId];
            return s.call(
                abi.encodeCall(
                    BajillionSettlement.challenge, (batchId, t.context, t.roots, t.withdrawalTotal, evidence)
                )
            );
        }
        if (op.kind == FINALIZE) return s.call(abi.encodeCall(BajillionSettlement.finalize, ()));
        if (op.kind == CLAIM_WITHDRAWAL) {
            bytes memory claim = abi.decode(op.args, (bytes));
            return s.call(abi.encodeCall(BajillionSettlement.claimWithdrawal, (_predecessor(_position(claim)), claim)));
        }
        if (op.kind == FAULT_EXPIRED) return s.call(abi.encodeCall(BajillionSettlement.faultExpired, ()));
        revert("differential: op kind not generated");
    }

    function _advance(bytes memory args) internal returns (uint16) {
        uint64 delta = abi.decode(args, (uint64));
        // The oracle's clock is a u64 and reports overflow as 1003 without moving.
        if (uint256(block.timestamp) + delta > type(uint64).max) return 1003;
        vm.warp(block.timestamp + delta);
        return OracleStatus.OK;
    }

    function _revertCode(bytes memory ret) internal pure returns (uint16) {
        if (ret.length < 4) return OracleStatus.UNMAPPED;
        return OracleStatus.fromSelector(bytes4(ret));
    }

    /// @dev Status-returning methods put `Status` in the first word; `faultExpired` and
    /// `claimWithdrawal` either revert or succeed.
    function _returnedCode(uint8 kind, bytes memory ret) internal view returns (uint16) {
        if (kind == FAULT_EXPIRED || kind == CLAIM_WITHDRAWAL) return OracleStatus.OK;
        BajillionSettlement.Status status = BajillionSettlement.Status(abi.decode(ret, (uint8)));
        if (status != BajillionSettlement.Status.Rejected) return OracleStatus.fromStatus(status);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == BajillionSettlement.Rejected.selector) {
                return OracleStatus.fromSelector(abi.decode(logs[i].data, (bytes4)));
            }
        }
        return OracleStatus.UNMAPPED;
    }

    /// @dev Keep the embedding ledgers in step with an accepted op.
    function _record(Op memory op) internal {
        if (op.kind == RECORD_DEPOSIT) {
            (, bytes32 account, uint64 amount) = abi.decode(op.args, (bytes32, bytes32, uint64));
            inbox.push(abi.encodePacked(account, amount));
        } else if (op.kind == REGISTER_EPOCH) {
            (,, bytes memory deposits, bytes memory withdrawals) = abi.decode(op.args, (bytes, uint64, bytes, bytes));
            registeredDeposits[settlement.registeredEnd() - 1] = deposits;
            registeredWithdrawals[settlement.registeredEnd() - 1] = withdrawals;
        } else if (op.kind == ADMIT) {
            targets[admittingId] = admitting;
        }
    }

    // ---- Witnesses ----------------------------------------------------------------------

    /// @dev The individual deposits at inbox indices `[pulled, end)`, or nothing when `end` is
    /// out of range (the contract then fails `IntakeRange` before reading the witness).
    function _pulledDeposits(uint64 end) internal view returns (bytes memory out) {
        uint64 pulled = settlement.pulled();
        if (end < pulled || end > inbox.length) return out;
        for (uint64 i = pulled; i < end; ++i) {
            out = bytes.concat(out, inbox[i]);
        }
    }

    /// @dev Build the contract's admission from the oracle's four arguments. The frontier's bound
    /// context must be read before the call, which may promote the next frontier, so it is staged
    /// here under the batch id the admission would get and committed by `_record`.
    function _admission(bytes memory args) internal returns (BajillionSettlement.Admission memory a) {
        bytes memory certificate;
        (a.header, a.roots, a.withdrawalTotal, certificate) = abi.decode(args, (bytes32, bytes, uint64, bytes));
        a.certificate = certificate;
        if (certificate.length >= 48) {
            bytes memory signature = new bytes(48);
            for (uint256 i; i < 48; ++i) {
                signature[i] = certificate[certificate.length - 48 + i];
            }
            a.signature = G1Decompress.decompress(signature);
        }
        a.committee = committee;
        if (settlement.registeredEnd() > settlement.admittedEnd()) {
            uint64 frontier = settlement.admittedEnd();
            a.deposits = registeredDeposits[frontier];
            a.withdrawals = registeredWithdrawals[frontier];
            admittingId = sha256(abi.encodePacked("_COMMONWARE_CLEARING_BATCH_ID", a.header));
            admitting = Target(settlement.frontierContext(), a.roots, a.withdrawalTotal);
        } else {
            a.deposits = hex"00";
            a.withdrawals = hex"00";
        }
    }

    /// @dev `claim.position()`: the opening's start, after the output's destination and amount.
    function _position(bytes memory claim) internal view returns (uint64) {
        (uint256 length, uint256 pos, bool ok) = this.readVarint(claim);
        if (!ok || claim.length < pos + length + 16) return 0;
        uint256 offset = pos + length + 8;
        uint64 start;
        for (uint256 i; i < 8; ++i) {
            start = (start << 8) | uint8(claim[offset + i]);
        }
        return start;
    }

    function readVarint(bytes calldata data) external pure returns (uint256 value, uint256 next, bool ok) {
        return Codec.readVarint(data, 0, 32);
    }

    /// @dev The start of the claimed range at or before `index`, walking the contract's list.
    function _predecessor(uint64 index) internal view returns (uint64 predecessor) {
        uint64 cursor = settlement.claimedHead();
        while (cursor != 0 && cursor <= index) {
            predecessor = cursor;
            (, cursor) = settlement.claimed(cursor);
        }
    }
}
