// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { LibBLS12381 as BLS } from "commonware/certificate/LibBLS12381.sol";
import { BajillionSettlement } from "../src/BajillionSettlement.sol";
import { LibVectorCommitment as Vector } from "../src/verify/LibVectorCommitment.sol";
import { SettlementHarness } from "./tmp/SettlementHarness.sol";
import { TmpBLS } from "./tmp/TmpBLS.sol";
import { MockTIP20 } from "./mocks/MockTIP20.sol";

/// @dev Shared deployment and close construction. All vectors are TEMPORARY (see test/tmp/).
abstract contract SettlementBase is Test {
    bytes internal constant HEADER_ROOT_NAMESPACE = "_COMMONWARE_CLEARING_HEADER_ROOT";
    bytes internal constant EPOCH_ANCHOR_NAMESPACE = "_COMMONWARE_CLEARING_EPOCH_ANCHOR";
    bytes internal constant HEADER_NAMESPACE = "_COMMONWARE_CLEARING_HEADER";
    bytes internal constant COMMITTEE_NAMESPACE = "_COMMONWARE_CLEARING_COMMITTEE";
    bytes internal constant POP_NAMESPACE = "_PARADIGMHACK_TEST_POP";

    bytes32 internal constant DEPLOYMENT = keccak256("deployment");
    bytes32 internal constant OPERATOR = keccak256("operator");
    bytes32 internal constant GENESIS_ROOT = keccak256("genesis state root");
    uint64 internal constant ADMISSION_DELAY = 10;
    uint64 internal constant CHALLENGE_DURATION = 100;
    uint64 internal constant DEPOSIT_TIMEOUT = 1000;
    uint64 internal constant BOND = 5_000_000;
    uint64 internal constant START = 1_000_000;

    uint256 internal constant N = 4;

    MockTIP20 internal token;
    SettlementHarness internal settlement;

    // Committee in canonical (compressed-byte) order.
    uint256[] internal secretKeys;
    bytes[] internal compressedKeys;
    BLS.G2Point[] internal points;

    function setUp() public virtual {
        vm.warp(START);
        token = new MockTIP20();
        _buildCommittee();
        settlement = _deploy(_args());
    }

    function _buildCommittee() internal {
        uint256[] memory sks = new uint256[](N);
        bytes[] memory keys = new bytes[](N);
        for (uint256 i; i < N; ++i) {
            sks[i] = i + 1;
            keys[i] = TmpBLS.compressG2(TmpBLS.mulG2(TmpBLS.g2Generator(), sks[i]));
        }
        // Sort by compressed bytes, as `Committee::new` orders members.
        for (uint256 i; i < N; ++i) {
            for (uint256 j = i + 1; j < N; ++j) {
                if (_less(keys[j], keys[i])) {
                    (keys[i], keys[j]) = (keys[j], keys[i]);
                    (sks[i], sks[j]) = (sks[j], sks[i]);
                }
            }
        }
        for (uint256 i; i < N; ++i) {
            secretKeys.push(sks[i]);
            compressedKeys.push(keys[i]);
            points.push(TmpBLS.mulG2(TmpBLS.g2Generator(), sks[i]));
        }
    }

    function _args() internal view returns (BajillionSettlement.DeploymentArgs memory d) {
        d.deployment = DEPLOYMENT;
        d.operator = OPERATOR;
        d.expectedEpoch = 0;
        d.genesis = BajillionSettlement.Genesis(GENESIS_ROOT, 1, 0);
        d.config = BajillionSettlement.SettlementConfig(
            ADMISSION_DELAY, CHALLENGE_DURATION, DEPOSIT_TIMEOUT, 2000, 4000, 64, 1_000_000
        );
        d.asset = address(token);
        d.bond = BOND;
        d.popNamespace = POP_NAMESPACE;
        d.committee = new BajillionSettlement.Validator[](N);
        for (uint256 i; i < N; ++i) {
            BLS.G1Point memory pop = TmpBLS.proveKey(secretKeys[i], POP_NAMESPACE, compressedKeys[i]);
            d.committee[i] = BajillionSettlement.Validator(
                compressedKeys[i], points[i], TmpBLS.compressG1(pop), TmpBLS.uncompressedG1(pop)
            );
        }
    }

    function _deploy(BajillionSettlement.DeploymentArgs memory d) internal returns (SettlementHarness s) {
        uint256 funding = uint256(d.genesis.liability) + d.bond;
        token.mint(address(this), funding);
        token.approve(vm.computeCreateAddress(address(this), vm.getNonce(address(this))), funding);
        s = new SettlementHarness(d);
    }

    // ---- Epoch registration -------------------------------------------------------------

    function _limits() internal pure returns (bytes memory) {
        uint64 v = uint64(1 << 24);
        return abi.encodePacked(v, v, v, v, v, type(uint64).max, type(uint64).max, type(uint64).max);
    }

    function _committeeCommitment() internal view returns (bytes32) {
        bytes memory encoded = abi.encodePacked(uint8(N));
        for (uint256 i; i < N; ++i) {
            encoded = bytes.concat(encoded, compressedKeys[i]);
        }
        return sha256(bytes.concat(COMMITTEE_NAMESPACE, encoded));
    }

    function _epochContext(uint64 epoch, bytes memory deposits) internal view returns (bytes memory) {
        bytes32 depositRoot = this.depositRootOf(deposits);
        bytes32 withdrawalRoot = Vector.emptyWithdrawalRoot();
        bytes32 anchor = sha256(
            abi.encodePacked(
                EPOCH_ANCHOR_NAMESPACE,
                DEPLOYMENT,
                depositRoot,
                withdrawalRoot,
                epoch,
                OPERATOR,
                _limits(),
                _committeeCommitment()
            )
        );
        return abi.encodePacked(
            anchor, epoch, OPERATOR, DEPLOYMENT, depositRoot, withdrawalRoot, _limits(), _committeeCommitment()
        );
    }

    /// @dev External so the batch can be sliced as calldata.
    function depositRootOf(bytes calldata deposits) external pure returns (bytes32) {
        uint256 count = uint8(deposits[0]);
        return Vector.depositRoot(deposits[1:], count);
    }

    function _register(uint64 epoch) internal returns (BajillionSettlement.Status) {
        return settlement.registerEpoch(_epochContext(epoch, hex"00"), settlement.pulled(), hex"00", hex"00", "");
    }

    // ---- Admission ----------------------------------------------------------------------

    /// @dev A RootBundle that satisfies `validate_close_amounts` with no rows and no withdrawals.
    function _roots(bytes32 successor) internal view returns (bytes memory) {
        BajillionSettlement.Head memory h = settlement.head();
        uint64 epoch = settlement.admittedEnd();
        BajillionSettlement.Epoch memory rec = settlement.epochRecord(epoch);
        return abi.encodePacked(
            keccak256(abi.encode("activity", epoch)),
            h.activity.operations + 1,
            rec.floorActivity,
            uint64(0),
            keccak256(abi.encode("payouts", epoch)),
            h.payouts.operations + 1,
            rec.floorPayouts,
            successor,
            uint64(1),
            uint64(0),
            keccak256(abi.encode("proposal", epoch))
        );
    }

    function _header(bytes memory roots, uint64 withdrawalTotal) internal view returns (bytes32) {
        return sha256(abi.encodePacked(HEADER_ROOT_NAMESPACE, settlement.frontierContext(), roots, withdrawalTotal));
    }

    /// @dev Certificate in crate encoding plus its uncompressed aggregate, signed by `signers`
    /// (bitmap over canonical indices).
    function _certificate(bytes32 header, uint8 signers)
        internal
        view
        returns (bytes memory certificate, bytes memory signature)
    {
        BLS.G1Point memory aggregate;
        bool first = true;
        for (uint256 i; i < N; ++i) {
            if (signers & (1 << i) == 0) continue;
            BLS.G1Point memory s = TmpBLS.sign(secretKeys[i], HEADER_NAMESPACE, abi.encodePacked(header));
            aggregate = first ? s : TmpBLS.addG1(aggregate, s);
            first = false;
        }
        certificate = abi.encodePacked(uint64(N), signers, TmpBLS.compressG1(aggregate));
        signature = TmpBLS.uncompressedG1(aggregate);
    }

    function _admission(bytes memory deposits, uint8 signers)
        internal
        view
        returns (BajillionSettlement.Admission memory a)
    {
        a.roots = _roots(keccak256(abi.encode("successor", settlement.admittedEnd())));
        a.withdrawalTotal = 0;
        a.header = _header(a.roots, 0);
        (a.certificate, a.signature) = _certificate(a.header, signers);
        a.committee = points;
        a.deposits = deposits;
        a.withdrawals = hex"00";
    }

    function _admit() internal returns (BajillionSettlement.Status status, bytes32 batchId) {
        return settlement.admit(_admission(hex"00", 0x03));
    }

    // ---- Utilities ----------------------------------------------------------------------

    function _less(bytes memory a, bytes memory b) internal pure returns (bool) {
        for (uint256 i; i < a.length; ++i) {
            if (a[i] != b[i]) return uint8(a[i]) < uint8(b[i]);
        }
        return false;
    }

    function _challengeDeadline(uint64 epoch) internal view returns (uint64) {
        return settlement.epochRecord(epoch).challengeDeadline;
    }

    function _admissionDeadline(uint64 epoch) internal view returns (uint64) {
        return settlement.epochRecord(epoch).admissionDeadline;
    }
}
