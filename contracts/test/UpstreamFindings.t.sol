// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { BajillionSettlement } from "../src/BajillionSettlement.sol";
import { MockTIP20 } from "./mocks/MockTIP20.sol";
import { Fixture } from "./utils/Fixture.sol";

/// @notice Evidence for .notes/upstream.md, finding 2: commonware-sol's BLS12-381 helpers call the
/// EIP-2537 precompiles with `gas()` (sol/src/certificate/LibBLS12381.sol:161, 226, 228, 230, 250
/// at dd6d60cb). A precompile that rejects its input consumes all gas forwarded to it, so a
/// malformed point burns 63/64 of the caller's gas before the verifier can return false.
contract UpstreamFindingsTest is Test {
    uint256 internal constant GAS = 30_000_000;

    function test_BlsPrecompileErrorBurnsForwardedGas() public {
        MockTIP20 token = new MockTIP20();
        BajillionSettlement.DeploymentArgs memory d = Fixture.deploymentArgs(address(token), 0);
        token.mint(address(this), d.genesis.liability);
        token.approve(vm.computeCreateAddress(address(this), vm.getNonce(address(this))), d.genesis.liability);
        BajillionSettlement settlement = new BajillionSettlement(d);
        vm.warp(Fixture.uintAt(".scenario.timing.register_at"));
        settlement.registerEpoch(
            Fixture.hexFile("epoch_context"),
            0,
            Fixture.hexFile("deposit_batch"),
            Fixture.hexFile("withdrawal_batch"),
            ""
        );
        vm.warp(Fixture.uintAt(".scenario.timing.admit_at"));
        BajillionSettlement.Admission memory a = Fixture.admission();

        // Honest admission, for scale.
        uint256 snapshot = vm.snapshotState();
        uint256 before = gasleft();
        settlement.admit{ gas: GAS }(a);
        uint256 honest = before - gasleft();
        vm.revertToState(snapshot);

        // The same certificate with the hint's last y byte changed: x still recompresses to the
        // certificate (the sign bit is unchanged), but (x, y) is off the curve.
        a.signature[95] ^= 0x01;
        before = gasleft();
        (bool ok, bytes memory ret) =
            address(settlement).call{ gas: GAS }(abi.encodeCall(BajillionSettlement.admit, (a)));
        uint256 burned = before - gasleft();
        assertFalse(ok);
        assertEq(bytes4(ret), BajillionSettlement.InvalidCertificate.selector, "still the right error");
        emit log_named_uint("honest admit gas", honest);
        emit log_named_uint("malformed-hint admit gas (30M forwarded)", burned);
        assertGt(burned, GAS * 9 / 10, "the precompile error consumed nearly all forwarded gas");
    }
}
