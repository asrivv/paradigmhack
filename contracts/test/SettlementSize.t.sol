// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { BajillionSettlement } from "../src/BajillionSettlement.sol";
import { MockTIP20 } from "./mocks/MockTIP20.sol";
import { Fixture } from "./utils/Fixture.sol";

/// @notice EIP-170 caps deployed bytecode at 24,576 bytes. Forge does not enforce it in tests,
/// so this test does. foundry.toml compiles BajillionSettlement alone at 200 optimizer runs; the
/// linked verifier libraries are separate contracts with their own limit and keep 1,000,000.
contract SettlementSizeTest is Test {
    uint256 internal constant EIP170_LIMIT = 24_576;

    function test_DeployedSizeWithinEip170() public {
        MockTIP20 token = new MockTIP20();
        BajillionSettlement.DeploymentArgs memory d = Fixture.deploymentArgs(address(token), 0);
        token.mint(address(this), d.genesis.liability);
        token.approve(vm.computeCreateAddress(address(this), vm.getNonce(address(this))), d.genesis.liability);
        BajillionSettlement settlement = new BajillionSettlement(d);
        uint256 size = address(settlement).code.length;
        emit log_named_uint("BajillionSettlement deployed bytes", size);
        assertLe(size, EIP170_LIMIT, "BajillionSettlement exceeds EIP-170");
    }
}
