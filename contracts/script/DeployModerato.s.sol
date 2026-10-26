// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { console } from "forge-std/console.sol";
import { BajillionSettlement } from "../src/BajillionSettlement.sol";
import { Fixture } from "../test/utils/Fixture.sol";
import { ModeratoBase } from "./ModeratoBase.sol";

interface IERC20Approve {
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @notice Deployment plan and verification for BajillionSettlement on Tempo Moderato, with the
/// crate fixtures' deployment (deployment id, operator, 4-validator committee with proofs of
/// possession, genesis) and the demo policy in ModeratoBase.
///
/// Forge's local simulation cannot run Tempo's native TIP-20 precompiles (pathUSD reverts with
/// `OpcodeNotFound` under forge 1.5.1) and prices state creation by the Ethereum schedule rather
/// than Tempo's (250,000 gas per new slot, 1,000 per code byte). So this script builds the exact
/// transactions and verifies the result, and `cast send` broadcasts them with the node's gas
/// estimate (deployments/README.md has the commands):
///
///     forge script script/DeployModerato.s.sol --rpc-url moderato            # writes the plan
///     forge script script/DeployModerato.s.sol --rpc-url moderato --sig "verify()"
///
/// Libraries come from their canonical 1,000,000-run artifacts and are linked by hand: every
/// `__$<keccak(fqn)[:17]>$__` placeholder is replaced with the library's address, which is fixed
/// by the deployer's nonce at broadcast. Forge also writes 200-run copies (`*.settlement.json`) for
/// the restricted settlement job, and its own linker does not say which it uses, so nothing here
/// relies on it. The plan checks each artifact's optimizer runs; `verify` checks each library's
/// on-chain code hash against its linked artifact.
contract DeployModerato is ModeratoBase {
    struct Lib {
        string fqn;
        string artifact;
        address addr;
    }

    Lib[] internal libs;

    /// @dev `PLAN_FILE` overrides the plan path, so a local replay keeps its own plan.
    function _planFile() internal view returns (string memory) {
        return vm.envOr("PLAN_FILE", string("../deployments/moderato.plan.json"));
    }
    string internal constant SETTLEMENT_ARTIFACT = "out/BajillionSettlement.sol/BajillionSettlement.json";

    function run() external {
        require(block.chainid == CHAIN_ID, "not Moderato");
        address deployer = vm.addr(_key());
        uint64 nonce = vm.getNonce(deployer);
        _libraries(deployer, nonce);
        require(_runs(SETTLEMENT_ARTIFACT) == 200, "settlement artifact is not the 200-run build");

        // Transactions in order: one CREATE per library, the pathUSD approval for the genesis
        // liability the constructor pulls, then the settlement CREATE.
        string memory txs = "txs";
        string memory list;
        for (uint256 i; i < libs.length; ++i) {
            require(_runs(libs[i].artifact) == 1_000_000, "library artifact is not the 1,000,000-run build");
            list = vm.serializeBytes(txs, _key3(i), _linked(libs[i].artifact, ".bytecode.object"));
        }
        address settlement = vm.computeCreateAddress(deployer, nonce + libs.length + 1);
        BajillionSettlement.DeploymentArgs memory d = _args();
        list = vm.serializeBytes(
            txs, _key3(libs.length), abi.encodeCall(IERC20Approve.approve, (settlement, d.genesis.liability))
        );
        list = vm.serializeBytes(
            txs, _key3(libs.length + 1), bytes.concat(_linked(SETTLEMENT_ARTIFACT, ".bytecode.object"), abi.encode(d))
        );

        string memory root = "plan";
        vm.serializeAddress(root, "deployer", deployer);
        vm.serializeUint(root, "startNonce", nonce);
        vm.serializeAddress(root, "settlement", settlement);
        vm.serializeAddress(root, "pathUSD", PATH_USD);
        vm.serializeString(root, "libraries", _libraryJson());
        string memory json = vm.serializeString(root, "transactions", list);
        vm.writeJson(json, _planFile());
        console.log("plan written for deployer", deployer);
        console.log("settlement will deploy at", settlement);
    }

    /// @notice Check the broadcast deployment against the plan.
    function verify() external view {
        string memory plan = vm.readFile(_planFile());
        address deployer = vm.parseJsonAddress(plan, ".deployer");
        uint64 nonce = uint64(vm.parseJsonUint(plan, ".startNonce"));
        address settlementAddress = vm.parseJsonAddress(plan, ".settlement");
        Lib[] memory list = _plannedLibraries(deployer, nonce);
        for (uint256 i; i < list.length; ++i) {
            bytes memory expected = _linkedWith(list, list[i].artifact, ".deployedBytecode.object");
            _setDeployAddress(expected, list[i].artifact, list[i].addr);
            require(
                keccak256(list[i].addr.code) == keccak256(expected),
                string.concat(list[i].fqn, ": on-chain code differs from its 1,000,000-run artifact")
            );
            console.log("library verified", list[i].fqn, list[i].addr);
        }
        BajillionSettlement s = BajillionSettlement(settlementAddress);
        require(settlementAddress.code.length <= 24_576, "settlement over EIP-170");
        require(s.challengeDuration() == CHALLENGE_DURATION && s.admissionDelay() == ADMISSION_DELAY, "config");
        require(s.asset() == PATH_USD, "asset");
        require(s.custodyBalance() == 200, "genesis custody");
        console.log("settlement verified", settlementAddress, settlementAddress.code.length);
    }

    function _args() internal view returns (BajillionSettlement.DeploymentArgs memory d) {
        d = Fixture.deploymentArgs(PATH_USD, 0);
        d.config = BajillionSettlement.SettlementConfig(
            ADMISSION_DELAY,
            CHALLENGE_DURATION,
            DEPOSIT_INCLUSION_TIMEOUT,
            MINIMUM_WITHDRAWAL_NOTICE,
            MAXIMUM_WITHDRAWAL_NOTICE,
            MAX_DESTINATION_BYTES,
            MAX_DEPOSIT_IDS
        );
    }

    /// @dev Libraries in dependency order (each links only those before it), at the addresses
    /// their CREATEs from `nonce` onward produce.
    function _libraries(address deployer, uint64 nonce) internal {
        Lib[] memory list = _plannedLibraries(deployer, nonce);
        for (uint256 i; i < list.length; ++i) {
            libs.push(list[i]);
        }
    }

    function _plannedLibraries(address deployer, uint64 nonce) internal pure returns (Lib[] memory list) {
        string[2][11] memory names = [
            ["src/verify/LibEd25519.sol:Ed25519Verifier", "out/LibEd25519.sol/Ed25519Verifier.json"],
            [
                "src/verify/BajillionVerifiers.sol:CertificateVerifier",
                "out/BajillionVerifiers.sol/CertificateVerifier.json"
            ],
            ["src/verify/BajillionVerifiers.sol:PayoutVerifier", "out/BajillionVerifiers.sol/PayoutVerifier.json"],
            [
                "src/verify/BajillionVerifiers.sol:AdmissionVerifier",
                "out/BajillionVerifiers.sol/AdmissionVerifier.json"
            ],
            ["src/verify/WithdrawalVerifiers.sol:WithdrawalCodec", "out/WithdrawalVerifiers.sol/WithdrawalCodec.json"],
            ["src/verify/WithdrawalVerifiers.sol:StateVerifier", "out/WithdrawalVerifiers.sol/StateVerifier.json"],
            ["src/BajillionChallenge.sol:BajillionChallenge", "out/BajillionChallenge.sol/BajillionChallenge.json"],
            [
                "src/BajillionWithdrawals.sol:BajillionWithdrawals",
                "out/BajillionWithdrawals.sol/BajillionWithdrawals.json"
            ],
            ["src/BajillionClaims.sol:BajillionClaims", "out/BajillionClaims.sol/BajillionClaims.json"],
            ["src/BajillionLiveness.sol:BajillionLiveness", "out/BajillionLiveness.sol/BajillionLiveness.json"],
            ["src/BajillionRecovery.sol:BajillionRecovery", "out/BajillionRecovery.sol/BajillionRecovery.json"]
        ];
        list = new Lib[](names.length);
        for (uint256 i; i < names.length; ++i) {
            list[i] = Lib(names[i][0], names[i][1], vm.computeCreateAddress(deployer, nonce + i));
        }
    }

    /// @dev Under via-IR, a library with state-changing functions guards against direct calls
    /// with an immutable, `library_deploy_address`, which its constructor fills with its own
    /// address. Write that address at each offset the artifact records; view-only libraries have
    /// none.
    function _setDeployAddress(bytes memory code, string memory artifact, address self) internal view {
        string memory json = vm.readFile(artifact);
        string memory refs = ".deployedBytecode.immutableReferences.library_deploy_address";
        for (uint256 k;; ++k) {
            string memory path = string.concat(refs, "[", vm.toString(k), "].start");
            if (!vm.keyExistsJson(json, path)) break;
            uint256 start = vm.parseJsonUint(json, path);
            bytes32 word = bytes32(uint256(uint160(self)));
            for (uint256 b; b < 32; ++b) {
                code[start + b] = word[b];
            }
        }
    }

    function _libraryJson() internal returns (string memory out) {
        for (uint256 i; i < libs.length; ++i) {
            out = vm.serializeAddress("libs", libs[i].fqn, libs[i].addr);
        }
    }

    function _key3(uint256 i) internal pure returns (string memory) {
        return string.concat(i < 10 ? "0" : "", vm.toString(i));
    }

    function _linked(string memory artifact, string memory field) internal view returns (bytes memory) {
        return _linkedWith(libs, artifact, field);
    }

    /// @dev The artifact's bytecode with every library in `list` linked in. Fails if a placeholder
    /// remains.
    function _linkedWith(Lib[] memory list, string memory artifact, string memory field)
        internal
        view
        returns (bytes memory)
    {
        string memory code = vm.parseJsonString(vm.readFile(artifact), field);
        for (uint256 i; i < list.length; ++i) {
            code = vm.replace(code, _placeholder(list[i].fqn), _hexNoPrefix(list[i].addr));
        }
        require(vm.indexOf(code, "__$") == type(uint256).max, string.concat(artifact, ": unlinked library"));
        return vm.parseBytes(code);
    }

    function _placeholder(string memory fqn) internal pure returns (string memory) {
        return string.concat("__$", _slice(vm.toString(abi.encodePacked(keccak256(bytes(fqn)))), 2, 36), "$__");
    }

    function _hexNoPrefix(address a) internal pure returns (string memory) {
        return _slice(vm.toLowercase(vm.toString(a)), 2, 42);
    }

    function _slice(string memory text, uint256 start, uint256 end) internal pure returns (string memory) {
        bytes memory b = bytes(text);
        bytes memory out = new bytes(end - start);
        for (uint256 i; i < out.length; ++i) {
            out[i] = b[start + i];
        }
        return string(out);
    }

    function _runs(string memory artifact) internal view returns (uint256) {
        return vm.parseJsonUint(vm.readFile(artifact), ".metadata.settings.optimizer.runs");
    }
}
