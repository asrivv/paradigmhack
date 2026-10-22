// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { LibBLS12381 as BLS } from "commonware/certificate/LibBLS12381.sol";
import { LibBLS12381PoP } from "../src/verify/LibBLS12381PoP.sol";
import { LibBLS12381Point } from "../src/verify/LibBLS12381Point.sol";
import { Fixture } from "./utils/Fixture.sol";
import { ScenarioBLS } from "./utils/ScenarioBLS.sol";
import { ScenarioMMR } from "./utils/ScenarioMMR.sol";
import { ScenarioEd25519 } from "./utils/ScenarioEd25519.sol";
import { LibEd25519 } from "../src/verify/LibEd25519.sol";

/// @notice The scenario generators in test/utils/ reproduce crate bytes for the fixture inputs, so
/// scenario tests built on them exercise the same encodings the crate emits.
contract ScenarioAnchorsTest is Test {
    function _g1(bytes memory eip2537) internal pure returns (BLS.G1Point memory) {
        return abi.decode(eip2537, (BLS.G1Point));
    }

    function test_BLSCompressionMatchesCrate() public view {
        for (uint256 i; i < 4; ++i) {
            string memory m = string.concat(".bls.committee[", vm.toString(i), "].");
            BLS.G2Point memory key = Fixture.g2(string.concat(m, "public_key.eip2537"));
            bytes memory compressed = Fixture.bytesAt(string.concat(m, "public_key.compressed"));
            assertEq(ScenarioBLS.compressG2(key), compressed);
            assertTrue(LibBLS12381Point.matchesG2(compressed, key));
            BLS.G1Point memory pop = _g1(Fixture.bytesAt(string.concat(m, "proof_of_possession.eip2537")));
            assertEq(ScenarioBLS.compressG1(pop), Fixture.bytesAt(string.concat(m, "proof_of_possession.compressed")));
        }
        BLS.G1Point memory sig = _g1(Fixture.bytesAt(".bls.certificate.aggregate_signature.eip2537"));
        assertEq(ScenarioBLS.compressG1(sig), Fixture.bytesAt(".bls.certificate.aggregate_signature.compressed"));
        assertEq(
            ScenarioBLS.compressG2(Fixture.g2(".bls.negated_g2_generator.eip2537")),
            Fixture.bytesAt(".bls.negated_g2_generator.compressed")
        );
    }

    /// @dev Hash-to-G1 for the header message (upstream LibBLS12381) and for proofs of possession
    /// (our LibBLS12381PoP copy) match the crate's points.
    function test_HashToCurveMatchesCrate() public view {
        bytes memory header = Fixture.hexFile("header");
        BLS.G1Point memory hm = BLS.hashToG1(Fixture.bytesAt(".bls.header_namespace"), header);
        assertEq(abi.encode(hm), Fixture.bytesAt(".bls.header_message_hash.eip2537"));
        assertEq(
            BLS.encodeMessage(Fixture.bytesAt(".bls.header_namespace"), header), Fixture.bytesAt(".bls.header_message")
        );
        bytes memory ns = Fixture.bytesAt(".bls.pop_namespace");
        for (uint256 i; i < 4; ++i) {
            string memory m = string.concat(".bls.committee[", vm.toString(i), "].");
            bytes memory key = Fixture.bytesAt(string.concat(m, "public_key.compressed"));
            assertEq(BLS.encodeMessage(ns, key), Fixture.bytesAt(string.concat(m, "pop_signed_bytes")));
            assertEq(
                abi.encode(LibBLS12381PoP.hashToG1(ns, key)),
                Fixture.bytesAt(string.concat(m, "pop_message_hash.eip2537"))
            );
        }
    }

    /// @dev The payout-log model reproduces the crate's payout head, opening and claim encoding.
    function test_PayoutLogModelMatchesCrate() public view {
        address destination = address(bytes20(Fixture.bytesAt(".payout_claim.destination")));
        uint64 amount = uint64(Fixture.uintAt(".payout_claim.amount"));
        bytes[] memory ops = new bytes[](3);
        ops[0] = ScenarioMMR.commit(0);
        ops[1] = ScenarioMMR.appendOutput(destination, amount);
        ops[2] = ScenarioMMR.commit(0);
        assertEq(ScenarioMMR.root(ops, 0), Fixture.bytes32At(".payout_claim.payout_head.root"));
        bytes memory claim = ScenarioMMR.claim(destination, amount, 1, 3, 0, ScenarioMMR.proof(ops, 0, 1));
        assertEq(claim, Fixture.hexFile("payout_claim"));
    }

    /// @dev RFC 8032 section 7.1, TEST 1 (empty message) and TEST 2 (one byte).
    function test_Ed25519SignerMatchesRfc8032() public view {
        ScenarioEd25519.Key memory key =
            ScenarioEd25519.fromSeed(0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60);
        assertEq(key.publicKey, 0xd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a);
        bytes memory signature = ScenarioEd25519.sign(key, "");
        assertEq(
            signature,
            hex"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        assertTrue(LibEd25519.verify(key.publicKey, signature, ""));
        key = ScenarioEd25519.fromSeed(0x4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb);
        assertEq(key.publicKey, 0x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c);
        assertEq(
            ScenarioEd25519.sign(key, hex"72"),
            hex"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        );
    }
}
