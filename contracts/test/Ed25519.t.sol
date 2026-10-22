// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { LibCodec } from "commonware/codec/LibCodec.sol";
import { LibEd25519 } from "../src/verify/LibEd25519.sol";

contract Ed25519Wrapper {
    function verify(bytes32 key, bytes calldata signature, bytes calldata message) external view returns (bool) {
        return LibEd25519.verify(key, signature, message);
    }

    function isStrictKey(bytes32 key) external view returns (bool) {
        return LibEd25519.isStrictKey(key);
    }
}

/// @notice LibEd25519 against the crate's 18 fixture signatures and ed25519-speccheck's ZIP215 cases.
contract Ed25519Test is Test {
    Ed25519Wrapper internal ed;
    string internal manifest;

    function setUp() public {
        ed = new Ed25519Wrapper();
        manifest = vm.readFile("test/fixtures/manifest.json");
    }

    function _field(uint256 i, string memory name) internal view returns (bytes memory) {
        return vm.parseJsonBytes(manifest, string.concat(".ed25519[", vm.toString(i), "].", name));
    }

    /// @dev Every crate signature verifies over its exact signed bytes, which are the namespace
    /// framed with its varint length followed by the message (utils/src/lib.rs:183-192).
    function test_VerifiesAllFixtureSignatures() public view {
        for (uint256 i; i < 18; ++i) {
            bytes memory ns = _field(i, "namespace");
            bytes memory signed = _field(i, "signed_bytes");
            assertEq(signed, bytes.concat(LibCodec.encodeVarint(uint64(ns.length)), ns, _field(i, "message")));
            bytes32 key = bytes32(_field(i, "public_key"));
            bytes memory signature = _field(i, "signature");
            assertTrue(ed.verify(key, signature, signed), "fixture signature rejected");
            assertTrue(ed.isStrictKey(key), "fixture key is not strict");

            bytes memory tampered = bytes.concat(signed);
            tampered[tampered.length - 1] ^= 0x01;
            assertFalse(ed.verify(key, signature, tampered), "tampered message accepted");
            bytes memory badSig = bytes.concat(signature);
            badSig[0] ^= 0x01;
            assertFalse(ed.verify(key, badSig, signed), "tampered R accepted");
            badSig = bytes.concat(signature);
            badSig[40] ^= 0x01;
            assertFalse(ed.verify(key, badSig, signed), "tampered s accepted");
        }
    }

    /// @dev `s + L` encodes the same scalar non-canonically and must be rejected (signing.rs:353-355).
    function test_RejectsNonCanonicalScalar() public view {
        bytes32 key = bytes32(_field(0, "public_key"));
        bytes memory signature = _field(0, "signature");
        bytes memory signed = _field(0, "signed_bytes");
        uint256 s;
        for (uint256 j; j < 32; ++j) {
            s |= uint256(uint8(signature[32 + j])) << (8 * j);
        }
        s += LibEd25519.L;
        bytes memory wide = new bytes(64);
        for (uint256 j; j < 32; ++j) {
            wide[j] = signature[j];
            wide[32 + j] = bytes1(uint8(s >> (8 * j)));
        }
        assertFalse(ed.verify(key, wide, signed));
        assertFalse(ed.verify(key, bytes.concat(signature, hex"00"), signed), "65-byte signature");
    }

    /// @dev ed25519-speccheck vectors with the results of Zebra, the ZIP215 reference.
    function test_SpeccheckMatchesZip215() public view {
        string memory json = vm.readFile("test/vectors/ed25519_speccheck.json");
        for (uint256 i; i < 12; ++i) {
            string memory c = string.concat(".cases[", vm.toString(i), "].");
            bool expected = vm.parseJsonBool(json, string.concat(c, "zip215_valid"));
            bool actual = ed.verify(
                bytes32(vm.parseJsonBytes(json, string.concat(c, "pub_key"))),
                vm.parseJsonBytes(json, string.concat(c, "signature")),
                vm.parseJsonBytes(json, string.concat(c, "message"))
            );
            assertEq(actual, expected, string.concat("speccheck case ", vm.toString(i)));
        }
    }

    /// @dev Small-order, mixed-order, non-canonical and identity keys are not strict keys.
    function test_StrictKeyRejectsWeakEncodings() public view {
        string memory json = vm.readFile("test/vectors/ed25519_speccheck.json");
        // Case 0: small order. Case 3: mixed order (torsion component). Case 10: y >= p.
        uint256[3] memory weak = [uint256(0), 3, 10];
        for (uint256 i; i < weak.length; ++i) {
            bytes32 key = bytes32(vm.parseJsonBytes(json, string.concat(".cases[", vm.toString(weak[i]), "].pub_key")));
            assertFalse(ed.isStrictKey(key));
        }
        assertFalse(ed.isStrictKey(bytes32(uint256(1) << 248)), "identity");
        // The base point is strict; with the sign bit set (negative zero is not involved) it is
        // its negation, also strict.
        bytes32 base = 0x5866666666666666666666666666666666666666666666666666666666666666;
        assertTrue(ed.isStrictKey(base));
    }

    function test_GasVerify() public {
        bytes32 key = bytes32(_field(0, "public_key"));
        bytes memory signature = _field(0, "signature");
        bytes memory signed = _field(0, "signed_bytes");
        ed.verify(key, signature, signed);
        vm.snapshotGasLastCall("Ed25519", "verify_ack_185_bytes");
        ed.isStrictKey(key);
        vm.snapshotGasLastCall("Ed25519", "isStrictKey");
    }
}
