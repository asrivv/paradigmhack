// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

// Scenario generator, not a conformance vector. RFC 8032 Ed25519 key derivation and signing,
// used to build challenge evidence for epochs the single crate fixture epoch cannot cover.
// ScenarioAnchors.t.sol checks it against RFC 8032 section 7.1 test vector 1.

import { LibEd25519 } from "../../src/verify/LibEd25519.sol";
import { Sha2Ext } from "../../src/verify/vendor/sha512/Sha2Ext.sol";

library ScenarioEd25519 {
    struct Key {
        uint256 scalar;
        bytes32 prefix;
        bytes32 publicKey;
    }

    /// @dev RFC 8032 section 5.1.5: hash the seed, clamp the low half, keep the high half.
    function fromSeed(bytes32 seed) internal view returns (Key memory key) {
        (bytes32 first, bytes32 second) = Sha2Ext.sha512(abi.encodePacked(seed));
        uint256 a = LibEd25519._le(first);
        a &= ~uint256(7);
        a &= (uint256(1) << 254) - 1;
        a |= uint256(1) << 254;
        key.scalar = a;
        key.prefix = second;
        key.publicKey = compress(LibEd25519._scalarMul(a % LibEd25519.L, LibEd25519.basePoint()));
    }

    /// @dev RFC 8032 section 5.1.6, over an already framed message.
    function sign(Key memory key, bytes memory message) internal view returns (bytes memory) {
        uint256 r = LibEd25519._hashToScalar(abi.encodePacked(key.prefix, message));
        bytes32 rBytes = compress(LibEd25519._scalarMul(r, LibEd25519.basePoint()));
        uint256 k = LibEd25519._hashToScalar(abi.encodePacked(rBytes, key.publicKey, message));
        uint256 s = addmod(r, mulmod(k, key.scalar % LibEd25519.L, LibEd25519.L), LibEd25519.L);
        return abi.encodePacked(rBytes, bytes32(LibEd25519._le(bytes32(s))));
    }

    /// @dev Frame `payload` with its namespace as `union_unique` does (utils/src/lib.rs:183-192).
    function signNamespaced(Key memory key, bytes memory namespace, bytes memory payload)
        internal
        view
        returns (bytes memory)
    {
        return sign(key, abi.encodePacked(uint8(namespace.length), namespace, payload));
    }

    function compress(LibEd25519.Point memory q) internal view returns (bytes32) {
        uint256 zInv = LibEd25519._pow(q.z, LibEd25519.P - 2);
        uint256 x = mulmod(q.x, zInv, LibEd25519.P);
        uint256 y = mulmod(q.y, zInv, LibEd25519.P);
        return bytes32(LibEd25519._le(bytes32(y | ((x & 1) << 255))));
    }
}
