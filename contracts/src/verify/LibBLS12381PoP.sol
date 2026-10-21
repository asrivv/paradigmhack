// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

// Copied from commonwarexyz/monorepo sol/src/certificate/LibBLS12381.sol at
// dd6d60cb44fb3dc05cee1efa06d957ce30df1340, which adapts hash-to-curve from Solady and Ithaca:
// https://github.com/Vectorized/solady/blob/2afba69bf67b78dd4abeadcc696052b3a6f71499/src/utils/ext/ithaca/BLS.sol
//
// Copyright (c) 2022-2026 Solady.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import { LibBLS12381 as BLS } from "commonware/certificate/LibBLS12381.sol";

/// @notice MinSig proof-of-possession verification with EIP-2537.
/// @dev The functional change from upstream `LibBLS12381` is the domain separation tag:
/// `BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_` instead of `BLS_SIG_...`. Upstream hardcodes the
/// message DST in a private function (LibBLS12381.sol:179-186), so the proof-of-possession suite
/// the crate uses (cryptography/src/bls12381/primitives/group.rs:430, ops/mod.rs:109-125) cannot be
/// reached through it. Both tags are 43 bytes, so the expansion layout is unchanged.
library LibBLS12381PoP {
    /// @notice Verify a MinSig proof of possession for `publicKey`.
    /// @param signature Uncompressed G1 `x || y`, each 48 bytes. The caller binds it to the crate's
    /// compressed bytes with `LibBLS12381Point.matchesG1`.
    /// @param publicKey The G2 key in EIP-2537 encoding.
    /// @param namespace The deployment's PoP namespace, without a length prefix.
    /// @param compressedKey The crate's 96-byte compressed encoding of `publicKey`, which is the
    /// signed message (`ops::sign_proof_of_possession` signs `public.encode()`).
    function verify(
        bytes memory signature,
        BLS.G2Point memory publicKey,
        bytes memory namespace,
        bytes memory compressedKey
    ) internal view returns (bool) {
        if (signature.length != 96) return false;
        BLS.G1Point memory sig;
        uint256 out;
        assembly ("memory-safe") { out := sig }
        _unpack(signature, out);
        return _pairing(abi.encode(sig, _negativeG2(), hashToG1(namespace, compressedKey), publicKey));
    }

    /// @notice Hash a namespaced message to G1 with `BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_`.
    function hashToG1(bytes memory namespace, bytes memory message) internal view returns (BLS.G1Point memory result) {
        uint256 out;
        assembly ("memory-safe") { out := result }
        _hashToG1(BLS.encodeMessage(namespace, message), out);
    }

    /// @dev Upstream `LibBLS12381._unpack` reading memory instead of calldata, because constructor
    /// arguments live in memory.
    function _unpack(bytes memory signature, uint256 out) private pure {
        assembly ("memory-safe") {
            let src := add(signature, 0x20)
            for { let i := 0 } lt(i, mload(signature)) { i := add(i, 48) } {
                mstore(out, shr(128, mload(add(src, i))))
                mstore(add(out, 32), mload(add(add(src, i), 16)))
                out := add(out, 64)
            }
        }
    }

    /// @dev Upstream `LibBLS12381._hashToCurve` restricted to G1, with the PoP DST.
    function _hashToG1(bytes memory message, uint256 out) private view {
        uint256 scratchLength = (0x100 + 0x40 + message.length + 0x60 + 31) & ~uint256(31);
        if (scratchLength < 0x300) scratchLength = 0x300;
        assembly ("memory-safe") {
            function fail() {
                mstore(0x00, 0x84e81692) // `PrecompileFailed()`.
                revert(0x1c, 0x04)
            }
            function dstPrime(o, counter) -> end {
                mstore8(o, counter)
                mstore(add(o, 1), "BLS_POP_BLS12381G1_XMD:SHA-256_S")
                mstore(add(o, 0x21), "SWU_RO_POP_\x2b")
                end := add(o, 0x2d)
            }
            function sha2(data, length) -> digest {
                let ok := staticcall(gas(), 2, data, length, 0, 0x20)
                if iszero(and(ok, eq(returndatasize(), 0x20))) { fail() }
                digest := mload(0)
            }
            let b := mload(0x40)
            let end := add(b, scratchLength)
            let s := add(b, 0x100)
            mstore(s, 0)
            mstore(add(s, 0x20), 0)
            for { let i := 0 } lt(i, mload(message)) { i := add(i, 0x20) } {
                mstore(add(add(s, 0x40), i), mload(add(add(message, 0x20), i)))
            }
            let uniformLength := 0x80
            let o := add(add(s, 0x40), mload(message))
            mstore(o, shl(240, uniformLength))
            let b0 := sha2(s, sub(dstPrime(add(o, 2), 0), s))
            mstore(s, b0)
            mstore(b, sha2(s, sub(dstPrime(add(s, 0x20), 1), s)))
            for { let i := 1 } lt(i, shr(5, uniformLength)) { i := add(i, 1) } {
                mstore(s, xor(b0, mload(add(b, shl(5, sub(i, 1))))))
                mstore(add(b, shl(5, i)), sha2(s, sub(dstPrime(add(s, 0x20), add(i, 1)), s)))
            }
            // Modexp with exponent one reduces each 64-byte hash limb modulo the base field.
            mstore(s, 0x40)
            mstore(add(s, 0x20), 0x20)
            mstore(add(s, 0x40), 0x40)
            mstore(add(s, 0xa0), 1)
            mstore(add(s, 0xc0), 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
            mstore(add(s, 0xe0), 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
            for { let i := 0 } lt(i, uniformLength) { i := add(i, 0x40) } {
                mstore(add(s, 0x60), mload(add(b, i)))
                mstore(add(s, 0x80), mload(add(add(b, i), 0x20)))
                let ok := staticcall(gas(), 5, s, 0x100, add(b, i), 0x40)
                if iszero(and(ok, eq(returndatasize(), 0x40))) { fail() }
            }
            let ok := staticcall(gas(), 0x10, b, 0x40, s, 0x80)
            if iszero(and(ok, eq(returndatasize(), 0x80))) { fail() }
            ok := staticcall(gas(), 0x10, add(b, 0x40), 0x40, add(s, 0x80), 0x80)
            if iszero(and(ok, eq(returndatasize(), 0x80))) { fail() }
            ok := staticcall(gas(), 0x0b, s, 0x100, out, 0x80)
            if iszero(and(ok, eq(returndatasize(), 0x80))) { fail() }
            for { let p := b } lt(p, end) { p := add(p, 0x20) } { mstore(p, 0) }
        }
    }

    /// @dev Upstream `LibBLS12381._pairing`, unchanged.
    function _pairing(bytes memory input) private view returns (bool valid) {
        assembly ("memory-safe") {
            let data := add(input, 0x20)
            let nonzero := 1
            for { let p := data } lt(p, add(data, 0x300)) { p := add(p, 0x180) } {
                let g1 := 0
                let g2 := 0
                for { let i := 0 } lt(i, 0x80) { i := add(i, 0x20) } { g1 := or(g1, mload(add(p, i))) }
                for { let i := 0x80 } lt(i, 0x180) { i := add(i, 0x20) } { g2 := or(g2, mload(add(p, i))) }
                nonzero := and(nonzero, and(iszero(iszero(g1)), iszero(iszero(g2))))
            }
            if nonzero {
                let ok := staticcall(gas(), 0x0f, data, 0x300, 0, 0x20)
                valid := and(and(ok, eq(returndatasize(), 0x20)), eq(mload(0), 1))
            }
        }
    }

    /// @dev Upstream `LibBLS12381._negativeG2`, unchanged.
    function _negativeG2() private pure returns (BLS.G2Point memory) {
        return BLS.G2Point(
            0x00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051,
            0xc6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8,
            0x0000000000000000000000000000000013e02b6052719f607dacd3a088274f65,
            0x596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e,
            0x000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bc,
            0xb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa,
            0x0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d,
            0x993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed
        );
    }
}
