// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { Sha2Ext } from "./vendor/sha512/Sha2Ext.sol";

/// @notice Ed25519 verification with the ZIP215 rules `commonware-cryptography-curve25519` uses.
/// @dev Port of `VerifyingKey::verify_message` and the `StrictVerifyingKey` decode check in
/// cryptography/curve25519/src/signing.rs (:1-24, :350-401, :403-415) of commonwarexyz/monorepo at
/// dd6d60cb44fb3dc05cee1efa06d957ce30df1340:
/// - `s` must be canonical (`s < L`).
/// - `R` and `A` may be non-canonical encodings (`y >= p`, or negative zero `x`) as long as they
///   decode to a curve point; the hash uses the raw bytes.
/// - The equation is cofactored: `[8](s·B - (k·A + R)) == identity`, `k = SHA-512(R || A || M) mod L`.
/// - `isStrictKey` additionally requires a canonical, non-identity point of prime order, which
///   upstream enforces when decoding a `StrictVerifyingKey`.
///
/// No maintained Solidity Ed25519 library implements these rules: SCL (get-smooth/crypto-lib) and
/// chengwenxi/Ed25519 both do cofactorless RFC 8032 with canonical R, which rejects signatures the
/// crate accepts. This file reuses SCL's vendored SHA-512 (`vendor/sha512/`), and implements the
/// group law with the complete twisted-Edwards formulas of RFC 8032 section 5.1.4 (`a = -1`), which
/// have no exceptional cases, and decoding per RFC 8032 section 5.1.3 with the ZIP215 relaxations.
/// Edge-case behaviour is tested against ed25519-speccheck's ZIP215 (Zebra) results.
///
/// Byte strings are as on the wire: points and scalars are 32-byte little-endian encodings.
library LibEd25519 {
    uint256 internal constant P = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
    uint256 internal constant L = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed;
    uint256 internal constant D = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3;
    uint256 internal constant D2 = 0x2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159;
    uint256 internal constant SQRT_M1 = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0;
    uint256 internal constant BX = 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a;
    uint256 internal constant BY = 0x6666666666666666666666666666666666666666666666666666666666666658;
    /// @dev `2^256 mod L`, for reducing the 512-bit hash.
    uint256 internal constant R256 = 0x0ffffffffffffffffffffffffffffffec6ef5bf4737dcf70d6ec31748d98951d;
    /// @dev `(p - 5) / 8`, the exponent of the RFC 8032 square-root candidate.
    uint256 internal constant SQRT_EXP = 0x0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd;

    /// @dev A point in extended coordinates `(X : Y : Z : T)` with `x = X/Z`, `y = Y/Z`, `xy = T/Z`.
    struct Point {
        uint256 x;
        uint256 y;
        uint256 z;
        uint256 t;
    }

    /// @notice Verify a signature over `message`, which the caller has already framed (for the
    /// crate: `varint(namespace.length) || namespace || payload`, utils `union_unique`).
    function verify(bytes32 publicKey, bytes memory signature, bytes memory message) internal view returns (bool) {
        if (signature.length != 64) return false;
        bytes32 rBytes;
        bytes32 sBytes;
        assembly ("memory-safe") {
            rBytes := mload(add(signature, 0x20))
            sBytes := mload(add(signature, 0x40))
        }
        uint256 s = _le(sBytes);
        if (s >= L) return false;
        (bool okR, Point memory r) = decompress(rBytes);
        if (!okR) return false;
        (bool okA, Point memory a) = decompress(publicKey);
        if (!okA) return false;
        uint256 k = _hashToScalar(abi.encodePacked(rBytes, publicKey, message));

        // s·B + k·(-A), then subtract R, then multiply by the cofactor.
        Point memory q = _doubleScalarMul(s, k, _negate(a));
        q = _add(q, _negate(r));
        q = _double(_double(_double(q)));
        return _isIdentity(q);
    }

    /// @notice Whether `publicKey` decodes to a canonical, non-identity point of prime order
    /// (`StrictVerifyingKey`, signing.rs:403-415).
    function isStrictKey(bytes32 publicKey) internal view returns (bool) {
        uint256 v = _le(publicKey);
        uint256 y = v & ((1 << 255) - 1);
        if (y >= P) return false;
        (bool ok, Point memory a) = decompress(publicKey);
        if (!ok) return false;
        // Negative zero (x = 0 with the sign bit set) is not canonical.
        if (a.x == 0 && v >> 255 == 1) return false;
        if (a.x == 0 && a.y == 1) return false;
        return _isIdentity(_scalarMul(L, a));
    }

    /// @notice Decode a 32-byte point with ZIP215 rules: `y` is reduced mod p, and a negative-zero
    /// `x` is accepted.
    function decompress(bytes32 encoded) internal view returns (bool ok, Point memory point) {
        uint256 v = _le(encoded);
        uint256 sign = v >> 255;
        uint256 y = (v & ((1 << 255) - 1)) % P;
        uint256 yy = mulmod(y, y, P);
        uint256 u = addmod(yy, P - 1, P);
        uint256 w = addmod(mulmod(D, yy, P), 1, P);
        // x = u·w^3·(u·w^7)^((p-5)/8)
        uint256 w3 = mulmod(mulmod(w, w, P), w, P);
        uint256 w7 = mulmod(mulmod(w3, w3, P), w, P);
        uint256 x = mulmod(mulmod(u, w3, P), _pow(mulmod(u, w7, P), SQRT_EXP), P);
        uint256 check = mulmod(w, mulmod(x, x, P), P);
        if (check != u) {
            if (check != (P - u) % P) return (false, point);
            x = mulmod(x, SQRT_M1, P);
        }
        if (x & 1 != sign) x = (P - x) % P;
        return (true, Point(x, y, 1, mulmod(x, y, P)));
    }

    // -------------------------------------------------------------------------------------------
    // Group law (RFC 8032 section 5.1.4, a = -1)
    // -------------------------------------------------------------------------------------------

    function _add(Point memory p1, Point memory p2) private pure returns (Point memory) {
        uint256 a = mulmod(addmod(p1.y, P - p1.x, P), addmod(p2.y, P - p2.x, P), P);
        uint256 b = mulmod(addmod(p1.y, p1.x, P), addmod(p2.y, p2.x, P), P);
        uint256 c = mulmod(mulmod(p1.t, D2, P), p2.t, P);
        uint256 d = mulmod(mulmod(p1.z, 2, P), p2.z, P);
        uint256 e = addmod(b, P - a, P);
        uint256 f = addmod(d, P - c, P);
        uint256 g = addmod(d, c, P);
        uint256 h = addmod(b, a, P);
        return Point(mulmod(e, f, P), mulmod(g, h, P), mulmod(f, g, P), mulmod(e, h, P));
    }

    function _double(Point memory p1) private pure returns (Point memory) {
        uint256 a = mulmod(p1.x, p1.x, P);
        uint256 b = mulmod(p1.y, p1.y, P);
        uint256 c = mulmod(2, mulmod(p1.z, p1.z, P), P);
        uint256 h = addmod(a, b, P);
        uint256 xy = addmod(p1.x, p1.y, P);
        uint256 e = addmod(h, P - mulmod(xy, xy, P), P);
        uint256 g = addmod(a, P - b, P);
        uint256 f = addmod(c, g, P);
        return Point(mulmod(e, f, P), mulmod(g, h, P), mulmod(f, g, P), mulmod(e, h, P));
    }

    function _negate(Point memory p1) private pure returns (Point memory) {
        return Point((P - p1.x) % P, p1.y, p1.z, (P - p1.t) % P);
    }

    function _identity() private pure returns (Point memory) {
        return Point(0, 1, 1, 0);
    }

    function _isIdentity(Point memory p1) private pure returns (bool) {
        return p1.x % P == 0 && p1.y % P == p1.z % P;
    }

    /// @dev `s·B + k·Q` by joint double-and-add (Shamir's trick) over 253 bits; `s, k < L < 2^253`.
    function _doubleScalarMul(uint256 s, uint256 k, Point memory q) private pure returns (Point memory acc) {
        Point memory base = Point(BX, BY, 1, mulmod(BX, BY, P));
        Point memory both = _add(base, q);
        acc = _identity();
        for (uint256 i = 253; i > 0; --i) {
            acc = _double(acc);
            uint256 bits = ((s >> (i - 1)) & 1) | (((k >> (i - 1)) & 1) << 1);
            if (bits == 1) acc = _add(acc, base);
            else if (bits == 2) acc = _add(acc, q);
            else if (bits == 3) acc = _add(acc, both);
        }
    }

    /// @dev `n·Q` by double-and-add over 253 bits; `n <= L < 2^253`.
    function _scalarMul(uint256 n, Point memory q) private pure returns (Point memory acc) {
        acc = _identity();
        for (uint256 i = 253; i > 0; --i) {
            acc = _double(acc);
            if ((n >> (i - 1)) & 1 == 1) acc = _add(acc, q);
        }
    }

    // -------------------------------------------------------------------------------------------
    // Encoding and hashing
    // -------------------------------------------------------------------------------------------

    /// @dev `Scalar::from_bytes_mod_order_wide` of the 64-byte SHA-512 digest, read little-endian.
    function _hashToScalar(bytes memory input) private pure returns (uint256) {
        (bytes32 first, bytes32 second) = Sha2Ext.sha512(input);
        // Read little-endian, the digest's first 32 bytes are the low limb.
        return addmod(mulmod(_le(second) % L, R256, L), _le(first) % L, L);
    }

    /// @dev Interpret 32 bytes as a little-endian integer.
    function _le(bytes32 b) private pure returns (uint256 v) {
        v = uint256(b);
        v = ((v & 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00) >> 8)
            | ((v & 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff) << 8);
        v = ((v & 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000) >> 16)
            | ((v & 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff) << 16);
        v = ((v & 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000) >> 32)
            | ((v & 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff) << 32);
        v = ((v & 0xffffffffffffffff0000000000000000ffffffffffffffff0000000000000000) >> 64)
            | ((v & 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff) << 64);
        v = (v >> 128) | (v << 128);
    }

    /// @dev `base^exponent mod p` through the modexp precompile.
    function _pow(uint256 base, uint256 exponent) private view returns (uint256 result) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, 0x20)
            mstore(add(ptr, 0x20), 0x20)
            mstore(add(ptr, 0x40), 0x20)
            mstore(add(ptr, 0x60), base)
            mstore(add(ptr, 0x80), exponent)
            mstore(add(ptr, 0xa0), P)
            if iszero(staticcall(gas(), 0x05, ptr, 0xc0, ptr, 0x20)) { revert(0, 0) }
            result := mload(ptr)
        }
    }
}
