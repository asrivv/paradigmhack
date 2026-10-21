// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { LibBLS12381 as BLS } from "commonware/certificate/LibBLS12381.sol";

/// @notice Bind uncompressed BLS12-381 points to the compressed encodings the crate produces.
/// @dev The crate writes compressed points (ZCash / blst format): G1 as 48 bytes `x`, G2 as
/// 96 bytes `x.c1 || x.c0`, with three flag bits in the first byte: 0x80 compressed (always set),
/// 0x40 infinity, 0x20 sign. The sign bit is set iff `y` is lexicographically largest, that is
/// `y > (p - 1) / 2`; for Fp2 the comparison uses `y.c1`, or `y.c0` when `y.c1 == 0`.
/// commonware-sol's verifiers need uncompressed coordinates (sol/src/certificate/LibBLS12381.sol:30
/// at dd6d60cb). Callers pass an uncompressed hint and this library checks that it compresses to
/// the exact crate bytes, so the crate encoding stays authoritative. Curve and subgroup membership
/// are not checked here: every hinted point reaches the EIP-2537 pairing precompile, which checks
/// both. Infinity never matches because the expected flags never include 0x40.
library LibBLS12381Point {
    /// @dev `(p - 1) / 2` split into the 16 high bytes and 32 low bytes of its 48-byte encoding.
    uint256 private constant HALF_HI = 0x0d0088f51cbff34d258dd3db21a5d66b;
    uint256 private constant HALF_LO = 0xb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd555;

    /// @notice Check that a 96-byte uncompressed G1 `x || y` compresses to a 48-byte crate encoding.
    function matchesG1(bytes memory compressed, bytes memory uncompressed) internal pure returns (bool) {
        if (compressed.length != 48 || uncompressed.length != 96) return false;
        (uint256 xHi, uint256 xLo) = _load48(uncompressed, 0);
        (uint256 yHi, uint256 yLo) = _load48(uncompressed, 48);
        return _matches(compressed, 0, xHi, xLo, _flags(_largest(yHi, yLo)));
    }

    /// @notice Check that an EIP-2537 G2 point compresses to a 96-byte crate encoding.
    function matchesG2(bytes memory compressed, BLS.G2Point memory point) internal pure returns (bool) {
        if (compressed.length != 96) return false;
        uint256 mask = type(uint256).max << 128;
        // EIP-2537 padding: the high 16 bytes of every Hi word must be zero.
        if ((uint256(point.xC0Hi) | uint256(point.xC1Hi) | uint256(point.yC0Hi) | uint256(point.yC1Hi)) & mask != 0) {
            return false;
        }
        bool sign = (uint256(point.yC1Hi) | uint256(point.yC1Lo)) != 0
            ? _largest(uint256(point.yC1Hi), uint256(point.yC1Lo))
            : _largest(uint256(point.yC0Hi), uint256(point.yC0Lo));
        // Flags live only in the first byte, so the `x.c0` field must match with none set.
        return _matches(compressed, 0, uint256(point.xC1Hi), uint256(point.xC1Lo), _flags(sign))
            && _matches(compressed, 48, uint256(point.xC0Hi), uint256(point.xC0Lo), 0);
    }

    /// @dev Expected first-byte flags for a finite point with the given sign.
    function _flags(bool sign) private pure returns (uint256) {
        return 0x80 | (sign ? 0x20 : 0);
    }

    /// @dev Compare the 48-byte compressed field at `offset` with `x` plus `flags` in its top byte.
    function _matches(bytes memory compressed, uint256 offset, uint256 xHi, uint256 xLo, uint256 flags)
        private
        pure
        returns (bool)
    {
        // A field element below p never sets the top three bits of its 48-byte encoding.
        if (xHi >> 125 != 0) return false;
        (uint256 cHi, uint256 cLo) = _load48(compressed, offset);
        return cHi == (xHi | (flags << 120)) && cLo == xLo;
    }

    /// @dev Return whether a 48-byte field element exceeds `(p - 1) / 2`.
    function _largest(uint256 hi, uint256 lo) private pure returns (bool) {
        return hi > HALF_HI || (hi == HALF_HI && lo > HALF_LO);
    }

    /// @dev Load 48 bytes at `offset` as a 16-byte high word and a 32-byte low word. The caller
    /// checks `offset + 48 <= data.length`.
    function _load48(bytes memory data, uint256 offset) private pure returns (uint256 hi, uint256 lo) {
        assembly ("memory-safe") {
            let p := add(add(data, 0x20), offset)
            hi := shr(128, mload(p))
            lo := mload(add(p, 16))
        }
    }
}
