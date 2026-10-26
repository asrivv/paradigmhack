// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

/// @notice Decompress a 48-byte BLS12-381 G1 point (ZCash / blst format) into the 96-byte
/// uncompressed `x || y` hint `admit` takes. Test helper: the differential oracle returns only
/// the crate's compressed certificate, and the contract checks that the hint compresses back to
/// it, so a wrong decompression fails the test instead of passing silently.
/// @dev `y = (x^3 + 4)^((p + 1) / 4) mod p`, valid because `p = 3 mod 4`, using the modexp
/// precompile. Returns an all-zero hint when the bytes are not a finite point on the curve.
library G1Decompress {
    uint256 private constant P_HI = 0x1a0111ea397fe69a4b1ba7b6434bacd7;
    uint256 private constant P_LO = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;
    uint256 private constant SQRT_HI = 0x680447a8e5ff9a692c6e9ed90d2eb35;
    uint256 private constant SQRT_LO = 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab;
    uint256 private constant HALF_HI = 0x0d0088f51cbff34d258dd3db21a5d66b;
    uint256 private constant HALF_LO = 0xb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd555;

    function decompress(bytes memory compressed) internal view returns (bytes memory hint) {
        hint = new bytes(96);
        if (compressed.length != 48) return hint;
        uint8 flags = uint8(compressed[0]) & 0xe0;
        // Compressed and finite; the sign bit is the only other flag allowed.
        if (flags & 0x80 == 0 || flags & 0x40 != 0) return hint;
        bytes memory x = bytes.concat(compressed);
        x[0] = bytes1(uint8(x[0]) & 0x1f);

        bytes memory p = abi.encodePacked(bytes16(uint128(P_HI)), P_LO);
        // rhs = x^3 + 4, reduced: modexp reduces its base, so add 4 to x^3 mod p and reduce once.
        (uint256 hi, uint256 lo) = _split(_modexp(x, hex"03", p));
        unchecked {
            uint256 sum = lo + 4;
            if (sum < lo) ++hi;
            lo = sum;
        }
        bytes memory rhs = _modexp(abi.encodePacked(bytes16(uint128(hi)), lo), hex"01", p);
        bytes memory y = _modexp(rhs, abi.encodePacked(bytes16(uint128(SQRT_HI)), SQRT_LO), p);
        if (keccak256(_modexp(y, hex"02", p)) != keccak256(rhs)) return hint;

        (uint256 yHi, uint256 yLo) = _split(y);
        bool largest = yHi > HALF_HI || (yHi == HALF_HI && yLo > HALF_LO);
        if (largest != (flags & 0x20 != 0)) {
            // y = p - y. Both are 384-bit values held as 16 + 32 bytes.
            unchecked {
                uint256 borrow = P_LO < yLo ? 1 : 0;
                yLo = P_LO - yLo;
                yHi = P_HI - yHi - borrow;
            }
        }
        hint = abi.encodePacked(x, bytes16(uint128(yHi)), yLo);
    }

    function _modexp(bytes memory base, bytes memory exponent, bytes memory modulus)
        private
        view
        returns (bytes memory out)
    {
        bool ok;
        (ok, out) = address(0x05)
            .staticcall(abi.encodePacked(base.length, exponent.length, modulus.length, base, exponent, modulus));
        require(ok && out.length == 48, "modexp");
    }

    function _split(bytes memory v) private pure returns (uint256 hi, uint256 lo) {
        assembly ("memory-safe") {
            hi := shr(128, mload(add(v, 0x20)))
            lo := mload(add(v, 0x30))
        }
    }
}
