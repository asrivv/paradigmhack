// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

/// @notice Decoding helpers for the `commonware-codec` encodings the settlement contract reads.
/// @dev commonware-sol's LibCodec only encodes varints (sol/src/codec/LibCodec.sol:6-15 at
/// dd6d60cb), so every decoder the contract needs lives here. Fixed-width integers are big-endian.
library LibClearingCodec {
    /// @notice Decode one canonical unsigned LEB128 varint of at most `maxBits` bits.
    /// @dev Port of `codec/src/varint.rs:118-153` (`Decoder::feed`) at dd6d60cb: a zero byte after
    /// the first is non-canonical, and the byte that must be last may not set bits past `maxBits`.
    /// `usize` and `u32` fields use 32 bits; `u64` fields such as `Location` use 64.
    /// @return value The decoded value.
    /// @return next The offset after the varint.
    /// @return ok False on truncation, a non-canonical encoding, or overflow.
    function readVarint(bytes calldata data, uint256 offset, uint256 maxBits)
        internal
        pure
        returns (uint256 value, uint256 next, bool ok)
    {
        uint256 bits;
        while (offset < data.length) {
            uint256 b = uint8(data[offset++]);
            if (b == 0 && bits > 0) return (0, 0, false);
            uint256 remaining = maxBits - bits;
            if (remaining <= 7 && _bitLength(b) > remaining) return (0, 0, false);
            value |= (b & 0x7f) << bits;
            if (b & 0x80 == 0) return (value, offset, true);
            bits += 7;
        }
        return (0, 0, false);
    }

    /// @notice Read a big-endian u64 at `offset`. The caller bounds `offset + 8`.
    function readU64(bytes calldata data, uint256 offset) internal pure returns (uint64 value) {
        assembly ("memory-safe") {
            value := shr(192, calldataload(add(data.offset, offset)))
        }
    }

    /// @notice Read a 32-byte word at `offset`. The caller bounds `offset + 32`.
    function readBytes32(bytes calldata data, uint256 offset) internal pure returns (bytes32 value) {
        assembly ("memory-safe") {
            value := calldataload(add(data.offset, offset))
        }
    }

    function _bitLength(uint256 b) private pure returns (uint256 n) {
        while (b != 0) {
            ++n;
            b >>= 1;
        }
    }
}
