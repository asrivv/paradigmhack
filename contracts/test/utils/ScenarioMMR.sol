// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

// Scenario generator, not a conformance vector. A Solidity model of a keyless QMDB MMR payout log
// following storage/src/merkle/hasher.rs:94-139 (BackwardFold root) and
// storage/src/merkle/proof.rs:800-1005 (single-element proof layout) at dd6d60cb. The crate fixture
// covers a three-operation payout log; claim-order and range scenarios need larger logs.
// ScenarioAnchors.t.sol checks that this model reproduces the fixture's payout head, opening and
// claim bytes exactly.

library ScenarioMMR {
    /// @dev Variable keyless operations (storage/src/qmdb/keyless/operation/variable.rs:15-26).
    function appendOutput(address destination, uint64 amount) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"01", output(destination, amount));
    }

    function output(address destination, uint64 amount) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(20), destination, amount);
    }

    /// @dev `Commit(None, floor)` for a floor below 128.
    function commit(uint8 floor) internal pure returns (bytes memory) {
        require(floor < 128, "floor");
        return abi.encodePacked(hex"0000", floor);
    }

    function position(uint256 loc) internal pure returns (uint256) {
        uint256 ones;
        for (uint256 x = loc; x != 0; x &= x - 1) {
            ++ones;
        }
        return 2 * loc - ones;
    }

    function node(bytes[] memory ops, uint256 start, uint256 height) internal pure returns (bytes32) {
        if (height == 0) return sha256(abi.encodePacked(uint64(position(start)), ops[start]));
        uint256 half = 1 << (height - 1);
        bytes32 left = node(ops, start, height - 1);
        bytes32 right = node(ops, start + half, height - 1);
        uint256 pos = position(start) + (1 << (height + 1)) - 2;
        return sha256(abi.encodePacked(uint64(pos), left, right));
    }

    function peaks(uint256 n) internal pure returns (uint256[] memory starts, uint256[] memory heights) {
        uint256 count;
        for (uint256 x = n; x != 0; x &= x - 1) {
            ++count;
        }
        starts = new uint256[](count);
        heights = new uint256[](count);
        uint256 cursor;
        uint256 k;
        for (uint256 i; i < 64; ++i) {
            uint256 h = 63 - i;
            if (n & (1 << h) == 0) continue;
            starts[k] = cursor;
            heights[k] = h;
            cursor += 1 << h;
            ++k;
        }
    }

    function inactivePeaks(uint256 n, uint256 floor) internal pure returns (uint256 count) {
        (, uint256[] memory heights) = peaks(n);
        uint256 sum;
        for (uint256 i; i < heights.length; ++i) {
            sum += 1 << heights[i];
            if (sum > floor) break;
            ++count;
        }
    }

    function root(bytes[] memory ops, uint256 inactive) internal pure returns (bytes32) {
        (uint256[] memory starts, uint256[] memory heights) = peaks(ops.length);
        bytes32[] memory p = new bytes32[](starts.length);
        for (uint256 i; i < p.length; ++i) {
            p[i] = node(ops, starts[i], heights[i]);
        }
        bytes32 acc = p[0];
        uint256 first = inactive > 1 ? inactive : 1;
        for (uint256 i = 1; i < first && i < p.length; ++i) {
            acc = sha256(abi.encodePacked(acc, p[i]));
        }
        if (first < p.length) {
            bytes32 bag = p[p.length - 1];
            for (uint256 j = p.length - 1; j > first; --j) {
                bag = sha256(abi.encodePacked(p[j - 1], bag));
            }
            acc = sha256(abi.encodePacked(acc, bag));
        }
        if (inactive == 0) return sha256(abi.encodePacked(uint64(ops.length), acc));
        return sha256(abi.encodePacked(uint64(ops.length), uint64(inactive), acc));
    }

    function proof(bytes[] memory ops, uint256 inactive, uint256 loc) internal pure returns (bytes32[] memory) {
        (uint256[] memory starts, uint256[] memory heights) = peaks(ops.length);
        bytes32[] memory out = new bytes32[](128);
        uint256 len;
        uint256 k;
        while (!(loc >= starts[k] && loc < starts[k] + (1 << heights[k]))) {
            ++k;
        }
        // Fold prefix: inactive peaks before the target.
        bool folded;
        bytes32 acc;
        for (uint256 i; i < k && i < inactive; ++i) {
            bytes32 d = node(ops, starts[i], heights[i]);
            acc = folded ? sha256(abi.encodePacked(acc, d)) : d;
            folded = true;
        }
        if (folded) out[len++] = acc;
        // Active peaks before the target, individually.
        for (uint256 i = inactive; i < k; ++i) {
            out[len++] = node(ops, starts[i], heights[i]);
        }
        // Inactive peaks after the target, individually.
        for (uint256 i = k + 1; i < starts.length && i < inactive; ++i) {
            out[len++] = node(ops, starts[i], heights[i]);
        }
        // Active peaks after the target, collapsed by backward folding.
        uint256 suffixStart = k + 1 > inactive ? k + 1 : inactive;
        if (suffixStart < starts.length) {
            bytes32 bag = node(ops, starts[starts.length - 1], heights[starts.length - 1]);
            for (uint256 j = starts.length - 1; j > suffixStart; --j) {
                bag = sha256(abi.encodePacked(node(ops, starts[j - 1], heights[j - 1]), bag));
            }
            out[len++] = bag;
        }
        len = _siblings(ops, starts[k], heights[k], loc, out, len);
        bytes32[] memory trimmed = new bytes32[](len);
        for (uint256 i; i < len; ++i) {
            trimmed[i] = out[i];
        }
        return trimmed;
    }

    /// @dev Left-first DFS siblings (storage/src/merkle/proof.rs:610-625).
    function _siblings(
        bytes[] memory ops,
        uint256 start,
        uint256 height,
        uint256 loc,
        bytes32[] memory out,
        uint256 len
    ) private pure returns (uint256) {
        if (height == 0) return len;
        uint256 half = 1 << (height - 1);
        if (loc < start + half) {
            len = _siblings(ops, start, height - 1, loc, out, len);
            out[len++] = node(ops, start + half, height - 1);
        } else {
            out[len++] = node(ops, start, height - 1);
            len = _siblings(ops, start + half, height - 1, loc, out, len);
        }
        return len;
    }

    /// @dev The crate's `WithdrawalClaim` encoding (transition.rs:1024-1029, logs.rs:435-440,
    /// storage/src/merkle/proof.rs:89-95).
    function claim(
        address destination,
        uint64 amount,
        uint64 loc,
        uint256 leaves,
        uint256 inactive,
        bytes32[] memory digests
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            output(destination, amount),
            loc,
            varint(leaves),
            varint(inactive),
            varint(digests.length),
            abi.encodePacked(digests)
        );
    }

    function varint(uint256 value) internal pure returns (bytes memory encoded) {
        do {
            uint8 digit = uint8(value & 127);
            value >>= 7;
            encoded = abi.encodePacked(encoded, bytes1(value == 0 ? digit : digit | 128));
        } while (value != 0);
    }
}
