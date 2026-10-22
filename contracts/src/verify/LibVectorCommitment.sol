// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

/// @notice Build `commonware-clearing` boundary vector roots with SHA-256.
/// @dev Port of `clearing/src/bajillion/commitment.rs` (`leaf_digest` :171-185, `bind_root` :221-225)
/// over `storage/src/bmt/mod.rs` (`Builder::build` :228-232, `Tree::new` :254-288, `finalize` :113-115)
/// at dd6d60cb44fb3dc05cee1efa06d957ce30df1340. commonware-sol's LibBMT only verifies proofs, so the
/// settlement contract needs this builder to recompute the deposit and withdrawal roots that
/// `validate_boundary_roots` (transition.rs:1806-1820) compares.
///
/// Vector element `i` of `n`: `SHA256(leafDomain || u32 n || u32 i || u64 len || encoded_i)`.
/// BMT leaf: `SHA256(u32 i || element)`. Parent: `SHA256(left || right)`, with an unpaired last
/// node hashed with itself. Empty tree root: `SHA256("")`. BMT root: `SHA256(u32 n || treeRoot)`.
/// Vector root: `SHA256(rootDomain || u32 n || bmtRoot)`.
library LibVectorCommitment {
    bytes internal constant DEPOSIT_LEAF_DOMAIN = "_COMMONWARE_CLEARING_DEPOSIT_LEAF";
    bytes internal constant DEPOSIT_ROOT_DOMAIN = "_COMMONWARE_CLEARING_DEPOSIT_ROOT";
    bytes internal constant WITHDRAWAL_LEAF_DOMAIN = "_COMMONWARE_CLEARING_WITHDRAWAL_LEAF";
    bytes internal constant WITHDRAWAL_ROOT_DOMAIN = "_COMMONWARE_CLEARING_WITHDRAWAL_ROOT";

    /// @dev Encoded `DepositRecord` width: 32-byte account and u64 amount (boundary.rs:59-68).
    uint256 internal constant DEPOSIT_RECORD_SIZE = 40;
    uint64 internal constant DEPOSIT_RECORD_LENGTH = 40;

    /// @notice Root of a deposit vector whose `count` records are packed in `records`.
    /// @dev The caller bounds `count` and checks `records.length == count * 40`.
    function depositRoot(bytes calldata records, uint256 count) internal pure returns (bytes32) {
        bytes32[] memory level = new bytes32[](count == 0 ? 1 : count);
        if (count == 0) {
            level[0] = sha256("");
        } else {
            // forge-lint: disable-next-line(unsafe-typecast) callers bound count by MAX_VECTOR_LENGTH (2^24)
            uint32 n = uint32(count);
            for (uint32 i; i < n; ++i) {
                bytes calldata encoded = records[i * DEPOSIT_RECORD_SIZE:(i + 1) * DEPOSIT_RECORD_SIZE];
                bytes32 element = sha256(abi.encodePacked(DEPOSIT_LEAF_DOMAIN, n, i, DEPOSIT_RECORD_LENGTH, encoded));
                level[i] = sha256(abi.encodePacked(i, element));
            }
        }
        return _bind(DEPOSIT_ROOT_DOMAIN, count, _treeRoot(level));
    }

    /// @notice Root of a withdrawal vector whose encoded `SignedWithdrawal` records are packed in
    /// `records`, record `i` ending at `ends[i]`. The caller bounds the count and checks that the
    /// offsets are increasing and end at `records.length`.
    function withdrawalRoot(bytes calldata records, uint256[] memory ends) internal pure returns (bytes32) {
        uint256 count = ends.length;
        if (count == 0) return emptyWithdrawalRoot();
        bytes32[] memory level = new bytes32[](count);
        // forge-lint: disable-next-line(unsafe-typecast) callers bound count by MAX_VECTOR_LENGTH (2^24)
        uint32 n = uint32(count);
        uint256 start;
        for (uint32 i; i < n; ++i) {
            bytes calldata encoded = records[start:ends[i]];
            // forge-lint: disable-next-line(unsafe-typecast) a record fits in calldata, far below 2^64
            uint64 length = uint64(encoded.length);
            bytes32 element = sha256(abi.encodePacked(WITHDRAWAL_LEAF_DOMAIN, n, i, length, encoded));
            level[i] = sha256(abi.encodePacked(i, element));
            start = ends[i];
        }
        return _bind(WITHDRAWAL_ROOT_DOMAIN, count, _treeRoot(level));
    }

    /// @notice Root of the empty withdrawal vector.
    function emptyWithdrawalRoot() internal pure returns (bytes32) {
        return _bind(WITHDRAWAL_ROOT_DOMAIN, 0, sha256(""));
    }

    /// @dev Fold a nonempty level in place until one node remains.
    function _treeRoot(bytes32[] memory level) private pure returns (bytes32) {
        uint256 width = level.length;
        while (width > 1) {
            uint256 parents = (width + 1) >> 1;
            for (uint256 j; j < parents; ++j) {
                bytes32 left = level[2 * j];
                bytes32 right = 2 * j + 1 < width ? level[2 * j + 1] : left;
                level[j] = sha256(abi.encodePacked(left, right));
            }
            width = parents;
        }
        return level[0];
    }

    function _bind(bytes memory rootDomain, uint256 count, bytes32 treeRoot) private pure returns (bytes32) {
        // forge-lint: disable-next-line(unsafe-typecast) bounded by the checks above
        bytes32 bmtRoot = sha256(abi.encodePacked(uint32(count), treeRoot));
        // forge-lint: disable-next-line(unsafe-typecast) bounded by the checks above
        return sha256(abi.encodePacked(rootDomain, uint32(count), bmtRoot));
    }
}
