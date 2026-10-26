// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

import { LibQMDBCurrent } from "commonware/qmdb/LibQMDBCurrent.sol";
import { LibQMDBCurrentMMB } from "commonware/qmdb/LibQMDBCurrentMMB.sol";
import { LibClearingCodec as Codec } from "./LibClearingCodec.sol";
import { LibVectorCommitment as Vector } from "./LibVectorCommitment.sol";

/// @notice Linked-library decoders for signed withdrawals and withdrawal batches, ported from
/// clearing/src/bajillion/boundary.rs at commonwarexyz/monorepo
/// dd6d60cb44fb3dc05cee1efa06d957ce30df1340.
/// @dev `SignedWithdrawal` (boundary.rs:458-479) encodes as
/// `account(32) || deployment(32) || varint(len) || destination || action || u64 deadline ||
/// signature(64)`, with `action = 0x01 || u64 amount` (`Amount`, nonzero) or `0x02` (`Close`)
/// (boundary.rs:255-283). The signed body is everything between the account and the signature
/// (boundary.rs:338-343). Account strictness and the signature are checked by the caller through
/// `Ed25519Verifier`, so this library stays free of curve arithmetic.
library WithdrawalCodec {
    bytes internal constant ID_NAMESPACE = "_COMMONWARE_CLEARING_BOUNDARY_WITHDRAWAL_ID"; // boundary.rs:22

    uint8 internal constant AMOUNT = 1;
    uint8 internal constant CLOSE = 2;

    /// @notice One decoded request. Offsets are relative to the bytes passed to the decoder.
    struct Request {
        bytes32 account;
        bytes32 deployment;
        uint8 action;
        uint64 amount;
        uint64 deadline;
        /// First byte of the encoded request and one past its last byte.
        uint256 start;
        uint256 end;
        /// The destination's first byte and length.
        uint256 destination;
        uint256 destinationLength;
        /// `SignedWithdrawal::id` (boundary.rs:420-427).
        bytes32 id;
        /// keccak256 of the exact encoded request, for verbatim comparison.
        bytes32 digest;
    }

    /// @notice Decode exactly one `SignedWithdrawal` filling `encoded`.
    function decodeRequest(bytes calldata encoded, uint256 maxDestinationBytes)
        public
        pure
        returns (bool ok, Request memory r)
    {
        uint256 end;
        (ok, r, end) = _read(encoded, 0, maxDestinationBytes);
        ok = ok && end == encoded.length;
    }

    /// @notice Decode a `WithdrawalBatch` (boundary.rs:588-615): `varint(count) || requests`, with
    /// accounts strictly increasing by bytes and nothing trailing, and compute its vector root.
    function decodeBatch(bytes calldata encoded, uint256 maxRecords, uint256 maxDestinationBytes)
        public
        pure
        returns (bool ok, Request[] memory requests, bytes32 root)
    {
        (uint256 n, uint256 pos, bool countOk) = Codec.readVarint(encoded, 0, 32);
        if (!countOk || n > maxRecords) return (false, requests, bytes32(0));
        requests = new Request[](n);
        uint256[] memory ends = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            Request memory r;
            (ok, r, pos) = _read(encoded, pos, maxDestinationBytes);
            if (!ok || (i > 0 && r.account <= requests[i - 1].account)) return (false, requests, bytes32(0));
            requests[i] = r;
            ends[i] = pos;
        }
        if (pos != encoded.length) return (false, requests, bytes32(0));
        // Vector leaves are the encoded requests; `ends` are relative to the records slice.
        uint256 header = n == 0 ? encoded.length : requests[0].start;
        for (uint256 i; i < n; ++i) {
            ends[i] -= header;
        }
        return (true, requests, Vector.withdrawalRoot(encoded[header:], ends));
    }

    function _read(bytes calldata data, uint256 start, uint256 maxDestinationBytes)
        private
        pure
        returns (bool ok, Request memory r, uint256 end)
    {
        if (data.length < start + 64) return (false, r, 0);
        r.start = start;
        r.account = Codec.readBytes32(data, start);
        r.deployment = Codec.readBytes32(data, start + 32);
        (uint256 length, uint256 pos, bool lengthOk) = Codec.readVarint(data, start + 64, 32);
        if (!lengthOk || length > maxDestinationBytes || data.length < pos + length + 1) return (false, r, 0);
        r.destination = pos;
        r.destinationLength = length;
        pos += length;
        r.action = uint8(data[pos]);
        if (r.action == AMOUNT) {
            if (data.length < pos + 9) return (false, r, 0);
            r.amount = Codec.readU64(data, pos + 1);
            if (r.amount == 0) return (false, r, 0);
            pos += 9;
        } else if (r.action == CLOSE) {
            pos += 1;
        } else {
            return (false, r, 0);
        }
        if (data.length < pos + 8 + 64) return (false, r, 0);
        r.deadline = Codec.readU64(data, pos);
        pos += 8;
        r.id = sha256(abi.encodePacked(ID_NAMESPACE, r.account, data[start + 32:pos]));
        end = pos + 64;
        r.end = end;
        r.digest = keccak256(data[start:end]);
        ok = true;
    }
}

/// @notice Linked-library verifier for `StateOpening` (clearing/src/bajillion/qmdb.rs:629-650,
/// 705-725): a current ordered QMDB membership proof over an MMB, verified with commonware-sol's
/// `LibQMDBCurrentMMB` and SHA-256 at `address(2)`.
/// @dev Encoding (storage/src/qmdb/current/ordered/proof.rs:72-97, current/proof/operation.rs:86-127,
/// current/proof/mod.rs:572-609, merkle/proof.rs:89-114, merkle/location.rs:186-212):
/// `account(32) || balance u64 (nonzero) || varint loc || chunk(32) || varint leaves ||
/// varint inactive_peaks || varint(n) || n digests || option pending || option partial ||
/// ops_root(32) || next_key(32)`. An option is one byte, 0 or 1, then the digest when 1. The
/// authenticated operation is the fixed ordered `Update` (storage/src/qmdb/any/operation/fixed.rs:51-62,
/// update/ordered.rs:90-101): `0xd2 || key || balance || next_key`, 73 bytes with no padding.
library StateVerifier {
    /// @dev `qmdb::StateDb` uses 32-byte bitmap chunks (clearing/src/bajillion/qmdb.rs:44, :54).
    uint256 internal constant CHUNK_BYTES = 32;
    /// @dev `mmb::Family::MAX_LEAVES` (storage/src/merkle/mmb/mod.rs:161).
    uint256 internal constant MMB_MAX_LEAVES = 0x4000_0000_0000_001E;
    uint8 internal constant UPDATE_CONTEXT = 0xd2; // storage/src/qmdb/any/operation/mod.rs:18

    /// @notice Decode an opening of at most `maxDigests` proof digests.
    /// @return ok False when the bytes are not a canonical `StateOpening` encoding.
    /// @return account The opened account. The caller checks that it is a strict key.
    /// @return balance The opened positive balance.
    /// @return nextKey The proof's next active key.
    /// @return proof The proof in commonware-sol's layout.
    function decode(bytes calldata encoded, uint256 maxDigests)
        public
        pure
        returns (bool ok, bytes32 account, uint64 balance, bytes32 nextKey, LibQMDBCurrent.Proof memory proof)
    {
        if (encoded.length < 40) return (false, 0, 0, 0, proof);
        account = Codec.readBytes32(encoded, 0);
        balance = Codec.readU64(encoded, 32);
        if (balance == 0) return (false, 0, 0, 0, proof);
        uint256 pos;
        (proof.location, pos, ok) = Codec.readVarint(encoded, 40, 64);
        if (!ok || proof.location > MMB_MAX_LEAVES || encoded.length < pos + CHUNK_BYTES) {
            return (false, 0, 0, 0, proof);
        }
        proof.chunk = encoded[pos:pos + CHUNK_BYTES];
        (proof.leaves, pos, ok) = Codec.readVarint(encoded, pos + CHUNK_BYTES, 64);
        if (!ok || proof.leaves > MMB_MAX_LEAVES) return (false, 0, 0, 0, proof);
        (proof.inactivePeaks, pos, ok) = Codec.readVarint(encoded, pos, 64);
        if (!ok) return (false, 0, 0, 0, proof);
        uint256 n;
        (n, pos, ok) = Codec.readVarint(encoded, pos, 32);
        if (!ok || n > maxDigests || encoded.length < pos + n * 32) return (false, 0, 0, 0, proof);
        proof.digests = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            proof.digests[i] = Codec.readBytes32(encoded, pos + i * 32);
        }
        pos += n * 32;
        (ok, proof.pending, pos) = _option(encoded, pos);
        if (!ok) return (false, 0, 0, 0, proof);
        (ok, proof.partialDigest, pos) = _option(encoded, pos);
        if (!ok || encoded.length != pos + 64) return (false, 0, 0, 0, proof);
        proof.opsRoot = Codec.readBytes32(encoded, pos);
        nextKey = Codec.readBytes32(encoded, pos + 32);
        ok = true;
    }

    /// @notice `KeyValueProof::verify` (storage/src/qmdb/current/ordered/proof.rs:56-69).
    function verify(bytes32 root, bytes32 account, uint64 balance, bytes32 nextKey, LibQMDBCurrent.Proof calldata proof)
        public
        view
        returns (bool)
    {
        bytes memory operation = abi.encodePacked(UPDATE_CONTEXT, account, balance, nextKey);
        return LibQMDBCurrentMMB.verify(root, operation, proof, CHUNK_BYTES, address(2));
    }

    /// @dev `Option<Digest>`: a `bool` byte (0 or 1, codec/src/types/primitives.rs:285-296), then
    /// the digest when present. An absent digest is zero in commonware-sol's layout.
    function _option(bytes calldata data, uint256 pos) private pure returns (bool ok, bytes32 value, uint256 next) {
        if (data.length < pos + 1) return (false, 0, 0);
        uint8 tag = uint8(data[pos]);
        if (tag == 0) return (true, 0, pos + 1);
        if (tag != 1 || data.length < pos + 33) return (false, 0, 0);
        return (true, Codec.readBytes32(data, pos + 1), pos + 33);
    }
}
