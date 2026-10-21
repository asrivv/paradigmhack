// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.36;

// TEMPORARY VECTORS. Everything in contracts/test/tmp/ is synthetic data generated in Solidity
// for this pass. Replace with crate output from offchain/fixtures (contracts/test/fixtures/) once
// that branch lands; until then these vectors prove internal consistency, not crate conformance.
// The compression helpers below are anchored to the standard generator encodings in
// test_PointCompressionKnownVectors.

import { LibBLS12381 as BLS } from "commonware/certificate/LibBLS12381.sol";
import { LibBLS12381PoP } from "../../src/verify/LibBLS12381PoP.sol";

library TmpBLS {
    uint256 internal constant HALF_HI = 0x0d0088f51cbff34d258dd3db21a5d66b;
    uint256 internal constant HALF_LO = 0xb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd555;

    function g1Generator() internal pure returns (BLS.G1Point memory) {
        return BLS.G1Point(
            0x0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f,
            0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb,
            0x0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4,
            0xfcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
        );
    }

    function g2Generator() internal pure returns (BLS.G2Point memory) {
        return BLS.G2Point(
            0x00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051,
            0xc6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8,
            0x0000000000000000000000000000000013e02b6052719f607dacd3a088274f65,
            0x596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e,
            0x000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351a,
            0xadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801,
            0x000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99,
            0xcb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be
        );
    }

    function mulG1(BLS.G1Point memory p, uint256 scalar) internal view returns (BLS.G1Point memory r) {
        bytes memory out = _call(address(0x0c), abi.encode(p, scalar), 128);
        r = abi.decode(out, (BLS.G1Point));
    }

    function mulG2(BLS.G2Point memory p, uint256 scalar) internal view returns (BLS.G2Point memory r) {
        bytes memory out = _call(address(0x0e), abi.encode(p, scalar), 256);
        r = abi.decode(out, (BLS.G2Point));
    }

    function addG1(BLS.G1Point memory a, BLS.G1Point memory b) internal view returns (BLS.G1Point memory r) {
        bool ok;
        (ok, r) = BLS.addG1(a, b);
        require(ok, "g1 add");
    }

    /// @dev MinSig signature `sk * H(namespace, message)` with the message DST.
    function sign(uint256 sk, bytes memory namespace, bytes memory message) internal view returns (BLS.G1Point memory) {
        return mulG1(BLS.hashToG1(namespace, message), sk);
    }

    /// @dev Proof of possession over the compressed public key.
    function proveKey(uint256 sk, bytes memory namespace, bytes memory compressedKey)
        internal
        view
        returns (BLS.G1Point memory)
    {
        return mulG1(LibBLS12381PoP.hashToG1(namespace, compressedKey), sk);
    }

    function uncompressedG1(BLS.G1Point memory p) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes16(uint128(uint256(p.xHi))), p.xLo, bytes16(uint128(uint256(p.yHi))), p.yLo);
    }

    function compressG1(BLS.G1Point memory p) internal pure returns (bytes memory) {
        uint8 flags = 0x80 | (_largest(uint256(p.yHi), uint256(p.yLo)) ? 0x20 : 0);
        bytes memory out = abi.encodePacked(bytes16(uint128(uint256(p.xHi))), p.xLo);
        out[0] = bytes1(uint8(out[0]) | flags);
        return out;
    }

    function compressG2(BLS.G2Point memory p) internal pure returns (bytes memory) {
        bool sign_ = (uint256(p.yC1Hi) | uint256(p.yC1Lo)) != 0
            ? _largest(uint256(p.yC1Hi), uint256(p.yC1Lo))
            : _largest(uint256(p.yC0Hi), uint256(p.yC0Lo));
        bytes memory out = abi.encodePacked(
            bytes16(uint128(uint256(p.xC1Hi))), p.xC1Lo, bytes16(uint128(uint256(p.xC0Hi))), p.xC0Lo
        );
        out[0] = bytes1(uint8(out[0]) | 0x80 | (sign_ ? 0x20 : 0));
        return out;
    }

    function _largest(uint256 hi, uint256 lo) private pure returns (bool) {
        return hi > HALF_HI || (hi == HALF_HI && lo > HALF_LO);
    }

    function _call(address precompile, bytes memory input, uint256 size) private view returns (bytes memory out) {
        bool ok;
        (ok, out) = precompile.staticcall(input);
        require(ok && out.length == size, "precompile");
    }
}
