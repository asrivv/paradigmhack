//! Uncompressed EIP-2537 encodings of BLS12-381 points.
//!
//! The crate encodes points in the compressed ZCash format (48-byte G1, 96-byte G2). EIP-2537
//! precompiles take uncompressed affine coordinates with every base field element left-padded
//! from 48 to 64 bytes, and they order an Fp2 element as `c0 || c1`. The ZCash format orders it
//! `c1 || c0`, so G2 coordinates are swapped here, not just padded.

use blst::{
    BLST_ERROR, blst_p1_affine, blst_p1_affine_serialize, blst_p1_uncompress, blst_p2_affine,
    blst_p2_affine_serialize, blst_p2_uncompress,
};

/// Bytes in one compressed ZCash G1 point.
pub const G1_COMPRESSED: usize = 48;
/// Bytes in one compressed ZCash G2 point.
pub const G2_COMPRESSED: usize = 96;
/// Bytes in one EIP-2537 G1 point.
pub const G1_EIP2537: usize = 128;
/// Bytes in one EIP-2537 G2 point.
pub const G2_EIP2537: usize = 256;

const FP: usize = 48;
const PADDED_FP: usize = 64;

/// Encodes a ZCash-uncompressed affine G1 point (`x || y`) for EIP-2537.
pub fn g1_from_affine(serialized: &[u8; 2 * FP]) -> [u8; G1_EIP2537] {
    let mut out = [0u8; G1_EIP2537];
    out[PADDED_FP - FP..PADDED_FP].copy_from_slice(&serialized[..FP]);
    out[2 * PADDED_FP - FP..].copy_from_slice(&serialized[FP..]);
    out
}

/// Encodes a ZCash-uncompressed affine G2 point (`x.c1 || x.c0 || y.c1 || y.c0`) for EIP-2537
/// (`x.c0 || x.c1 || y.c0 || y.c1`).
pub fn g2_from_affine(serialized: &[u8; 4 * FP]) -> [u8; G2_EIP2537] {
    let mut out = [0u8; G2_EIP2537];
    // ZCash limb order: x.c1, x.c0, y.c1, y.c0. EIP-2537 slot of each limb: 1, 0, 3, 2.
    for (limb, slot) in [1usize, 0, 3, 2].into_iter().enumerate() {
        let end = (slot + 1) * PADDED_FP;
        out[end - FP..end].copy_from_slice(&serialized[limb * FP..(limb + 1) * FP]);
    }
    out
}

/// Converts a compressed crate G1 point to its EIP-2537 encoding.
pub fn g1(compressed: &[u8]) -> [u8; G1_EIP2537] {
    assert_eq!(compressed.len(), G1_COMPRESSED, "compressed G1 length");
    let mut affine = blst_p1_affine::default();
    let mut serialized = [0u8; 2 * FP];
    // SAFETY: `compressed` holds 48 bytes and `serialized` 96, the sizes blst reads and writes.
    unsafe {
        assert_eq!(
            blst_p1_uncompress(&mut affine, compressed.as_ptr()),
            BLST_ERROR::BLST_SUCCESS,
            "crate G1 bytes decompress"
        );
        blst_p1_affine_serialize(serialized.as_mut_ptr(), &affine);
    }
    g1_from_affine(&serialized)
}

/// Converts a compressed crate G2 point to its EIP-2537 encoding.
pub fn g2(compressed: &[u8]) -> [u8; G2_EIP2537] {
    assert_eq!(compressed.len(), G2_COMPRESSED, "compressed G2 length");
    let mut affine = blst_p2_affine::default();
    let mut serialized = [0u8; 4 * FP];
    // SAFETY: `compressed` holds 96 bytes and `serialized` 192, the sizes blst reads and writes.
    unsafe {
        assert_eq!(
            blst_p2_uncompress(&mut affine, compressed.as_ptr()),
            BLST_ERROR::BLST_SUCCESS,
            "crate G2 bytes decompress"
        );
        blst_p2_affine_serialize(serialized.as_mut_ptr(), &affine);
    }
    g2_from_affine(&serialized)
}
