//! Shared pieces of the Bajillion fixture generator.
//!
//! The binary in `main.rs` drives one epoch through the upstream crate and writes the results.
//! This library holds the parts that are not specific to that scenario: a SHA-256 hasher that
//! records every preimage the crate hashes, the EIP-2537 point encodings, and the native store
//! configuration ported from the upstream test helpers.

pub mod eip2537;
pub mod storage;
pub mod trace;

/// Lowercase `0x`-prefixed hex, the format Foundry's `vm.parseBytes` accepts.
pub fn hex(bytes: impl AsRef<[u8]>) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// Parses the output of [`hex`]. Panics on malformed input because fixtures are trusted files.
pub fn unhex(text: &str) -> Vec<u8> {
    let text = text.trim();
    let digits = text.strip_prefix("0x").expect("fixture hex starts with 0x");
    assert!(digits.len().is_multiple_of(2), "fixture hex has odd length");
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).expect("fixture hex digit"))
        .collect()
}
