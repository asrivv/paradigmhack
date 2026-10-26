//! `vm.ffi` entry point for the Bajillion settlement differential tests.
//!
//! Usage:
//!   bajillion-oracle apply <0x-hex abi.encode(uint64 seed, Op[] ops)>
//!   bajillion-oracle materialize <0x-hex abi.encode(uint64 seed, Op[] ops)>
//!
//! Prints one `0x`-prefixed hex ABI value on success; prints `error: ...` to stderr and exits
//! with status 2 on a malformed command line or input blob.

use bajillion_oracle::{decode_input, encode_ops, encode_output, run};
use std::process::ExitCode;

fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let digits = text
        .trim()
        .strip_prefix("0x")
        .ok_or("input must start with 0x")?;
    if !digits.len().is_multiple_of(2) {
        return Err("input has an odd number of hex digits".into());
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn execute(args: &[String]) -> Result<Vec<u8>, String> {
    let [command, input] = args else {
        return Err("usage: bajillion-oracle <apply|materialize> <0x-hex input>".into());
    };
    let (seed, ops) = decode_input(&parse_hex(input)?)?;
    match command.as_str() {
        "apply" => Ok(encode_output(&run(seed, ops))),
        "materialize" => Ok(encode_ops(&run(seed, ops))),
        other => Err(format!("unknown command {other}")),
    }
}

fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match execute(&args) {
        Ok(encoded) => {
            println!("{}", bajillion_fixtures::hex(encoded));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}
