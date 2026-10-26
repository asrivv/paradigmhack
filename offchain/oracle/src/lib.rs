//! Differential oracle for the Solidity port of the clearing crate's `SettlementChain`.
//!
//! Foundry calls the binary through `vm.ffi` with one ABI blob `(uint64 seed, Op[] ops)`. The
//! oracle applies every op to a real `SettlementChain` configured exactly like the fixtures
//! deployment and reports a status per op, whether a failed op still changed state (the
//! liveness fence), and a digest of the observable state. The contract must produce the same
//! three values for the same ops. See README.md for the byte-level contract.
//!
//! An op whose `args` are empty has them materialized from the seed: real crate bytes for
//! registrations, closes, certificates, challenges, and claims, built against the oracle's own
//! validator replica, with the seed choosing honest or invalid evidence, signer subsets, and
//! time offsets. The `materialize` command returns the ops with those args filled in, so the
//! Solidity side can replay the exact bytes the oracle applied.

pub mod status;
mod world;

use alloy_sol_types::{
    SolType, sol,
    sol_data::{Array, Bool, FixedBytes, Uint},
};

sol! {
    /// One settlement operation. `args` is the canonical ABI encoding of the kind's parameters,
    /// or empty to have the oracle materialize them.
    #[derive(Debug, PartialEq, Eq)]
    struct Op {
        uint8 kind;
        bytes args;
    }
}

/// Op kinds, numbered in the order the oracle specification lists them.
pub mod kind {
    pub const RECORD_DEPOSIT: u8 = 0;
    pub const QUEUE_WITHDRAWAL: u8 = 1;
    pub const REGISTER_EPOCH: u8 = 2;
    pub const ADMIT: u8 = 3;
    pub const CHALLENGE: u8 = 4;
    pub const FINALIZE: u8 = 5;
    pub const CLAIM_WITHDRAWAL: u8 = 6;
    pub const FAULT_EXPIRED: u8 = 7;
    pub const ADVANCE_TIME: u8 = 8;
    /// Number of defined kinds.
    pub const COUNT: u8 = 9;
}

/// The outcome of one oracle run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    /// The applied ops, with every materialized `args` filled in.
    pub ops: Vec<Op>,
    /// One status code per op (see [`status::TABLE`]).
    pub statuses: Vec<u16>,
    /// Per op: the op failed and the settlement state still changed.
    pub mutated_on_error: Vec<bool>,
    /// SHA-256 of the canonical observable state after the last op.
    pub state_digest: [u8; 32],
}

pub use world::run;

type Input = (Uint<64>, Array<Op>);
type Output = (Array<Uint<16>>, Array<Bool>, FixedBytes<32>);

/// Decodes the strict canonical `abi.encode(uint64 seed, Op[] ops)` input.
pub fn decode_input(blob: &[u8]) -> Result<(u64, Vec<Op>), String> {
    let decoded = Input::abi_decode_params_validate(blob).map_err(|error| error.to_string())?;
    if Input::abi_encode_params(&decoded) != blob {
        return Err("input is not the canonical ABI encoding".into());
    }
    Ok(decoded)
}

/// Encodes an input blob, the inverse of [`decode_input`].
pub fn encode_input(seed: u64, ops: &[Op]) -> Vec<u8> {
    Input::abi_encode_params(&(seed, ops.to_vec()))
}

/// Encodes `abi.encode(uint16[] statuses, bool[] mutatedOnError, bytes32 stateDigest)`.
pub fn encode_output(run: &Run) -> Vec<u8> {
    Output::abi_encode_params(&(
        run.statuses.clone(),
        run.mutated_on_error.clone(),
        run.state_digest,
    ))
}

/// Encodes `abi.encode(Op[] ops)` with every materialized `args` filled in.
pub fn encode_ops(run: &Run) -> Vec<u8> {
    Array::<Op>::abi_encode(&run.ops)
}
