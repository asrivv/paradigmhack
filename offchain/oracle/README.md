# bajillion-oracle

Differential oracle for `contracts/src/BajillionSettlement.sol`, the Solidity port of
`SettlementChain` from `commonware-clearing` at rev
`dd6d60cb44fb3dc05cee1efa06d957ce30df1340`. Foundry fuzzes a sequence of operations, runs it
through both the contract and this binary, and requires the same statuses, the same
mutated-on-error flags, and the same state digest. Like upstream `sol/fuzz`, every command prints
one hex-encoded ABI value. Run from `offchain/`.

```sh
cargo build --release --locked -p bajillion-oracle
cargo test --release --locked -p bajillion-oracle
target/release/bajillion-oracle apply <0x-hex input>
target/release/bajillion-oracle materialize <0x-hex input>
```

- `apply`: run the ops and print `abi.encode(uint16[] statuses, bool[] mutatedOnError, bytes32 stateDigest)`.
- `materialize`: run the same ops and print `abi.encode(Op[] ops)` with every materialized
  `args` filled in (see below), so the Solidity side can replay the exact bytes the oracle applied.

Both commands print `0x`-prefixed lowercase hex and a newline on stdout and exit 0. A malformed
command line or input blob prints `error: ...` to stderr, nothing to stdout, and exits 2;
`vm.ffi` then reverts. A failing op is never an error: it is reported through its status.

As in upstream `sol/foundry.toml`, run the differential tests under a profile with FFI enabled:

```toml
[profile.differential]
ffi = true

[profile.differential.fuzz]
runs = 256
```

```solidity
struct Op { uint8 kind; bytes args; }

function oracle(uint64 seed, Op[] memory ops)
    internal
    returns (uint16[] memory statuses, bool[] memory mutatedOnError, bytes32 stateDigest)
{
    string[] memory cmd = new string[](3);
    cmd[0] = "offchain/target/release/bajillion-oracle";
    cmd[1] = "apply";
    cmd[2] = vm.toString(abi.encode(seed, ops));
    return abi.decode(vm.ffi(cmd), (uint16[], bool[], bytes32));
}
```

`FOUNDRY_PROFILE=differential forge test` then runs them.

## Input

One argument: the hex of `abi.encode(uint64 seed, Op[] ops)` with
`struct Op { uint8 kind; bytes args; }`. The blob must be exactly the canonical encoding Solidity
produces: a `uint64` or `uint8` with high bits set, non-zero padding, non-standard offsets, or
trailing bytes are rejected (exit 2).

`args` is either empty, in which case the oracle materializes it from the seed, or the canonical
`abi.encode(...)` of the kind's parameters below. Crate values inside `bytes` parameters are the
exact `commonware-codec` encodings and must consume every byte.

| Kind | Name | `args` = `abi.encode(...)` | Upstream call |
|---|---|---|---|
| 0 | `recordDeposit` | `bytes32 id, bytes32 account, uint64 amount` | `record_deposit(now, id, account, amount)` |
| 1 | `queueWithdrawal` | `bytes signedWithdrawal, bytes stateOpening` | `queue_withdrawal(now, request, &opening, eligible)` |
| 2 | `registerEpoch` | `bytes epochContext, uint64 end, bytes depositBatch, bytes withdrawalBatch` | `register_epoch(now, context, end, deposits, withdrawals, eligible)` |
| 3 | `admit` | `bytes32 header, bytes rootBundle, uint64 withdrawalTotal, bytes certificate` | `admit(now, header, roots, withdrawalTotal, certificate)` |
| 4 | `challenge` | `bytes32 batchId, bytes challenge` | `challenge_encoded(now, batchId, challenge, 65536)` |
| 5 | `finalize` | must be empty | `finalize(now)` |
| 6 | `claimWithdrawal` | `bytes claim` | `claim_withdrawal(neighbors, &claim)` |
| 7 | `faultExpired` | must be empty | `fault_expired(now)` |
| 8 | `advanceTime` | `uint64 delta` | `now += delta` (oracle clock only) |

Kinds 9 to 255 are unknown and report 1002. Crate decoding of the parameters:

- `id`: a SHA-256 digest. `account`: an ed25519 public key, which must be a valid strict key.
- `signedWithdrawal`: `SignedWithdrawal<Ed25519, Sha256>`, destination at most 256 bytes.
- `stateOpening`: `StateOpening<Ed25519, Sha256>` with at most 256 proof digests.
- `epochContext`: `EpochContext<Ed25519, Sha256>`.
- `depositBatch`: `DepositBatch<Ed25519>`, at most 1024 records.
- `withdrawalBatch`: `WithdrawalBatch<Ed25519, Sha256>`, at most 1024 records, destinations at
  most 256 bytes.
- `header`: `Header<Sha256>` (one digest). `rootBundle`: `RootBundle<Sha256>`.
- `certificate`: `bls12381::Certificate` (MinSig) for a 4-member committee.
- `batchId`: a SHA-256 digest. `challenge` is passed to settlement undecoded: a challenge that
  does not decode is a settlement error (44), not a malformed-args status.
- `claim`: `WithdrawalClaim<Sha256>`, destination at most 256 bytes.

Any decode failure reports 1001 and calls nothing.

### Deployment

The chain starts from the `offchain/fixtures` deployment (seed 4664): the same deployment id,
operator, 4-validator BLS12-381 MinSig committee, genesis balances a=100, b=40, c=25, d=35,
first epoch 1, Sha256 hasher, and ed25519 accounts. `SettlementConfig`: admission delay 10,
challenge duration 20, deposit inclusion timeout 100, withdrawal notice 50 to 1000. The seed in
the input never changes the deployment, only materialized args.

### Embedding

The oracle plays the role of the embedding contract around `SettlementChain`:

- `now` starts at 0 and only `advanceTime` moves it. Every op that takes a time uses `now`.
- Every withdrawal destination is eligible (`eligible` always returns true).
- Claimed payout ranges are kept as a sorted set of disjoint half-open `[start, end)` ranges.
  `claimWithdrawal` passes the range at or before the claim position and the first range
  starting strictly after it; on success the merged range replaces them. A successful
  `finalize` also records the trailing Commit location it returns as claimed, the same way.
- `registerEpoch`: the embedding supplies the aggregate of the pulled prefix
  (`settlement.rs:14-16`), so the deposit batch must be exactly the per-account sum of the
  stored deposits at `[pulled, end)`. Upstream checks only part of this: it panics (a
  documented caller precondition) when a root-consistent batch credits an account more than its
  unpulled deposits, and it cannot see a batch that credits less. The oracle runs the call on a
  copy of the state and reports 1004 with nothing applied for either violation, at the point
  where upstream checks the batch: every earlier boundary, anchor and intake error still wins.
  The contract must revert without any state change for that input.

### Materialized args

For an op with empty `args` (other than `finalize` and `faultExpired`, which take none), the
oracle builds the args from `seed` and the op's index, independently of every other op, so
replacing one op's args with concrete bytes never changes another op's choices. It builds real
crate bytes against its own validator replica, which follows every close it built and that was
then admitted:

- `recordDeposit`: fresh or (15%) previously used ids, fixture or (20%) unfunded accounts,
  amounts 1 to 50 or (10%) zero.
- `queueWithdrawal`: requests signed by fixture or unknown accounts with openings at the
  finalized root, sometimes for the wrong account or foreign deployment, notices inside and just
  outside the configured window, amounts above and below the balance, and `Close` requests.
- `registerEpoch`: the exact pulled deposits and due withdrawals for the next epoch, sometimes
  with an extra operator-carried withdrawal, a wrong epoch, an end past intake, a context that
  binds other deposits, or a foreign committee.
- `admit`: an honest close with seed-chosen payments when the replica can build one, otherwise
  dummy roots; certified by 2 to 4 signers, or by 1 signer (below quorum), over another header,
  or with a withdrawal total that does not match the certified header.
- `challenge`: against a pending or bogus batch id: proven `AckFork` evidence, identical
  acknowledgments, a fork with a tampered operator signature, honest and invalid
  `HigherAckDebit` evidence (as in upstream `tests/challenges.rs`), or random bytes.
- `claimWithdrawal`: a real payout opening under the finalized payout head, sometimes with an
  inflated amount, or the never-claimable genesis Commit when there is no payout.
- `advanceTime`: one of 1, 1, 2, 5, 9, 10, 11, 20, 31, 60, 150, straddling the configured
  deadlines.

The materialization algorithm is an oracle detail, not part of the contract under test: the
Solidity test should call `materialize` and replay the returned ops through both sides.
Applying the returned ops gives the same output for any seed.

## Output

`abi.encode(uint16[] statuses, bool[] mutatedOnError, bytes32 stateDigest)`, with one entry per
input op in both arrays.

- `statuses[i]`: 0 if op `i` succeeded, otherwise the code from the table below.
- `mutatedOnError[i]`: true if and only if op `i` failed (`statuses[i] != 0`) and the settlement
  state still changed, compared through the crate's canonical `SettlementChain` encoding before
  and after the op. This is the liveness fence: upstream deliberately records an observed
  missed deadline (for example a hard fault for an expired deposit or registration) before
  returning the error. A Solidity port must commit that state instead of reverting. Oracle
  statuses (1001 to 1004) are always `false`.
- `stateDigest`: SHA-256 of the observable state after the last op (see below).

## Status codes

Codes are stable and append-only. Settlement errors are numbered in the declaration order of
`SettlementError`; wrapped errors (`Boundary`, `Transition`, `Challenge`, `State`,
`Commitment`, and `ClaimError::Proof`) report one code regardless of their inner cause. The
table is `TABLE` in `src/status.rs`; a test checks that this section matches it.

| Code | Name |
|---|---|
| 0 | `Ok` |
| 1 | `SettlementError::Deployment` |
| 2 | `SettlementError::OperatorMismatch` |
| 3 | `SettlementError::EpochSequence` |
| 4 | `SettlementError::StateAncestry` |
| 5 | `SettlementError::CommitteeMismatch` |
| 6 | `SettlementError::BoundaryRoot` |
| 7 | `SettlementError::DepositWitness` |
| 8 | `SettlementError::WithdrawalWitness` |
| 9 | `SettlementError::IntakeRange` |
| 10 | `SettlementError::IntakeOverflow` |
| 11 | `SettlementError::ClaimAlreadyConsumed` |
| 12 | `SettlementError::ZeroDeposit` |
| 13 | `SettlementError::DuplicateDeposit` |
| 14 | `SettlementError::PendingDepositUnavailable` |
| 15 | `SettlementError::DepositCapacity` |
| 16 | `SettlementError::DepositDeadlineOverflow` |
| 17 | `SettlementError::IneligibleDestination` |
| 18 | `SettlementError::DestinationTooLarge` |
| 19 | `SettlementError::WithdrawalOpening` |
| 20 | `SettlementError::WithdrawalBalance` |
| 21 | `SettlementError::DuplicateWithdrawal` |
| 22 | `SettlementError::DuplicateWithdrawalAuthorization` |
| 23 | `SettlementError::WithdrawalDeadlineTooSoon` |
| 24 | `SettlementError::WithdrawalDeadlineTooLate` |
| 25 | `SettlementError::WithdrawalNoticeOrder` |
| 26 | `SettlementError::DeadlineNotReached` |
| 27 | `SettlementError::OperatorHardFaulted` |
| 28 | `SettlementError::OperatorNotHardFaulted` |
| 29 | `SettlementError::HardFaultAlreadySettled` |
| 30 | `SettlementError::HardFaultSettlementNotStarted` |
| 31 | `SettlementError::CustodyArithmetic` |
| 32 | `SettlementError::CustodyMismatch` |
| 33 | `SettlementError::NoRegisteredEpoch` |
| 34 | `SettlementError::EpochDeadlineOverflow` |
| 35 | `SettlementError::InvalidCertificate` |
| 36 | `SettlementError::NoPendingBatch` |
| 37 | `SettlementError::AlreadyChallenged` |
| 38 | `SettlementError::BatchInvalidated` |
| 39 | `SettlementError::PreFaultBatchPending` |
| 40 | `SettlementError::ChallengeWindowOpen` |
| 41 | `SettlementError::EpochOverflow` |
| 42 | `SettlementError::Boundary` |
| 43 | `SettlementError::Transition` |
| 44 | `SettlementError::Challenge` |
| 45 | `SettlementError::State` |
| 46 | `SettlementError::Commitment` |
| 101 | `ClaimError::Unavailable` |
| 102 | `ClaimError::Reserve` |
| 103 | `ClaimError::Proof` |
| 1001 | `Oracle::MalformedArgs` |
| 1002 | `Oracle::UnknownKind` |
| 1003 | `Oracle::ClockOverflow` |
| 1004 | `Oracle::Precondition` |

The oracle codes mean:

- 1001 `MalformedArgs`: `args` are not the canonical ABI encoding the kind requires, a crate
  value inside them does not decode, or `finalize`/`faultExpired` got non-empty args.
- 1002 `UnknownKind`: `kind` is 9 or greater.
- 1003 `ClockOverflow`: `advanceTime` would overflow the 64-bit clock; `now` is unchanged.
- 1004 `Precondition`: the `registerEpoch` deposit-aggregate precondition above.

## State digest

`stateDigest = sha256(preimage)`. All integers are big-endian; `u64` is 8 bytes, `u32` is 4,
`u8` is 1. Digests and roots are 32 bytes. Fields in order:

| Field | Encoding |
|---|---|
| tag | the 25 ASCII bytes `BAJILLION_ORACLE_STATE_V1` |
| `now` | u64, the oracle clock |
| `nextRegistrationEpoch` | u64, `next_registration_epoch()`, or `2^64-1` on error |
| `nextAdmissionEpoch` | u64, `next_admission_epoch()`, or `2^64-1` on error |
| `expectedEpoch` | u64, next epoch to finalize |
| `intake` | u64, deposit inbox length |
| `pulled` | u64, deposits pulled by registrations |
| frontier flag | u8: 1 if an epoch is registered and awaiting admission, else 0 |
| frontier | only if the flag is 1: u64 epoch, 32-byte anchor, u64 admission deadline, u64 challenge deadline |
| pending count | u32, admitted unfinalized closes |
| pending batches | per close, oldest first: 32-byte batch id, u8 status, u8 challenge kind, u64 withdrawal total, u64 successor liability |
| activity head | 32-byte root, u64 operations, u64 floor of the finalized activity log |
| payout head | 32-byte root, u64 operations, u64 floor of the finalized payout log |
| state root | 32-byte current (finalized) state root |
| claimed count | u32, claimed payout ranges |
| claimed ranges | per range in ascending start order: u64 start, u64 end (exclusive) |
| `custody` | u64, active custody balance |
| `claimable` | u64, custody reserved for unconsumed claims |
| `liability` | u64, liability of the finalized state root |
| fault reason | u8: 0 none, 1 ProvenChallenge, 2 ExpiredDeposit, 3 ExpiredWithdrawal, 4 ExpiredRegistration |
| `expiredAt` | u64, the missed deadline for reasons 2 to 4, else 0 |
| fence flag | u8: 1 if an admission fence epoch is set, else 0 |
| fence epoch | u64, the fence epoch, else 0 |
| invalid flag | u8: 1 if a receipt-invalidated close exists, else 0 |
| `invalidFrom` | 32-byte batch id of the earliest invalidated close, else 32 zero bytes |

A pending batch's status is 0 pending, 1 challenged, 2 invalidated. Its challenge kind is
1 `HigherAckDebit`, 2 `HigherAckEntry`, 3 `AckFork` while challenged, otherwise 0. The batch id
is `Header::batch_id`, and the anchor is the frontier context's payment anchor.

The frontier is only the registered epoch awaiting admission; registrations queued behind it are
observable through `nextRegistrationEpoch`. Pending withdrawal requests and unpulled deposits
are not hashed directly: they are observable through `intake`, `pulled`, and the statuses of
later ops.

### Test vector

The genesis state, which is the digest of an empty op list for any seed, has a 285-byte
preimage:

```
0x42414a494c4c494f4e5f4f5241434c455f53544154455f56310000000000000000000000000000000100000000000000010000000000000001000000000000000000000000000000000000000000550b70a7c0fd428441985a82b1e8b1e9d64fb376d4d2b451f25d368fdff437d100000000000000010000000000000000550b70a7c0fd428441985a82b1e8b1e9d64fb376d4d2b451f25d368fdff437d1000000000000000100000000000000006d68250818907071bbe9eea0db384fe1d96aaa6fad1227dbd1d8875f84ae23e70000000000000000000000c8000000000000000000000000000000c8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

and digest

```
0x5cf6f6c247c1f0f401825bf6c145f66ad6b40952e49af543850d1bc6f6b90f73
```

A test rebuilds this preimage from upstream genesis values and the layout above and checks it
against both the oracle and this file.
