# Protocol notes: Bajillion settlement

These notes describe what the Tempo settlement contract must verify and store. Bajillion and the
`commonware-clearing` crate are designed and maintained by Commonware. These notes record how their
pinned code behaves. They do not propose changes to it.

## Pinned upstream

- Repository: `commonwarexyz/monorepo`, fetched from `refs/pull/4664/head`.
- Commit: `dd6d60cb44fb3dc05cee1efa06d957ce30df1340` ("[clearing, terminal] Sign close batches with
  the operator receipt key", 2026-10-01).
- Workspace version `2026.9.0`, license `MIT OR Apache-2.0` (`Cargo.toml:68`, `Cargo.toml:70`).
- The crate calls Bajillion ALPHA: API, wire format and storage may change (`clearing/README.md:17`).
- Every path below is relative to the monorepo root at that commit. `settlement.rs`,
  `transition.rs` and the other bare file names live in `clearing/src/bajillion/`.

## Conventions

- `D` is the digest type. The reference application uses `Sha256` throughout
  (`examples/terminal/src/chain/state.rs:1637` declares `SettlementChain<Sha256, Key>`), so every
  digest below is 32 bytes and every hash is SHA-256.
- `P` is the account key type. The reference application uses `StrictVerifyingKey` from
  `commonware_cryptography_curve25519::signing` (`examples/terminal/src/protocol.rs:36-56`), a
  32-byte Ed25519 verifying key with 64-byte signatures.
- `u64` encodes as 8 bytes big-endian (`codec/src/types/primitives.rs:77`). `NonZeroU64` encodes
  the same way (`codec/src/types/primitives.rs:134-140`).
- `usize` encodes as an unsigned LEB128 varint of a `u32` (`codec/src/types/primitives.rs:168-173`).
  `Bytes` and `Vec<T>` are a `usize` varint length followed by the items
  (`codec/src/types/bytes.rs:9-14`, `codec/src/types/vec.rs:13-17`).
- `H::hash(&[a, b, ...])` hashes the plain concatenation of its parts. No length framing is added
  unless a part writes its own.

## 1. Wire formats

All fixed sizes assume `D = 32` bytes and `P = 32` bytes.

### transition::Header (32 bytes)

`Header` is a newtype around one digest (`transition.rs:304`) and encodes as that digest
(`transition.rs:338-345`). Its preimage (`transition.rs:307-318`):

```
header = SHA256(
    "_COMMONWARE_CLEARING_HEADER_ROOT"      // HEADER_ROOT_HASH_NAMESPACE, 32 bytes, transition.rs:38
 || CloseContext.encode()                    // 448 bytes, see below
 || RootBundle.encode()                      // 184 bytes, see below
 || withdrawal_total as u64 big-endian       // 8 bytes
)
```

The preimage is `32 + 448 + 184 + 8 = 672` bytes. `Header::verify` also recomputes the epoch anchor (`transition.rs:320-328`), so a header is valid
only if its context's anchor binds its own parameters. The batch identifier used to address a
pending close is `BatchId = SHA256("_COMMONWARE_CLEARING_BATCH_ID" || header)`
(`transition.rs:36`, `transition.rs:334-336`).

### PaymentContext (72 bytes)

`payment.rs:42-46`, encoding `payment.rs:82-92`:

| Offset | Size | Field |
|---|---|---|
| 0 | 32 | `anchor` (digest) |
| 32 | 8 | `epoch` (u64 BE, `Epoch = u64`, `payment.rs:34`) |
| 40 | 32 | `operator` (account key) |

### CloseLimits (64 bytes)

Eight u64 BE values in this order (`transition.rs:448-463`): `max_states`, `max_rows`,
`max_withdrawals`, `max_account_entries`, `max_total_entries`, `max_payment_total`,
`max_deposit_total`, `max_withdrawal_total`.

### EpochContext (264 bytes)

Fields `transition.rs:492-499`, encoding `transition.rs:690-704`:

| Offset | Size | Field |
|---|---|---|
| 0 | 72 | `payment: PaymentContext` |
| 72 | 32 | `deployment` |
| 104 | 32 | `deposit_root: VectorRoot` (one digest, `commitment.rs:95-118`) |
| 136 | 32 | `withdrawal_root: VectorRoot` |
| 168 | 64 | `limits: CloseLimits` |
| 232 | 32 | `committee` (committee commitment digest) |

The payment anchor is (`transition.rs:533-551`):

```
anchor = SHA256(
    "_COMMONWARE_CLEARING_EPOCH_ANCHOR"      // transition.rs:40
 || deployment || deposit_root || withdrawal_root
 || epoch as u64 BE || operator || limits.encode() || committee
)
```

The anchor field itself is not in its own preimage. `verify_anchor` recomputes it and compares
(`transition.rs:549-551`).

### LogHead, Heads, Floors

- `LogHead` is 48 bytes: `root` (32) `|| operations` (u64 BE) `|| floor` (u64 BE)
  (`logs.rs:168-176`, `logs.rs:228-238`). Decoding requires `operations > 0`, a valid MMR location,
  and `floor < operations` (`logs.rs:178-194`).
- `Heads` is 96 bytes: `activity: LogHead || payouts: LogHead` (`logs.rs:252-291`).
- `Floors` is 16 bytes: `activity` (u64 BE) `|| payouts` (u64 BE) (`logs.rs:306-333`).

### CloseContext (448 bytes)

Fields `transition.rs:730-739`, encoding `transition.rs:870-890`:

| Offset | Size | Field |
|---|---|---|
| 0 | 264 | `epoch: EpochContext` |
| 264 | 32 | `predecessor_root: StateRoot` (one digest, `qmdb.rs:63-82`) |
| 296 | 96 | `predecessor_logs: Heads` |
| 392 | 8 | `predecessor_rows.start` (u64 BE) |
| 400 | 8 | `predecessor_rows.end` (u64 BE) |
| 408 | 8 | `predecessor_liability` (u64 BE) |
| 416 | 8 | `admission_deadline` (u64 BE, `Deadline = u64`, `boundary.rs:25`) |
| 424 | 8 | `challenge_deadline` (u64 BE) |
| 432 | 16 | `floors: Floors` |

Settlement builds the context itself when an epoch becomes the admission frontier
(`settlement.rs:1418-1440`, `transition.rs:595-615`). The predecessor fields come from the
admitted head, not from the operator. A contract port therefore never accepts a CloseContext from
calldata; it stores the bound fields and re-encodes them to hash the header.

### RootBundle (184 bytes)

Fields `transition.rs:128-143`, encoding `transition.rs:271-298`, size `transition.rs:282-284`
(`2 * 48 + 2 * 32 + 3 * 8 = 184`):

| Offset | Size | Field |
|---|---|---|
| 0 | 48 | `change: LogHead` (cumulative activity log) |
| 48 | 8 | `row_count` (u64 BE) |
| 56 | 48 | `withdrawal_outputs: LogHead` (cumulative payout log) |
| 104 | 32 | `successor: StateRoot` |
| 136 | 8 | `successor_operations` (u64 BE) |
| 144 | 8 | `successor_sync_boundary` (u64 BE) |
| 152 | 32 | `proposal: ProposalId` (one digest, `transition.rs:91-124`) |

### WithdrawalOutput (variable)

Fields `transition.rs:911-914`, encoding `transition.rs:940-955`:

```
varint(destination.len()) || destination || amount as u64 BE
```

`destination` is opaque adapter bytes, bounded by `SettlementConfig::max_destination_bytes`
(`settlement.rs:250-251`). For a Tempo adapter it will be a 20-byte address, so an output encodes
as `0x14 || address || amount`, 29 bytes.

In the payout log each output is wrapped as a keyless QMDB `Append` operation
(`logs.rs:145`, `logs.rs:399-406`). The variable encoding prefixes the tag `APPEND_CONTEXT = 1`
(`storage/src/qmdb/keyless/operation/mod.rs:17-19`,
`storage/src/qmdb/keyless/operation/variable.rs:15-26`):

```
payout_operation = 0x01 || WithdrawalOutput.encode()
```

Commit operations use tag `0x00` and carry no output, which is why a commit location can never be
paid (`settlement.rs:1616-1620`).

### WithdrawalClaim (variable)

Fields `transition.rs:981-984`, encoding `transition.rs:1024-1047`:

```
WithdrawalOutput.encode() || Opening.encode()
Opening  = start as u64 BE || mmr::Proof.encode()                     (logs.rs:355-361, 435-440)
mmr::Proof = varint(leaves) || varint(inactive_peaks) || Vec<digest>   (storage/src/merkle/proof.rs:89-95,
                                                                        storage/src/merkle/location.rs:186-191)
```

`claim.position()` is `opening.start`, the native Append location (`transition.rs:1003-1007`).
Opening decoding caps the digest vector at `mmr::MAX_PROOF_DIGESTS_PER_ELEMENT * 2`
(`logs.rs:442-456`).

### MinSig multisig certificate

`bls12381::Certificate = multisig::Certificate<MinSig>` (`admission/certificate.rs:195`). Encoding
(`cryptography/src/bls12381/certificate/multisig/mod.rs:356-393`):

```
signers   = bit_count as u64 BE (8 bytes)                  // utils/src/bitmap/mod.rs:860-870, 876-880
         || ceil(bit_count / 8) bitmap bytes, LSB first     // utils/src/bitmap/mod.rs:553
signature = compressed G1 point (48 bytes)                  // group.rs:427, group.rs:1254-1258
```

Note the bit-count prefix is a fixed 8-byte u64, not a varint: `BitMap::len` returns `u64`
(`utils/src/bitmap/mod.rs:138`) and `u64` writes as 8 bytes big-endian. Decoding rejects nonzero
trailing bits (`utils/src/bitmap/mod.rs:900-905`) and a certificate with zero signers
(`multisig/mod.rs:381-386`).

Verification (`admission/certificate.rs:359-386`):

1. `signers.len() == n` (bitmap length equals committee size) and `signers.count() >= q`.
2. Aggregate the selected committee keys, verify the aggregate signature once over
   `union_unique(HEADER_NAMESPACE, header.encode())`.

`HEADER_NAMESPACE = "_COMMONWARE_CLEARING_HEADER"` (`admission/certificate.rs:14`). `union_unique`
is `varint(namespace.len()) || namespace || message` (`utils/src/lib.rs:183-192`). The signed
message is therefore `0x1b || "_COMMONWARE_CLEARING_HEADER" || header`, 60 bytes, hashed to G1 with
DST `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_` (`group.rs:438`,
`cryptography/src/bls12381/primitives/ops/mod.rs:80-86`).

Quorum: `n = 3f + 1` is enforced at committee construction (`admission/certificate.rs:132-134`),
`f = (n - 1) / 3` via `max_faults::<N3f1>` and `q = f + 1` (`admission/certificate.rs:58-70`). The
crate states what this buys: at least one honest signer validated and retained the dealing, and
certificates do not establish a unique close (`admission/certificate.rs:63-67`).

Committee: an ordered `Set<G2>` of compressed 96-byte G2 keys, sorted by compressed bytes
(`group.rs:1739-1743`), encoded as `varint(n) || n * 96 bytes`. Its commitment is
`SHA256("_COMMONWARE_CLEARING_COMMITTEE" || Set<G2>.encode())` (`admission/certificate.rs:16-27`),
and `EpochContext.committee` must equal it (`settlement.rs:1275-1277`). The crate requires the
embedding to verify each MinSig proof of possession before building the committee
(`admission/certificate.rs:39-42`). PoP uses DST `BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_` over
`union_unique(namespace, compressed_g2_key)` (`group.rs:430`, `ops/mod.rs:109-125`). The clearing
crate does not fix the PoP namespace; the deployment chooses it.

### What commonware-sol's LibCodec decodes

None of these fields. `sol/src/codec/LibCodec.sol:6-15` contains one function, `encodeVarint`, used
to frame BLS namespaces. Every decode in the contract (CloseContext, RootBundle, Certificate,
WithdrawalOutput, Opening) must be written by us.

### Encoding mismatches between the crate and commonware-sol

| Value | Crate bytes | commonware-sol input | Gap |
|---|---|---|---|
| Aggregate signature | 48-byte compressed G1 | 96-byte uncompressed `x \|\| y` (`LibBLS12381Multisig.sol:15`, `LibBLS12381.sol:30`) | needs decompression; sol has none |
| Signer bitmap | 8-byte u64 BE bit count + bitmap | raw bitmap, `ceil(n/8)` bytes, no prefix (`LibBLS12381Multisig.sol:11-12`) | strip prefix, check it equals `n` |
| Committee key | 96-byte compressed G2 | `G2Point`, 256 bytes, EIP-2537 padded (`LibBLS12381.sol:44-53`) | needs decompression; sol has none |
| Proof of possession | DST `BLS_POP_...` | hash-to-curve DST fixed to `BLS_SIG_...` (`LibBLS12381.sol:179-186`) | no PoP verifier in sol |

## 2. Proof map

Hasher: the reference application uses SHA-256. commonware-sol's Merkle and QMDB libraries take a
`hasher` address: `address(0)` selects native keccak256 and any other address is called with the
raw preimage and must return 32 bytes (`sol/src/qmdb/LibQMDBKeylessMMR.sol:7-12`,
`sol/src/merkle/LibBMT.sol:1-8`). The SHA-256 precompile at `address(2)` matches the crate. The sol
test suite runs every Merkle and QMDB case twice, once per hasher, e.g.
`LibQMDBKeylessMMRSha256Test` returns `address(2)` (`sol/test/LibQMDBKeyless.t.sol:394-396`) and
`LibQMDBKeylessMMRKeccak256Test` returns `address(0)` (`sol/test/LibQMDBKeyless.t.sol:388-391`);
`sol/test/LibMMR.t.sol:241-249` does the same. The differential fuzzer builds keyless MMR fixtures
with `Sha256` (`sol/fuzz/src/qmdb.rs:838`). The contract must pass `address(2)` everywhere.

### admit (`settlement.rs:1446-1545`)

| Check | Crate function | Solidity |
|---|---|---|
| Header equals `SHA256(namespace \|\| context \|\| roots \|\| total)` and the anchor verifies | `transition::validate_header` (`transition.rs:1758-1769`) | our encoder + `sha256` |
| Certificate: bitmap length `n`, popcount `>= q`, aggregate signature over header | `bls12381::Scheme::verify` (`admission/certificate.rs:359-386`) | `LibBLS12381Multisig.verifyMinSig` (`LibBLS12381Multisig.sol:22-41`) after converting encodings |
| Deposit and withdrawal batches hash to the registered roots | `validate_boundary_roots` (`transition.rs:1806-1820`) | our BMT builder; `LibBMT` only verifies proofs, it does not build roots |
| Withdrawal total bound, activity range, payout-log count and floors, successor bounds, liability | `validate_close_amounts` (`transition.rs:1771-1805`), `RootBundle::activity_range` (`transition.rs:154-186`) | plain arithmetic, no proof |

`verifyMinSig` itself enforces `n > 0`, `0 < q <= n`, bitmap length `ceil(n/8)`, zero unused high
bits and popcount `>= q` (`LibBLS12381Multisig.sol:75-91`). The Rust check `signers.len() == n`
corresponds to our check that the stripped u64 prefix equals `n`.

### finalize (`settlement.rs:1621-1701`)

No proof. Checks are: front status `Pending`, `now > challenge_deadline`, the front's
`predecessor_logs` equal the finalized logs, and the commit location
`withdrawal_outputs.operations - 1 >= finalized payouts.operations`. The returned commit location
must be inserted into the claimed-range map in the same transaction (`settlement.rs:1616-1620`).

### claim_withdrawal (`settlement.rs:1710-1736`)

| Check | Crate function | Solidity |
|---|---|---|
| Claimed-range neighbours valid and not covering the index | `ClaimedRange::insert` (`settlement.rs:501-521`) | our port |
| Neighbours and merged range end at or below finalized payout `operations` | `settlement.rs:1717-1724` | our port |
| Output is an `Append` at `opening.start` under the finalized payout head | `WithdrawalClaim::verify` -> `Opening::verify_payout` (`transition.rs:1014-1021`, `logs.rs:399-433`) | `LibQMDBKeylessMMR.verify(root, 0x01 \|\| output, proof, address(2))` (`LibQMDBKeylessMMR.sol:20-37`) |
| Amount fits the claimable reserve | `settlement.rs:1726-1729` | our port |

`Opening::verify` adds checks the sol library does not do and the contract must: the location is
a valid index, `start + 1 <= operations - 1` (the trailing commit is never claimable),
`proof.leaves == operations`, and `proof.inactive_peaks == mmr::Family::inactive_peaks(operations,
floor)` (`logs.rs:416-430`). sol hashes each leaf as `SHA256(uint64_be(position) || operation)`
(`LibQMDBCommon.sol` `reconstructRange`).

### Challenges (later phase)

`challenge` adjudicates `challenge::Challenge` against the stored context, header and roots
(`settlement.rs:1574-1614`). A proven challenge marks the target `Challenged`, every later pending
close `Invalidated`, and enters a hard fault (`settlement.rs:1604-1612`). Payer and receipt
signatures in challenges are Ed25519 over the curve25519 key type; Tempo verification cost for those
is open until the Phase 1 spike.

## 3. Mutation on error

The module doc (`settlement.rs:3-12`):

> This module is a runtime-agnostic in-memory transition primitive, not a persistence or asset
> adapter. The embedding settlement environment must commit each state mutation and its returned
> custody effects atomically and idempotently. Every public mutation that accepts `now` first
> observes expired liveness deadlines. That permanent fence can be the method's only state
> change even when the requested operation returns an error. Callers must therefore provide one
> authenticated, monotonic clock and persist mutation-on-error results.

The struct doc repeats it: "Every method accepting `now` may record a permanent deadline fence
before returning an error" (`settlement.rs:639-642`).

`observe_time` (`settlement.rs:861-874`) does two things: it enters a hard fault if any liveness
deadline expired, and it prunes withdrawal replay ids whose deadline is `<= now`. Either can be the
only state change of a failing call.

| Method | Observation | Can still fail after it |
|---|---|---|
| `record_deposit` | `ensure_operating_at` (`settlement.rs:990`) | yes: `OperatorHardFaulted` if the fence fired, then every deposit check |
| `queue_withdrawal` | `ensure_operating_at` (`settlement.rs:1152`) | yes |
| `register_epoch` | `ensure_operating_at` (`settlement.rs:1263`) | yes |
| `admit` | `ensure_operating_at` (`settlement.rs:1454`) | yes |
| `challenge` | `observe_time` (`settlement.rs:1554`) | yes: continues after a fault, so challenges on the pre-fault prefix still work |
| `challenge_encoded` | `observe_time` (`settlement.rs:1566`) | yes, including decode errors |
| `finalize` | `observe_time` (`settlement.rs:1625`) | yes: continues after a fault, so the pre-fault prefix still finalizes |
| `claim_pending_deposit` | `observe_time` (`settlement.rs:1811`) | yes |
| `fault_expired` | `ensure_operating` then `expired_reason` (`settlement.rs:1784-1794`) | only before mutating (`OperatorHardFaulted`, `DeadlineNotReached`); does not prune replay ids |

`claim_withdrawal`, `begin_hard_fault_settlement` and `claim_hard_fault` take no `now` and observe
nothing.

On an EVM a revert discards every write, so a port cannot "persist and return an error" with
`revert`. The contract must commit the fence and return a status, as the reference application does
(`examples/terminal/src/chain/state.rs:21-24`: "retaining those observations even if a subsequent
request is rejected").

### Deadline comparisons

| Deadline | Expires when | Source |
|---|---|---|
| Admission | `now > admission_deadline` (inclusive deadline) | `settlement.rs:810-825` |
| Challenge window | challenge accepted while `now <= challenge_deadline` | `settlement.rs:1594-1596` |
| Finalize | allowed when `now > challenge_deadline` | `settlement.rs:1643-1645` |
| Deposit inclusion | `now >= deadline` | `settlement.rs:772-776` |
| Withdrawal | `now >= deadline` | `settlement.rs:777-779` |

Deadlines are assigned when an epoch becomes the frontier: `admission = now + admission_delay`,
`challenge = admission + challenge_duration`, and `challenge < u64::MAX` so one later tick exists
(`settlement.rs:881-893`). Carried withdrawals must have `deadline > latest challenge deadline + 1`
(`settlement.rs:1362-1385`). That gives SPEC invariant 7 directly.

## 4. Account keys are 32 bytes

`qmdb::account_key` (`qmdb.rs:621-625`):

```rust
/// Convert the canonical account encoding without hashing, padding, or truncation.
pub fn account_key<P: PublicKey>(account: &P) -> Result<AccountKey, Error> {
    let bytes: [u8; 32] = account.as_ref().try_into().map_err(|_| Error::AccountKey)?;
    Ok(AccountKey::new(bytes))
}
```

`AccountKey = FixedBytes<32>` (`qmdb.rs:38`). Other places that assume or require 32-byte keys:

- `posted::decode_with_strategy` rejects any `P::SIZE != 32` (`posted.rs:57-59`) and reads keys in
  fixed 32-byte slices sized by `reader.remaining() / 33` (`posted.rs:61-69`).
- `posted::encode` rejects `P::SIZE != 32` (`posted.rs:157`).
- `PackedWithdrawals::find` compares the first `P::SIZE` bytes of each encoded request
  (`settlement.rs:396-405`). It is size generic but relies on the account being the fixed-width
  prefix of `SignedWithdrawal` (`boundary.rs:475-478`).
- Encoded sizes that include `P::SIZE` and become 32 for the reference key: `PaymentContext`
  (`payment.rs:91`), `DepositRecord` (`boundary.rs:67`), `Run` (`settlement.rs:2609`),
  `vector.rs:49`, `challenge.rs:136`, `challenge.rs:182`, `state.rs:287`, `qmdb.rs:713`.

The contract treats account keys as `bytes32`. Tempo addresses are 20 bytes, so a deposit must name
a 32-byte clearing account explicitly; the depositor's `msg.sender` is not the account.

## 5. Things the settlement layer must supply

- An authenticated monotonic clock. The terminal example uses block height
  (`examples/terminal/src/chain/state.rs:21`). On Tempo we must choose `block.timestamp` or
  `block.number`; that is a deployment decision, not a crate one.
- Atomic commit of each mutation with its custody effect (`settlement.rs:5-7`).
- Deposit storage under `(deployment, index)` and the per-account aggregate at registration
  (`settlement.rs:14-17`).
- The claimed-range ordered map under `(deployment, start)` (`settlement.rs:475-483`).
- Genesis root, operation count and liability from trusted setup (`settlement.rs:580-629`), and the
  two bootstrap log heads `Heads::empty` (`logs.rs:261-280`), whose roots are the keyless root of
  a single `Commit(None, 0)` operation (`storage/src/qmdb/keyless/mod.rs:81-89`).
- Proof-of-possession verification for every committee key (`admission/certificate.rs:39-42`).
- A destination eligibility predicate for withdrawals (`settlement.rs:1139-1141`).

## 6. Where SPEC.md and the pinned code differ

| SPEC.md | Pinned code |
|---|---|
| `registerCommittee` is a method | The committee is a constructor argument, immutable per deployment (`settlement.rs:696-719`) |
| `deposit` | `record_deposit(now, deposit_id, account, amount)` with lifetime deposit-id replay protection and an inclusion deadline (`settlement.rs:983-1055`) |
| `admitClose` | `admit` (`settlement.rs:1446`) |
| `challengeAckFork`, `challengeDebitMismatch`, `challengeEntryMismatch` | one `challenge` taking a typed `Challenge`; kinds `HigherAckDebit`, `HigherAckEntry`, `AckFork` (`settlement.rs:2227-2233`) |
| `claimPayout` | `claim_withdrawal` (`settlement.rs:1710`) |
| `triggerHardFault` | `fault_expired` (`settlement.rs:1784`); a proven challenge also hard-faults (`settlement.rs:1611`) |
| `recoverBalance` | `begin_hard_fault_settlement`, `claim_hard_fault`, `claim_pending_deposit` (`settlement.rs:1806-2062`) |
| "operator bond", "bond slashed" | No bond or slashing anywhere in `SettlementChain`. A proven challenge fences the whole deployment and moves it to terminal settlement |
| "A successful challenge invalidates that close and every later pending close" | Matches (`settlement.rs:1606-1609`), and additionally hard-faults the deployment |
| Withdrawals | Each withdrawal is an Ed25519-signed `SignedWithdrawal` whose signature settlement verifies at intake and registration (`settlement.rs:1112`, `boundary.rs:454-472`) |
| `pathUSD` amounts | Crate amounts are u64 (`settlement.rs:79`, `transition.rs:913`); at 6 decimals (TIP-20 decimals to be confirmed in the Phase 1 spike) u64 covers about 1.8e13 USD |

## 7. Embedding decisions in BajillionSettlement

These are choices the crate leaves to the settlement environment, or gaps between the crate and
commonware-sol, and how `contracts/src/BajillionSettlement.sol` resolves them.

| Gap | Resolution |
|---|---|
| Certificates carry a 48-byte compressed G1 signature; `verifyMinSig` needs 96 uncompressed bytes | `admit` takes the crate's exact certificate bytes plus an uncompressed hint and checks the hint compresses to them (`src/verify/LibBLS12381Point.sol`). The pairing precompile then checks curve and subgroup membership |
| Committee keys are 96-byte compressed G2; `verifyMinSig` needs EIP-2537 `G2Point`s | Same hint check at construction. Keys are not stored (8 new slots each on Tempo); `admit` takes them as calldata against a stored keccak256 |
| commonware-sol has no proof-of-possession verifier | `src/verify/LibBLS12381PoP.sol` copies upstream hash-to-curve with the `BLS_POP_` DST. The PoP namespace is a deployment parameter |
| Withdrawals are Ed25519-signed; the EVM has no Ed25519 precompile | `LibEd25519` (ZIP215) verifies each signature where upstream does: at `queueWithdrawal` intake for chain-queued requests and at registration for operator-carried extras. Admission does not re-verify; the registered withdrawal root binds the same bytes |
| `queue_withdrawal` takes a `StateOpening`: a current ordered QMDB proof over an MMB | `StateVerifier` decodes the crate encoding into commonware-sol's `LibQMDBCurrent.Proof` and verifies it with `LibQMDBCurrentMMB`, SHA-256 at `address(2)`, 32-byte chunks, at most 256 digests |
| `pending_withdrawal_deadlines` is an ordered set | A list sorted by `(deadline, account bytes)`; `queueWithdrawal` takes the predecessor and the contract checks it in O(1). Its head is the earliest chain-queued deadline |
| `observe_time` prunes expired replay ids, and that pruning can be a failed call's only state change | An id is consumed while its deadline is later than `now`. The only reader is the intake check, which always follows an observation at the same `now`, so the answers match without the write. The oracle does not count a pruning-only change as mutated on error |
| `enter_hard_fault` clears every `carried` flag | A request records its carrying epoch; it is carried only while that epoch is a live registration, which a fault ends |
| Deposits and chain-queued withdrawals share inbox indices | Both enter the inbox hash chain. A withdrawal's entry has amount zero, which no deposit can have, so the 40-byte registration witness distinguishes them and lists the requests a pull owes |
| The destination eligibility predicate | Eligible iff the destination is exactly 20 bytes, one Tempo address. The oracle treats every destination as eligible and materializes only 20-byte ones |
| `SettlementChain` has no bond | The constructor escrows a bond outside custody accounting. Nothing reads it yet |
| A revert discards the liveness fence | Once a call writes the fence it returns a `Status` and emits `HardFault` instead of reverting |
| The embedding supplies the pulled deposit aggregate | The contract keeps a hash chain over deposits and requires the aggregate to match exactly |
| Claimed ranges come from an authenticated ordered map | A linked list keyed by range start; the caller names the predecessor and the contract checks it in O(1) |
| Unbounded queues of registrations and admitted closes | A 64-epoch ring; `registerEpoch` reverts with `PipelineFull` past it |
| Clock | `block.timestamp` |
| EIP-170 | `foundry.toml` compiles `BajillionSettlement.sol` alone at 200 runs, and the stateful halves live in linked libraries whose external functions run by DELEGATECALL on state in the contract's storage, so the deployment keeps one address: `BajillionWithdrawals` (withdrawal bookkeeping), `BajillionClaims` (claimed ranges and payout claims), `BajillionRecovery` (terminal settlement), `BajillionLiveness` (`expired_reason`), and `BajillionChallenge` (target lookup, adjudication, cascade marking). `BajillionTypes.sol` holds the storage types they share. 24,385 bytes. `test/SettlementSize.t.sol` fails above 24,576 bytes |
| Terminal claims pay amounts "directly to the account", which is an Ed25519 key with no Tempo address | Deposit refunds and state residuals are credited to the clearing account; `sweepRecovered` pays the credit to a recipient the account signs for: `union_unique("_PARADIGMHACK_BAJILLION_RECOVERY", deployment \|\| recipient \|\| u64 nonce)`. Upstream's `claim_pending_deposit` stays permissionless. A signed withdrawal's output already names a 20-byte destination and is paid there directly |
| Terminal settlement reads admitted deposit batches and carried requests, which the contract does not store | `claimPendingDeposit` takes the drained closes' deposit batches, checked against their registered roots, and `claimHardFault` takes the account's one request, checked against its stored digest (192 bits beside the deadline). Both are public: admission and registration calldata published them |
| `begin_hard_fault_settlement` sums per-account deposits to check custody | The contract keeps `pendingDepositTotal`, the sum of unadmitted deposits, and adds the drained closes' deposit totals |
| Two builds of each library | Libraries imported by the settlement compile twice: canonical artifacts at 1,000,000 runs and `*.settlement.json` copies at 200 runs. Forge test linking currently picks the 200-run copies for contracts that embed the settlement (in-test Ed25519 verification costs 1,154,164 gas, against 949,348 at 1,000,000 runs), so gas snapshots understate production libraries. The deploy script deploys and links the 1,000,000-run artifacts explicitly |

### Behaviour inherited from commonware-sol

`LibBLS12381._pairing` and the hash-to-curve helpers call EIP-2537 precompiles with `gas()`. A
precompile error, such as a hint coordinate that is not on the curve, consumes all gas forwarded
to it. `admit` with a malformed signature hint therefore still reverts with `InvalidCertificate`,
but only after burning 63/64 of the caller's gas. Only the submitter pays and no state changes.
`test_Inv09_RejectsMutatedCertificate` caps gas per call for this reason. This is worth raising
upstream.

## 8. Differential testing against SettlementChain

`contracts/test/Differential.t.sol` (invariant 10) runs seed-chosen op sequences through
`BajillionSettlement` and through `offchain/oracle`, which applies the same bytes to the crate's
`SettlementChain` with the fixtures deployment. Both sides must report the same status code per
op, the same mutated-on-error flag (the liveness fence) and the same state digest. The status
table and digest layout are in `offchain/oracle/README.md`; `test/differential/OracleStatus.sol`
is the one map from contract errors onto that table.

```sh
(cd offchain && cargo build --release --locked -p bajillion-oracle)
(cd contracts && FOUNDRY_PROFILE=differential forge test --match-contract '^DifferentialTest$')
```

Skipped ops, pinned by `test_Inv10_SkipList`:

| Op | Why |
|---|---|
| `recordDeposit` reusing a deposit id | Not applicable: the contract assigns ids, so `DuplicateDeposit` cannot occur |

The deposit aggregate is one place where the contract is stricter than the crate on purpose.
`register_epoch` can only reject a batch that credits an account more than its unpulled total,
because it keeps no per-deposit amounts (`settlement.rs:1290-1308`), and it leaves the exact
aggregate to the embedding (`settlement.rs:14-16`). The contract checks the exact aggregate
against its inbox hash chain. The oracle, as the embedding, reports both violations as status 1004.
