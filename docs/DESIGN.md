# Settling Bajillion on Tempo

An independent integration of Bajillion, the clearing protocol designed by Patrick O'Grady at
Commonware ([commonware.xyz/blogs/clearing](https://commonware.xyz/blogs/clearing), crate
`commonware-clearing`). The protocol and the clearing crate are theirs. This note describes the
Tempo settlement contract we wrote for it: what it ports, where it deviates and why, how it is
tested, and what it costs. Every claim cites the code, a test, or a measurement script.

Upstream is pinned at `commonwarexyz/monorepo` `dd6d60cb44fb3dc05cee1efa06d957ce30df1340`. The
crate labels Bajillion ALPHA (`clearing/README.md:17`), so its API and wire format can change;
everything below is relative to that commit.

## 1. The problem

A payer that pays many services through payment channels locks capital in one channel per
service. Bajillion nets many-to-many payments instead. Within an epoch, an operator acknowledges
each payment with a countersigned receipt, and at the end of the epoch it deals a close: the new
account balances, a log of every account's activity, and the withdrawals to pay. A committee of
validators re-executes the close against its own copy of the state and certifies it with a
BLS12-381 MinSig quorum certificate. A settlement chain admits certified closes in order, gives
receipt holders a window to prove a contradiction, and then finalizes.

`commonware-clearing` implements that state machine as `SettlementChain`
(`clearing/src/bajillion/settlement.rs`), an in-memory, runtime-agnostic primitive. Its module
documentation is explicit about what it leaves to the embedding: an authenticated monotonic clock,
atomic persistence of each mutation together with its asset effects, deposit storage, and the
claimed-payout map (`settlement.rs:3-17`). Nobody had published a settlement layer for it. This
project is one: a Solidity port of `SettlementChain` for Tempo, where custody is a TIP-20
stablecoin (pathUSD on the Moderato testnet).

## 2. What was ported

`contracts/src/BajillionSettlement.sol` ports the public surface of `SettlementChain`, method by
method, with each function citing the Rust lines it follows and the Rust error order preserved:

- **Deposits**: `deposit` (`record_deposit`), with inclusion deadlines run-length encoded as
  upstream does.
- **Withdrawals**: `queueWithdrawal` (`queue_withdrawal`), including the intake battery, the
  balance opening at the finalized root, replay ids, and one unfinalized withdrawal per account.
- **Registration**: `registerEpoch`, with deposit and withdrawal boundaries, the anchor check,
  operator-carried extras, supersession of chain-queued requests, and the rule that a carried
  withdrawal's deadline falls after the earliest tick its close could finalize.
- **Admission**: `admit`, which recomputes the header from the bound `CloseContext`, verifies
  the certificate, and validates the close's amounts, log ranges and successor liability
  (`validate_header`, `validate_close_amounts`).
- **Challenges**: `challenge` (`challenge_encoded`), adjudicating `AckFork` and `HigherAckDebit`.
  A proven challenge marks the close challenged, every later pending close invalidated, and
  hard-faults the deployment.
- **Finalization**: `finalize`, strictly FIFO and only after the inclusive challenge window.
- **Payouts**: `claimWithdrawal` (`claim_withdrawal`), against the finalized payout log, with the
  claimed-range map.
- **Liveness**: `faultExpired` and the observation every time-taking method performs first
  (`observe_time`), with upstream's tie-breaks between expired deposits, withdrawals and
  registrations.
- **Terminal settlement**: `beginHardFaultSettlement`, `claimHardFault` and
  `claimPendingDeposit`. Settlement freezes the last finalized root and drains the admitted
  pipeline; each account then recovers once, and unadmitted deposits refund.

Not ported: the `HigherAckEntry` challenge (it decodes and is rejected with
`ChallengeKindUnsupported`). This is the contradiction a service needs when the operator drops a
payment to it, so it is the first item in section 9.

The proof verifiers come from commonware-sol, Commonware's Solidity library, at the same commit:
`LibQMDBCommon` and `LibQMDBKeylessMMR` for payout and activity openings, `LibQMDBCurrentMMB` for
balance openings, and `LibBLS12381Multisig` for certificates. SHA-256 is the precompile at
`address(2)` everywhere, matching the crate's reference hasher.

## 3. Deliberate deviations

Each of these is a choice the crate leaves to the embedding, or a gap between the crate and the
EVM. `docs/protocol-notes.md` sections 6 and 7 list them with line references; the reasons are
summarized here.

**Errors cannot always revert.** Every time-taking upstream method first observes expired
deadlines, and that observation can permanently fence the deployment even when the requested
operation then fails (`settlement.rs:3-12`). A revert would discard the fence. So once a call has
written the fence, the contract returns a `Status` and emits the error's selector instead of
reverting. When nothing was written it reverts with the custom error for the same Rust variant.

**Deposit ids.** Upstream takes an external deposit id and rejects duplicates. The contract is the
deposit source, so the inbox index is the id and `DuplicateDeposit` cannot occur.

**The exact deposit aggregate.** Upstream keeps no per-deposit amounts, so `register_epoch` can
only reject a deposit batch that credits an account more than its unpulled total; a batch that
credits less would leave pulled deposits uncredited and without an inclusion deadline
(`settlement.rs:1225-1227`). The crate assigns the exact aggregate to the embedding
(`settlement.rs:14-16`). The contract keeps a hash chain over its inbox and requires the
registration's witness to reproduce it, so it checks equality.

**Replay ids expire lazily.** Upstream prunes withdrawal replay ids whose deadline has passed every
time it observes time. Their only reader is the intake check, which always follows an observation
at the same `now`, so "consumed while the deadline is later than `now`" answers every check the
same way without the pruning writes.

**Storage witnesses instead of storage.** Tempo charges 250,000 gas for each new storage slot. The
contract stores roots and digests and takes the bytes they bind as calldata: the committee's G2
keys (against a stored keccak256), the target's `CloseContext` and `RootBundle` for a challenge
(against the stored batch id), the admitted deposit batches and the account's withdrawal request
for terminal claims (against stored roots and digests), and the predecessor in the sorted
claimed-range and pending-withdrawal lists (checked in O(1)). Every such witness was published
earlier as calldata, so it adds no data-availability assumption beyond chain history.

**Recovered amounts are credits.** Upstream returns deposit refunds and state residuals "directly
to the account", which is an Ed25519 key, not a Tempo address. The contract credits them to the
clearing account, and `sweepRecovered` pays the credit to an address the account signs for, over
`deployment || recipient || nonce`. Upstream's `claim_pending_deposit` stays permissionless. A
signed withdrawal already names a 20-byte destination and is paid there directly. This is our
addition.

**Destinations.** Eligible withdrawal destinations are exactly 20 bytes, one Tempo address.

**Bounded queues.** Registrations and admitted closes live in a 64-epoch ring; upstream bounds
neither.

**Clock.** `block.timestamp`, in seconds.

**Size.** EIP-170 limits deployed code to 24,576 bytes. The settlement compiles alone at 200
optimizer runs, and its stateful halves (withdrawal bookkeeping, claimed ranges, terminal
settlement, the deadline scan, challenge lookup) are linked libraries whose external functions
run by DELEGATECALL on state in the settlement's storage. The deployment keeps one address and
one storage. The contract is 24,385 bytes, enforced by `test/SettlementSize.t.sol`. The verifier
libraries compile at 1,000,000 runs, as commonware-sol does.

**No bond.** `SettlementChain` has no bond and slashes nothing; a proven challenge fences the
deployment and moves it to terminal settlement. The contract escrows a bond outside custody
accounting, and nothing reads it. Section 6 discusses what that means.

## 4. BLS: hint and recompress

The crate encodes a MinSig certificate's aggregate signature as a 48-byte compressed G1 point and
committee keys as 96-byte compressed G2 points (protocol-notes section 1). commonware-sol's
verifiers take uncompressed points (`LibBLS12381.sol:30`), and decompressing on chain needs a
square root in Fp, or in Fp2 for G2.

The contract does not decompress. `admit` takes the crate's exact certificate bytes plus an
uncompressed hint, and `LibBLS12381Point` checks that the hint compresses back to those bytes: the
same x coordinate, and the sign flag set exactly when y is the larger root, in the ZCash and blst
encoding the crate uses. The pairing precompile then rejects any point that is off the curve or
outside the subgroup. The crate's bytes stay authoritative, and recompressing costs a comparison.
A wrong hint cannot change what is verified: either it recompresses to the certified bytes, in
which case it is the unique point with that encoding, or the call fails.

Committee keys get the same treatment at construction, together with a proof of possession for
each key. commonware-sol has no proof-of-possession verifier and fixes its hash-to-curve DST to
the signature one, so `LibBLS12381PoP` copies its hash-to-curve with the `BLS_POP_` DST, as the
crate requires (`admission/certificate.rs:39-42`).

## 5. Ed25519: ZIP215, and why strict verification would be unsafe

Clearing accounts, payer acknowledgments, operator countersignatures and withdrawal
authorizations are Ed25519. The crate verifies them with ZIP215 rules
(`cryptography/curve25519/src/signing.rs:350-401`): the scalar `s` must be canonical, `R` and the
public key `A` may be non-canonical encodings of curve points, and the equation is cofactored,
`[8](sB - R - kA) = 0`, with `k` hashed over the raw bytes. Account keys are additionally
`StrictVerifyingKey`s: canonical, non-identity, prime order.

The EVM has no Ed25519 precompile, and the maintained Solidity libraries implement cofactorless
RFC 8032 verification with canonical `R`. That is stricter than the crate, and stricter is unsafe
here. A challenge is evidence: an operator-countersigned acknowledgment that contradicts what the
close certified. Receipt holders and validators verify countersignatures with the crate's rules.
If the contract were stricter, a dishonest operator could countersign with a signature that every
crate verifier accepts, for example with a small-order component in `R` or a non-canonical `R`
encoding, and the contract would reject the proof built from it. The receipt holder would hold
evidence that is valid everywhere except where it matters, and the fraud would finalize. A more
lenient contract has the mirror problem in the other direction. The only safe choice is exact
parity.

`contracts/src/verify/LibEd25519.sol` is our port of those rules, using complete twisted-Edwards
formulas and the vendored SHA-512 from SCL. It reproduces the ed25519-speccheck ZIP215 verdicts,
verifies all 18 crate signatures in the fixtures over their exact signed bytes, and the TypeScript
payment method checks the same rules against the crate's own Wycheproof and ZIP215 vectors. One
verification costs 949,348 gas and one strict-key check 327,584 (`bench/ed25519.md`, local).

## 6. Threat model

| Party | Assumed | If violated |
|---|---|---|
| Operator | nothing | a fork or a payer-side debit omission is provable by a receipt holder; the challenge invalidates the close and its descendants and hard-faults the deployment |
| Validator committee | at least one of the q = f + 1 signers is honest and keeps the close's data | a certified close may have no honest holder of its data, so the openings needed for challenges and terminal claims may be unavailable |
| Receipt holders | at least one honest holder per relied-on receipt is online before the challenge deadline | unchallenged fraud finalizes |
| Tempo | live, and includes a challenge before its deadline | censoring a challenge for the window defeats it |

**What a certificate proves.** A q = f + 1 certificate shows that at least one honest validator
re-executed the close against its own state and kept the data (`admission/certificate.rs:63-67`).
It proves the close is internally valid. It cannot prove the close is complete: an operator can
sign a receipt and leave the payment out of the close, and no validator can know. That is what
challenges are for. The crate also notes that certificates do not establish a unique close.

**Windows.** A challenge is accepted while `now <= challengeDeadline` and rejected one second
later; finalization needs `now > challengeDeadline`. The window is a deployment parameter. The
Moderato deployment uses 30 seconds, a demo setting chosen so the demo finalizes in minutes; a
real deployment must size it for watcher latency and for Tempo's inclusion guarantees.

**If the operator and every validator collude.** They can certify a close that omits payments or
misreports balances, and if no receipt holder challenges in time, it finalizes and becomes the
state everything else recovers from. Receipt holders can still prove forks and debit omissions in
the window. After any hard fault, unadmitted deposits refund from data on chain alone, finalized
payouts stay claimable, and each account recovers its balance at the last finalized root. That
recovery needs a balance opening, which needs someone to serve the state; with every validator and
the operator withholding data, deposits and finalized payouts remain recoverable, balances do not.

**Economic security.** None yet. Upstream has no bond or slashing, and the contract's escrowed
bond has no destination. A proven fraud costs the operator its deployment, nothing more. Deciding
the bond's size, recipient and evidence is open (section 9).

## 7. How it is tested

Three layers, all against the pinned crate's own output.

**Conformance.** `offchain/fixtures` runs the crate to produce one complete epoch from the
Bajillion blog's 4-account example: the committee and its proofs of possession, the epoch context,
every acknowledgment, the dealing, the certificate, the payout opening, six challenges, and the
balance openings and sweep signature terminal settlement needs. That is 38 files plus a manifest
of every hash preimage. `contracts/test/Conformance.t.sol` and the challenge tests require the
contract to accept every valid fixture byte for byte, reach the crate's verdict on every
challenge, and reject every mutation of every field.

**Differential.** `offchain/oracle` wraps the real `SettlementChain`, configured like the
fixtures deployment, behind a `vm.ffi` binary. `contracts/test/Differential.t.sol` generates
seed-chosen sequences over all twelve operation kinds, has the oracle materialize them into real
crate bytes (closes it deals against its own validator replica, certificates, challenges,
openings), replays the same bytes through the contract, and requires three things to match: every
operation's status code, whether each failing operation still changed state (the liveness fence),
and a SHA-256 digest of the observable state after the run. The default run is 1,000 seeds, and
the latest 1,000-seed survey covered 38,900 operations with zero mismatches.

The harness has found three divergences, and in all three the contract was right:

- The oracle accepted a registration whose deposit batch credited less than it pulled, which the
  crate cannot detect and the contract rejects (section 3).
- The oracle counted a failed call that only pruned replay ids as a state change (section 3).
- The oracle's mirror of the finalized liability did not reset when terminal settlement drained,
  while the crate and the contract both zero it.

Each fix has a regression seed that fails without it. To check that the harness can see bugs at
all, planted bugs were run through it: removing the opening-account check, an off-by-one in the
balance check, and an off-by-one in the notice window first failed at seeds 0, 10 and 0. The
balance case went unseen in 100 seeds until the oracle was changed to choose amounts exactly at the
bound.

**Invariants.** Each of SPEC.md's ten invariants has named tests (`test_Inv01_*` through
`test_Inv10_*`), plus three stateful invariant tests over fuzzed claim orders: each payout index
pays at most once, claimed ranges stay disjoint and bounded, and the reserve never goes negative.
The differential harness also asserts on every run that the contract's token balance equals
active custody, plus the claim reserve, plus unswept recovery credits.

**On chain.** Before admitting on Moderato, the deployment script requires the contract's
`frontierContext()` to equal the crate's `CloseContext` byte for byte, so the header the committee
certified is the one the contract recomputes. After deployment, `verify()` checks every library's
on-chain code against its linked 1,000,000-run artifact.

## 8. Measured cost on Tempo

The contract runs on Tempo Moderato at `0x78F12F6Fbc6d5b5BdC249cb59dAe541fDBee81a9`
(`deployments/moderato.json`). The fixture epoch ran end to end on it. `bench/gas.md` sets every
receipt beside the same transactions replayed on a local node with the standard Ethereum schedule:

| Step | Local gas | Moderato gas |
|---|---|---|
| Deploy 11 libraries and the settlement | 24,279,137 | 115,386,355 |
| `registerEpoch` (one carried withdrawal) | 1,481,379 | 3,779,029 |
| `admit` (3-of-4 certificate) | 483,985 | 2,328,112 |
| `finalize` | 176,756 | 869,356 |
| `claimWithdrawal` (to a new account) | 127,756 | 356,117 |

Tempo charges 250,000 gas per new storage slot, 250,000 per new account, and 1,000 per byte of
deployed code, against 20,000, zero and 200 on Ethereum, and caps a transaction at 30M gas.
Computation costs the same on both. Two consequences follow. Storage, not cryptography, dominates
per-epoch cost on Tempo, which is why the contract stores roots and takes witnesses. And code size
is a deployment constraint on Tempo, not only an EIP-170 one: the settlement's deployment uses
28,057,414 gas, 93.5 percent of the cap, of which about 24.4M is the code deposit.

A proven challenge costs 2.3M to 3.0M gas locally (`bench/ed25519.md`), within one transaction.

## 9. Limitations

- **`HigherAckEntry` is not ported.** A service whose payment the operator dropped from a close
  cannot yet prove it on chain. This is the most important missing piece, because it is the fraud
  a paid service is best placed to catch.
- **No economic security.** There is no bond logic and no slashing (section 6).
- **No real watcher.** Data availability for challenges and terminal claims rests on validators
  and the operator serving openings, and nothing in this repository yet fetches them, checks
  every receipt, or submits challenges automatically.
- **Demo parameters.** The Moderato deployment's 30-second window and 60-second admission delay
  suit a demo only.
- **Gas.** One Ed25519 verification costs about 0.95M gas, and registering an operator-carried
  withdrawal or queueing one pays for at least one.
- **Deposits to invalid keys.** `deposit` accepts any 32-byte account, while the crate's account
  type admits only strict Ed25519 keys. Funds deposited to an invalid key can be refunded to its
  credit but never swept, since nobody can sign for it.
- **Not measured on Moderato.** Deposits, queued withdrawals, challenges and terminal settlement
  did not run on the live deployment, because each would fault it. Their costs are local only.
- **Upstream is ALPHA.** A change to the crate's wire format at a later commit invalidates the
  conformance fixtures and the port's decoders together; the pin is deliberate.

## 10. Upstream findings

Two findings are drafted for Commonware, not yet filed, each with a test as evidence.

**Account keys are silently 32 bytes.** `SettlementChain` accepts any `P: PublicKey`, and the same
crate ships 33-byte secp256r1 keys, but `qmdb::account_key` (`qmdb.rs:621-625`) converts the key's
encoding into `[u8; 32]` and rejects every other width with `Error::AccountKey`. A secp256r1
deployment type-checks and constructs, then fails at its first balance opening or dealing.
`offchain/upstream/tests/account_key.rs` shows it. A bound or a construction-time check would turn
this into an early error.

**BLS precompile calls forward all gas.** commonware-sol calls the EIP-2537 precompiles with
`staticcall(gas(), ...)` (`LibBLS12381.sol:161`, `:226`, `:228`, `:230`, `:250`), and a
precompile that rejects its input consumes everything it was given. A certificate with one byte of
its signature hint changed burns 29,074,255 of 30,000,000 forwarded gas before failing, against
386,305 for a valid one (`contracts/test/UpstreamFindings.t.sol`). Forwarding each precompile's
fixed cost would make failures cheap and gas predictable.

Smaller gaps in commonware-sol that every clearing embedding will meet: no proof-of-possession
verifier, verifiers that take uncompressed points while the crate emits compressed ones, and no
Ed25519 verifier with the crate's ZIP215 rules.
