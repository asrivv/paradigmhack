//! The settlement chain, its embedding ledgers, and the validator replica that builds evidence.

use crate::{Op, Run, kind, status};
use alloy_sol_types::{
    SolType,
    abi::TokenSeq,
    sol_data::{Bytes as AbiBytes, FixedBytes, Uint},
};
use bajillion_fixtures::{
    deployment::{
        Deployment, EPOCH, FIXTURE_SEED, MAX_CHALLENGE_BYTES, MAX_DEPOSIT_IDS,
        MAX_DESTINATION_BYTES, MAXIMUM_WITHDRAWAL_NOTICE, MINIMUM_WITHDRAWAL_NOTICE, VALIDATORS,
        acknowledge, settlement_config,
    },
    storage::FixtureReplica,
};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    admission::bls12381,
    boundary::{DepositBatch, DepositRecord, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    challenge::{AckWitness, Challenge, ChallengeKind},
    commitment::{self, VectorKind, VectorRoot},
    custody::Epoch,
    logs::PayoutOperation,
    payment::{SendAuthorization, VECTOR_SEND_SIGNATURE_NAMESPACE, VectorAck, VectorSendBody},
    qmdb::{StateOpening, account_key},
    settlement::{
        BatchStatus, Bounds, ClaimedRange, HardFaultReason, SettlementChain, SettlementError,
    },
    transition::{
        BatchId, Close, CloseContext, CloseLimits, EpochContext, Header, PreparedClose, RootBundle,
        Terminal, WithdrawalClaim, WithdrawalOutput, prepare_close_with_strategy,
    },
    vector::{OutEntry, OutVector},
};
use commonware_codec::{Copying, Decode, DecodeExt, Encode, RangeCfg};
use commonware_cryptography::{
    Hasher, Sha256, Signer as _,
    bls12381::primitives::{ops::aggregate, variant::MinSig},
    certificate::Signers,
    sha256::Digest,
};
use commonware_cryptography_curve25519::signing::{SigningKey, StrictVerifyingKey as Key};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
use commonware_utils::iter::NonEmpty;
use std::{
    collections::BTreeMap,
    num::NonZeroU64,
    panic::{AssertUnwindSafe, catch_unwind},
};

type Chain = SettlementChain<Sha256, Key>;

/// Maximum proof digests accepted when decoding a balance opening.
const MAX_OPENING_DIGESTS: usize = 256;
/// Maximum records accepted when decoding a deposit or withdrawal batch.
const MAX_BATCH_RECORDS: usize = 1_024;
/// Domain tag that starts the state digest preimage.
pub(crate) const STATE_DIGEST_TAG: &[u8] = b"BAJILLION_ORACLE_STATE_V2";

const BOUNDS: Bounds = Bounds {
    committee: VALIDATORS,
    items: MAX_DEPOSIT_IDS,
    destination: MAX_DESTINATION_BYTES,
};

/// Runs `ops` from genesis and reports every op's outcome and the final state digest.
pub fn run(seed: u64, ops: Vec<Op>) -> Run {
    deterministic::Runner::default().start(|context| async move {
        let mut world = World::new(context, seed).await;
        let mut applied = Vec::with_capacity(ops.len());
        let mut statuses = Vec::with_capacity(ops.len());
        let mut mutated_on_error = Vec::with_capacity(ops.len());
        for (index, op) in ops.into_iter().enumerate() {
            let args = if op.args.is_empty() && takes_args(op.kind) {
                world.materialize(op.kind, index as u64).await
            } else {
                op.args.to_vec()
            };
            let before = world.chain.encode();
            let pruned = observes_time(op.kind).then(|| world.pruned_only());
            let status = world.apply(op.kind, &args).await;
            // `finish_hard_fault_if_drained` (settlement.rs:2064-2082) zeroes the finalized
            // liability, which settlement keeps private; keep the mirror in step.
            if world.chain.hard_fault_is_settled() {
                world.finalized_liability = 0;
            }
            let after = world.chain.encode();
            mutated_on_error.push(
                status != status::OK
                    && after != before
                    && pruned.flatten().is_none_or(|pruned| after != pruned),
            );
            statuses.push(status);
            applied.push(Op {
                kind: op.kind,
                args: args.into(),
            });
        }
        Run {
            ops: applied,
            statuses,
            mutated_on_error,
            state_digest: world.digest(),
        }
    })
}

/// Kinds whose upstream call observes `now` first (`observe_time`, settlement.rs:861-874).
fn observes_time(kind: u8) -> bool {
    kind <= kind::FINALIZE || kind == kind::CLAIM_PENDING_DEPOSIT
}

fn takes_args(kind: u8) -> bool {
    !matches!(
        kind,
        kind::FINALIZE | kind::FAULT_EXPIRED | kind::BEGIN_HARD_FAULT_SETTLEMENT
    )
}

/// Decodes `args` only if they are exactly the canonical ABI encoding of `T`'s parameters.
fn abi<T: SolType>(args: &[u8]) -> Option<T::RustType>
where
    for<'a> T::Token<'a>: TokenSeq<'a>,
{
    let decoded = T::abi_decode_params_validate(args).ok()?;
    (T::abi_encode_params(&decoded) == args).then_some(decoded)
}

/// Decodes a configless crate value that must consume every byte.
fn crate_value<T: DecodeExt<()>>(bytes: &[u8]) -> Option<T> {
    T::decode(Copying(bytes)).ok()
}

fn digest_of(bytes: &[u8]) -> Option<Digest> {
    crate_value(bytes)
}

type RecordDepositArgs = (FixedBytes<32>, FixedBytes<32>, Uint<64>);
type QueueWithdrawalArgs = (AbiBytes, AbiBytes);
type RegisterEpochArgs = (AbiBytes, Uint<64>, AbiBytes, AbiBytes);
type AdmitArgs = (FixedBytes<32>, AbiBytes, Uint<64>, AbiBytes);
type ChallengeArgs = (FixedBytes<32>, AbiBytes);
type ClaimArgs = (AbiBytes,);
type AdvanceTimeArgs = (Uint<64>,);
type AccountArgs = (FixedBytes<32>,);

/// Splitmix64 stream for one op, independent of every other op's choices so that replacing one
/// op's args with concrete bytes never shifts another op's materialization.
struct Pick(u64);

impl Pick {
    fn new(seed: u64, index: u64) -> Self {
        let mut pick = Self(seed ^ index.wrapping_mul(0xd1b5_4a32_d192_ed03));
        pick.next();
        pick
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n` for `n > 0`.
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    /// True with probability `percent / 100`.
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    fn bytes32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_be_bytes());
        }
        out
    }
}

/// An honest close built against the replica, kept until an admission decides its fate.
struct Built {
    header: Header<Digest>,
    prepared: PreparedClose<Key, Digest>,
}

struct World {
    seed: u64,
    fixture: Deployment,
    chain: Chain,
    now: u64,
    /// The embedding's claimed payout ranges, keyed by start.
    claimed: BTreeMap<u64, u64>,
    /// Liability of the finalized state root; settlement keeps it private.
    finalized_liability: u64,
    /// QMDB operation count of the finalized state root, for historical openings.
    finalized_operations: u64,
    /// The embedding's unpulled deposits by inbox index.
    deposits: BTreeMap<u64, (Key, u64)>,
    /// Every deposit id settlement accepted, for duplicate-id evidence.
    deposit_ids: Vec<Digest>,
    /// Validator replica at the admitted head. `None` once an admitted close could not be
    /// followed, after which evidence that needs native proofs falls back to weaker forms.
    replica: Option<FixtureReplica<Sha256>>,
    /// The last admitted close the replica applied; its rows hold payer predecessors.
    last_close: Option<Close<Key, Digest>>,
    built: Option<Built>,
    /// Bound contexts of admitted closes, captured from the frontier at admission.
    admitted: BTreeMap<BatchId<Digest>, CloseContext<Key, Digest>>,
}

impl World {
    async fn new(context: deterministic::Context, seed: u64) -> Self {
        let fixture = Deployment::new(FIXTURE_SEED);
        let (replica, genesis) = fixture.genesis(context.child("replica"), "oracle").await;
        let chain = Chain::new(
            fixture.deployment,
            fixture.operator.public_key(),
            fixture.committee.clone(),
            &genesis,
            EPOCH,
            settlement_config(),
        )
        .expect("the fixtures deployment is valid");
        Self {
            seed,
            chain,
            now: 0,
            claimed: BTreeMap::new(),
            finalized_liability: genesis.liability(),
            finalized_operations: genesis.operations(),
            deposits: BTreeMap::new(),
            deposit_ids: Vec::new(),
            replica: Some(replica),
            last_close: None,
            built: None,
            admitted: BTreeMap::new(),
            fixture,
        }
    }

    // ---------------------------------------------------------------------------------------
    // Application
    // ---------------------------------------------------------------------------------------

    /// The state after observing `now` alone, when that observation only prunes expired
    /// withdrawal replay ids and does not fence. Upstream prunes on every observation, and the
    /// pruned set's only reader is the intake check, which always follows an observation at the
    /// same `now`. A port that treats an id as consumed only while its deadline is later than
    /// `now` answers every check identically without the write, so a failed op whose only change
    /// is that pruning does not count as mutated on error. `None` when the observation fences,
    /// since the fence is then a real mutation.
    fn pruned_only(&self) -> Option<Bytes> {
        let mut copy = Chain::decode_cfg(self.chain.encode(), &BOUNDS)
            .expect("settlement state round-trips through its codec");
        // Observes `now`, then fails decoding the empty challenge without further effect.
        let _ = copy.challenge_encoded(self.now, BatchId::new(Sha256::hash(&[])), &[], 0);
        (copy.hard_fault() == self.chain.hard_fault()).then(|| copy.encode())
    }

    async fn apply(&mut self, kind: u8, args: &[u8]) -> u16 {
        let result = match kind {
            kind::RECORD_DEPOSIT => self.record_deposit(args),
            kind::QUEUE_WITHDRAWAL => self.queue_withdrawal(args),
            kind::REGISTER_EPOCH => self.register_epoch(args),
            kind::ADMIT => self.admit(args).await,
            kind::CHALLENGE => self.challenge(args),
            kind::FINALIZE if args.is_empty() => self.finalize(),
            kind::CLAIM_WITHDRAWAL => self.claim(args),
            kind::FAULT_EXPIRED if args.is_empty() => self
                .chain
                .fault_expired(self.now)
                .map(|_| ())
                .map_err(|error| status::settlement(&error)),
            kind::ADVANCE_TIME => self.advance_time(args),
            kind::BEGIN_HARD_FAULT_SETTLEMENT if args.is_empty() => self
                .chain
                .begin_hard_fault_settlement()
                .map(|_| ())
                .map_err(|error| status::settlement(&error)),
            kind::CLAIM_HARD_FAULT => self.claim_hard_fault(args),
            kind::CLAIM_PENDING_DEPOSIT => self.claim_pending_deposit(args),
            kind::FINALIZE | kind::FAULT_EXPIRED | kind::BEGIN_HARD_FAULT_SETTLEMENT => {
                Err(status::MALFORMED_ARGS)
            }
            _ => Err(status::UNKNOWN_KIND),
        };
        result.err().unwrap_or(status::OK)
    }

    fn record_deposit(&mut self, args: &[u8]) -> Result<(), u16> {
        let (id, account, amount) = abi::<RecordDepositArgs>(args).ok_or(status::MALFORMED_ARGS)?;
        let id = digest_of(id.as_slice()).ok_or(status::MALFORMED_ARGS)?;
        let account: Key = crate_value(account.as_slice()).ok_or(status::MALFORMED_ARGS)?;
        let index = self
            .chain
            .record_deposit(self.now, id, account.clone(), amount)
            .map_err(|error| status::settlement(&error))?;
        self.deposits.insert(index, (account, amount));
        self.deposit_ids.push(id);
        Ok(())
    }

    fn queue_withdrawal(&mut self, args: &[u8]) -> Result<(), u16> {
        let (request, opening) = abi::<QueueWithdrawalArgs>(args).ok_or(status::MALFORMED_ARGS)?;
        let request = SignedWithdrawal::<Key, Digest>::decode_cfg(
            Copying(&request),
            &RangeCfg::new(..=MAX_DESTINATION_BYTES),
        )
        .map_err(|_| status::MALFORMED_ARGS)?;
        let opening =
            StateOpening::<Key, Digest>::decode_cfg(Copying(&opening), &MAX_OPENING_DIGESTS)
                .map_err(|_| status::MALFORMED_ARGS)?;
        self.chain
            .queue_withdrawal(self.now, request, &opening, |_| true)
            .map(|_| ())
            .map_err(|error| status::settlement(&error))
    }

    fn register_epoch(&mut self, args: &[u8]) -> Result<(), u16> {
        let (context, end, deposits, withdrawals) =
            abi::<RegisterEpochArgs>(args).ok_or(status::MALFORMED_ARGS)?;
        let context: EpochContext<Key, Digest> =
            crate_value(&context).ok_or(status::MALFORMED_ARGS)?;
        let deposits = DepositBatch::<Key>::decode_cfg(
            Copying(&deposits),
            &RangeCfg::new(..=MAX_BATCH_RECORDS),
        )
        .map_err(|_| status::MALFORMED_ARGS)?;
        let withdrawals = WithdrawalBatch::<Key, Digest>::decode_cfg(
            Copying(&withdrawals),
            &(
                RangeCfg::new(..=MAX_BATCH_RECORDS),
                RangeCfg::new(..=MAX_DESTINATION_BYTES),
            ),
        )
        .map_err(|_| status::MALFORMED_ARGS)?;
        let pulled = self.chain.pulled();
        // The embedding supplies the aggregate of the pulled prefix (settlement.rs:14-16).
        // Settlement keeps no per-deposit amounts, so it only asserts the batch never exceeds
        // an account's unpulled total; an embedding that stores each deposit must supply it
        // exactly, or a pulled deposit loses its inclusion deadline uncredited.
        let exact = (pulled..=self.chain.intake()).contains(&end)
            && deposits.encode() == self.deposits_between(pulled, end).encode();

        // Upstream panics when a root-consistent deposit batch credits an account more than its
        // unpulled deposits. Run the call on a copy so that caller precondition is reported as a
        // status instead, with nothing (not even the time observation) applied.
        let mut copy = Chain::decode_cfg(self.chain.encode(), &BOUNDS)
            .expect("settlement state round-trips through its codec");
        let now = self.now;
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            copy.register_epoch(now, context, end, deposits, withdrawals, |_| true)
        }));
        std::panic::set_hook(hook);
        let Ok(result) = outcome else {
            return Err(status::PRECONDITION);
        };
        // An inexact batch violates the same precondition from the point where upstream checks
        // the batch against unpulled totals: after every boundary, anchor and intake check, so
        // those errors still win. `EpochOverflow` before that point needs epoch 2^64 - 1; after
        // it, only a carried withdrawal raises it.
        if !exact && !result.as_ref().is_err_and(checked_before_deposits) {
            return Err(status::PRECONDITION);
        }
        self.chain = copy;
        result.map_err(|error| status::settlement(&error))?;
        // The embedding deletes the deposit records the registration pulled.
        self.deposits
            .retain(|index, _| !(pulled..end).contains(index));
        Ok(())
    }

    async fn admit(&mut self, args: &[u8]) -> Result<(), u16> {
        let (header, roots, total, certificate) =
            abi::<AdmitArgs>(args).ok_or(status::MALFORMED_ARGS)?;
        let header: Header<Digest> =
            crate_value(header.as_slice()).ok_or(status::MALFORMED_ARGS)?;
        let roots: RootBundle<Digest> = crate_value(&roots).ok_or(status::MALFORMED_ARGS)?;
        let certificate = bls12381::Certificate::decode_cfg(Copying(&certificate), &VALIDATORS)
            .map_err(|_| status::MALFORMED_ARGS)?;
        let frontier = self
            .chain
            .registered()
            .map(|registered| registered.context.clone());
        let batch_id = self
            .chain
            .admit(self.now, header, roots, total, certificate)
            .map_err(|error| status::settlement(&error))?;
        self.admitted
            .insert(batch_id, frontier.expect("admission requires a frontier"));
        // The replica follows the admitted head only if it built this exact close.
        match (self.built.take(), self.replica.take()) {
            (Some(built), Some(replica)) if built.header == header => {
                match Box::pin(built.prepared.apply::<_, Sha256>(replica)).await {
                    Ok((replica, close)) => {
                        self.replica = Some(replica);
                        self.last_close = Some(close);
                    }
                    Err(_) => self.last_close = None,
                }
            }
            _ => self.last_close = None,
        }
        Ok(())
    }

    fn challenge(&mut self, args: &[u8]) -> Result<(), u16> {
        let (batch_id, challenge) = abi::<ChallengeArgs>(args).ok_or(status::MALFORMED_ARGS)?;
        let batch_id = BatchId::new(digest_of(batch_id.as_slice()).ok_or(status::MALFORMED_ARGS)?);
        self.chain
            .challenge_encoded(self.now, batch_id, &challenge, MAX_CHALLENGE_BYTES)
            .map(|_| ())
            .map_err(|error| status::settlement(&error))
    }

    fn finalize(&mut self) -> Result<(), u16> {
        let front = self
            .chain
            .pending()
            .map(|batch| (batch.successor_liability, batch.roots.successor_operations));
        let (_, commit) = self
            .chain
            .finalize(self.now)
            .map_err(|error| status::settlement(&error))?;
        let (liability, operations) = front.expect("finalization requires a pending close");
        self.finalized_liability = liability;
        self.finalized_operations = operations;
        // The embedding records the trailing Commit as consumed atomically with finalization.
        let neighbors = self.neighbors(commit);
        if let Ok(claimed) = ClaimedRange::insert(commit, &neighbors) {
            self.merge(neighbors, claimed);
        }
        Ok(())
    }

    fn claim(&mut self, args: &[u8]) -> Result<(), u16> {
        let (claim,) = abi::<ClaimArgs>(args).ok_or(status::MALFORMED_ARGS)?;
        let claim = WithdrawalClaim::<Digest>::decode_cfg(
            Copying(&claim),
            &RangeCfg::new(..=MAX_DESTINATION_BYTES),
        )
        .map_err(|_| status::MALFORMED_ARGS)?;
        let neighbors = self.neighbors(claim.position());
        let effect = self
            .chain
            .claim_withdrawal(&neighbors, &claim)
            .map_err(|error| status::claim(&error))?;
        self.merge(neighbors, effect.claimed);
        Ok(())
    }

    fn claim_hard_fault(&mut self, args: &[u8]) -> Result<(), u16> {
        let (opening,) = abi::<ClaimArgs>(args).ok_or(status::MALFORMED_ARGS)?;
        let opening =
            StateOpening::<Key, Digest>::decode_cfg(Copying(&opening), &MAX_OPENING_DIGESTS)
                .map_err(|_| status::MALFORMED_ARGS)?;
        self.chain
            .claim_hard_fault(&opening)
            .map(|_| ())
            .map_err(|error| status::settlement(&error))
    }

    fn claim_pending_deposit(&mut self, args: &[u8]) -> Result<(), u16> {
        let (account,) = abi::<AccountArgs>(args).ok_or(status::MALFORMED_ARGS)?;
        let account: Key = crate_value(account.as_slice()).ok_or(status::MALFORMED_ARGS)?;
        self.chain
            .claim_pending_deposit(self.now, &account)
            .map(|_| ())
            .map_err(|error| status::settlement(&error))
    }

    fn advance_time(&mut self, args: &[u8]) -> Result<(), u16> {
        let (delta,) = abi::<AdvanceTimeArgs>(args).ok_or(status::MALFORMED_ARGS)?;
        self.now = self.now.checked_add(delta).ok_or(status::CLOCK_OVERFLOW)?;
        Ok(())
    }

    /// The claimed range at or before `index` and the first one strictly after it.
    fn neighbors(&self, index: u64) -> [Option<ClaimedRange>; 2] {
        let before = self
            .claimed
            .range(..=index)
            .next_back()
            .map(|(&start, &end)| ClaimedRange { start, end });
        let after = self
            .claimed
            .range(index.saturating_add(1)..)
            .next()
            .filter(|(start, _)| **start > index)
            .map(|(&start, &end)| ClaimedRange { start, end });
        [before, after]
    }

    /// Applies a merged range: drop a successor it absorbed, then upsert it.
    fn merge(&mut self, neighbors: [Option<ClaimedRange>; 2], claimed: ClaimedRange) {
        if let Some(after) = neighbors[1]
            && claimed.end == after.end
        {
            self.claimed.remove(&after.start);
        }
        self.claimed.insert(claimed.start, claimed.end);
    }

    // ---------------------------------------------------------------------------------------
    // Materialization
    // ---------------------------------------------------------------------------------------

    async fn materialize(&mut self, kind: u8, index: u64) -> Vec<u8> {
        let mut pick = Pick::new(self.seed, index);
        match kind {
            kind::RECORD_DEPOSIT => self.make_deposit(&mut pick),
            kind::QUEUE_WITHDRAWAL => self.make_withdrawal(&mut pick).await,
            kind::REGISTER_EPOCH => self.make_registration(&mut pick),
            kind::ADMIT => self.make_admission(&mut pick).await,
            kind::CHALLENGE => self.make_challenge(&mut pick).await,
            kind::CLAIM_WITHDRAWAL => self.make_claim(&mut pick).await,
            kind::CLAIM_HARD_FAULT => self.make_hard_fault_claim(&mut pick).await,
            kind::CLAIM_PENDING_DEPOSIT => {
                let account: [u8; 32] = self
                    .signer(&mut pick, 20)
                    .public_key()
                    .encode()
                    .as_ref()
                    .try_into()
                    .unwrap();
                AccountArgs::abi_encode_params(&(account,))
            }
            kind::ADVANCE_TIME => {
                const DELTAS: [u64; 11] = [1, 1, 2, 5, 9, 10, 11, 20, 31, 60, 150];
                AdvanceTimeArgs::abi_encode_params(&(DELTAS[pick.below(11) as usize],))
            }
            // Unknown kinds keep empty args and are rejected when applied.
            _ => Vec::new(),
        }
    }

    /// A fixture account, or with `percent` chance a fresh key with no genesis balance.
    fn signer(&self, pick: &mut Pick, percent: u64) -> SigningKey {
        if pick.chance(percent) {
            SigningKey::from_seed(1_000_000 + pick.below(8))
        } else {
            let index = pick.below(self.fixture.accounts.len() as u64) as usize;
            self.fixture.accounts[index].signer.clone()
        }
    }

    fn make_deposit(&self, pick: &mut Pick) -> Vec<u8> {
        let id = if !self.deposit_ids.is_empty() && pick.chance(15) {
            self.deposit_ids[pick.below(self.deposit_ids.len() as u64) as usize]
        } else {
            Sha256::hash(&[b"oracle-deposit", &pick.bytes32()])
        };
        let account = self.signer(pick, 20).public_key();
        let amount = if pick.chance(10) {
            0
        } else {
            1 + pick.below(50)
        };
        let account: [u8; 32] = account.encode().as_ref().try_into().unwrap();
        RecordDepositArgs::abi_encode_params(&(
            <[u8; 32]>::try_from(id.as_ref()).unwrap(),
            account,
            amount,
        ))
    }

    /// A balance opening for `account` at the finalized root, if the replica can serve one.
    async fn opening(&self, account: &Key) -> Option<StateOpening<Key, Digest>> {
        self.replica
            .as_ref()?
            .state()
            .opening_at(
                self.chain.current_state_root(),
                self.finalized_operations,
                account.clone(),
            )
            .await
            .ok()
    }

    async fn make_withdrawal(&self, pick: &mut Pick) -> Vec<u8> {
        let signer = self.signer(pick, 10);
        let account = signer.public_key();
        // An absent account has no opening; present another account's to exercise the
        // account binding check.
        let mut opening = self.opening(&account).await;
        if opening.is_none() || pick.chance(5) {
            let other = &self.fixture.accounts[pick.below(4) as usize].key;
            opening = self.opening(other).await.or(opening);
        }
        let balance = opening.as_ref().map_or(50, |opening| opening.balance.get());
        // Amounts and notices land on both sides of each bound, and on the bound itself.
        let amount = match pick.below(20) {
            0..=2 => balance,
            3 => balance + 1,
            _ => 1 + pick.below(balance + 10),
        };
        let action = if pick.chance(25) {
            WithdrawalAction::Close
        } else {
            WithdrawalAction::Amount(NonZeroU64::new(amount.max(1)).unwrap())
        };
        let notice = match pick.below(20) {
            0 | 1 => MINIMUM_WITHDRAWAL_NOTICE - 1,
            2 | 3 => MAXIMUM_WITHDRAWAL_NOTICE + 1,
            4 => MINIMUM_WITHDRAWAL_NOTICE,
            5 => MAXIMUM_WITHDRAWAL_NOTICE,
            _ => {
                MINIMUM_WITHDRAWAL_NOTICE
                    + pick.below(MAXIMUM_WITHDRAWAL_NOTICE - MINIMUM_WITHDRAWAL_NOTICE + 1)
            }
        };
        let deployment = if pick.chance(5) {
            Sha256::hash(&[b"oracle-foreign-deployment"])
        } else {
            self.fixture.deployment
        };
        let request = SignedWithdrawal::<Key, Digest>::sign(
            deployment,
            Bytes::copy_from_slice(&pick.bytes32()[..20]),
            action,
            self.now.saturating_add(notice),
            &signer,
        );
        let opening = opening.map_or_else(|| vec![0u8], |opening| opening.encode().to_vec());
        QueueWithdrawalArgs::abi_encode_params(&(request.encode().to_vec(), opening))
    }

    fn make_registration(&self, pick: &mut Pick) -> Vec<u8> {
        let epoch = self.chain.next_registration_epoch().unwrap_or(u64::MAX);
        let (pulled, intake) = (self.chain.pulled(), self.chain.intake());
        let mut end = if pick.chance(70) {
            intake
        } else {
            pulled + pick.below(intake - pulled + 1)
        };
        let deposits = self.deposits_between(pulled, end);
        let mut requests = self.chain.pending_withdrawals(end).requests().to_vec();
        if pick.chance(20) {
            // An operator-carried extra for an account with no unfinalized withdrawal.
            let signer = &self.fixture.accounts[pick.below(4) as usize].signer;
            let account = signer.public_key();
            if self
                .chain
                .unfinalized_withdrawal_deadline(&account)
                .is_none()
                && !requests.iter().any(|request| request.account() == &account)
            {
                requests.push(SignedWithdrawal::sign(
                    self.fixture.deployment,
                    Bytes::copy_from_slice(&pick.bytes32()[..20]),
                    WithdrawalAction::Amount(NonZeroU64::new(1 + pick.below(20)).unwrap()),
                    self.now.saturating_add(MAXIMUM_WITHDRAWAL_NOTICE / 2),
                    signer,
                ));
            }
        }
        let withdrawals =
            WithdrawalBatch::new(requests).unwrap_or_else(|_| WithdrawalBatch::empty());

        let mut context_epoch = epoch;
        let mut committee = self.fixture.committee.commitment::<Sha256>();
        let mut context_deposits = deposits.clone();
        match pick.below(20) {
            0 => context_epoch = epoch.wrapping_add(1),
            1 => end = intake + 1,
            2 => {
                let account = self.fixture.accounts[0].key.clone();
                context_deposits =
                    DepositBatch::new(vec![DepositRecord::new(account, 1).unwrap()]).unwrap();
            }
            3 => committee = Sha256::hash(&[b"oracle-foreign-committee"]),
            _ => {}
        }
        let context = EpochContext::new::<Sha256>(
            self.fixture.deployment,
            context_epoch,
            self.fixture.operator.public_key(),
            &context_deposits,
            &withdrawals,
            CloseLimits::protocol_maximum(),
            committee,
        )
        .or_else(|_| {
            EpochContext::new::<Sha256>(
                self.fixture.deployment,
                context_epoch,
                self.fixture.operator.public_key(),
                &DepositBatch::empty(),
                &WithdrawalBatch::empty(),
                CloseLimits::protocol_maximum(),
                committee,
            )
        })
        .expect("empty boundaries always form a context");
        RegisterEpochArgs::abi_encode_params(&(
            context.encode().to_vec(),
            end,
            deposits.encode().to_vec(),
            withdrawals.encode().to_vec(),
        ))
    }

    /// The per-account aggregate of the stored deposits at inbox indices `start..end`.
    fn deposits_between(&self, start: u64, end: u64) -> DepositBatch<Key> {
        let mut totals = BTreeMap::<Vec<u8>, (Key, u64)>::new();
        for (account, amount) in self.deposits.range(start..end.max(start)).map(|(_, d)| d) {
            let entry = totals
                .entry(account.encode().to_vec())
                .or_insert((account.clone(), 0));
            entry.1 = entry.1.saturating_add(*amount);
        }
        DepositBatch::new(
            totals
                .into_values()
                .filter_map(|(account, amount)| DepositRecord::new(account, amount).ok())
                .collect(),
        )
        .unwrap_or_else(|_| DepositBatch::empty())
    }

    /// The payer's terminal vector root in the last admitted close, or the empty root.
    fn predecessor(&self, payer: &Key) -> VectorRoot<Digest> {
        self.last_close
            .as_ref()
            .and_then(|close| {
                close
                    .activity_input::<Sha256>()
                    .rows()
                    .iter()
                    .find(|row| row.account() == payer)
                    .map(|row| row.send_root())
            })
            .unwrap_or_else(|| commitment::empty_root::<Sha256>(VectorKind::OutEntry))
    }

    /// Seed-chosen payments among fixture accounts, each payer debiting at most half its
    /// predecessor balance so every honest close is spendable.
    async fn terminals(
        &self,
        pick: &mut Pick,
        context: &CloseContext<Key, Digest>,
    ) -> Vec<Terminal<Key, Digest>> {
        let Some(replica) = self.replica.as_ref() else {
            return Vec::new();
        };
        let epoch = context.payment().epoch();
        let mut budgets = BTreeMap::new();
        for (index, account) in self.fixture.accounts.iter().enumerate() {
            let key = account_key(&account.key).unwrap();
            let balance = replica
                .state()
                .get(&key)
                .await
                .ok()
                .flatten()
                .map_or(0, NonZeroU64::get);
            budgets.insert(index, balance / 2);
        }
        let mut vectors: BTreeMap<usize, Vec<OutEntry<Key>>> = BTreeMap::new();
        for _ in 0..pick.below(4) {
            let payer = pick.below(4) as usize;
            let recipient = (payer + 1 + pick.below(3) as usize) % 4;
            let budget = budgets.get_mut(&payer).unwrap();
            if *budget == 0 {
                continue;
            }
            let amount = 1 + pick.below((*budget).min(8));
            *budget -= amount;
            let recipient = self.fixture.accounts[recipient].key.clone();
            let entries = vectors.entry(payer).or_default();
            match entries
                .iter_mut()
                .find(|entry| entry.recipient == recipient)
            {
                Some(entry) => {
                    entry.cumulative += amount;
                    entry.count += 1;
                }
                None => entries.push(OutEntry {
                    recipient,
                    cumulative: amount,
                    count: 1,
                }),
            }
        }
        let mut terminals = Vec::new();
        for (payer, mut entries) in vectors {
            let account = &self.fixture.accounts[payer];
            entries.sort_unstable_by(|a, b| a.recipient.cmp(&b.recipient));
            let Ok(vector) = OutVector::new(epoch, account.key.clone(), entries) else {
                continue;
            };
            let (Ok(root), Ok((debit, _))) = (vector.root::<Sha256, Digest>(), vector.totals())
            else {
                continue;
            };
            let ack = VectorAck::sign_by_authorities(
                VectorSendBody::new(context.payment(), account.key.clone(), 0, debit, root),
                self.predecessor(&account.key),
                &account.signer,
                &self.fixture.operator,
            );
            terminals.push(Terminal {
                authorization: SendAuthorization::from_raw_unchecked(
                    ack.body().clone(),
                    ack.predecessor(),
                    ack.payer_signature().clone(),
                ),
                vector,
            });
        }
        terminals.sort_unstable_by(|a, b| {
            a.authorization
                .body()
                .payer()
                .as_ref()
                .cmp(b.authorization.body().payer().as_ref())
        });
        terminals
    }

    /// Builds the frontier's close against the replica, if both exist and agree.
    async fn build_close(&self, pick: &mut Pick) -> Option<PreparedClose<Key, Digest>> {
        let registered = self.chain.registered()?;
        let replica = self.replica.as_ref()?;
        if replica.state().root() != *registered.context.predecessor_root() {
            return None;
        }
        let context = registered.context.clone();
        let deposits = registered.deposits.clone();
        let withdrawals = registered.withdrawals.clone();
        let terminals = self.terminals(pick, &context).await;
        for terminals in [terminals, Vec::new()] {
            if let Ok(prepared) = prepare_close_with_strategy::<Sha256, _, _, _, _>(
                replica,
                &context,
                &self.fixture.operator,
                &deposits,
                &withdrawals,
                terminals,
                &Sequential,
            )
            .await
            {
                return Some(prepared);
            }
        }
        None
    }

    /// A certificate over `header` from the committee members at `indices`, assembled without
    /// the quorum check so undersized sets can be produced as evidence.
    fn certificate(&self, header: &Header<Digest>, indices: &[usize]) -> bls12381::Certificate {
        let votes = indices
            .iter()
            .map(|index| self.fixture.signer(*index).sign(header).unwrap())
            .collect::<Vec<_>>();
        let signatures = votes
            .iter()
            .map(|vote| *vote.signature.get().unwrap())
            .collect::<Vec<_>>();
        bls12381::Certificate {
            signers: Signers::new(VALIDATORS as u32, votes.iter().map(|vote| vote.signer)).unwrap(),
            signature: aggregate::combine_signatures::<MinSig, _>(
                NonEmpty::try_new(signatures.iter()).unwrap(),
            )
            .into(),
        }
    }

    /// A random subset of the committee of the given size, in canonical order.
    fn subset(pick: &mut Pick, size: usize) -> Vec<usize> {
        let mut indices = (0..VALIDATORS).collect::<Vec<_>>();
        for i in (1..VALIDATORS).rev() {
            indices.swap(i, pick.below(i as u64 + 1) as usize);
        }
        indices.truncate(size);
        indices.sort_unstable();
        indices
    }

    async fn make_admission(&mut self, pick: &mut Pick) -> Vec<u8> {
        let (header, roots, mut total, signed) = match self.build_close(pick).await {
            Some(prepared) => {
                let close = prepared.close();
                let (header, roots, total) = (close.header, close.roots, close.withdrawal_total);
                self.built = Some(Built { header, prepared });
                (header, roots, total, header)
            }
            None => {
                let header = Header::decode(Sha256::hash(&[b"oracle-dummy-header"]).encode())
                    .expect("a digest is a header");
                (header, dummy_roots(), 0, header)
            }
        };
        let (signed, signers) = match pick.below(20) {
            // One signer is below the f + 1 quorum.
            0 | 1 => (signed, Self::subset(pick, 1)),
            // A quorum over a different header.
            2 | 3 => {
                let other = Header::decode(
                    Sha256::hash(&[b"oracle-other", header.digest().as_ref()]).encode(),
                )
                .expect("a digest is a header");
                (other, Self::subset(pick, 3))
            }
            // The certified header no longer matches the claimed withdrawal total.
            4 | 5 => {
                total = total.wrapping_add(1);
                (signed, Self::subset(pick, 3))
            }
            _ => {
                let size = 2 + pick.below(3) as usize;
                (signed, Self::subset(pick, size))
            }
        };
        let certificate = self.certificate(&signed, &signers);
        AdmitArgs::abi_encode_params(&(
            <[u8; 32]>::try_from(header.encode().as_ref()).unwrap(),
            roots.encode().to_vec(),
            total,
            certificate.encode().to_vec(),
        ))
    }

    /// A pair of operator-countersigned acknowledgments for one payer and sequence.
    fn fork(
        &self,
        context: &CloseContext<Key, Digest>,
        payer: &SigningKey,
        pick: &mut Pick,
    ) -> (VectorAck<Key, Digest>, VectorAck<Key, Digest>) {
        let seq = pick.below(3);
        let recipient = self.fixture.accounts[0].key.clone();
        let ack = |debit: u64| {
            let vector = OutVector::new(
                context.payment().epoch(),
                payer.public_key(),
                vec![OutEntry {
                    recipient: recipient.clone(),
                    cumulative: debit,
                    count: 1,
                }],
            )
            .unwrap();
            acknowledge(context, payer, &self.fixture.operator, &vector, seq, debit)
        };
        (ack(1), ack(2))
    }

    async fn make_challenge(&self, pick: &mut Pick) -> Vec<u8> {
        let batches = self
            .chain
            .pending_batches()
            .map(|batch| (batch.header.batch_id::<Sha256>(), batch.roots))
            .collect::<Vec<_>>();
        let target = (!batches.is_empty() && !pick.chance(10))
            .then(|| batches[pick.below(batches.len() as u64) as usize]);
        let batch_id = target.map_or_else(
            || BatchId::new(Sha256::hash(&[b"oracle-bogus-batch", &pick.bytes32()])),
            |(batch_id, _)| batch_id,
        );
        let encode = |challenge: Vec<u8>| {
            ChallengeArgs::abi_encode_params(&(
                <[u8; 32]>::try_from(batch_id.encode().as_ref()).unwrap(),
                challenge,
            ))
        };
        let Some(context) = self.admitted.get(&batch_id) else {
            return encode(vec![3]);
        };
        let phantom = SigningKey::from_seed(2_000_000 + pick.below(8));
        let challenge = match pick.below(10) {
            0..=2 => {
                let (left, right) = self.fork(context, &phantom, pick);
                Some(Challenge::AckFork {
                    left: Box::new(AckWitness::from_ack(&left)),
                    right: Box::new(AckWitness::from_ack(&right)),
                })
            }
            3 => {
                let (left, _) = self.fork(context, &phantom, pick);
                Some(Challenge::AckFork {
                    left: Box::new(AckWitness::from_ack(&left)),
                    right: Box::new(AckWitness::from_ack(&left)),
                })
            }
            4..=6 => {
                let signer = self.signer(pick, 50);
                let (_, roots) = target.unwrap();
                self.higher_ack_debit(context, &roots, &signer, true).await
            }
            7 => {
                self.higher_ack_debit(context, &target.unwrap().1, &phantom, false)
                    .await
            }
            8 => {
                let (left, right) = self.fork(context, &phantom, pick);
                let mut right = AckWitness::from_ack(&right);
                let send = VectorSendBody::new(
                    context.payment(),
                    right.payer.clone(),
                    right.seq,
                    right.cumulative_debit,
                    right.send_root,
                );
                let mut message = send.encode().to_vec();
                message.extend_from_slice(&right.predecessor.encode());
                right.operator_signature = self
                    .fixture
                    .operator
                    .sign(VECTOR_SEND_SIGNATURE_NAMESPACE, &message);
                Some(Challenge::AckFork {
                    left: Box::new(AckWitness::from_ack(&left)),
                    right: Box::new(right),
                })
            }
            _ => return encode(pick.bytes32()[..1 + pick.below(32) as usize].to_vec()),
        };
        // Without native proofs, HigherAckDebit evidence falls back to a proven fork.
        let challenge = challenge.unwrap_or_else(|| {
            let (left, right) = self.fork(context, &phantom, pick);
            Challenge::AckFork {
                left: Box::new(AckWitness::from_ack(&left)),
                right: Box::new(AckWitness::from_ack(&right)),
            }
        });
        encode(challenge.encode().to_vec())
    }

    /// A HigherAckDebit challenge from `payer`: above its public terminal debit when `higher`,
    /// otherwise a zero-debit acknowledgment that contradicts nothing.
    async fn higher_ack_debit(
        &self,
        context: &CloseContext<Key, Digest>,
        roots: &RootBundle<Digest>,
        payer: &SigningKey,
        higher: bool,
    ) -> Option<Challenge<Key, Digest>> {
        let logs = self.replica.as_ref()?.logs();
        let range = roots.activity_range(context).ok()?;
        let epoch = Epoch::at(logs, context.payment().epoch(), range)
            .await
            .ok()?;
        let account = payer.public_key();
        let lookup = epoch.account_lookup(logs, &account).await.ok()?;
        let (terminal, _) = lookup.resolve::<Sha256>(&range, &account).ok()?;
        let (debit, seq, vector) = if higher {
            let debit = terminal.checked_add(1)?;
            let vector = OutVector::new(
                context.payment().epoch(),
                account.clone(),
                vec![OutEntry {
                    recipient: self.fixture.accounts[0].key.clone(),
                    cumulative: debit,
                    count: 1,
                }],
            )
            .ok()?;
            (debit, 1_000, vector)
        } else {
            (
                0,
                0,
                OutVector::empty(context.payment().epoch(), account.clone()),
            )
        };
        let ack = acknowledge(context, payer, &self.fixture.operator, &vector, seq, debit);
        Some(Challenge::HigherAckDebit {
            ack: Box::new(AckWitness::from_ack(&ack)),
            payer: Box::new(lookup),
        })
    }

    /// A balance opening at the finalized (after terminal settlement starts, the frozen) root,
    /// sometimes for an account with no balance, which falls back to another account's opening.
    async fn make_hard_fault_claim(&self, pick: &mut Pick) -> Vec<u8> {
        let account = self.signer(pick, 15).public_key();
        let mut opening = self.opening(&account).await;
        if opening.is_none() {
            let other = &self.fixture.accounts[pick.below(4) as usize].key;
            opening = self.opening(other).await;
        }
        let opening = opening.map_or_else(|| vec![0u8], |opening| opening.encode().to_vec());
        ClaimArgs::abi_encode_params(&(opening,))
    }

    async fn make_claim(&self, pick: &mut Pick) -> Vec<u8> {
        let encode = |claim: Vec<u8>| ClaimArgs::abi_encode_params(&(claim,));
        let Some(replica) = self.replica.as_ref() else {
            return encode(vec![0]);
        };
        let head = self.chain.finalized_payouts();
        let mut outputs = Vec::new();
        for position in 1..head.operations.saturating_sub(1) {
            if let Ok((opening, operations)) = replica
                .logs()
                .payout_opening(&head, position, NonZeroU64::MIN)
                .await
                && let [PayoutOperation::Append(output)] = operations.as_slice()
            {
                outputs.push(WithdrawalClaim::new(output.clone(), opening));
            }
        }
        if !outputs.is_empty() {
            let claim = outputs.swap_remove(pick.below(outputs.len() as u64) as usize);
            let mut bytes = claim.encode().to_vec();
            if pick.chance(15) {
                // Raise the amount: the last 8 bytes of the output precede the opening.
                let amount_end = claim.output().encode().len();
                bytes[amount_end - 1] = bytes[amount_end - 1].wrapping_add(1);
            }
            return encode(bytes);
        }
        // No payout yet: claim the genesis Commit location, which is never claimable.
        let output = WithdrawalOutput::decode_cfg(Copying(&[0u8; 9]), &RangeCfg::new(..=0))
            .expect("an empty destination and zero amount decode");
        match replica
            .logs()
            .payout_opening(&head, 0, NonZeroU64::MIN)
            .await
        {
            Ok((opening, _)) => encode(WithdrawalClaim::new(output, opening).encode().to_vec()),
            Err(_) => encode(vec![0]),
        }
    }

    // ---------------------------------------------------------------------------------------
    // State digest
    // ---------------------------------------------------------------------------------------

    /// SHA-256 over the canonical observable state documented in README.md.
    fn digest(&self) -> [u8; 32] {
        let chain = &self.chain;
        let mut out = STATE_DIGEST_TAG.to_vec();
        let u64 = |out: &mut Vec<u8>, value: u64| out.extend_from_slice(&value.to_be_bytes());
        u64(&mut out, self.now);
        u64(
            &mut out,
            chain.next_registration_epoch().unwrap_or(u64::MAX),
        );
        u64(&mut out, chain.next_admission_epoch().unwrap_or(u64::MAX));
        u64(&mut out, chain.expected_epoch());
        u64(&mut out, chain.intake());
        u64(&mut out, chain.pulled());
        match chain.registered() {
            Some(registered) => {
                let context = registered.context;
                out.push(1);
                u64(&mut out, context.payment().epoch());
                out.extend_from_slice(context.payment().anchor().as_ref());
                u64(&mut out, context.admission_deadline());
                u64(&mut out, context.challenge_deadline());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&(chain.pending_epoch_count() as u32).to_be_bytes());
        for batch in chain.pending_batches() {
            out.extend_from_slice(batch.header.batch_id::<Sha256>().digest().as_ref());
            let (code, kind) = match &batch.status {
                BatchStatus::Pending => (0, None),
                BatchStatus::Challenged(kind) => (1, Some(*kind)),
                BatchStatus::Invalidated(_) => (2, None),
            };
            out.push(code);
            out.push(kind.map_or(0, kind_code));
            u64(&mut out, batch.withdrawal_total);
            u64(&mut out, batch.successor_liability);
        }
        let logs = chain.finalized_logs();
        for head in [logs.activity, logs.payouts] {
            out.extend_from_slice(head.root.as_ref());
            u64(&mut out, head.operations);
            u64(&mut out, head.floor);
        }
        out.extend_from_slice(chain.current_state_root().encode().as_ref());
        out.extend_from_slice(&(self.claimed.len() as u32).to_be_bytes());
        for (start, end) in &self.claimed {
            u64(&mut out, *start);
            u64(&mut out, *end);
        }
        u64(&mut out, chain.custody_balance());
        u64(&mut out, chain.claimable_balance());
        u64(&mut out, self.finalized_liability);
        let (reason, expired_at) = match chain.hard_fault() {
            None => (0, 0),
            Some(HardFaultReason::ProvenChallenge { .. }) => (1, 0),
            Some(HardFaultReason::ExpiredDeposit { expired_at, .. }) => (2, *expired_at),
            Some(HardFaultReason::ExpiredWithdrawal { expired_at, .. }) => (3, *expired_at),
            Some(HardFaultReason::ExpiredRegistration { expired_at, .. }) => (4, *expired_at),
        };
        out.push(reason);
        u64(&mut out, expired_at);
        out.push(u8::from(chain.admission_fence_epoch().is_some()));
        u64(&mut out, chain.admission_fence_epoch().unwrap_or(0));
        out.push(u8::from(chain.invalid_from().is_some()));
        out.extend_from_slice(
            &chain
                .invalid_from()
                .map_or([0u8; 32], |id| id.digest().as_ref().try_into().unwrap()),
        );
        // Terminal settlement: started (claims open, including after they drain) and settled.
        out.push(u8::from(chain.hard_fault_settlement_started()));
        out.push(u8::from(chain.hard_fault_is_settled()));
        Sha256::hash(&[&out]).as_ref().try_into().unwrap()
    }
}

/// Whether `register_epoch` returns `error` before it compares the deposit batch with unpulled
/// totals (settlement.rs:1263-1288).
fn checked_before_deposits(error: &SettlementError) -> bool {
    matches!(
        error,
        SettlementError::OperatorHardFaulted
            | SettlementError::Deployment
            | SettlementError::OperatorMismatch
            | SettlementError::EpochSequence
            | SettlementError::EpochOverflow
            | SettlementError::CommitteeMismatch
            | SettlementError::IntakeRange
            | SettlementError::BoundaryRoot
            | SettlementError::Commitment(_)
            | SettlementError::Transition(_)
    )
}

fn kind_code(kind: ChallengeKind) -> u8 {
    match kind {
        ChallengeKind::HigherAckDebit => 1,
        ChallengeKind::HigherAckEntry => 2,
        ChallengeKind::AckFork => 3,
    }
}

/// A well-formed root bundle that commits nothing, used when no close can be built.
fn dummy_roots() -> RootBundle<Digest> {
    // Each log head is a zero root with one operation (its bootstrap Commit) and floor zero.
    let head = [
        [0u8; 32].as_slice(),
        &1u64.to_be_bytes(),
        &0u64.to_be_bytes(),
    ]
    .concat();
    let bytes = [
        head.as_slice(),
        &0u64.to_be_bytes(), // row_count
        &head,
        &[0u8; 32],          // successor state root
        &1u64.to_be_bytes(), // successor_operations
        &0u64.to_be_bytes(), // successor_sync_boundary
        &[0u8; 32],          // proposal
    ]
    .concat();
    RootBundle::decode(Copying(&bytes)).expect("dummy roots decode")
}
