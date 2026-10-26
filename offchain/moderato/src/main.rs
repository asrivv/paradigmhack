//! Builds the fixture epoch for a live deployment, as its operator and validators would.
//!
//! The crate fixtures (offchain/fixtures) bind absolute times: registration at 100, a signed
//! withdrawal with deadline 400. A chain whose clock reads about 1.76e9 rejects both. This tool
//! rebuilds the same epoch (fixture deployment, accounts, committee, payments and withdrawal
//! amount) for a real clock, using the crate's own functions on a `SettlementChain` configured
//! exactly like the deployed contract:
//!
//! - `epoch --deadline D`: the epoch context and boundary batches to register, with the
//!   withdrawal signed for deadline `D`.
//! - `close --deadline D --registered-at T`: replays the registration at the chain's recorded time
//!   `T`, deals and certifies the close (3 of 4 validators), finalizes one tick after its challenge
//!   deadline, and returns the admission arguments and the payout claim.
//!
//! Output is one JSON object of 0x-hex fields on stdout. Usage, from offchain/:
//! `cargo run --release -p bajillion-moderato -- close --deadline D --registered-at T`.

use bajillion_fixtures::{
    deployment::{Deployment, EPOCH, FIXTURE_SEED, VALIDATORS, acknowledge},
    eip2537, hex,
};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    admission::bls12381,
    boundary::{DepositBatch, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    logs::PayoutOperation,
    payment::SendAuthorization,
    settlement::{EpochDeadlinePolicy, SettlementChain, SettlementConfig},
    transition::{
        CloseLimits, EpochContext, Header, Terminal, WithdrawalClaim, prepare_close_with_strategy,
    },
    vector::{OutEntry, OutVector},
};
use commonware_codec::Encode;
use commonware_cryptography::{
    Sha256, Signer as _,
    bls12381::primitives::{ops::aggregate, variant::MinSig},
    certificate::Signers,
    sha256::Digest,
};
use commonware_cryptography_curve25519::signing::StrictVerifyingKey as Key;
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
use commonware_utils::iter::NonEmpty;
use serde_json::json;
use std::{
    collections::BTreeMap,
    num::{NonZeroU64, NonZeroUsize},
    process::ExitCode,
};

/// Demo settlement policy, matching contracts/script/DeployModerato.s.sol. Demo settings, not
/// production ones: a 30-second challenge window is far too short for real watchers.
pub const ADMISSION_DELAY: u64 = 60;
pub const CHALLENGE_DURATION: u64 = 30;
pub const DEPOSIT_INCLUSION_TIMEOUT: u64 = 300;
pub const MINIMUM_WITHDRAWAL_NOTICE: u64 = 120;
pub const MAXIMUM_WITHDRAWAL_NOTICE: u64 = 3_600;
pub const MAX_DESTINATION_BYTES: usize = 256;
pub const MAX_DEPOSIT_IDS: usize = 1_024;

/// The fixture epoch's payments and withdrawal (offchain/fixtures/src/main.rs).
const PAYMENTS: [(&str, &str, u64); 6] = [
    ("a", "b", 20),
    ("b", "c", 12),
    ("c", "d", 7),
    ("d", "a", 5),
    ("c", "b", 4),
    ("d", "b", 6),
];
const WITHDRAWER: &str = "a";
const WITHDRAWAL_AMOUNT: u64 = 10;
const WITHDRAWAL_DESTINATION: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa1, 0x1c,
];
const SIGNING_VALIDATORS: [usize; 3] = [0, 2, 3];

type Chain = SettlementChain<Sha256, Key>;

fn config() -> SettlementConfig {
    SettlementConfig::new(
        EpochDeadlinePolicy::new(
            NonZeroU64::new(ADMISSION_DELAY).unwrap(),
            NonZeroU64::new(CHALLENGE_DURATION).unwrap(),
        ),
        NonZeroU64::new(DEPOSIT_INCLUSION_TIMEOUT).unwrap(),
        NonZeroU64::new(MINIMUM_WITHDRAWAL_NOTICE).unwrap(),
        NonZeroU64::new(MAXIMUM_WITHDRAWAL_NOTICE).unwrap(),
        MAX_DESTINATION_BYTES,
        NonZeroUsize::new(MAX_DEPOSIT_IDS).unwrap(),
    )
}

/// The registration inputs: the withdrawal signed for `deadline`.
fn boundary(
    fixture: &Deployment,
    deadline: u64,
) -> (
    EpochContext<Key, Digest>,
    DepositBatch<Key>,
    WithdrawalBatch<Key, Digest>,
) {
    let withdrawal = SignedWithdrawal::sign(
        fixture.deployment,
        Bytes::copy_from_slice(&WITHDRAWAL_DESTINATION),
        WithdrawalAction::Amount(NonZeroU64::new(WITHDRAWAL_AMOUNT).unwrap()),
        deadline,
        &fixture.account(WITHDRAWER).signer,
    );
    let deposits = DepositBatch::empty();
    let withdrawals = WithdrawalBatch::new(vec![withdrawal]).unwrap();
    let context = EpochContext::new::<Sha256>(
        fixture.deployment,
        EPOCH,
        fixture.operator.public_key(),
        &deposits,
        &withdrawals,
        CloseLimits::protocol_maximum(),
        fixture.committee.commitment::<Sha256>(),
    )
    .unwrap();
    (context, deposits, withdrawals)
}

fn run(args: &[String]) -> Result<serde_json::Value, String> {
    let flag = |name: &str| -> Option<u64> {
        args.iter()
            .position(|arg| arg == name)
            .and_then(|i| args.get(i + 1))
            .and_then(|value| value.parse().ok())
    };
    let command = args
        .first()
        .ok_or("usage: bajillion-moderato <epoch|close> --deadline D [--registered-at T]")?;
    let deadline = flag("--deadline").ok_or("--deadline is required")?;
    let fixture = Deployment::new(FIXTURE_SEED);
    let (epoch_context, deposits, withdrawals) = boundary(&fixture, deadline);
    let mut out = json!({
        "deployment": hex(fixture.deployment.encode()),
        "operator": hex(fixture.operator.public_key().encode()),
        "epochContext": hex(epoch_context.encode()),
        "depositBatch": hex(deposits.encode()),
        "withdrawalBatch": hex(withdrawals.encode()),
        "withdrawalDeadline": deadline,
    });
    if command == "epoch" {
        return Ok(out);
    }
    if command != "close" {
        return Err(format!("unknown command {command}"));
    }
    let registered_at = flag("--registered-at").ok_or("--registered-at is required for close")?;

    deterministic::Runner::default().start(|context| async move {
        let (replica, genesis) = fixture.genesis(context.child("replica"), "moderato").await;
        let mut chain = Chain::new(
            fixture.deployment,
            fixture.operator.public_key(),
            fixture.committee.clone(),
            &genesis,
            EPOCH,
            config(),
        )
        .map_err(|e| format!("chain: {e:?}"))?;
        chain
            .register_epoch(
                registered_at,
                epoch_context,
                0,
                deposits.clone(),
                withdrawals.clone(),
                |_| true,
            )
            .map_err(|e| format!("register_epoch at {registered_at}: {e:?}"))?;
        let close_context = chain.registered().unwrap().context.clone();

        // The fixture payments, each extending its payer's cumulative vector.
        let mut vectors: BTreeMap<&str, Vec<OutEntry<Key>>> = BTreeMap::new();
        let mut last = BTreeMap::new();
        let mut seqs: BTreeMap<&str, u64> = BTreeMap::new();
        for (from, to, amount) in PAYMENTS {
            let payer = fixture.account(from);
            let recipient = fixture.account(to).key.clone();
            let entries = vectors.entry(from).or_default();
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
            entries.sort_unstable_by(|a, b| a.recipient.cmp(&b.recipient));
            let vector = OutVector::new(EPOCH, payer.key.clone(), entries.clone()).unwrap();
            let debit = vector.totals().unwrap().0;
            let seq = seqs.entry(from).or_default();
            let ack = acknowledge(
                &close_context,
                &payer.signer,
                &fixture.operator,
                &vector,
                *seq,
                debit,
            );
            *seq += 1;
            last.insert(from, ack);
        }
        let mut terminals = fixture
            .accounts
            .iter()
            .filter_map(|payer| {
                let ack = last.get(payer.name)?;
                Some(Terminal {
                    authorization: SendAuthorization::from_raw_unchecked(
                        ack.body().clone(),
                        ack.predecessor(),
                        ack.payer_signature().clone(),
                    ),
                    vector: OutVector::new(EPOCH, payer.key.clone(), vectors[payer.name].clone())
                        .unwrap(),
                })
            })
            .collect::<Vec<_>>();
        terminals.sort_unstable_by(|a, b| {
            a.authorization
                .body()
                .payer()
                .as_ref()
                .cmp(b.authorization.body().payer().as_ref())
        });

        let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &replica,
            &close_context,
            &fixture.operator,
            &deposits,
            &withdrawals,
            terminals,
            &Sequential,
        )
        .await
        .map_err(|e| format!("prepare_close: {e:?}"))?;
        let close = prepared.close();
        let (header, roots, total) = (close.header, close.roots, close.withdrawal_total);
        let certificate = certify(&fixture, &header);

        chain
            .admit(registered_at, header, roots, total, certificate.clone())
            .map_err(|e| format!("admit: {e:?}"))?;
        let finalize_at = close_context.challenge_deadline() + 1;
        chain
            .finalize(finalize_at)
            .map_err(|e| format!("finalize: {e:?}"))?;
        let (replica, _) = prepared
            .apply::<_, Sha256>(replica)
            .await
            .map_err(|e| format!("apply: {e:?}"))?;

        // The one payout: the withdrawal's output, the first append after the bootstrap commit.
        let head = chain.finalized_payouts();
        let (opening, operations) = replica
            .logs()
            .payout_opening(&head, 1, NonZeroU64::MIN)
            .await
            .map_err(|e| format!("payout opening: {e:?}"))?;
        let [PayoutOperation::Append(output)] = operations.as_slice() else {
            return Err("the payout opening holds one append".into());
        };
        let claim = WithdrawalClaim::new(output.clone(), opening);

        let signature = certificate.encode();
        let compressed = &signature[signature.len() - 48..];
        let padded = eip2537::g1(compressed);
        let mut hint = padded[16..64].to_vec();
        hint.extend_from_slice(&padded[80..128]);

        out["registeredAt"] = json!(registered_at);
        out["admissionDeadline"] = json!(close_context.admission_deadline());
        out["challengeDeadline"] = json!(close_context.challenge_deadline());
        out["closeContext"] = json!(hex(close_context.encode()));
        out["header"] = json!(hex(header.encode()));
        out["rootBundle"] = json!(hex(roots.encode()));
        out["withdrawalTotal"] = json!(total);
        out["certificate"] = json!(hex(certificate.encode()));
        out["signatureHint"] = json!(hex(hint));
        out["payoutClaim"] = json!(hex(claim.encode()));
        out["finalizeAfter"] = json!(close_context.challenge_deadline());
        Ok(out)
    })
}

/// A quorum certificate over `header` from the fixture validators in `SIGNING_VALIDATORS`.
fn certify(fixture: &Deployment, header: &Header<Digest>) -> bls12381::Certificate {
    let votes = SIGNING_VALIDATORS
        .iter()
        .map(|index| fixture.signer(*index).sign(header).unwrap())
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

fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match run(&args) {
        Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}
