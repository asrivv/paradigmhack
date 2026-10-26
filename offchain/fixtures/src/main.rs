//! Generates the Bajillion settlement fixtures for the EVM contract tests.
//!
//! One fixed seed drives a single 4-account epoch through the upstream clearing crate exactly as
//! an operator, a 4-validator committee, and the settlement chain would: payments are
//! acknowledged, the operator deals the close, validators seal and vote, the certificate is
//! admitted, two kinds of challenge evidence are adjudicated, the close finalizes, and one payout
//! is claimed. Every byte string the contract must reproduce or verify is written to
//! `contracts/test/fixtures/` and indexed by `manifest.json`.
//!
//! Usage: `cargo run -p bajillion-fixtures [output-dir]`.

use bajillion_fixtures::{
    deployment::{
        ACCOUNTS, ADMISSION_DELAY, CHALLENGE_DURATION, DEPOSIT_INCLUSION_TIMEOUT, Deployment,
        EPOCH, FIXTURE_SEED, MAX_CHALLENGE_BYTES, MAX_DEPOSIT_IDS, MAX_DESTINATION_BYTES,
        MAXIMUM_WITHDRAWAL_NOTICE, MINIMUM_WITHDRAWAL_NOTICE, VALIDATOR_KEY_DST, VALIDATORS,
        acknowledge, settlement_config,
    },
    eip2537, hex,
    trace::{Hashed, TracingSha256, record},
};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    admission::{COMMITTEE_HASH_NAMESPACE, HEADER_NAMESPACE, Vote, bls12381, seal},
    boundary::{
        DepositBatch, SignedWithdrawal, WITHDRAWAL_ID_HASH_NAMESPACE,
        WITHDRAWAL_SIGNATURE_NAMESPACE, WithdrawalAction, WithdrawalBatch,
    },
    challenge::{AccountLookup, AckWitness, Challenge, ChallengeKind, Verdict, adjudicate},
    commitment::VectorRoot,
    custody::Epoch,
    payment::{
        SendAuthorization, VECTOR_ACK_SIGNATURE_NAMESPACE, VECTOR_SEND_SIGNATURE_NAMESPACE,
        VectorAck, VectorSendBody,
    },
    qmdb::{StateOpening, account_key},
    settlement::{Bounds, ClaimedRange, SettlementChain},
    transition::{
        BATCH_ID_HASH_NAMESPACE, CloseLimits, EPOCH_ANCHOR_HASH_NAMESPACE, EpochContext,
        HEADER_ROOT_HASH_NAMESPACE, Header, ProposalId, TERMINAL_BATCH_HASH_NAMESPACE,
        TERMINAL_BATCH_SIGNATURE_NAMESPACE, Terminal, WithdrawalClaim, prepare_dealing,
    },
    vector::{OutEntry, OutVector},
};
use commonware_codec::{Decode as _, DecodeExt as _, Encode, FixedSize as _};
use commonware_cryptography::{
    Hasher, Sha256, Signer as _,
    bls12381::primitives::{
        group::{G1, G2},
        ops::{
            aggregate, compute_public, hash_with_namespace, sign_proof_of_possession,
            verify_proof_of_possession,
        },
        variant::{MinSig, Variant},
    },
    sha256::Digest,
};
use commonware_cryptography_curve25519::signing::{
    BatchVerifier, Signature, StrictVerifyingKey as Key,
};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
use commonware_utils::{TestRng, iter::NonEmpty, union_unique};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    num::NonZeroU64,
    path::{Path, PathBuf},
};

const UPSTREAM_REPOSITORY: &str = "https://github.com/commonwarexyz/monorepo";
const UPSTREAM_REV: &str = "dd6d60cb44fb3dc05cee1efa06d957ce30df1340";
const UPSTREAM_REF: &str = "refs/pull/4664/head";

/// Payments in acceptance order. Each payment is its own acknowledged batch, so a payer with two
/// payments ends the epoch at sequence 1.
const PAYMENTS: [(&str, &str, u64); 6] = [
    ("a", "b", 20),
    ("b", "c", 12),
    ("c", "d", 7),
    ("d", "a", 5),
    ("c", "b", 4),
    ("d", "b", 6),
];
/// Expected balances after the epoch, computed by hand from the table above and the withdrawal
/// below, never from the crate's own derivation.
const EXPECTED_FINAL: [(&str, u64); 4] = [("a", 75), ("b", 58), ("c", 26), ("d", 31)];

// A payout claim needs a withdrawal output, and the payments alone produce none. Account `a`
// therefore also withdraws a fixed amount to a 20-byte EVM address in the same epoch.
const WITHDRAWER: &str = "a";
const WITHDRAWAL_AMOUNT: u64 = 10;
const WITHDRAWAL_DESTINATION: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xa1, 0x1c,
];

/// Settlement timing in abstract chain ticks (block heights on Tempo).
const REGISTER_AT: u64 = 100;
const ADMIT_AT: u64 = 105;
const ADMISSION_DEADLINE: u64 = REGISTER_AT + ADMISSION_DELAY;
const CHALLENGE_DEADLINE: u64 = ADMISSION_DEADLINE + CHALLENGE_DURATION;
/// Finalization requires a time strictly after the challenge deadline.
const FINALIZE_AT: u64 = CHALLENGE_DEADLINE + 1;
const WITHDRAWAL_DEADLINE: u64 = 400;
/// Namespace of BajillionSettlement's recovery sweep authorization (our embedding, not the
/// crate's): the account signs `deployment || recipient || u64 nonce`.
const RECOVERY_SWEEP_NAMESPACE: &[u8] = b"_PARADIGMHACK_BAJILLION_RECOVERY";
/// Recipient of the sample sweep authorization.
const RECOVERY_RECIPIENT: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa1, 0xa1,
];

/// Committee indices whose votes form the certificate. Three of four is the terminal example's
/// consensus quorum (the crate itself accepts f + 1 = 2), and skipping index 1 makes the signer
/// bitmap non-contiguous.
const SIGNING_VALIDATORS: [usize; 3] = [0, 2, 3];

/// Upstream leaves proof-of-possession checks to the embedding and defines no namespace for
/// them, so the fixture fixes one. The contract must use the same bytes.
const POP_NAMESPACE: &[u8] = b"_PARADIGMHACK_BAJILLION_VALIDATOR_POP";
/// Inline literal in `ProposalId::for_dealing`; upstream exports no constant for it.
const PROPOSAL_ID_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_PROPOSAL_ID";

/// The payer whose acknowledgments back the challenge evidence.
const CHALLENGED_PAYER: &str = "c";

type Chain = SettlementChain<TracingSha256, Key>;

/// Collects fixture files and the manifest while the scenario runs.
#[derive(Default)]
struct Output {
    files: BTreeMap<String, Vec<u8>>,
    entries: serde_json::Map<String, Value>,
    hashes: serde_json::Map<String, Value>,
    traces: serde_json::Map<String, Value>,
    ed25519: Vec<Value>,
}

impl Output {
    /// Registers a crate-encoded value as `<name>.hex`.
    fn file(&mut self, name: &str, kind: &str, description: &str, bytes: impl AsRef<[u8]>) {
        let bytes = bytes.as_ref().to_vec();
        let file = format!("{name}.hex");
        self.entries.insert(
            name.to_string(),
            json!({
                "file": file,
                "type": kind,
                "bytes": bytes.len(),
                "description": description,
            }),
        );
        assert!(self.files.insert(file, bytes).is_none(), "duplicate {name}");
    }

    /// Records a hash the contract recomputes, checking the assembled preimage against the
    /// crate's own digest.
    fn hash(&mut self, name: &str, parts: &[(&str, &[u8])], digest: &Digest, description: &str) {
        let preimage = parts.iter().flat_map(|(_, part)| part.iter().copied());
        let preimage = preimage.collect::<Vec<_>>();
        assert_eq!(Sha256::hash(&[&preimage]), *digest, "{name} preimage");
        let file = format!("{name}_preimage.hex");
        self.hashes.insert(
            name.to_string(),
            json!({
                "algorithm": "sha256",
                "description": description,
                "parts": parts
                    .iter()
                    .map(|(label, part)| json!({ "label": label, "hex": hex(part) }))
                    .collect::<Vec<_>>(),
                "preimage_file": file,
                "digest": hex(digest),
            }),
        );
        assert!(
            self.files.insert(file, preimage).is_none(),
            "duplicate {name}"
        );
    }

    /// Stores the ordered SHA-256 trace of one crate operation.
    fn trace(&mut self, name: &str, description: &str, trace: &[Hashed]) {
        let calls = trace
            .iter()
            .map(|hashed| {
                json!({
                    "parts": hashed.parts.iter().map(hex).collect::<Vec<_>>(),
                    "preimage": hex(hashed.preimage()),
                    "digest": hex(hashed.digest),
                })
            })
            .collect::<Vec<_>>();
        self.traces.insert(
            name.to_string(),
            json!({ "description": description, "calls": calls }),
        );
    }

    /// Records one ed25519 signature after checking it against the claimed message.
    fn ed25519(
        &mut self,
        label: &str,
        signer: &str,
        key: &Key,
        namespace: &[u8],
        message: &[u8],
        signature: &Signature,
    ) {
        assert!(
            key.verify(namespace, message, signature),
            "{label} verifies"
        );
        self.ed25519.push(json!({
            "label": label,
            "signer": signer,
            "public_key": hex(key.encode()),
            "namespace": hex(namespace),
            "message": hex(message),
            "signed_bytes": hex(union_unique(namespace, message)),
            "signature": hex(signature.encode()),
        }));
    }
}

/// The message every ed25519 signature over a send covers: the body then the predecessor.
fn send_message(body: &VectorSendBody<Key, Digest>, predecessor: &VectorRoot<Digest>) -> Vec<u8> {
    let mut message = body.encode().to_vec();
    message.extend_from_slice(&predecessor.encode());
    message
}

fn bls_point(compressed: &[u8]) -> Value {
    let eip = match compressed.len() {
        eip2537::G1_COMPRESSED => eip2537::g1(compressed).to_vec(),
        eip2537::G2_COMPRESSED => eip2537::g2(compressed).to_vec(),
        length => panic!("not a compressed BLS point: {length} bytes"),
    };
    json!({ "compressed": hex(compressed), "eip2537": hex(eip) })
}

fn negated_g2_generator() -> [u8; eip2537::G2_COMPRESSED] {
    let mut out = [0u8; eip2537::G2_COMPRESSED];
    // SAFETY: blst returns a valid static generator; `out` holds the 96 bytes blst writes.
    unsafe {
        let mut point = *blst::blst_p2_generator();
        blst::blst_p2_cneg(&mut point, true);
        blst::blst_p2_compress(out.as_mut_ptr(), &point);
    }
    out
}

fn verdict_name(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Proven(kind) => format!("Proven({kind:?})"),
        Verdict::NoContradiction => "NoContradiction".to_string(),
    }
}

fn main() {
    let output_dir = std::env::args().nth(1).map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/test/fixtures"),
        PathBuf::from,
    );
    let (out, manifest) = deterministic::Runner::default().start(generate);
    write(&output_dir, &out, manifest);
}

#[allow(clippy::too_many_lines)]
async fn generate(runtime: deterministic::Context) -> (Output, Value) {
    let mut out = Output::default();
    let mut rng = TestRng::new(FIXTURE_SEED);

    let fixture = Deployment::new(FIXTURE_SEED);
    let operator = &fixture.operator;
    let accounts = &fixture.accounts;
    let validators = &fixture.validators;
    let committee = &fixture.committee;
    let committee_commitment = committee.commitment::<Sha256>();
    let deployment = fixture.deployment;

    // Genesis state shared by the operator, every validator, and the settlement chain.
    let (replica, genesis) = fixture.genesis(runtime.child("replica"), "replica").await;
    let config = settlement_config();
    let (chain, new_trace) = record(|| {
        Chain::new(
            deployment,
            operator.public_key(),
            committee.clone(),
            &genesis,
            EPOCH,
            config,
        )
    });
    let mut chain = chain.unwrap();

    // Terminal settlement claims open account balances against a frozen root; when nothing has
    // finalized, that root is genesis. One opening per account, checked by the crate.
    for account in accounts.iter() {
        let opening: StateOpening<Key, Digest> = replica
            .state()
            .opening_at(genesis.root(), genesis.operations(), account.key.clone())
            .await
            .unwrap();
        assert!(opening.verify::<Sha256>(&genesis.root()).is_ok());
        out.file(
            &format!("state_opening_{}_genesis", account.name),
            "qmdb::StateOpening<StrictVerifyingKey, sha256::Digest>",
            "The account's balance opening at the genesis state root: account, u64 balance, then \
             the current ordered QMDB membership proof over the MMB.",
            opening.encode(),
        );
    }
    let sweeper = fixture.account(WITHDRAWER);
    let mut sweep = deployment.as_ref().to_vec();
    sweep.extend_from_slice(&RECOVERY_RECIPIENT);
    sweep.extend_from_slice(&0u64.to_be_bytes());
    out.file(
        "recovery_sweep_signature",
        "curve25519::Signature",
        "Account a's signature over union_unique(RECOVERY_SWEEP_NAMESPACE, deployment || \
         recipient || u64 nonce 0) for BajillionSettlement.sweepRecovered.",
        sweeper
            .signer
            .sign(RECOVERY_SWEEP_NAMESPACE, &sweep)
            .encode(),
    );
    out.trace(
        "settlement_new",
        "SettlementChain::new: commits the committee once for the deployment.",
        &new_trace,
    );

    // Registration: an empty deposit boundary and one operator-carried withdrawal.
    let withdrawer = fixture.account(WITHDRAWER);
    let withdrawal = SignedWithdrawal::sign(
        deployment,
        Bytes::copy_from_slice(&WITHDRAWAL_DESTINATION),
        WithdrawalAction::Amount(NonZeroU64::new(WITHDRAWAL_AMOUNT).unwrap()),
        WITHDRAWAL_DEADLINE,
        &withdrawer.signer,
    );
    let deposits = DepositBatch::empty();
    let withdrawals = WithdrawalBatch::new(vec![withdrawal.clone()]).unwrap();
    let epoch_context = EpochContext::new::<Sha256>(
        deployment,
        EPOCH,
        operator.public_key(),
        &deposits,
        &withdrawals,
        CloseLimits::protocol_maximum(),
        committee_commitment,
    )
    .unwrap();
    let (registered, register_trace) = record(|| {
        chain.register_epoch(
            REGISTER_AT,
            epoch_context.clone(),
            0,
            deposits.clone(),
            withdrawals.clone(),
            |_| true,
        )
    });
    registered.unwrap();
    out.trace(
        "register_epoch",
        "SettlementChain::register_epoch at REGISTER_AT: boundary roots, anchor, and withdrawal \
         intake.",
        &register_trace,
    );
    let context = chain.registered().unwrap().context.clone();
    // Validators bind the same registration against their own replica; both bindings must agree.
    let validator_context = epoch_context
        .clone()
        .bind::<Sha256, _, _>(
            &replica,
            &deposits,
            &withdrawals,
            0..0,
            genesis.liability(),
            ADMISSION_DEADLINE,
            CHALLENGE_DEADLINE,
            chain.registration_floors(),
        )
        .unwrap();
    assert_eq!(validator_context, context);

    // Payments. Each one is an acknowledged batch extending its payer's cumulative vector.
    let mut vectors: BTreeMap<&str, Vec<OutEntry<Key>>> = BTreeMap::new();
    let mut acks: BTreeMap<&str, Vec<VectorAck<Key, Digest>>> = BTreeMap::new();
    let mut payment_records = Vec::new();
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
        let history = acks.entry(from).or_default();
        let seq = history.len() as u64;
        let ack = acknowledge(&context, &payer.signer, operator, &vector, seq, debit);
        ack.verify(context.payment()).unwrap();
        let message = send_message(ack.body(), &ack.predecessor());
        let label = format!("ack_{from}_seq{seq}");
        out.ed25519(
            &format!("{label}_payer"),
            from,
            &payer.key,
            VECTOR_SEND_SIGNATURE_NAMESPACE,
            &message,
            ack.payer_signature(),
        );
        out.ed25519(
            &format!("{label}_operator"),
            "operator",
            &operator.public_key(),
            VECTOR_ACK_SIGNATURE_NAMESPACE,
            &message,
            ack.operator_signature(),
        );
        out.file(
            &label,
            "VectorAck<StrictVerifyingKey, sha256::Digest>",
            &format!("Dual-signed acknowledgment after payment {from}->{to} {amount}."),
            ack.encode(),
        );
        payment_records.push(json!({
            "from": from,
            "to": to,
            "amount": amount,
            "seq": seq,
            "cumulative_debit": debit,
            "ack": label,
        }));
        history.push(ack);
    }

    // Terminal endpoints, in the strictly increasing payer-byte order the dealing requires.
    let mut terminals = accounts
        .iter()
        .filter_map(|payer| {
            let ack = acks.get(payer.name)?.last()?;
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

    // The operator deals the close.
    let (dealing, dealing_trace) = record(|| {
        prepare_dealing::<TracingSha256, Key, Digest>(
            context.epoch_context(),
            operator,
            &deposits,
            &withdrawals,
            terminals.clone(),
        )
    });
    let dealing = dealing.unwrap();
    out.trace(
        "prepare_dealing",
        "transition::prepare_dealing: payer vector roots and the terminal batch digest the \
         operator signs.",
        &dealing_trace,
    );
    let terminal_batch = dealing_trace
        .iter()
        .find(|hashed| {
            hashed.parts.first().map(Vec::as_slice) == Some(TERMINAL_BATCH_HASH_NAMESPACE)
        })
        .expect("the dealing hashes its terminal batch")
        .clone();
    let terminal_parts = terminal_batch
        .parts
        .iter()
        .enumerate()
        .map(|(index, part)| {
            let label = match index {
                0 => "TERMINAL_BATCH_HASH_NAMESPACE".to_string(),
                1 => "EpochContext.encode()".to_string(),
                n => format!(
                    "terminal[{}]: VectorSendBody.encode() || predecessor",
                    n - 2
                ),
            };
            (label, part.as_slice())
        })
        .collect::<Vec<_>>();
    out.hash(
        "terminal_batch_digest",
        &terminal_parts
            .iter()
            .map(|(label, part)| (label.as_str(), *part))
            .collect::<Vec<_>>(),
        &terminal_batch.digest,
        "Digest the operator signs over the epoch context and ordered terminal messages.",
    );
    // Ed25519 is deterministic, so re-signing reproduces the signature embedded in the dealing.
    let batch_signature = operator.sign(
        TERMINAL_BATCH_SIGNATURE_NAMESPACE,
        terminal_batch.digest.as_ref(),
    );
    assert!(
        dealing
            .encoded()
            .windows(Signature::SIZE)
            .any(|window| window == batch_signature.encode().as_ref()),
        "the dealing carries the terminal batch signature"
    );
    out.ed25519(
        "terminal_batch_operator",
        "operator",
        &operator.public_key(),
        TERMINAL_BATCH_SIGNATURE_NAMESPACE,
        terminal_batch.digest.as_ref(),
        &batch_signature,
    );
    let encoded = dealing.encoded().clone();

    // Each signing validator seals the dealing against its replica and votes.
    let mut prepared = None;
    let mut votes: Vec<Vote> = Vec::new();
    for index in SIGNING_VALIDATORS {
        let scheme = bls12381::Scheme::signer(committee.clone(), validators[index].1.clone())
            .expect("validator is in the committee");
        assert_eq!(usize::from(scheme.me().unwrap()), index);
        let (vote, sealed) = seal::<Sha256, _, _, _, _, BatchVerifier, _>(
            &scheme,
            &replica,
            &context,
            &deposits,
            &withdrawals,
            encoded.clone(),
            &mut rng,
            &Sequential,
        )
        .await
        .expect("an honest dealing seals");
        if let Some(first) = &prepared {
            let first: &commonware_clearing::bajillion::transition::PreparedClose<Key, Digest> =
                first;
            assert_eq!(first.close().header, sealed.close().header);
        } else {
            prepared = Some(sealed);
        }
        votes.push(vote);
    }
    let prepared = prepared.unwrap();
    let close = prepared.close().clone();
    let header = close.header;
    let roots = close.roots;
    let withdrawal_total = close.withdrawal_total;
    assert_eq!(withdrawal_total, WITHDRAWAL_AMOUNT);
    assert_eq!(
        header,
        Header::new::<Sha256, Key>(&context, &roots, withdrawal_total)
    );
    assert_eq!(
        roots.proposal,
        ProposalId::for_dealing::<Sha256, Key>(context.epoch_context(), &encoded)
    );

    let verifier = bls12381::Scheme::verifier(committee.clone());
    for vote in &votes {
        assert!(verifier.verify_vote(&header, vote), "vote verifies");
    }
    let certificate = verifier.assemble(votes.clone()).unwrap();
    assert!(verifier.verify(&header, &certificate));

    // Admission.
    let (batch_id, admit_trace) = record(|| {
        chain.admit(
            ADMIT_AT,
            header,
            roots,
            withdrawal_total,
            certificate.clone(),
        )
    });
    let batch_id = batch_id.unwrap();
    assert_eq!(batch_id, header.batch_id::<Sha256>());
    out.trace(
        "admit",
        "SettlementChain::admit at ADMIT_AT: header reconstruction, anchor, and batch id. The \
         BLS certificate check hashes to G1 inside blst and is not part of this trace.",
        &admit_trace,
    );
    let pending = chain.pending().unwrap();
    assert_eq!(
        pending.successor_liability,
        genesis.liability() - WITHDRAWAL_AMOUNT
    );
    let admitted_chain = chain.encode();

    // Apply the close to obtain the successor stores that serve challenge and payout proofs.
    let (replica, applied) = Box::pin(prepared.apply::<_, Sha256>(replica))
        .await
        .unwrap();
    assert_eq!(applied.header, header);
    assert_eq!(replica.state().root(), roots.successor);
    for (name, balance) in EXPECTED_FINAL {
        let key = &fixture.account(name).key;
        let stored = replica
            .state()
            .get(&account_key(key).unwrap())
            .await
            .unwrap()
            .map_or(0, NonZeroU64::get);
        assert_eq!(stored, balance, "final balance of {name}");
    }

    // Challenge evidence against the admitted close, built as challenges.rs does.
    let range = roots.activity_range(&context).unwrap();
    let epoch = Epoch::at(replica.logs(), EPOCH, range).await.unwrap();
    let payer = fixture.account(CHALLENGED_PAYER);
    let lookup = epoch
        .account_lookup(replica.logs(), &payer.key)
        .await
        .unwrap();
    assert!(matches!(lookup, AccountLookup::Present(_)));
    let committed_ack = acks[CHALLENGED_PAYER].last().unwrap().clone();
    let committed_index = close
        .out_vectors
        .iter()
        .position(|vector| vector.payer() == &payer.key)
        .unwrap();
    let mut retained_entries = close.out_vectors[committed_index].entries().to_vec();
    retained_entries[0].cumulative += 1;
    retained_entries[0].count += 1;
    let retained = OutVector::new(EPOCH, payer.key.clone(), retained_entries).unwrap();
    let retained_debit = retained.totals().unwrap().0;
    let committed_seq = committed_ack.body().seq();
    // A later batch above the certified terminal debit.
    let higher = acknowledge(
        &context,
        &payer.signer,
        operator,
        &retained,
        committed_seq + 1,
        retained_debit,
    );
    // A different body countersigned at the certified terminal's own sequence number.
    let fork = acknowledge(
        &context,
        &payer.signer,
        operator,
        &retained,
        committed_seq,
        retained_debit,
    );
    // Wrong-role signatures, as in `signatures_for_other_roles_cannot_authorize_challenges`.
    let mut wrong_payer_role = AckWitness::from_ack(&higher);
    wrong_payer_role.payer_signature = payer.signer.sign(
        VECTOR_ACK_SIGNATURE_NAMESPACE,
        &send_message(higher.body(), &higher.predecessor()),
    );
    let mut wrong_operator_role = AckWitness::from_ack(&fork);
    wrong_operator_role.operator_signature = operator.sign(
        VECTOR_SEND_SIGNATURE_NAMESPACE,
        &send_message(fork.body(), &fork.predecessor()),
    );
    for (label, ack) in [
        ("challenge_ack_higher", &higher),
        ("challenge_ack_fork", &fork),
    ] {
        let message = send_message(ack.body(), &ack.predecessor());
        out.ed25519(
            &format!("{label}_payer"),
            CHALLENGED_PAYER,
            &payer.key,
            VECTOR_SEND_SIGNATURE_NAMESPACE,
            &message,
            ack.payer_signature(),
        );
        out.ed25519(
            &format!("{label}_operator"),
            "operator",
            &operator.public_key(),
            VECTOR_ACK_SIGNATURE_NAMESPACE,
            &message,
            ack.operator_signature(),
        );
    }

    let challenges: Vec<(&str, &str, Challenge<Key, Digest>, &str)> = vec![
        (
            "challenge_higher_ack_debit_proven",
            "HigherAckDebit",
            Challenge::HigherAckDebit {
                ack: Box::new(AckWitness::from_ack(&higher)),
                payer: Box::new(lookup.clone()),
            },
            "Payer c's acknowledgment at seq terminal+1 with debit above the certified terminal \
             debit. Proves the close invalid.",
        ),
        (
            "challenge_higher_ack_debit_no_contradiction",
            "HigherAckDebit",
            Challenge::HigherAckDebit {
                ack: Box::new(AckWitness::from_ack(&committed_ack)),
                payer: Box::new(lookup.clone()),
            },
            "Payer c's certified terminal acknowledgment. Authentic but consistent: the close \
             stands.",
        ),
        (
            "challenge_higher_ack_debit_wrong_payer_role",
            "HigherAckDebit",
            Challenge::HigherAckDebit {
                ack: Box::new(wrong_payer_role),
                payer: Box::new(lookup.clone()),
            },
            "The proven HigherAckDebit evidence with the payer signature made under the ack \
             namespace. Rejected: InvalidPayerSignature.",
        ),
        (
            "challenge_ack_fork_proven",
            "AckFork",
            Challenge::AckFork {
                left: Box::new(AckWitness::from_ack(&committed_ack)),
                right: Box::new(AckWitness::from_ack(&fork)),
            },
            "Two operator countersignatures for payer c at the same sequence number over \
             different bodies. Proves the close invalid.",
        ),
        (
            "challenge_ack_fork_no_contradiction",
            "AckFork",
            Challenge::AckFork {
                left: Box::new(AckWitness::from_ack(&committed_ack)),
                right: Box::new(AckWitness::from_ack(&committed_ack)),
            },
            "The same acknowledgment on both sides. Authentic but not a fork.",
        ),
        (
            "challenge_ack_fork_wrong_operator_role",
            "AckFork",
            Challenge::AckFork {
                left: Box::new(AckWitness::from_ack(&committed_ack)),
                right: Box::new(wrong_operator_role),
            },
            "The proven fork with the right-hand operator signature made under the send \
             namespace. Rejected: InvalidOperatorSignature.",
        ),
    ];
    let bounds = Bounds {
        committee: VALIDATORS,
        items: 1_024,
        destination: MAX_DESTINATION_BYTES,
    };
    let mut challenge_records = Vec::new();
    for (name, kind, challenge, description) in challenges {
        let bytes = challenge.encode();
        let direct = adjudicate::<Sha256, Key, Digest>(
            &context,
            &header,
            &roots,
            withdrawal_total,
            &challenge,
        );
        // Settlement adjudicates on a copy so a proven challenge does not fault the chain that
        // goes on to finalize.
        let mut copy = Chain::decode_cfg(admitted_chain.clone(), &bounds).unwrap();
        let (settled, trace) =
            record(|| copy.challenge_encoded(ADMIT_AT, batch_id, &bytes, MAX_CHALLENGE_BYTES));
        let expected = match (&direct, &settled) {
            (Ok(direct), Ok(settled)) => {
                assert_eq!(direct, settled);
                verdict_name(direct)
            }
            (Err(direct), Err(_)) => format!("Err({direct:?})"),
            _ => panic!("{name}: adjudication and settlement disagree"),
        };
        match kind {
            "AckFork" => assert!(!expected.contains("HigherAckDebit")),
            _ => assert!(!expected.contains("AckFork")),
        }
        out.file(
            name,
            "Challenge<StrictVerifyingKey, sha256::Digest>",
            description,
            &bytes,
        );
        out.trace(
            name,
            "SettlementChain::challenge_encoded at ADMIT_AT on the admitted chain: batch id \
             lookup, header reconstruction, anchor, and every opening the evidence carries.",
            &trace,
        );
        challenge_records.push(json!({
            "name": name,
            "kind": kind,
            "file": format!("{name}.hex"),
            "expected": expected,
            "description": description,
        }));
    }
    assert!(
        challenge_records
            .iter()
            .any(|record| record["expected"]
                == verdict_name(&Verdict::Proven(ChallengeKind::AckFork)))
    );
    assert!(challenge_records.iter().any(|record| record["expected"]
        == verdict_name(&Verdict::Proven(ChallengeKind::HigherAckDebit))));

    // Finalization and the payout claim.
    let ((finalized, commit_index), finalize_trace) =
        record(|| chain.finalize(FINALIZE_AT).unwrap());
    assert_eq!(finalized.batch_id, batch_id);
    out.trace(
        "finalize",
        "SettlementChain::finalize at FINALIZE_AT.",
        &finalize_trace,
    );
    let payouts = chain.finalized_payouts();
    assert_eq!(payouts, roots.withdrawal_outputs);
    let position = context.predecessor_logs().payouts.operations;
    let (opening, operations) = replica
        .logs()
        .payout_opening(&payouts, position, NonZeroU64::MIN)
        .await
        .unwrap();
    let [commonware_clearing::bajillion::logs::PayoutOperation::Append(output)] =
        operations.as_slice()
    else {
        panic!("a one-output proof contains its payout append");
    };
    assert_eq!(output, &close.withdrawal_outputs()[0]);
    let claim = WithdrawalClaim::new(output.clone(), opening.clone());
    // The embedding records the finalized trailing Commit as claimed before any payout claim.
    let neighbors = [
        None,
        Some(ClaimedRange {
            start: commit_index,
            end: commit_index + 1,
        }),
    ];
    let (effect, claim_trace) = record(|| chain.claim_withdrawal(&neighbors, &claim));
    let effect = effect.unwrap();
    assert_eq!(effect.output.amount(), WITHDRAWAL_AMOUNT);
    assert_eq!(effect.output.destination().as_ref(), WITHDRAWAL_DESTINATION);
    out.trace(
        "claim_withdrawal",
        "SettlementChain::claim_withdrawal: the payout opening's MMR walk under the finalized \
         payout head, from the leaf preimage up to the root.",
        &claim_trace,
    );

    // Named hashes, assembled from their parts and checked against the crate's digests.
    let context_bytes = context.encode();
    let roots_bytes = roots.encode();
    let total_bytes = withdrawal_total.encode();
    let mut header_preimage = HEADER_ROOT_HASH_NAMESPACE.to_vec();
    header_preimage.extend_from_slice(&context_bytes);
    header_preimage.extend_from_slice(&roots_bytes);
    header_preimage.extend_from_slice(&total_bytes);
    out.hash(
        "header",
        &[
            ("HEADER_ROOT_HASH_NAMESPACE", HEADER_ROOT_HASH_NAMESPACE),
            ("CloseContext.encode()", &context_bytes),
            ("RootBundle.encode()", &roots_bytes),
            ("withdrawal_total u64 big-endian", &total_bytes),
        ],
        header.digest(),
        "Header digest. This is also the message the committee signs (see bls.header_message).",
    );
    out.hash(
        "batch_id",
        &[
            ("BATCH_ID_HASH_NAMESPACE", BATCH_ID_HASH_NAMESPACE),
            ("Header", header.digest().as_ref()),
        ],
        batch_id.digest(),
        "Canonical admitted close identifier.",
    );
    let epoch_bytes = EPOCH.to_be_bytes();
    let deposit_root = context.deposit_root().encode();
    let withdrawal_root = context.withdrawal_root().encode();
    let limits = context.limits().encode();
    let operator_key = operator.public_key().encode();
    out.hash(
        "epoch_anchor",
        &[
            ("EPOCH_ANCHOR_HASH_NAMESPACE", EPOCH_ANCHOR_HASH_NAMESPACE),
            ("deployment", deployment.as_ref()),
            ("deposit_root", &deposit_root),
            ("withdrawal_root", &withdrawal_root),
            ("epoch u64 big-endian", &epoch_bytes),
            ("operator ed25519 key", &operator_key),
            ("CloseLimits.encode()", &limits),
            ("committee commitment", committee_commitment.as_ref()),
        ],
        context.payment().anchor(),
        "Payment anchor every acknowledgment and the header context bind.",
    );
    let committee_bytes = committee.encode();
    out.hash(
        "committee_commitment",
        &[
            ("COMMITTEE_HASH_NAMESPACE", COMMITTEE_HASH_NAMESPACE),
            ("Committee.encode()", &committee_bytes),
        ],
        &committee_commitment,
        "Commitment to the canonical committee: varint member count then compressed G2 keys.",
    );
    let withdrawal_account = withdrawal.account().encode();
    let withdrawal_body = withdrawal.body().encode();
    out.hash(
        "withdrawal_id",
        &[
            ("WITHDRAWAL_ID_HASH_NAMESPACE", WITHDRAWAL_ID_HASH_NAMESPACE),
            ("account ed25519 key", &withdrawal_account),
            ("WithdrawalBody.encode()", &withdrawal_body),
        ],
        withdrawal.id::<Sha256>().digest(),
        "Replay identifier of the carried withdrawal.",
    );
    let epoch_context_bytes = context.epoch_context().encode();
    out.hash(
        "proposal_id",
        &[
            (
                "\"_COMMONWARE_CLEARING_PROPOSAL_ID\"",
                PROPOSAL_ID_NAMESPACE,
            ),
            ("EpochContext.encode()", &epoch_context_bytes),
            ("dealing", &encoded),
        ],
        roots.proposal.digest(),
        "Identity of the dealing, carried in RootBundle.proposal.",
    );
    out.ed25519(
        "withdrawal_account",
        WITHDRAWER,
        &withdrawer.key,
        WITHDRAWAL_SIGNATURE_NAMESPACE,
        &withdrawal_body,
        withdrawal.signature(),
    );

    // Crate-encoded objects.
    out.file(
        "epoch_context",
        "EpochContext<StrictVerifyingKey, sha256::Digest>",
        "Registered, predecessor-independent epoch context.",
        epoch_context.encode(),
    );
    out.file(
        "close_context",
        "CloseContext<StrictVerifyingKey, sha256::Digest>",
        "The context settlement bound at registration; the first part of the header preimage.",
        &context_bytes,
    );
    out.file(
        "root_bundle",
        "RootBundle<sha256::Digest>",
        "Validator-derived successor roots; the second part of the header preimage.",
        &roots_bytes,
    );
    out.file(
        "header",
        "Header<sha256::Digest>",
        "Certified header digest.",
        header.encode(),
    );
    out.file(
        "batch_id",
        "BatchId<sha256::Digest>",
        "Batch id returned by SettlementChain::admit.",
        batch_id.encode(),
    );
    out.file(
        "certificate",
        "bls12381::Certificate (multisig::Certificate<MinSig>)",
        "Signer bitmap (u64 big-endian bit length, then LSB-first bytes) and the 48-byte \
         compressed aggregate G1 signature.",
        certificate.encode(),
    );
    out.file(
        "committee",
        "Committee",
        "Varint member count and compressed G2 keys in canonical order.",
        &committee_bytes,
    );
    out.file(
        "deposit_batch",
        "DepositBatch<StrictVerifyingKey>",
        "Registered deposit boundary (empty).",
        deposits.encode(),
    );
    out.file(
        "withdrawal_batch",
        "WithdrawalBatch<StrictVerifyingKey, sha256::Digest>",
        "Registered withdrawal boundary: the one operator-carried withdrawal.",
        withdrawals.encode(),
    );
    out.file(
        "dealing",
        "posted dealing bytes",
        "The operator's complete dealing every validator sealed.",
        &encoded,
    );
    out.file(
        "payout_claim",
        "WithdrawalClaim<sha256::Digest>",
        "WithdrawalOutput (varint-length destination, u64 amount) then the Opening (u64 start, \
         MMR proof) under the finalized payout head.",
        claim.encode(),
    );
    out.file(
        "payout_opening",
        "logs::Opening<sha256::Digest>",
        "The opening alone, as embedded at the end of payout_claim.",
        opening.encode(),
    );
    out.file(
        "settlement_chain_admitted",
        "SettlementChain<Sha256, StrictVerifyingKey>",
        "Settlement state immediately after admission, before finalization.",
        &admitted_chain,
    );
    out.file(
        "genesis_state_root",
        "qmdb::StateRoot<sha256::Digest>",
        "Genesis balance root the deployment is configured with.",
        genesis.root().encode(),
    );

    // BLS: committee, proofs of possession, votes, certificate, and verifier hints.
    let header_bytes = header.encode();
    let header_message = union_unique(HEADER_NAMESPACE, &header_bytes);
    let header_hash =
        hash_with_namespace::<MinSig>(MinSig::MESSAGE, HEADER_NAMESPACE, &header_bytes);
    let members = committee
        .members()
        .iter()
        .enumerate()
        .map(|(index, public)| {
            let private = &validators[index].1;
            assert_eq!(&compute_public::<MinSig>(private), public);
            let pop = sign_proof_of_possession::<MinSig>(private, POP_NAMESPACE);
            verify_proof_of_possession::<MinSig>(public, POP_NAMESPACE, &pop).unwrap();
            let public_bytes = public.encode();
            let pop_hash = hash_with_namespace::<MinSig>(
                MinSig::PROOF_OF_POSSESSION,
                POP_NAMESPACE,
                &public_bytes,
            );
            json!({
                "index": index,
                "public_key": bls_point(&public_bytes),
                "proof_of_possession": bls_point(&pop.encode()),
                "pop_signed_bytes": hex(union_unique(POP_NAMESPACE, &public_bytes)),
                "pop_message_hash": bls_point(&pop_hash.encode()),
            })
        })
        .collect::<Vec<_>>();
    let signer_indices = certificate
        .signers
        .iter()
        .map(usize::from)
        .collect::<Vec<_>>();
    assert_eq!(signer_indices, SIGNING_VALIDATORS);
    let aggregate_public = aggregate::combine_public_keys::<MinSig, _>(
        NonEmpty::try_new(
            signer_indices
                .iter()
                .map(|index| &committee.members()[*index]),
        )
        .unwrap(),
    )
    .encode();
    let certificate_bytes = certificate.encode();
    let aggregate_signature = &certificate_bytes[certificate_bytes.len() - G1::SIZE..];
    assert_eq!(
        certificate.signature.get().unwrap().encode().as_ref(),
        aggregate_signature
    );
    let negated_generator = negated_g2_generator();
    assert!(G2::decode(commonware_codec::Copying(&negated_generator)).is_ok());
    let mut pairing_input = eip2537::g1(&header_hash.encode()).to_vec();
    pairing_input.extend_from_slice(&eip2537::g2(&aggregate_public));
    pairing_input.extend_from_slice(&eip2537::g1(aggregate_signature));
    pairing_input.extend_from_slice(&eip2537::g2(&negated_generator));
    let vote_records = votes
        .iter()
        .map(|vote| {
            json!({
                "signer": usize::from(vote.signer),
                "signature": bls_point(&vote.signature.get().unwrap().encode()),
            })
        })
        .collect::<Vec<_>>();
    let bls = json!({
        "variant": "MinSig: G2 public keys, G1 signatures",
        "message_dst": String::from_utf8(MinSig::MESSAGE.to_vec()).unwrap(),
        "pop_dst": String::from_utf8(MinSig::PROOF_OF_POSSESSION.to_vec()).unwrap(),
        "pop_namespace": hex(POP_NAMESPACE),
        "pop_namespace_ascii": String::from_utf8(POP_NAMESPACE.to_vec()).unwrap(),
        "header_namespace": hex(HEADER_NAMESPACE),
        "header_message": hex(&header_message),
        "header_message_hash": bls_point(&header_hash.encode()),
        "committee": members,
        "quorum": committee.quorum(),
        "votes": vote_records,
        "certificate": {
            "file": "certificate.hex",
            "signers": signer_indices,
            "signer_count": VALIDATORS,
            "aggregate_signature": bls_point(aggregate_signature),
            "aggregate_public_key": bls_point(&aggregate_public),
        },
        "negated_g2_generator": bls_point(&negated_generator),
        "pairing_check_input": hex(&pairing_input),
        "pairing_check_note": "EIP-2537 pairing input for MinSig::verify: \
            e(header_message_hash, aggregate_public_key) * e(aggregate_signature, -G2) == 1.",
    });

    let account_records = accounts
        .iter()
        .zip(ACCOUNTS)
        .zip(EXPECTED_FINAL)
        .map(|((account, (_, opening)), (_, closing))| {
            json!({
                "name": account.name,
                "public_key": hex(account.key.encode()),
                "account_key": hex(account_key(&account.key).unwrap().as_ref()),
                "opening_balance": opening,
                "final_balance": closing,
            })
        })
        .collect::<Vec<_>>();
    let terminal_records = terminals
        .iter()
        .map(|terminal| {
            let body = terminal.authorization.body();
            json!({
                "payer": fixture.name_of(body.payer()),
                "seq": body.seq(),
                "cumulative_debit": body.cumulative_debit(),
                "send_root": hex(body.send_root().encode()),
                "entries": terminal.vector.entries().iter().map(|entry| json!({
                    "recipient": fixture.name_of(&entry.recipient),
                    "cumulative": entry.cumulative,
                    "count": entry.count,
                })).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();

    let manifest = json!({
        "format": "Each *.hex file holds one 0x-prefixed lowercase hex string with no trailing \
            newline. Integers inside crate encodings are fixed-width big-endian unless the type \
            says varint. Every digest is SHA-256.",
        "upstream": {
            "repository": UPSTREAM_REPOSITORY,
            "rev": UPSTREAM_REV,
            "ref": UPSTREAM_REF,
            "rust_toolchain": "1.95.0",
        },
        "seed": FIXTURE_SEED,
        "key_derivation": {
            "operator": "curve25519 SigningKey::from_seed(seed)",
            "accounts": "curve25519 SigningKey::from_seed(seed + 1 + i) for a, b, c, d",
            "validators": format!(
                "bls12381 Scalar::map(\"{}\", seed_be || index_be), sorted by public key",
                String::from_utf8(VALIDATOR_KEY_DST.to_vec()).unwrap()
            ),
            "deployment": "sha256(\"_COMMONWARE_EXAMPLES_TERMINAL_DEPLOYMENT\" || operator key)",
        },
        "scenario": {
            "epoch": EPOCH,
            "deployment": hex(deployment),
            "operator": hex(operator.public_key().encode()),
            "accounts": account_records,
            "payments": payment_records,
            "terminals": terminal_records,
            "withdrawal": {
                "account": WITHDRAWER,
                "action": "Amount",
                "amount": WITHDRAWAL_AMOUNT,
                "destination": hex(WITHDRAWAL_DESTINATION),
                "deadline": WITHDRAWAL_DEADLINE,
                "signed": hex(withdrawal.encode()),
            },
            "genesis": {
                "state_root": hex(genesis.root().encode()),
                "operations": genesis.operations(),
                "liability": genesis.liability(),
            },
            "settlement_config": {
                "admission_delay": ADMISSION_DELAY,
                "challenge_duration": CHALLENGE_DURATION,
                "deposit_inclusion_timeout": DEPOSIT_INCLUSION_TIMEOUT,
                "minimum_withdrawal_notice": MINIMUM_WITHDRAWAL_NOTICE,
                "maximum_withdrawal_notice": MAXIMUM_WITHDRAWAL_NOTICE,
                "max_destination_bytes": MAX_DESTINATION_BYTES,
                "max_deposit_ids": MAX_DEPOSIT_IDS,
                "max_challenge_bytes": MAX_CHALLENGE_BYTES,
            },
            "timing": {
                "register_at": REGISTER_AT,
                "admit_at": ADMIT_AT,
                "admission_deadline": ADMISSION_DEADLINE,
                "challenge_deadline": CHALLENGE_DEADLINE,
                "finalize_at": FINALIZE_AT,
            },
            "recovery": {
                "sweep_namespace": String::from_utf8(RECOVERY_SWEEP_NAMESPACE.to_vec()).unwrap(),
                "sweep_recipient": hex(RECOVERY_RECIPIENT),
                "sweep_nonce": 0,
                "sweep_account": WITHDRAWER,
            },
        },
        "close": {
            "header": hex(header.encode()),
            "batch_id": hex(batch_id.encode()),
            "withdrawal_total": withdrawal_total,
            "successor_liability": genesis.liability() - withdrawal_total,
            "row_count": roots.row_count,
            "activity_range": { "start": range.start, "end": range.end },
        },
        "payout_claim": {
            "file": "payout_claim.hex",
            "position": claim.position(),
            "destination": hex(output.destination()),
            "amount": output.amount(),
            "payout_head": {
                "root": hex(payouts.root),
                "operations": payouts.operations,
                "floor": payouts.floor,
            },
            "finalized_commit_index": commit_index,
            "claimed_neighbors_before_claim": [Value::Null, { "start": commit_index, "end": commit_index + 1 }],
            "claimed_range_after": { "start": effect.claimed.start, "end": effect.claimed.end },
            "trace": "claim_withdrawal",
        },
        "challenges": challenge_records,
        "fixtures": Value::Object(std::mem::take(&mut out.entries)),
        "hashes": Value::Object(std::mem::take(&mut out.hashes)),
        "traces": Value::Object(std::mem::take(&mut out.traces)),
        "ed25519": std::mem::take(&mut out.ed25519),
        "bls": bls,
    });
    (out, manifest)
}

fn write(dir: &Path, out: &Output, manifest: Value) {
    std::fs::create_dir_all(dir).unwrap();
    // Drop fixtures from earlier runs so renamed or removed outputs cannot linger.
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let stale = path.extension().is_some_and(|ext| ext == "hex")
            || path.file_name().is_some_and(|name| name == "manifest.json");
        if stale {
            std::fs::remove_file(path).unwrap();
        }
    }
    for (file, bytes) in &out.files {
        std::fs::write(dir.join(file), hex(bytes)).unwrap();
    }
    let mut text = serde_json::to_string_pretty(&manifest).unwrap();
    text.push('\n');
    std::fs::write(dir.join("manifest.json"), text).unwrap();
    println!(
        "wrote {} fixture files and manifest.json to {}",
        out.files.len(),
        dir.display()
    );
}
