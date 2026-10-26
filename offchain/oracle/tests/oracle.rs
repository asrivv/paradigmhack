//! Checks the oracle's determinism, its robustness to arbitrary op sequences, its ABI framing,
//! and that README.md documents exactly the status table the code reports.

use bajillion_oracle::{Op, decode_input, encode_input, encode_output, kind, run, status};
use std::process::Command;

/// Splitmix64, so the randomized cases are reproducible from their printed seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn op(kind: u8) -> Op {
    Op {
        kind,
        args: Default::default(),
    }
}

/// A sequence that exercises a full epoch: deposits, withdrawal requests, registration,
/// admission, the challenge window, finalization, payout claims, and a second epoch.
fn lifecycle() -> Vec<Op> {
    use kind::*;
    [
        RECORD_DEPOSIT,
        QUEUE_WITHDRAWAL,
        QUEUE_WITHDRAWAL,
        ADVANCE_TIME,
        REGISTER_EPOCH,
        ADVANCE_TIME,
        ADMIT,
        ADVANCE_TIME,
        ADVANCE_TIME,
        ADVANCE_TIME,
        FINALIZE,
        CLAIM_WITHDRAWAL,
        CLAIM_WITHDRAWAL,
        REGISTER_EPOCH,
        ADMIT,
        CHALLENGE,
        FAULT_EXPIRED,
        CLAIM_PENDING_DEPOSIT,
        BEGIN_HARD_FAULT_SETTLEMENT,
        CLAIM_HARD_FAULT,
        CLAIM_PENDING_DEPOSIT,
        CLAIM_WITHDRAWAL,
    ]
    .into_iter()
    .map(op)
    .collect()
}

#[test]
fn identical_inputs_give_identical_outputs() {
    for seed in [0, 1, 4664, u64::MAX] {
        let first = run(seed, lifecycle());
        let second = run(seed, lifecycle());
        assert_eq!(first, second, "seed {seed}");
        assert_eq!(encode_output(&first), encode_output(&second));
    }
}

#[test]
fn materialized_args_replay_to_the_same_result() {
    // Foundry replays the bytes `materialize` returns, so applying them as concrete args must
    // reproduce every status and the final digest.
    let mut succeeded = std::collections::BTreeSet::new();
    for seed in 0..16 {
        let materialized = run(seed, lifecycle());
        let replayed = run(seed ^ 0x5555, materialized.ops.clone());
        assert_eq!(replayed.ops, materialized.ops, "seed {seed}");
        assert_eq!(replayed.statuses, materialized.statuses, "seed {seed}");
        assert_eq!(
            replayed.mutated_on_error, materialized.mutated_on_error,
            "seed {seed}"
        );
        assert_eq!(
            replayed.state_digest, materialized.state_digest,
            "seed {seed}"
        );
        for (op, status) in materialized.ops.iter().zip(&materialized.statuses) {
            if *status == status::OK {
                succeeded.insert(op.kind);
            }
        }
    }
    // The replayed bytes must include real closes, certificates, and payout proofs.
    for kind in [
        kind::REGISTER_EPOCH,
        kind::ADMIT,
        kind::FINALIZE,
        kind::CLAIM_WITHDRAWAL,
    ] {
        assert!(succeeded.contains(&kind), "no successful op of kind {kind}");
    }
}

#[test]
fn different_seeds_reach_different_states() {
    // Guards against a digest or materializer that ignores its inputs.
    let digests = (0..4)
        .map(|seed| run(seed, lifecycle()).state_digest)
        .collect::<std::collections::BTreeSet<_>>();
    assert!(digests.len() > 1);
    assert_ne!(
        run(0, Vec::new()).state_digest,
        run(0, lifecycle()).state_digest
    );
}

#[test]
fn random_sequences_never_panic() {
    let mut rng = Rng(0x0dd_c0de);
    for case in 0..40 {
        let seed = rng.next();
        let length = 1 + rng.below(50) as usize;
        let ops = (0..length)
            .map(|_| {
                // Mostly defined kinds, sometimes unknown ones.
                let kind = if rng.below(10) == 0 {
                    kind::COUNT + rng.below(247) as u8
                } else {
                    rng.below(kind::COUNT as u64) as u8
                };
                // Mostly materialized args, sometimes garbage bytes of any length.
                let args = if rng.below(6) == 0 {
                    (0..rng.below(200)).map(|_| rng.next() as u8).collect()
                } else {
                    Vec::new()
                };
                Op {
                    kind,
                    args: args.into(),
                }
            })
            .collect::<Vec<_>>();
        let result = run(seed, ops.clone());
        assert_eq!(result.statuses.len(), length, "case {case} seed {seed}");
        assert_eq!(result.mutated_on_error.len(), length);
        assert_eq!(result.ops.len(), length);
        for ((op, status), mutated) in ops
            .iter()
            .zip(&result.statuses)
            .zip(&result.mutated_on_error)
        {
            assert!(status::name(*status).is_some(), "unlisted status {status}");
            assert!(!mutated || *status != status::OK);
            if op.kind >= kind::COUNT {
                assert_eq!(*status, status::UNKNOWN_KIND);
                assert!(!mutated);
            }
            if *status >= status::MALFORMED_ARGS {
                assert!(!mutated, "oracle rejections never touch settlement state");
            }
        }
    }
}

#[test]
fn malformed_args_are_rejected_without_effect() {
    let empty = run(7, Vec::new()).state_digest;
    let cases = [
        (kind::FINALIZE, vec![0u8]),
        (kind::FAULT_EXPIRED, vec![0u8; 32]),
        (kind::ADVANCE_TIME, vec![1u8; 31]),
        // A non-canonical uint64 (high bytes set) must not be truncated.
        (kind::ADVANCE_TIME, [vec![1u8; 24], vec![0u8; 8]].concat()),
        (kind::RECORD_DEPOSIT, vec![0u8; 96]),
        (kind::CLAIM_WITHDRAWAL, vec![0u8; 64]),
    ];
    for (kind, args) in cases {
        let result = run(
            7,
            vec![Op {
                kind,
                args: args.into(),
            }],
        );
        assert_eq!(result.statuses, vec![status::MALFORMED_ARGS], "kind {kind}");
        assert_eq!(result.state_digest, empty, "kind {kind}");
    }
}

#[test]
fn clock_overflow_is_reported() {
    let max = [vec![0u8; 24], u64::MAX.to_be_bytes().to_vec()].concat();
    let one = [vec![0u8; 31], vec![1u8]].concat();
    let result = run(
        0,
        vec![
            Op {
                kind: kind::ADVANCE_TIME,
                args: max.into(),
            },
            Op {
                kind: kind::ADVANCE_TIME,
                args: one.into(),
            },
        ],
    );
    assert_eq!(result.statuses, vec![status::OK, status::CLOCK_OVERFLOW]);
}

#[test]
fn input_must_be_canonical() {
    let ops = vec![op(kind::ADVANCE_TIME), op(kind::FINALIZE)];
    let blob = encode_input(9, &ops);
    assert_eq!(decode_input(&blob).unwrap(), (9, ops));
    assert!(decode_input(&blob[..blob.len() - 1]).is_err());
    let mut padded = blob.clone();
    padded.extend_from_slice(&[0u8; 32]);
    assert!(decode_input(&padded).is_err());
    let mut wide_seed = blob;
    wide_seed[0] = 1;
    assert!(decode_input(&wide_seed).is_err());
}

#[test]
fn genesis_digest_follows_the_documented_layout() {
    // Rebuilt from upstream genesis values and the README layout, not from the oracle's own
    // digest code, so a drift between the two is caught.
    use bajillion_fixtures::deployment::{Deployment, EPOCH, FIXTURE_SEED};
    use commonware_clearing::bajillion::logs::Heads;
    use commonware_cryptography::{Hasher, Sha256};
    use commonware_cryptography_curve25519::signing::StrictVerifyingKey as Key;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

    let genesis = deterministic::Runner::default().start(|context| async move {
        Deployment::new(FIXTURE_SEED)
            .genesis(context.child("replica"), "test")
            .await
            .1
    });
    let heads = Heads::empty::<Key, Sha256>();
    let mut preimage = b"BAJILLION_ORACLE_STATE_V2".to_vec();
    // now, nextRegistrationEpoch, nextAdmissionEpoch, expectedEpoch, intake, pulled
    for value in [0, EPOCH, EPOCH, EPOCH, 0, 0] {
        preimage.extend_from_slice(&u64::to_be_bytes(value));
    }
    preimage.push(0); // no frontier
    preimage.extend_from_slice(&0u32.to_be_bytes()); // no pending batches
    for head in [heads.activity, heads.payouts] {
        preimage.extend_from_slice(head.root.as_ref());
        preimage.extend_from_slice(&head.operations.to_be_bytes());
        preimage.extend_from_slice(&head.floor.to_be_bytes());
    }
    preimage.extend_from_slice(genesis.root().digest.as_ref());
    preimage.extend_from_slice(&0u32.to_be_bytes()); // no claimed ranges
    preimage.extend_from_slice(&genesis.liability().to_be_bytes()); // custody
    preimage.extend_from_slice(&0u64.to_be_bytes()); // claimable
    preimage.extend_from_slice(&genesis.liability().to_be_bytes()); // finalized liability
    preimage.extend_from_slice(&[0; 9]); // no fault, expiredAt 0
    preimage.extend_from_slice(&[0; 9]); // no fence, epoch 0
    preimage.extend_from_slice(&[0; 33]); // no invalidFrom
    preimage.extend_from_slice(&[0; 2]); // terminal settlement neither started nor settled
    assert_eq!(preimage.len(), 287);
    let expected: [u8; 32] = Sha256::hash(&[&preimage]).as_ref().try_into().unwrap();
    assert_eq!(run(123, Vec::new()).state_digest, expected);

    // The README quotes this vector for the Solidity side.
    let readme = include_str!("../README.md");
    assert!(readme.contains(&hex(&preimage)));
    assert!(readme.contains(&hex(&expected)));
}

fn hex(bytes: &[u8]) -> String {
    bajillion_fixtures::hex(bytes)
}

fn oracle(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bajillion-oracle"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn cli_prints_the_abi_output() {
    let ops = lifecycle();
    let input = hex(&encode_input(3, &ops));
    let expected = run(3, ops);

    let applied = oracle(&["apply", &input]);
    assert!(applied.status.success());
    let stdout = String::from_utf8(applied.stdout).unwrap();
    assert_eq!(stdout.trim(), hex(&encode_output(&expected)));

    let materialized = oracle(&["materialize", &input]);
    assert!(materialized.status.success());
    let stdout = String::from_utf8(materialized.stdout).unwrap();
    assert_eq!(stdout.trim(), hex(&bajillion_oracle::encode_ops(&expected)));

    for bad in [
        vec!["apply"],
        vec!["apply", "00"],
        vec!["apply", "0x0"],
        vec!["apply", "0xzz"],
        vec!["replay", input.as_str()],
    ] {
        let output = oracle(&bad);
        assert_eq!(output.status.code(), Some(2), "{bad:?}");
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn readme_documents_the_status_table() {
    let readme = include_str!("../README.md");
    let section = readme
        .split("\n## ")
        .find(|section| section.starts_with("Status codes"))
        .expect("README has a Status codes section");
    let documented = section
        .lines()
        .filter_map(|line| {
            let cells = line.split('|').map(str::trim).collect::<Vec<_>>();
            let [_, code, name, ..] = cells.as_slice() else {
                return None;
            };
            let code = code.parse::<u16>().ok()?;
            Some((code, name.trim_matches('`').to_string()))
        })
        .collect::<Vec<_>>();
    let expected = status::TABLE
        .iter()
        .map(|(code, name)| (*code, name.to_string()))
        .collect::<Vec<_>>();
    assert_eq!(documented, expected);
}
