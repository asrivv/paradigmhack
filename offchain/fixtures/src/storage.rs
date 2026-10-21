//! Native store configuration for the in-memory deterministic runtime.
//!
//! Ported from `config`, `logs_config`, and `new_state` in the upstream
//! `clearing/src/bajillion/tests.rs`, which are private to the crate's test module. The sizes
//! only affect how storage is laid out, not any committed value, but they are kept identical so
//! the fixture epoch exercises the same code paths as the upstream tests.

use commonware_clearing::bajillion::{
    logs::{self, Logs},
    qmdb::{self, State, account_key},
    replica::Replica,
};
use commonware_cryptography::Hasher;
use commonware_cryptography_curve25519::signing::StrictVerifyingKey;
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Supervisor as _, deterministic, utils::buffer::paged::CacheRef,
};
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig, merkle::full::Config as MerkleConfig,
    qmdb::current::FixedConfig, translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use core::num::NonZeroU64;

/// A validator or operator replica of all three native stores.
pub type FixtureReplica<H> = Replica<deterministic::Context, H, StrictVerifyingKey>;

fn state_config(context: &impl BufferPooler, prefix: &str) -> qmdb::Config<Sequential> {
    let page_cache = CacheRef::from_pooler(context, NZU16!(4092), NZUsize!(16));
    FixedConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("{prefix}-merkle"),
            metadata_partition: format!("{prefix}-merkle-meta"),
            items_per_blob: NZU64!(64),
            write_buffer: NZUsize!(4096),
            replay_buffer: NZUsize!(4096),
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: JournalConfig {
            partition: format!("{prefix}-operations"),
            items_per_blob: NZU64!(64),
            write_buffer: NZUsize!(4096),
            replay_buffer: NZUsize!(4096),
            page_cache,
        },
        grafted_metadata_partition: format!("{prefix}-grafted"),
        translator: EightCap,
        init_cache: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(4096),
        init_concurrency: (),
    }
}

fn logs_config(context: &impl BufferPooler, prefix: &str) -> logs::Config<Sequential> {
    let activity = state_config(context, &format!("{prefix}-activity"));
    let payouts = state_config(context, &format!("{prefix}-payouts"));
    logs::Config {
        activity: commonware_storage::qmdb::keyless::Config {
            merkle: activity.merkle_config,
            log: commonware_storage::journal::contiguous::variable::Config {
                partition: activity.journal_config.partition,
                items_per_section: NZU64!(4096),
                compression: None,
                codec_config: (),
                page_cache: activity.journal_config.page_cache,
                write_buffer: NZUsize!(4096),
                replay_buffer: NZUsize!(4096),
            },
        },
        payouts: commonware_storage::qmdb::keyless::Config {
            merkle: payouts.merkle_config,
            log: commonware_storage::journal::contiguous::variable::Config {
                partition: payouts.journal_config.partition,
                items_per_section: NZU64!(64),
                compression: None,
                codec_config: commonware_codec::RangeCfg::new(0..=1024),
                page_cache: payouts.journal_config.page_cache,
                write_buffer: NZUsize!(4096),
                replay_buffer: NZUsize!(4096),
            },
        },
    }
}

/// Creates a replica whose balance state holds exactly `balances` and whose logs hold only
/// their bootstrap commits.
pub async fn genesis_replica<H: Hasher>(
    context: deterministic::Context,
    prefix: &str,
    balances: &[(StrictVerifyingKey, u64)],
) -> FixtureReplica<H> {
    let mut genesis = balances
        .iter()
        .map(|(key, balance)| {
            (
                account_key(key).unwrap(),
                NonZeroU64::new(*balance).expect("genesis balances are positive"),
            )
        })
        .collect::<Vec<_>>();
    genesis.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let state = State::init(
        context.child("state"),
        state_config(&context, prefix),
        genesis,
    )
    .await
    .unwrap();
    let logs = Logs::open(context.child("logs"), logs_config(&context, prefix), None)
        .await
        .unwrap();
    Replica::from_parts(state, logs)
}
