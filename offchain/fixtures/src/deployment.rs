//! The seeded deployment every fixture and the differential oracle run against.
//!
//! One seed fixes the operator, the account keys, the 4-validator committee, the deployment
//! identity, the genesis balances, and the settlement policy. Keeping them in one place means the
//! static fixtures and the oracle's randomized sequences exercise the same deployment, so the
//! contract can be configured once for both.

use crate::storage::{FixtureReplica, genesis_replica};
use commonware_clearing::bajillion::{
    admission::{Committee, bls12381},
    commitment::{self, VectorKind},
    payment::{VectorAck, VectorSendBody},
    qmdb::account_key,
    settlement::{EpochDeadlinePolicy, Genesis, SettlementConfig},
    transition::CloseContext,
    vector::OutVector,
};
use commonware_codec::Encode;
use commonware_cryptography::{
    Hasher, Sha256, Signer as _,
    bls12381::primitives::{
        group::{G2, Private, Scalar},
        ops::compute_public,
        variant::MinSig,
    },
    sha256::Digest,
};
use commonware_cryptography_curve25519::signing::{SigningKey, StrictVerifyingKey as Key};
use commonware_runtime::deterministic;
use std::num::{NonZeroU64, NonZeroUsize};

/// The single seed every key in the fixture derives from.
pub const FIXTURE_SEED: u64 = 4664;
/// First epoch the deployment registers.
pub const EPOCH: u64 = 1;
/// Opening balances and the canonical names used in the manifest.
pub const ACCOUNTS: [(&str, u64); 4] = [("a", 100), ("b", 40), ("c", 25), ("d", 35)];
/// Committee size: one tolerated fault.
pub const VALIDATORS: usize = 4;

/// Settlement timing in abstract chain ticks (block heights on Tempo).
pub const ADMISSION_DELAY: u64 = 10;
pub const CHALLENGE_DURATION: u64 = 20;
pub const DEPOSIT_INCLUSION_TIMEOUT: u64 = 100;
pub const MINIMUM_WITHDRAWAL_NOTICE: u64 = 50;
pub const MAXIMUM_WITHDRAWAL_NOTICE: u64 = 1_000;
pub const MAX_DESTINATION_BYTES: usize = 256;
pub const MAX_DEPOSIT_IDS: usize = 1_024;
/// Outer byte bound applied to encoded challenges.
pub const MAX_CHALLENGE_BYTES: usize = 64 * 1024;

/// Domain for deriving validator scalars from the fixture seed.
pub const VALIDATOR_KEY_DST: &[u8] = b"_PARADIGMHACK_BAJILLION_FIXTURE_VALIDATOR_KEY";
/// The terminal example's deployment-identity namespace (examples/terminal/src/protocol.rs).
pub const DEPLOYMENT_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_TERMINAL_DEPLOYMENT";

/// The settlement policy shared by the fixtures and the oracle.
pub fn settlement_config() -> SettlementConfig {
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

/// One named ed25519 account.
pub struct Account {
    pub name: &'static str,
    pub signer: SigningKey,
    pub key: Key,
}

/// Keys and identities derived from one seed.
pub struct Deployment {
    pub operator: SigningKey,
    pub accounts: Vec<Account>,
    /// Validators in canonical committee order; certificate signer indices refer to it.
    pub validators: Vec<(G2, Private)>,
    pub committee: Committee,
    pub deployment: Digest,
}

impl Deployment {
    /// Derives every key from `seed`. `Signer::from_seed` is the derivation the upstream test
    /// helpers use for accounts and the operator.
    pub fn new(seed: u64) -> Self {
        let operator = SigningKey::from_seed(seed);
        let accounts = ACCOUNTS
            .iter()
            .enumerate()
            .map(|(index, (name, _))| {
                let signer = SigningKey::from_seed(seed + 1 + index as u64);
                Account {
                    name,
                    key: signer.public_key(),
                    signer,
                }
            })
            .collect::<Vec<_>>();
        let mut validators = (0..VALIDATORS)
            .map(|index| {
                let mut ikm = seed.to_be_bytes().to_vec();
                ikm.extend_from_slice(&(index as u64).to_be_bytes());
                let private = Private::new(Scalar::map(VALIDATOR_KEY_DST, &ikm));
                (compute_public::<MinSig>(&private), private)
            })
            .collect::<Vec<_>>();
        validators.sort_unstable_by_key(|(public, _)| *public);
        let committee = Committee::new(validators.iter().map(|(public, _)| *public).collect())
            .expect("4 distinct validators form a 3f+1 committee");
        let deployment = Sha256::hash(&[DEPLOYMENT_NAMESPACE, &operator.public_key().encode()]);
        Self {
            operator,
            accounts,
            validators,
            committee,
            deployment,
        }
    }

    pub fn account(&self, name: &str) -> &Account {
        self.accounts
            .iter()
            .find(|account| account.name == name)
            .expect("fixture account exists")
    }

    pub fn name_of(&self, key: &Key) -> &'static str {
        self.accounts
            .iter()
            .find(|account| &account.key == key)
            .map(|account| account.name)
            .expect("key belongs to a fixture account")
    }

    /// The signing scheme of the validator at canonical committee `index`.
    pub fn signer(&self, index: usize) -> bls12381::Scheme {
        bls12381::Scheme::signer(self.committee.clone(), self.validators[index].1.clone())
            .expect("validator is in the committee")
    }

    /// The opening balances as `(key, balance)` pairs.
    pub fn balances(&self) -> Vec<(Key, u64)> {
        ACCOUNTS
            .iter()
            .zip(&self.accounts)
            .map(|((_, balance), account)| (account.key.clone(), *balance))
            .collect()
    }

    /// Opens a validator replica at genesis and the matching trusted settlement genesis.
    pub async fn genesis(
        &self,
        context: deterministic::Context,
        prefix: &str,
    ) -> (FixtureReplica<Sha256>, Genesis<Digest>) {
        let balances = self.balances();
        let replica = genesis_replica::<Sha256>(context, prefix, &balances).await;
        let mut accounts = balances
            .iter()
            .map(|(key, balance)| {
                (
                    account_key(key).unwrap(),
                    NonZeroU64::new(*balance).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        accounts.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let genesis = Genesis::new(
            replica.state().root(),
            replica.state().head().operations(),
            &accounts,
        )
        .unwrap();
        (replica, genesis)
    }
}

/// Signs and countersigns one vector endpoint against the empty predecessor, mirroring
/// `acknowledge` in the upstream `clearing/src/bajillion/tests/challenges.rs`.
pub fn acknowledge(
    context: &CloseContext<Key, Digest>,
    payer: &SigningKey,
    operator: &SigningKey,
    vector: &OutVector<Key>,
    seq: u64,
    debit: u64,
) -> VectorAck<Key, Digest> {
    VectorAck::sign_by_authorities(
        VectorSendBody::new(
            context.payment(),
            payer.public_key(),
            seq,
            debit,
            vector.root::<Sha256, Digest>().unwrap(),
        ),
        commitment::empty_root::<Sha256>(VectorKind::OutEntry),
        payer,
        operator,
    )
}
