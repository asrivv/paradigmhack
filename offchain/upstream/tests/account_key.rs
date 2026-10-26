//! `qmdb::account_key` and secp256r1 accounts.
//!
//! `SettlementChain<H, P>` accepts any `P: PublicKey` (clearing/src/bajillion/settlement.rs:644-648),
//! and `commonware-cryptography` ships secp256r1 keys whose canonical encoding is 33 bytes
//! (`PUBLIC_KEY_LENGTH`, cryptography/src/secp256r1/common.rs:21). `account_key`
//! (clearing/src/bajillion/qmdb.rs:621-625) converts the encoding into `[u8; 32]` "without hashing,
//! padding, or truncation", so it rejects every such key with `Error::AccountKey`.

use commonware_clearing::bajillion::{
    qmdb::{Error, account_key},
    settlement::SettlementChain,
};
use commonware_cryptography::{
    Sha256, Signer as _,
    secp256r1::standard::{PrivateKey, PublicKey},
};

/// A secp256r1 account, 33 bytes encoded.
fn p256_account(seed: u64) -> PublicKey {
    let key = PrivateKey::from_seed(seed).public_key();
    assert_eq!(
        key.as_ref().len(),
        33,
        "compressed SEC1 point: parity byte then x"
    );
    key
}

/// The settlement chain type-checks with secp256r1 accounts: nothing in its bounds restricts the
/// key width.
#[allow(dead_code)]
fn settlement_chain_admits_secp256r1(_: Option<SettlementChain<Sha256, PublicKey>>) {}

/// What the generic bound implies: every `PublicKey` maps to a QMDB account key. Fails at the
/// pinned commit with `Err(AccountKey)`. Run with `cargo test -p bajillion-upstream -- --ignored`.
#[test]
#[ignore = "documents an upstream limitation: fails at dd6d60cb"]
fn account_key_accepts_a_33_byte_secp256r1_key() {
    let account = p256_account(1);
    assert!(
        account_key(&account).is_ok(),
        "account_key rejected a 33-byte secp256r1 key: {:?}",
        account_key(&account)
    );
}

/// The current behaviour, pinned so a change upstream is noticed: every secp256r1 key is rejected.
#[test]
fn account_key_rejects_every_secp256r1_key() {
    for seed in 0..16 {
        assert!(matches!(
            account_key(&p256_account(seed)),
            Err(Error::AccountKey)
        ));
    }
}
