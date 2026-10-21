//! A SHA-256 [`Hasher`] that records every preimage it hashes.
//!
//! Every verification routine in the clearing crate is generic over its hasher. Running a
//! routine with [`TracingSha256`] instead of [`Sha256`] yields the exact byte strings the crate
//! hashes, in order, so a contract can be checked against the crate's own verification path
//! instead of a re-derivation of it. The digest type is the crate's `sha256::Digest`, so values
//! produced under either hasher are interchangeable.

use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use std::sync::Mutex;

/// One SHA-256 invocation: the parts the crate passed, in order, and the resulting digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hashed {
    pub parts: Vec<Vec<u8>>,
    pub digest: Digest,
}

impl Hashed {
    /// The full preimage, which is the plain concatenation of the parts.
    pub fn preimage(&self) -> Vec<u8> {
        self.parts.concat()
    }
}

// A process-wide log rather than a thread-local one, because nothing guarantees the caller and
// the hasher run on the same thread. Recording is never nested.
static LOG: Mutex<Option<Vec<Hashed>>> = Mutex::new(None);

fn push(parts: &[&[u8]], digest: Digest) {
    if let Some(log) = LOG.lock().unwrap().as_mut() {
        log.push(Hashed {
            parts: parts.iter().map(|part| part.to_vec()).collect(),
            digest,
        });
    }
}

/// Runs `f` and returns its result together with every hash [`TracingSha256`] computed.
pub fn record<T>(f: impl FnOnce() -> T) -> (T, Vec<Hashed>) {
    {
        let mut log = LOG.lock().unwrap();
        assert!(log.is_none(), "hash recording is not reentrant");
        *log = Some(Vec::new());
    }
    let value = f();
    let log = LOG.lock().unwrap().take().expect("recording was started");
    (value, log)
}

/// SHA-256 with preimage recording. Outside [`record`] it behaves exactly like [`Sha256`].
#[derive(Default)]
pub struct TracingSha256 {
    parts: Vec<Vec<u8>>,
}

impl Hasher for TracingSha256 {
    type Digest = Digest;

    fn hash(parts: &[&[u8]]) -> Digest {
        let digest = Sha256::hash(parts);
        push(parts, digest);
        digest
    }

    fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> (Digest, Digest) {
        (Self::hash(left), Self::hash(right))
    }

    fn update(&mut self, bytes: &[u8]) -> &mut Self {
        self.parts.push(bytes.to_vec());
        self
    }

    fn finalize(self) -> (Self, Digest) {
        let parts = self.parts.iter().map(Vec::as_slice).collect::<Vec<_>>();
        (Self::default(), Self::hash(&parts))
    }
}
