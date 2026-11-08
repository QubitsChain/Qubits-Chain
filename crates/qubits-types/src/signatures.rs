use std::collections::HashSet;
use std::sync::Mutex;
use std::thread;

use qubits_crypto::{Domain, PublicKey, Signature};

use crate::hash::context;
use crate::{Error, Hash};

const GENERATION: usize = 200_000;
const PARALLEL_FROM: usize = 8;

#[derive(Default)]
struct Generations {
    young: HashSet<Hash>,
    old: HashSet<Hash>,
}

/// Remembers which signatures verified. A validator checks a transaction when it arrives, and
/// again in every block built on it; ML-DSA makes that the most expensive step of a block.
/// An entry is a fact about a key, a message and a signature, so it never goes stale. Whether
/// that key may sign for the account is still decided at execution.
#[derive(Default)]
pub struct SignatureCache {
    seen: Mutex<Generations>,
}

fn entry(key: &PublicKey, message: &[u8], signature: &Signature) -> Hash {
    let mut bytes = Vec::with_capacity(message.len() + 5_400);
    bytes.extend_from_slice(key.as_raw());
    bytes.extend_from_slice(&(message.len() as u64).to_le_bytes());
    bytes.extend_from_slice(message);
    bytes.extend_from_slice(signature.as_raw());
    Hash::digest(context::SIGNATURE_CACHE, &bytes)
}

impl SignatureCache {
    fn known(&self, entry: &Hash) -> bool {
        let seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.young.contains(entry) || seen.old.contains(entry)
    }

    fn remember(&self, entry: Hash) {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if seen.young.len() >= GENERATION {
            seen.old = std::mem::take(&mut seen.young);
        }
        seen.young.insert(entry);
    }

    pub fn verify(
        &self,
        key: &PublicKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), Error> {
        let entry = entry(key, message, signature);
        if self.known(&entry) {
            return Ok(());
        }
        key.verify(Domain::Transaction, message, signature)?;
        self.remember(entry);
        Ok(())
    }

    /// Verifies on all cores what isn't known yet. Failures are left for execution to report.
    pub fn prewarm(&self, jobs: &[(&PublicKey, &[u8], &Signature)]) {
        let missing: Vec<_> = jobs
            .iter()
            .filter(|(key, message, signature)| !self.known(&entry(key, message, signature)))
            .collect();
        let threads = thread::available_parallelism().map_or(1, usize::from);
        if missing.len() < PARALLEL_FROM || threads == 1 {
            return;
        }
        thread::scope(|scope| {
            for chunk in missing.chunks(missing.len().div_ceil(threads)) {
                scope.spawn(move || {
                    for (key, message, signature) in chunk {
                        let _ = self.verify(key, message, signature);
                    }
                });
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use qubits_crypto::{SchemeId, SecretKey};

    use super::*;

    #[test]
    fn only_signatures_that_verified_are_remembered() {
        let key = SecretKey::from_seed(SchemeId::MlDsa65, &[1; 32]).unwrap();
        let signature = key.sign(Domain::Transaction, b"pay bob").unwrap();
        let cache = SignatureCache::default();

        assert!(
            cache
                .verify(key.public_key(), b"pay eve", &signature)
                .is_err()
        );
        assert!(
            cache
                .verify(key.public_key(), b"pay eve", &signature)
                .is_err(),
            "a failure is not remembered as a success"
        );
        cache
            .verify(key.public_key(), b"pay bob", &signature)
            .unwrap();
        cache
            .verify(key.public_key(), b"pay bob", &signature)
            .unwrap();

        let other = SecretKey::from_seed(SchemeId::MlDsa65, &[2; 32]).unwrap();
        assert!(
            cache
                .verify(other.public_key(), b"pay bob", &signature)
                .is_err(),
            "an entry is bound to its key"
        );
    }

    #[test]
    fn a_signature_for_another_domain_is_not_cached_as_a_transaction() {
        let key = SecretKey::from_seed(SchemeId::MlDsa65, &[1; 32]).unwrap();
        let signature = key.sign(Domain::Message, b"pay bob").unwrap();
        let cache = SignatureCache::default();
        assert!(
            cache
                .verify(key.public_key(), b"pay bob", &signature)
                .is_err()
        );
    }

    #[test]
    fn prewarming_keeps_good_signatures_and_drops_bad_ones() {
        let key = SecretKey::from_seed(SchemeId::MlDsa65, &[1; 32]).unwrap();
        let messages: Vec<Vec<u8>> = (0..32u8).map(|i| vec![i; 16]).collect();
        let signatures: Vec<_> = messages
            .iter()
            .map(|m| key.sign(Domain::Transaction, m).unwrap())
            .collect();
        let jobs: Vec<_> = messages
            .iter()
            .zip(&signatures)
            .map(|(m, s)| (key.public_key(), m.as_slice(), s))
            .collect();
        let cache = SignatureCache::default();
        cache.prewarm(&jobs);
        for (k, m, s) in &jobs {
            assert!(cache.known(&entry(k, m, s)));
        }
        let bad = (key.public_key(), b"other".as_slice(), &signatures[0]);
        cache.prewarm(&vec![bad; 16]);
        assert!(!cache.known(&entry(bad.0, bad.1, bad.2)));
    }
}
