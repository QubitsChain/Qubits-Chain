use std::collections::{BTreeMap, HashMap};

use qubits_types::{Address, Hash, SignedTransaction};

pub const MAX_MEMPOOL_TRANSACTIONS: usize = 10_000;
pub const MAX_PER_SENDER: usize = 64;

struct Entry {
    tx: SignedTransaction,
    received_ms: u64,
}

#[derive(Default)]
pub struct Mempool {
    next_seq: u64,
    by_seq: BTreeMap<u64, Entry>,
    by_id: HashMap<Hash, u64>,
    per_sender: HashMap<Address, usize>,
}

impl Mempool {
    pub fn len(&self) -> usize {
        self.by_seq.len()
    }

    pub fn contains(&self, id: &Hash) -> bool {
        self.by_id.contains_key(id)
    }

    pub fn get(&self, id: &Hash) -> Option<&SignedTransaction> {
        self.by_id
            .get(id)
            .and_then(|seq| self.by_seq.get(seq))
            .map(|e| &e.tx)
    }

    pub fn sender_count(&self, sender: &Address) -> usize {
        self.per_sender.get(sender).copied().unwrap_or(0)
    }

    pub fn by_sender<'a>(
        &'a self,
        sender: &'a Address,
    ) -> impl Iterator<Item = &'a SignedTransaction> + 'a {
        self.iter().filter(move |tx| tx.tx.sender == *sender)
    }

    pub fn iter(&self) -> impl Iterator<Item = &SignedTransaction> {
        self.by_seq.values().map(|e| &e.tx)
    }

    pub fn insert(&mut self, tx: SignedTransaction, now_ms: u64) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.by_id.insert(tx.id(), seq);
        *self.per_sender.entry(tx.tx.sender).or_default() += 1;
        self.by_seq.insert(
            seq,
            Entry {
                tx,
                received_ms: now_ms,
            },
        );
    }

    pub fn remove(&mut self, id: &Hash) {
        if let Some(seq) = self.by_id.remove(id)
            && let Some(entry) = self.by_seq.remove(&seq)
            && let Some(count) = self.per_sender.get_mut(&entry.tx.tx.sender)
        {
            *count -= 1;
            if *count == 0 {
                self.per_sender.remove(&entry.tx.tx.sender);
            }
        }
    }

    pub fn expire(&mut self, now_ms: u64, ttl_ms: u64) -> usize {
        let expired: Vec<Hash> = self
            .by_seq
            .values()
            .filter(|e| e.received_ms + ttl_ms <= now_ms || e.tx.tx.valid_until_ms < now_ms)
            .map(|e| e.tx.id())
            .collect();
        for id in &expired {
            self.remove(id);
        }
        expired.len()
    }

    pub fn waiting_since(&self, now_ms: u64, age_ms: u64, limit: usize) -> Vec<SignedTransaction> {
        self.by_seq
            .values()
            .take_while(|e| e.received_ms + age_ms <= now_ms)
            .take(limit)
            .map(|e| e.tx.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use qubits_crypto::{SchemeId, SecretKey};
    use qubits_types::{AuthPolicy, Payload, Role, Transaction};

    use super::*;

    fn tx(seed: u8, nonce: u64) -> SignedTransaction {
        let sk = SecretKey::from_seed(SchemeId::MlDsa65, &[seed; 32]).unwrap();
        let policy = AuthPolicy::single(sk.public_key().clone());
        let t = Transaction {
            genesis_hash: Hash([1; 32]),
            sender: policy.address(),
            nonce,
            fee: 1,
            valid_until_ms: u64::MAX,
            role: Role::Owner,
            payload: Payload::CancelPending { id: 0 },
        };
        SignedTransaction::sign(t, &policy, None, &[&sk]).unwrap()
    }

    #[test]
    fn expiry_and_waiting_follow_arrival_time() {
        let mut pool = Mempool::default();
        let (a, b, c) = (tx(1, 0), tx(1, 1), tx(2, 0));
        pool.insert(a.clone(), 1_000);
        pool.insert(b.clone(), 2_000);
        pool.insert(c.clone(), 3_000);
        assert_eq!(pool.sender_count(&a.tx.sender), 2);

        assert_eq!(
            pool.waiting_since(3_500, 1_000, 10),
            vec![a.clone(), b.clone()]
        );
        assert_eq!(pool.waiting_since(3_500, 1_000, 1), vec![a.clone()]);
        assert!(pool.waiting_since(1_500, 1_000, 10).is_empty());

        assert_eq!(pool.expire(3_000, 1_500), 1, "only the first is old enough");
        assert!(!pool.contains(&a.id()));
        assert_eq!(pool.sender_count(&a.tx.sender), 1);
        assert_eq!(pool.expire(10_000, 1_500), 2);
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.sender_count(&c.tx.sender), 0);
    }

    #[test]
    fn a_transaction_past_its_validity_is_dropped_however_new_it_is() {
        let mut pool = Mempool::default();
        let mut short_lived = tx(1, 0);
        short_lived.tx.valid_until_ms = 2_000;
        let lasting = tx(2, 0);
        pool.insert(short_lived.clone(), 1_900);
        pool.insert(lasting.clone(), 1_900);
        assert_eq!(pool.expire(2_001, 60_000), 1);
        assert!(!pool.contains(&short_lived.id()));
        assert!(pool.contains(&lasting.id()));
    }
}
