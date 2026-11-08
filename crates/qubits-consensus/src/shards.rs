//! Spreads a large proposal so that no validator uploads more than about three copies of it.
//!
//! A leader sending a block to everyone uploads it n-1 times, which caps a chain at a fraction of
//! one uplink. Here it sends each validator one Reed-Solomon shard, each validator passes its
//! shard on to all others, and any n-2f shards rebuild the message. Up to f validators can drop
//! theirs and everyone still ends up with enough.
//!
//! This is transport only. What comes out is a signed proposal like any other, so a leader lying
//! about shards can waste its own round and nothing else: whoever can't rebuild the block fetches
//! it once a certificate names it.

use std::collections::{BTreeMap, BTreeSet};

use borsh::{BorshDeserialize, BorshSerialize};
use qubits_types::Hash;

use crate::types::{Round, ValidatorIndex};

/// What a leader may upload per block before shards win: at 1 Gbit/s about 50 ms, the time the
/// extra hop costs on a network spanning continents.
const DIRECT_BYTES: usize = 6 * 1024 * 1024;
const MAX_SIZE: u32 = 16 * 1024 * 1024;
const MAX_HELD_BYTES: usize = 128 * 1024 * 1024;
const ROUNDS_BEHIND: Round = 8;
const ROUNDS_AHEAD: Round = 64;
const ROOTS_PER_ROUND: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Shard {
    pub round: Round,
    pub proposer: ValidatorIndex,
    pub root: Hash,
    pub size: u32,
    pub index: u16,
    pub proof: Vec<Hash>,
    pub data: Vec<u8>,
}

/// How many shards rebuild a message: enough that the honest validators alone hold them.
pub fn data_shards(n: usize) -> usize {
    n - 2 * ((n - 1) / 3)
}

pub fn worthwhile(bytes: usize, n: usize) -> bool {
    n >= 4 && bytes.saturating_mul(n - 1) > DIRECT_BYTES && bytes <= MAX_SIZE as usize
}

fn shard_len(size: usize, k: usize) -> usize {
    size.div_ceil(k).next_multiple_of(2).max(2)
}

fn leaf(index: u16, data: &[u8]) -> Hash {
    let mut bytes = Vec::with_capacity(data.len() + 2);
    bytes.extend_from_slice(&index.to_le_bytes());
    bytes.extend_from_slice(data);
    Hash::digest("qubits.sh 2026-11 shard leaf", &bytes)
}

fn node(left: &Hash, right: &Hash) -> Hash {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&left.0);
    bytes[32..].copy_from_slice(&right.0);
    Hash::digest("qubits.sh 2026-11 shard node", &bytes)
}

fn seal(tree: &Hash, size: u32, round: Round, proposer: ValidatorIndex) -> Hash {
    let bytes = borsh::to_vec(&(tree, size, round, proposer)).expect("encoding cannot fail");
    Hash::digest("qubits.sh 2026-11 shard root", &bytes)
}

fn depth(n: usize) -> usize {
    n.next_power_of_two().trailing_zeros() as usize
}

/// Cuts a message into one shard per validator; shard `i` goes to validator `i`.
pub fn split(bytes: &[u8], round: Round, proposer: ValidatorIndex, n: usize) -> Vec<Shard> {
    let k = data_shards(n);
    let len = shard_len(bytes.len(), k);
    let mut padded = bytes.to_vec();
    padded.resize(len * k, 0);
    let recovery = reed_solomon_simd::encode(k, n - k, padded.chunks(len))
        .expect("shard counts and sizes are in range");
    let shards: Vec<&[u8]> = padded
        .chunks(len)
        .chain(recovery.iter().map(Vec::as_slice))
        .collect();

    let mut level: Vec<Hash> = shards
        .iter()
        .enumerate()
        .map(|(i, data)| leaf(i as u16, data))
        .collect();
    level.resize(n.next_power_of_two(), Hash::ZERO);
    let mut levels = vec![level];
    while levels.last().expect("starts with one").len() > 1 {
        let next = levels
            .last()
            .expect("starts with one")
            .chunks(2)
            .map(|pair| node(&pair[0], &pair[1]))
            .collect();
        levels.push(next);
    }
    let size = bytes.len() as u32;
    let root = seal(&levels[levels.len() - 1][0], size, round, proposer);
    shards
        .iter()
        .enumerate()
        .map(|(i, data)| Shard {
            round,
            proposer,
            root,
            size,
            index: i as u16,
            proof: levels[..levels.len() - 1]
                .iter()
                .enumerate()
                .map(|(height, level)| level[(i >> height) ^ 1])
                .collect(),
            data: data.to_vec(),
        })
        .collect()
}

impl Shard {
    fn valid(&self, n: usize) -> bool {
        let k = data_shards(n);
        if usize::from(self.index) >= n
            || self.size == 0
            || self.size > MAX_SIZE
            || self.data.len() != shard_len(self.size as usize, k)
            || self.proof.len() != depth(n)
        {
            return false;
        }
        let mut hash = leaf(self.index, &self.data);
        for (height, sibling) in self.proof.iter().enumerate() {
            hash = if (usize::from(self.index) >> height) & 1 == 0 {
                node(&hash, sibling)
            } else {
                node(sibling, &hash)
            };
        }
        seal(&hash, self.size, self.round, self.proposer) == self.root
    }
}

struct Partial {
    size: u32,
    shards: BTreeMap<u16, (ValidatorIndex, Vec<u8>)>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Received {
    /// this is our shard, straight from the proposer: pass it on to everyone
    pub relay: bool,
    /// the rebuilt message, once
    pub message: Option<Vec<u8>>,
}

pub struct Assembler {
    n: usize,
    me: ValidatorIndex,
    partial: BTreeMap<(Round, ValidatorIndex, Hash), Partial>,
    rebuilt: BTreeSet<(Round, ValidatorIndex, Hash)>,
    relayed: BTreeMap<(Round, ValidatorIndex), Vec<Hash>>,
    held: BTreeMap<ValidatorIndex, usize>,
}

impl Assembler {
    pub fn new(n: usize, me: ValidatorIndex) -> Assembler {
        Assembler {
            n,
            me,
            partial: BTreeMap::new(),
            rebuilt: BTreeSet::new(),
            relayed: BTreeMap::new(),
            held: BTreeMap::new(),
        }
    }

    /// `from` is the authenticated sender. Each validator passes on only the shard with its own
    /// index, so a sender holds at most one slot per message.
    pub fn add(&mut self, from: ValidatorIndex, shard: Shard, round: Round) -> Received {
        let mut received = Received::default();
        let in_window = shard.round.saturating_add(ROUNDS_BEHIND) >= round
            && shard.round <= round.saturating_add(ROUNDS_AHEAD);
        let sender_allowed = from == shard.index || from == shard.proposer;
        if !in_window
            || !sender_allowed
            || usize::from(shard.proposer) >= self.n
            || !shard.valid(self.n)
        {
            return received;
        }
        let key = (shard.round, shard.proposer, shard.root);
        if from == shard.proposer && shard.index == self.me {
            let roots = self
                .relayed
                .entry((shard.round, shard.proposer))
                .or_default();
            if !roots.contains(&shard.root) && roots.len() < ROOTS_PER_ROUND {
                roots.push(shard.root);
                received.relay = true;
            }
        }
        if self.rebuilt.contains(&key) {
            return received;
        }
        let held = self.held.entry(from).or_default();
        if *held + shard.data.len() > MAX_HELD_BYTES {
            return received;
        }
        let partial = self.partial.entry(key).or_insert(Partial {
            size: shard.size,
            shards: BTreeMap::new(),
        });
        if partial.shards.contains_key(&shard.index) {
            return received;
        }
        *held += shard.data.len();
        partial.shards.insert(shard.index, (from, shard.data));

        let k = data_shards(self.n);
        if partial.shards.len() >= k {
            let partial = self.partial.remove(&key).expect("just used");
            received.message = rebuild(&partial, k, self.n);
            self.rebuilt.insert(key);
            self.release(&partial);
        }
        received
    }

    fn release(&mut self, partial: &Partial) {
        for (from, data) in partial.shards.values() {
            if let Some(held) = self.held.get_mut(from) {
                *held = held.saturating_sub(data.len());
            }
        }
    }

    pub fn forget_before(&mut self, round: Round) {
        let cutoff = round.saturating_sub(ROUNDS_BEHIND);
        let stale: Vec<_> = self
            .partial
            .keys()
            .filter(|(r, _, _)| *r < cutoff)
            .copied()
            .collect();
        for key in stale {
            let partial = self.partial.remove(&key).expect("just listed");
            self.release(&partial);
        }
        self.rebuilt.retain(|(r, _, _)| *r >= cutoff);
        self.relayed.retain(|(r, _), _| *r >= cutoff);
    }
}

fn rebuild(partial: &Partial, k: usize, n: usize) -> Option<Vec<u8>> {
    let original = partial
        .shards
        .iter()
        .filter(|(i, _)| usize::from(**i) < k)
        .map(|(i, (_, data))| (usize::from(*i), data));
    let recovery = partial
        .shards
        .iter()
        .filter(|(i, _)| usize::from(**i) >= k)
        .map(|(i, (_, data))| (usize::from(*i) - k, data));
    let mut restored = reed_solomon_simd::decode(k, n - k, original, recovery).ok()?;
    let len = shard_len(partial.size as usize, k);
    let mut bytes = Vec::with_capacity(len * k);
    for i in 0..k {
        match partial.shards.get(&(i as u16)) {
            Some((_, data)) => bytes.extend_from_slice(data),
            None => bytes.extend_from_slice(&restored.remove(&i)?),
        }
    }
    bytes.truncate(partial.size as usize);
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn honest_validators_alone_hold_enough_shards() {
        for n in 4..=100 {
            let f = (n - 1) / 3;
            assert!(data_shards(n) <= n - f, "{n}");
            assert!(data_shards(n) > f, "{n}: f validators can't rebuild alone");
            let upload = n as f64 / data_shards(n) as f64;
            assert!(upload < 3.1, "{n}: everyone uploads {upload} copies");
        }
    }

    #[test]
    fn any_big_enough_set_of_shards_rebuilds_the_message() {
        for (n, len) in [(4, 1), (4, 1_000), (7, 12_345), (10, 99_999), (50, 1 << 20)] {
            let bytes = message(len);
            let shards = split(&bytes, 9, 1, n);
            assert_eq!(shards.len(), n);
            let k = data_shards(n);
            for start in [0, 1, n - k] {
                let mut assembler = Assembler::new(n, 0);
                let mut rebuilt = None;
                for shard in shards[start..start + k].iter().cloned() {
                    let from = shard.index;
                    assert!(rebuilt.is_none());
                    rebuilt = assembler.add(from, shard, 9).message;
                }
                assert_eq!(
                    rebuilt.as_ref(),
                    Some(&bytes),
                    "n={n} len={len} from {start}"
                );
            }
        }
    }

    #[test]
    fn a_shard_is_passed_on_once_and_only_if_it_is_ours_and_from_the_proposer() {
        let shards = split(&message(1_000), 3, 2, 4);
        let mut a = Assembler::new(4, 0);
        assert!(!a.add(1, shards[1].clone(), 3).relay, "someone else's");
        assert!(
            !a.add(0, shards[0].clone(), 3).relay,
            "not from the proposer"
        );
        let mut a = Assembler::new(4, 0);
        assert!(a.add(2, shards[0].clone(), 3).relay);
        assert!(!a.add(2, shards[0].clone(), 3).relay, "only once");
    }

    #[test]
    fn a_proposer_can_make_validators_relay_only_so_much_in_a_round() {
        let mut a = Assembler::new(4, 0);
        let relayed = (0..10u8)
            .filter(|i| {
                let shards = split(&message(100 + usize::from(*i)), 3, 2, 4);
                a.add(2, shards[0].clone(), 3).relay
            })
            .count();
        assert_eq!(relayed, ROOTS_PER_ROUND);
    }

    #[test]
    fn tampered_or_misplaced_shards_are_ignored() {
        let shards = split(&message(1_000), 3, 2, 4);
        let tried = |shard: Shard, from| {
            let mut a = Assembler::new(4, 0);
            a.add(from, shard, 3);
            a.partial.is_empty()
        };
        let mut flipped = shards[1].clone();
        flipped.data[0] ^= 1;
        assert!(tried(flipped, 1));
        let mut moved = shards[1].clone();
        moved.index = 3;
        assert!(tried(moved, 3));
        let mut resized = shards[1].clone();
        resized.size += 2;
        assert!(tried(resized, 1));
        let mut replayed = shards[1].clone();
        replayed.round = 4;
        assert!(tried(replayed, 1));
        assert!(
            tried(shards[1].clone(), 3),
            "only validator 1 relays shard 1"
        );
        assert!(!tried(shards[1].clone(), 1));
    }

    #[test]
    fn nonsense_never_panics() {
        let mut a = Assembler::new(7, 0);
        for size in [0, 1, u32::MAX] {
            let shard = Shard {
                round: Round::MAX,
                proposer: u16::MAX,
                root: Hash::ZERO,
                size,
                index: u16::MAX,
                proof: vec![],
                data: vec![],
            };
            a.add(u16::MAX, shard, 3);
        }
        assert!(a.partial.is_empty());
    }

    #[test]
    fn a_leader_committing_to_garbage_only_wastes_its_own_round() {
        let n = 4;
        let k = data_shards(n);
        let mut shards = split(&message(1_000), 3, 2, n);
        let other = split(&message(2_000), 3, 2, n);
        shards[1] = other[1].clone();
        let mut a = Assembler::new(n, 0);
        let mut rebuilt = Vec::new();
        for shard in shards.iter().take(k).cloned() {
            let from = shard.index;
            rebuilt.extend(a.add(from, shard, 3).message);
        }
        assert!(rebuilt.is_empty(), "two roots, neither complete");
    }

    #[test]
    fn memory_is_bounded_per_sender_and_by_round() {
        let mut a = Assembler::new(4, 0);
        for round in 1..=64 {
            let shards = split(&message(4 * 1024 * 1024), round, 2, 4);
            a.add(1, shards[1].clone(), 1);
        }
        assert!(a.held[&1] <= MAX_HELD_BYTES);
        a.forget_before(1_000);
        assert!(a.partial.is_empty());
        assert_eq!(a.held[&1], 0);
    }

    #[test]
    fn small_messages_and_small_networks_go_directly() {
        assert!(!worthwhile(1_000, 50));
        assert!(worthwhile(1 << 20, 50));
        assert!(!worthwhile(1 << 20, 4));
        assert!(!worthwhile(1 << 30, 3));
        assert!(worthwhile(8 << 20, 4));
    }
}
