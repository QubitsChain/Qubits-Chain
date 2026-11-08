//! Consensus over a simulated wide-area network, with real signatures. Prints what a network of
//! each size can do; assumed latencies, 1 Gbit/s uplinks, no CPU time.
//!
//! cargo test --release -p qubits-consensus --test wan -- --ignored --nocapture

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap};

use borsh::{BorshDeserialize, BorshSerialize};
use qubits_consensus::shards::{data_shards, worthwhile};
use qubits_consensus::*;
use qubits_crypto::{SchemeId, SecretKey};
use qubits_types::Hash;

const UPLINK_BYTES_PER_MS: u64 = 125_000;
const RUN_MS: u64 = 6_000;
const WARMUP_MS: u64 = 1_000;

/// One-way, in ms: Frankfurt, Virginia, Tokyo.
const REGIONS: [[u64; 3]; 3] = [[1, 45, 112], [45, 1, 75], [112, 75, 1]];

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct Payload {
    made_ms: u64,
    tag: u64,
}

#[derive(Default)]
struct WanApp {
    made: HashMap<u64, u64>,
}

impl App<Payload> for WanApp {
    fn propose(&mut self, _: &Hash, height: u64, round: Round, now: u64) -> Payload {
        Payload {
            made_ms: now,
            tag: round * 1_000 + height,
        }
    }

    fn verify(&mut self, _: &Hash, _: &Block<Payload>, _: u64) -> bool {
        true
    }

    fn commit(&mut self, chain: &[Final<'_, Payload>], _: &FinalityProof) {
        for f in chain {
            self.made.insert(f.block.height, f.block.payload.made_ms);
        }
    }
}

enum Event {
    Message(Box<Message<Payload>>),
    /// a shard of `spread[0]`, passed on if it's the receiver's own
    Shard(usize, bool),
}

struct Wan {
    nodes: Vec<Engine<Payload, WanApp>>,
    now: u64,
    seq: u64,
    queue: BinaryHeap<Reverse<(u64, u64)>>,
    events: BTreeMap<u64, (usize, usize, Event)>,
    spread: Vec<Message<Payload>>,
    shards_held: HashMap<(usize, usize), usize>,
    free_at: Vec<u64>,
    sent: Vec<u64>,
    payload_bytes: u64,
    use_shards: bool,
    latencies: Vec<u64>,
    commits: Vec<u64>,
}

fn size(msg: &Message<Payload>, payload_bytes: u64) -> u64 {
    let carries_block = matches!(msg, Message::Proposal(_) | Message::BlockResponse(_));
    borsh::object_length(msg).unwrap() as u64 + if carries_block { payload_bytes } else { 0 }
}

impl Wan {
    fn new(n: usize, payload_bytes: u64, use_shards: bool) -> Wan {
        let keys: Vec<SecretKey> = (0..n)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
                SecretKey::from_seed(SchemeId::MlDsa65, &seed).unwrap()
            })
            .collect();
        let validators =
            ValidatorSet::new(keys.iter().map(|k| k.public_key().clone()).collect()).unwrap();
        let chain = Hash::digest("wan", &[n as u8]);
        let mut wan = Wan {
            nodes: Vec::new(),
            now: 0,
            seq: 0,
            queue: BinaryHeap::new(),
            events: BTreeMap::new(),
            spread: Vec::new(),
            shards_held: HashMap::new(),
            free_at: vec![0; n],
            sent: vec![0; n],
            payload_bytes,
            use_shards,
            latencies: Vec::new(),
            commits: Vec::new(),
        };
        let mut pending = Vec::new();
        for (i, key) in keys.into_iter().enumerate() {
            let cfg = Config {
                me: i as ValidatorIndex,
                key,
                validators: validators.clone(),
                chain,
                round_timeout_ms: 2_000,
                min_block_interval_ms: 0,
            };
            let (engine, out) = Engine::new(cfg, WanApp::default(), Start::genesis(chain), 0);
            wan.nodes.push(engine);
            pending.push((i, out));
        }
        for (i, out) in pending {
            wan.dispatch(i, out);
        }
        wan
    }

    fn deliver(&mut self, from: usize, to: usize, msg: Message<Payload>) {
        let bytes = size(&msg, self.payload_bytes);
        self.transmit(from, to, Event::Message(Box::new(msg)), bytes);
    }

    fn transmit(&mut self, from: usize, to: usize, event: Event, bytes: u64) {
        if self.now >= WARMUP_MS {
            self.sent[from] += bytes;
        }
        let start = self.free_at[from].max(self.now);
        self.free_at[from] = start + bytes.div_ceil(UPLINK_BYTES_PER_MS);
        let at = self.free_at[from] + REGIONS[from % 3][to % 3];
        self.seq += 1;
        self.events.insert(self.seq, (from, to, event));
        self.queue.push(Reverse((at, self.seq)));
    }

    fn shard_bytes(&self, id: usize) -> u64 {
        let n = self.nodes.len();
        size(&self.spread[id], self.payload_bytes) / data_shards(n) as u64 + 300
    }

    fn broadcast(&mut self, from: usize, msg: Message<Payload>) {
        let n = self.nodes.len();
        let bytes = size(&msg, self.payload_bytes) as usize;
        if !self.use_shards || !matches!(msg, Message::Proposal(_)) || !worthwhile(bytes, n) {
            for to in 0..n {
                if to != from {
                    self.deliver(from, to, msg.clone());
                }
            }
            return;
        }
        let id = self.spread.len();
        self.spread.push(msg);
        let shard = self.shard_bytes(id);
        for to in 0..n {
            if to != from {
                self.transmit(from, to, Event::Shard(id, true), shard);
            }
        }
    }

    fn on_shard(&mut self, from: usize, to: usize, id: usize, relay: bool) {
        let n = self.nodes.len();
        if relay {
            let shard = self.shard_bytes(id);
            for peer in 0..n {
                if peer != to && peer != from {
                    self.transmit(to, peer, Event::Shard(id, false), shard);
                }
            }
        }
        let held = self.shards_held.entry((to, id)).or_default();
        *held += 1;
        if *held == data_shards(n) {
            let msg = self.spread[id].clone();
            let out = self.nodes[to].handle(from as ValidatorIndex, msg, self.now);
            self.dispatch(to, out);
        }
    }

    fn dispatch(&mut self, from: usize, outputs: Vec<Output<Payload>>) {
        for output in outputs {
            match output {
                Output::Send(to, msg) => self.deliver(from, usize::from(to), msg),
                Output::Broadcast(msg) => self.broadcast(from, msg),
                Output::Committed { height, .. } if self.now >= WARMUP_MS => {
                    let made = self.nodes[from].app().made[&height];
                    self.latencies.push(self.now - made);
                    if from == 0 {
                        self.commits.push(self.now);
                    }
                }
                _ => {}
            }
        }
    }

    fn run(&mut self) {
        let tick_every = 5;
        let mut next_tick = tick_every;
        while self.now < RUN_MS {
            let next_event = self.queue.peek().map(|Reverse((t, _))| *t);
            match next_event {
                Some(t) if t <= next_tick => {
                    self.now = t;
                    let Reverse((_, seq)) = self.queue.pop().unwrap();
                    match self.events.remove(&seq).unwrap() {
                        (from, to, Event::Message(msg)) => {
                            let out = self.nodes[to].handle(from as ValidatorIndex, *msg, t);
                            self.dispatch(to, out);
                        }
                        (from, to, Event::Shard(id, relay)) => self.on_shard(from, to, id, relay),
                    }
                }
                _ => {
                    self.now = next_tick;
                    for i in 0..self.nodes.len() {
                        let out = self.nodes[i].tick(next_tick);
                        self.dispatch(i, out);
                    }
                    next_tick += tick_every;
                }
            }
        }
    }

    fn report(&mut self, n: usize) {
        let blocks = self.commits.len() as u64;
        let seconds = (RUN_MS - WARMUP_MS) as f64 / 1000.0;
        self.latencies.sort_unstable();
        let at = |p: f64| {
            self.latencies
                .get((self.latencies.len() as f64 * p) as usize)
                .copied()
                .unwrap_or(0)
        };
        let mean_sent = self.sent.iter().sum::<u64>() as f64 / n as f64 / seconds;
        let max_sent = *self.sent.iter().max().unwrap() as f64 / seconds;
        println!(
            "{n:>3} {:>8} KiB {:>7.0} ms {:>6} ms {:>6} ms {:>9.2} MB/s {:>9.1} Mbit/s {:>9.1} Mbit/s",
            self.payload_bytes / 1024,
            1000.0 * seconds / blocks.max(1) as f64,
            at(0.5),
            at(0.99),
            blocks as f64 * self.payload_bytes as f64 / seconds / 1_000_000.0,
            mean_sent * 8.0 / 1_000_000.0,
            max_sent * 8.0 / 1_000_000.0,
        );
    }
}

#[test]
#[ignore = "prints a table, takes a minute in release"]
fn wide_area_table() {
    println!(
        "  n    payload     block    final    final    throughput     upload avg     upload max"
    );
    println!("                  period      p50      p99");
    for n in [4, 10, 25, 50] {
        for payload in [0, 64 * 1024, 1024 * 1024, 8 * 1024 * 1024] {
            let mut wan = Wan::new(n, payload, true);
            wan.run();
            wan.report(n);
        }
    }
}
