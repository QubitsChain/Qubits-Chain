use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};

use borsh::{BorshDeserialize, BorshSerialize};
use qubits_consensus::*;
use qubits_crypto::{SchemeId, SecretKey};
use qubits_types::Hash;

const TIMEOUT_MS: u64 = 1_000;

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct Payload {
    tag: u64,
    valid: bool,
}

#[derive(Default)]
struct SimApp {
    invalid_proposals: bool,
    idle: bool,
    committed: Vec<(Hash, u64)>,
    proposers: Vec<(u64, ValidatorIndex)>,
    verified: usize,
    finality_proofs: usize,
}

impl App<Payload> for SimApp {
    fn propose(&mut self, _parent: &Hash, height: u64, round: Round, _now: u64) -> Payload {
        Payload {
            tag: round * 1_000 + height,
            valid: !self.invalid_proposals,
        }
    }

    fn verify(&mut self, _id: &Hash, block: &Block<Payload>, _now: u64) -> bool {
        self.verified += 1;
        block.payload.valid
    }

    fn has_work(&self, _parent: &Hash) -> bool {
        !self.idle
    }

    fn commit(&mut self, chain: &[Final<'_, Payload>], proof: &FinalityProof) {
        for f in chain {
            if let Some((_, h)) = self.committed.last() {
                assert_eq!(*h + 1, f.block.height, "commits must be consecutive");
            }
            self.committed.push((f.id, f.block.height));
            self.proposers.push((f.block.height, f.block.proposer));
        }
        assert_eq!(
            proof.tip,
            chain.last().unwrap().id,
            "the proof is for the tip"
        );
        self.finality_proofs += 1;
    }
}

type Node = Engine<Payload, SimApp>;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }

    fn chance(&mut self, permille: u64) -> bool {
        self.next() % 1000 < permille
    }
}

struct Sim {
    nodes: Vec<Option<Node>>,
    keys: Vec<SecretKey>,
    chain: Hash,
    now: u64,
    seq: u64,
    queue: BinaryHeap<Reverse<(u64, u64)>>,
    events: BTreeMap<u64, (usize, usize, Message<Payload>)>,
    rng: Rng,
    delay: (u64, u64),
    drop_permille: u64,
    partition: Option<Vec<bool>>,
    equivocator: Option<usize>,
    deaf: Option<usize>,
    delivered: u64,
}

impl Sim {
    fn new(n: usize, seed: u64) -> Sim {
        let keys: Vec<SecretKey> = (0..n)
            .map(|i| SecretKey::from_seed(SchemeId::MlDsa65, &[i as u8 + 1; 32]).unwrap())
            .collect();
        let validators =
            ValidatorSet::new(keys.iter().map(|k| k.public_key().clone()).collect()).unwrap();
        let chain = Hash::digest("test chain", &seed.to_le_bytes());
        let mut sim = Sim {
            nodes: Vec::new(),
            keys: keys.clone(),
            chain,
            now: 0,
            seq: 0,
            queue: BinaryHeap::new(),
            events: BTreeMap::new(),
            rng: Rng(seed | 1),
            delay: (10, 100),
            drop_permille: 0,
            partition: None,
            equivocator: None,
            deaf: None,
            delivered: 0,
        };
        let mut pending = Vec::new();
        for (i, key) in keys.into_iter().enumerate() {
            let cfg = Config {
                me: i as ValidatorIndex,
                key,
                validators: validators.clone(),
                chain,
                round_timeout_ms: TIMEOUT_MS,
                min_block_interval_ms: 50,
            };
            let (engine, out) = Engine::new(cfg, SimApp::default(), Start::genesis(chain), 0);
            sim.nodes.push(Some(engine));
            pending.push((i, out));
        }
        for (i, out) in pending {
            sim.dispatch(i, out);
        }
        sim
    }

    fn crash(&mut self, i: usize) {
        self.nodes[i] = None;
    }

    fn honest(&self) -> impl Iterator<Item = (usize, &Node)> {
        self.nodes
            .iter()
            .enumerate()
            .filter(|(i, _)| Some(*i) != self.equivocator)
            .filter_map(|(i, n)| n.as_ref().map(|n| (i, n)))
    }

    fn schedule(&mut self, from: usize, to: usize, msg: Message<Payload>) {
        if self.nodes[to].is_none() || self.rng.chance(self.drop_permille) {
            return;
        }
        if self.deaf == Some(to) && matches!(msg, Message::Vote(_)) {
            return;
        }
        if let Some(groups) = &self.partition
            && groups[from] != groups[to]
        {
            return;
        }
        let at = self.now + self.rng.range(self.delay.0, self.delay.1);
        self.seq += 1;
        self.events.insert(self.seq, (from, to, msg));
        self.queue.push(Reverse((at, self.seq)));
    }

    fn dispatch(&mut self, from: usize, outputs: Vec<Output<Payload>>) {
        for output in outputs {
            match output {
                Output::Send(to, msg) => self.schedule(from, usize::from(to), msg),
                Output::Broadcast(msg) => {
                    let alternative = match (&msg, self.equivocator) {
                        (Message::Proposal(p), Some(e)) if e == from => Some(self.conflicting(p)),
                        _ => None,
                    };
                    for to in 0..self.nodes.len() {
                        if to == from {
                            continue;
                        }
                        let m = match &alternative {
                            Some(alt) if to % 2 == 1 => Message::Proposal(alt.clone()),
                            _ => msg.clone(),
                        };
                        self.schedule(from, to, m);
                    }
                }
                Output::PersistSafety(_) | Output::PersistBlock(_) | Output::Committed { .. } => {}
            }
        }
    }

    fn conflicting(&self, p: &Proposal<Payload>) -> Proposal<Payload> {
        let mut block = p.block.clone();
        block.payload.tag += 1;
        let key = &self.keys[usize::from(block.proposer)];
        Proposal::sign(block, p.justify.clone(), p.tc.clone(), key, &self.chain)
    }

    fn run(&mut self, until: u64) {
        let tick_every = 20;
        let mut next_tick = (self.now / tick_every + 1) * tick_every;
        loop {
            let next_event = self.queue.peek().map(|Reverse((t, _))| *t);
            let t = match next_event {
                Some(e) if e <= next_tick => e,
                _ => next_tick,
            };
            if t > until {
                self.now = until;
                return;
            }
            self.now = t;
            if next_event == Some(t) {
                let Reverse((_, seq)) = self.queue.pop().unwrap();
                let (from, to, msg) = self.events.remove(&seq).unwrap();
                if let Some(node) = self.nodes[to].as_mut() {
                    self.delivered += 1;
                    let out = node.handle(from as ValidatorIndex, msg, t);
                    self.dispatch(to, out);
                }
            } else {
                for i in 0..self.nodes.len() {
                    if let Some(node) = self.nodes[i].as_mut() {
                        let out = node.tick(t);
                        self.dispatch(i, out);
                    }
                }
                next_tick += tick_every;
            }
        }
    }

    fn committed(&self, i: usize) -> &[(Hash, u64)] {
        &self.nodes[i].as_ref().unwrap().app().committed
    }

    fn min_committed(&self) -> u64 {
        self.honest().map(|(_, n)| n.committed().1).min().unwrap()
    }

    fn assert_safe(&self) {
        let honest: Vec<usize> = self.honest().map(|(i, _)| i).collect();
        for &a in &honest {
            for &b in &honest {
                let (ca, cb) = (self.committed(a), self.committed(b));
                for (x, y) in ca.iter().zip(cb) {
                    assert_eq!(
                        x, y,
                        "validators {a} and {b} committed different blocks at height {}",
                        x.1
                    );
                }
            }
        }
    }
}

#[test]
fn four_validators_commit_steadily() {
    let mut sim = Sim::new(4, 1);
    sim.run(10_000);
    sim.assert_safe();
    let height = sim.min_committed();
    assert!(height >= 40, "only {height} blocks committed in 10 s");
    for (_, node) in sim.honest() {
        assert!(node.app().verified as u64 >= height);
        assert!(node.app().finality_proofs > 0);
    }
}

#[test]
fn single_validator_chain_commits() {
    let mut sim = Sim::new(1, 2);
    sim.run(2_000);
    assert!(sim.min_committed() >= 10);
}

#[test]
fn one_crashed_validator_of_four_is_tolerated() {
    let mut sim = Sim::new(4, 3);
    sim.crash(2);
    sim.run(30_000);
    sim.assert_safe();
    let height = sim.min_committed();
    assert!(height >= 15, "only {height} blocks with one validator down");
}

#[test]
fn validator_crashing_mid_run_is_tolerated() {
    let mut sim = Sim::new(4, 4);
    sim.run(5_000);
    let before = sim.min_committed();
    sim.crash(1);
    sim.run(30_000);
    sim.assert_safe();
    assert!(sim.min_committed() > before + 10);
}

#[test]
fn two_crashed_of_four_halts_without_forking() {
    let mut sim = Sim::new(4, 5);
    sim.run(3_000);
    let before = sim.min_committed();
    sim.crash(0);
    sim.crash(3);
    sim.run(20_000);
    sim.assert_safe();
    assert!(
        sim.min_committed() <= before + 2,
        "committed without a quorum"
    );
}

#[test]
fn equivocating_leader_cannot_cause_a_fork() {
    for seed in 10..14 {
        let mut sim = Sim::new(4, seed);
        sim.equivocator = Some(1);
        sim.run(20_000);
        sim.assert_safe();
        assert!(sim.min_committed() >= 10, "seed {seed}: liveness lost");
    }
}

#[test]
fn lost_messages_slow_but_do_not_stop_or_fork_the_chain() {
    let mut sim = Sim::new(4, 6);
    sim.drop_permille = 150;
    sim.run(60_000);
    sim.assert_safe();
    let height = sim.min_committed();
    assert!(height >= 10, "only {height} blocks with 15% message loss");
}

#[test]
fn partition_without_quorum_halts_then_heals() {
    let mut sim = Sim::new(4, 7);
    sim.run(3_000);
    sim.partition = Some(vec![true, true, false, false]);
    sim.run(4_000);
    let during = sim.min_committed();
    sim.run(15_000);
    sim.assert_safe();
    assert!(
        sim.min_committed() <= during + 2,
        "a 2|2 split must not make progress"
    );
    sim.partition = None;
    sim.run(45_000);
    sim.assert_safe();
    assert!(
        sim.min_committed() >= during + 10,
        "no progress after the partition healed"
    );
}

#[test]
fn minority_partition_falls_behind_and_catches_up() {
    let mut sim = Sim::new(4, 8);
    sim.partition = Some(vec![true, true, true, false]);
    sim.run(20_000);
    sim.assert_safe();
    let isolated = sim.nodes[3].as_ref().unwrap().committed().1;
    let majority = sim.nodes[0].as_ref().unwrap().committed().1;
    assert!(majority >= 5, "the 3-validator side should keep committing");
    assert!(isolated < majority);
    sim.partition = None;
    sim.run(30_000);
    sim.assert_safe();
    let caught_up = sim.nodes[3].as_ref().unwrap().committed().1;
    assert!(
        caught_up > majority,
        "the isolated validator never caught up"
    );
}

#[test]
fn leader_proposing_invalid_blocks_is_skipped() {
    let mut sim = Sim::new(4, 9);
    sim.nodes[2].as_mut().unwrap().app_mut().invalid_proposals = true;
    sim.run(30_000);
    sim.assert_safe();
    assert!(sim.min_committed() >= 15);
    for (i, _) in sim.honest() {
        let node = sim.nodes[i].as_ref().unwrap();
        assert!(node.app().committed.len() as u64 == node.committed().1);
    }
}

#[test]
fn ten_validators_tolerate_three_crashes() {
    let mut sim = Sim::new(10, 11);
    for i in [2, 5, 7] {
        sim.crash(i);
    }
    sim.run(40_000);
    sim.assert_safe();
    let height = sim.min_committed();
    assert!(height >= 5, "only {height} blocks with 3 of 10 down");
}

#[test]
fn ten_validators_with_four_crashes_halt() {
    let mut sim = Sim::new(10, 12);
    for i in [1, 4, 6, 9] {
        sim.crash(i);
    }
    sim.run(20_000);
    sim.assert_safe();
    assert_eq!(sim.min_committed(), 0, "4 of 10 down leaves no quorum");
}

#[test]
fn random_seeds_with_loss_crash_and_equivocation_stay_safe() {
    for seed in 100..106 {
        let mut sim = Sim::new(7, seed);
        sim.drop_permille = 50;
        sim.equivocator = Some((seed % 7) as usize);
        sim.crash(((seed + 3) % 7) as usize);
        sim.run(25_000);
        sim.assert_safe();
        assert!(sim.min_committed() >= 3, "seed {seed}: no progress");
    }
}

fn proposers(sim: &Sim, node: usize) -> Vec<(u64, ValidatorIndex)> {
    sim.nodes[node].as_ref().unwrap().app().proposers.clone()
}

#[test]
fn crashed_validators_stop_being_chosen_as_leaders() {
    let mut sim = Sim::new(4, 21);
    sim.run(3_000);
    let at_crash = sim.min_committed();
    sim.crash(2);
    sim.run(30_000);
    sim.assert_safe();
    let height = sim.min_committed();
    assert!(
        height >= at_crash + 80,
        "only {} blocks after the crash",
        height - at_crash
    );
    let late: Vec<_> = proposers(&sim, 0)
        .into_iter()
        .filter(|(h, _)| *h > at_crash + 2 * REPUTATION_WINDOW as u64)
        .collect();
    assert!(!late.is_empty());
    assert!(
        late.iter().all(|(_, p)| *p != 2),
        "crashed validator still chosen"
    );
}

#[test]
fn ten_validators_with_three_crashed_keep_a_fast_pace() {
    let mut sim = Sim::new(10, 22);
    for i in [2, 5, 7] {
        sim.crash(i);
    }
    sim.run(30_000);
    sim.assert_safe();
    let height = sim.min_committed();
    assert!(height >= 100, "only {height} blocks with 3 of 10 down");
}

#[test]
fn validator_that_returns_leads_again() {
    let mut sim = Sim::new(4, 23);
    sim.partition = Some(vec![true, true, true, false]);
    sim.run(10_000);
    sim.partition = None;
    sim.run(20_000);
    let healed_at = sim.nodes[0].as_ref().unwrap().committed().1;
    sim.run(30_000);
    sim.assert_safe();
    let back: Vec<_> = proposers(&sim, 0)
        .into_iter()
        .filter(|(h, p)| *h > healed_at && *p == 3)
        .collect();
    assert!(
        !back.is_empty(),
        "validator 3 never led again after rejoining"
    );
}

#[test]
fn the_block_interval_holds_for_the_whole_chain_not_for_each_leader() {
    let mut sim = Sim::new(4, 41);
    sim.delay = (1, 2);
    sim.run(10_000);
    sim.assert_safe();
    let height = sim.min_committed();
    assert!(
        height <= 10_000 / 50 + 2,
        "{height} blocks at one per 50 ms"
    );
    assert!(height >= 150, "only {height} blocks");
}

#[test]
fn a_validator_that_hears_no_votes_still_follows_the_chain() {
    let mut sim = Sim::new(4, 43);
    sim.deaf = Some(3);
    sim.run(30_000);
    sim.assert_safe();
    let heard = sim.nodes[3].as_ref().unwrap().committed().1;
    assert!(
        heard >= 10,
        "only {heard} blocks without its own certificates"
    );
}

#[test]
fn idle_chain_pauses_without_traffic_and_resumes() {
    let mut sim = Sim::new(4, 31);
    sim.run(3_000);
    assert!(sim.min_committed() >= 10);
    let set_idle = |sim: &mut Sim, idle: bool| {
        for node in sim.nodes.iter_mut().flatten() {
            node.app_mut().idle = idle;
        }
    };
    set_idle(&mut sim, true);
    sim.run(6_000);
    let (height, messages) = (sim.min_committed(), sim.delivered);
    sim.run(30_000);
    sim.assert_safe();
    assert_eq!(sim.min_committed(), height, "no blocks while idle");
    assert_eq!(sim.delivered, messages, "no messages at all while idle");

    set_idle(&mut sim, false);
    sim.run(35_000);
    sim.assert_safe();
    assert!(
        sim.min_committed() >= height + 10,
        "the chain did not resume"
    );
}
