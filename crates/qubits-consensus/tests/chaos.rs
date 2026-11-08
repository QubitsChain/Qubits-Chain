use std::cell::RefCell;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};
use std::rc::Rc;

use qubits_consensus::*;
use qubits_crypto::{SchemeId, SecretKey};
use qubits_types::Hash;

type Payload = u64;
type Committed = Rc<RefCell<BTreeMap<u64, Hash>>>;
type Log = Rc<RefCell<Vec<(Hash, Block<Payload>, QuorumCert)>>>;

const TIMEOUT_MS: u64 = 400;

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

struct TestApp {
    log: Log,
    all: Committed,
    honest: bool,
    validators: ValidatorSet,
    chain: Hash,
}

impl App<Payload> for TestApp {
    fn propose(&mut self, _: &Hash, height: u64, round: Round, _: u64) -> Payload {
        round * 1_000 + height
    }

    fn verify(&mut self, _: &Hash, _: &Block<Payload>, _: u64) -> bool {
        true
    }

    fn commit(&mut self, chain: &[Final<'_, Payload>], proof: &FinalityProof) {
        let mut log = self.log.borrow_mut();
        for f in chain {
            if let Some((_, last, _)) = log.last() {
                assert_eq!(
                    last.height + 1,
                    f.block.height,
                    "commits must be consecutive"
                );
            }
            log.push((f.id, f.block.clone(), proof.qc.clone()));
            if self.honest {
                let mut all = self.all.borrow_mut();
                let first = *all.entry(f.block.height).or_insert(f.id);
                assert_eq!(
                    first, f.id,
                    "conflicting blocks at height {}",
                    f.block.height
                );
            }
        }
        let tip = chain.last().unwrap();
        assert_eq!(proof.tip, tip.id);
        assert!(
            proof.verify(tip.block.round, &self.validators, &self.chain),
            "a commit needs a proof that convinces anyone"
        );
    }
}

struct Disk {
    log: Log,
    safety: SafetyState,
    blocks: BTreeMap<(u64, Hash), Proposal<Payload>>,
}

struct Chaos {
    keys: Vec<SecretKey>,
    validators: ValidatorSet,
    chain: Hash,
    now: u64,
    seq: u64,
    engines: Vec<Option<Engine<Payload, TestApp>>>,
    disks: Vec<Disk>,
    all: Committed,
    queue: BinaryHeap<Reverse<(u64, u64)>>,
    events: BTreeMap<u64, (u16, u16, Message<Payload>)>,
    rng: Rng,
    delay: (u64, u64),
    loss: u64,
    groups: Vec<u8>,
    equivocator: Option<u16>,
    certificates: Vec<QuorumCert>,
    proposals: Vec<Proposal<Payload>>,
    rivals: BTreeMap<Round, Hash>,
    seen_blocks: BTreeMap<Hash, Block<Payload>>,
}

impl Chaos {
    fn new(n: usize, seed: u64, equivocator: Option<u16>) -> Chaos {
        let keys: Vec<SecretKey> = (0..n)
            .map(|i| SecretKey::from_seed(SchemeId::MlDsa65, &[i as u8 + 1; 32]).unwrap())
            .collect();
        let validators =
            ValidatorSet::new(keys.iter().map(|k| k.public_key().clone()).collect()).unwrap();
        let mut chaos = Chaos {
            keys,
            validators,
            chain: Hash::digest("chaos", &seed.to_le_bytes()),
            now: 1_000,
            seq: 0,
            engines: (0..n).map(|_| None).collect(),
            disks: (0..n)
                .map(|_| Disk {
                    log: Rc::default(),
                    safety: SafetyState::default(),
                    blocks: BTreeMap::new(),
                })
                .collect(),
            all: Rc::default(),
            queue: BinaryHeap::new(),
            events: BTreeMap::new(),
            rng: Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1),
            delay: (5, 60),
            loss: 0,
            groups: vec![0; n],
            equivocator,
            certificates: Vec::new(),
            proposals: Vec::new(),
            rivals: BTreeMap::new(),
            seen_blocks: BTreeMap::new(),
        };
        for i in 0..n {
            chaos.boot(i as u16);
        }
        chaos
    }

    fn boot(&mut self, i: u16) {
        let index = usize::from(i);
        let cfg = Config {
            me: i,
            key: self.keys[index].clone(),
            validators: self.validators.clone(),
            chain: self.chain,
            round_timeout_ms: TIMEOUT_MS,
            min_block_interval_ms: 10,
        };
        let disk = &self.disks[index];
        let log = disk.log.borrow();
        let height = log.last().map_or(0, |(_, b, _)| b.height);
        let mut start: Start<Payload> = match log.last() {
            Some((id, block, qc)) => Start {
                committed: *id,
                committed_height: block.height,
                committed_round: block.round,
                high_qc: qc.clone(),
                safety: disk.safety.clone(),
                recent: log
                    .iter()
                    .rev()
                    .take(REPUTATION_WINDOW)
                    .rev()
                    .map(|(_, b, _)| Recent::of(b))
                    .collect(),
                blocks: Vec::new(),
            },
            None => Start {
                safety: disk.safety.clone(),
                ..Start::genesis(self.chain)
            },
        };
        drop(log);
        start.blocks = disk
            .blocks
            .iter()
            .filter(|((h, _), _)| *h > height)
            .map(|(_, p)| p.clone())
            .collect();
        let app = TestApp {
            log: disk.log.clone(),
            all: self.all.clone(),
            honest: self.equivocator != Some(i),
            validators: self.validators.clone(),
            chain: self.chain,
        };
        let (engine, out) = Engine::new(cfg, app, start, self.now);
        self.engines[index] = Some(engine);
        self.dispatch(i, out);
    }

    fn crash(&mut self, i: u16) {
        self.engines[usize::from(i)] = None;
    }

    /// Carries out outputs in order. Sometimes the process dies halfway through them.
    fn dispatch(&mut self, from: u16, outputs: Vec<Output<Payload>>) {
        let dies_at = self
            .rng
            .chance(4)
            .then(|| self.rng.range(0, outputs.len() as u64));
        for (i, output) in outputs.into_iter().enumerate() {
            if dies_at == Some(i as u64) {
                self.crash(from);
                return;
            }
            let disk = &mut self.disks[usize::from(from)];
            match output {
                Output::PersistSafety(state) => disk.safety = state,
                Output::PersistBlock(p) => {
                    disk.blocks.insert((p.block.height, p.block.id()), p);
                }
                Output::Send(to, m) => self.send(from, to, m),
                Output::Broadcast(m) => {
                    let conflicting = match (&m, self.equivocator) {
                        (Message::Proposal(p), Some(e)) if e == from => {
                            let mut block = p.block.clone();
                            block.payload += 1;
                            // half the time it forks from further back, past what's certified
                            if let Some(parent) = self.seen_blocks.get(&block.parent)
                                && self.rng.chance(500)
                            {
                                block.parent = parent.parent;
                                block.height = parent.height;
                            }
                            let key = &self.keys[usize::from(from)];
                            // and the two halves get different kinds of proposal
                            let certified = self.engines[usize::from(from)]
                                .as_ref()
                                .map(|e| e.high_qc().clone())
                                .filter(|qc| {
                                    qc.block == block.parent && qc.round + 1 == block.round
                                });
                            let justify = certified.or_else(|| p.justify.clone());
                            let keep = self.rng.chance(500);
                            let (justify, tc) = if keep {
                                (justify, p.tc.clone().filter(|_| p.justify.is_some()))
                            } else {
                                (None, None)
                            };
                            self.rivals.insert(p.block.round, block.id());
                            Some(Proposal::sign(block, justify, tc, key, &self.chain))
                        }
                        // votes for everything: every kind, and both sides of its own fork
                        (Message::Vote(v), Some(e)) if e == from => {
                            let key = self.keys[usize::from(from)].clone();
                            let rival = self.rivals.get(&v.round).copied();
                            for block in [Some(v.block), rival].into_iter().flatten() {
                                for kind in
                                    [VoteKind::Optimistic, VoteKind::Normal, VoteKind::Fallback]
                                {
                                    let vote =
                                        Vote::sign(block, v.round, kind, from, &key, &self.chain);
                                    for to in 0..self.disks.len() as u16 {
                                        if to != from && to % 2 == 1 {
                                            self.send(from, to, Message::Vote(vote.clone()));
                                        }
                                    }
                                }
                            }
                            None
                        }
                        _ => None,
                    };
                    for to in 0..self.disks.len() as u16 {
                        if to == from {
                            continue;
                        }
                        let message = match &conflicting {
                            Some(alt) if to % 2 == 1 => Message::Proposal(alt.clone()),
                            _ => m.clone(),
                        };
                        self.send(from, to, message);
                    }
                }
                Output::Committed { .. } => {}
            }
        }
    }

    fn send(&mut self, from: u16, to: u16, message: Message<Payload>) {
        if let Message::Proposal(p) = &message {
            self.seen_blocks.insert(p.block.id(), p.block.clone());
        }
        if let Message::Proposal(p) = &message
            && self.proposals.len() < 64
        {
            self.certificates.extend(p.justify.clone());
            self.proposals.push(p.clone());
        }
        if let Message::Timeout(t) = &message
            && self.certificates.len() < 64
        {
            self.certificates.push(t.high_qc.clone());
        }
        if self.rng.chance(self.loss)
            || self.groups[usize::from(from)] != self.groups[usize::from(to)]
        {
            return;
        }
        let at = self.now + self.rng.range(self.delay.0, self.delay.1);
        self.seq += 1;
        self.events.insert(self.seq, (from, to, message));
        self.queue.push(Reverse((at, self.seq)));
    }

    fn run(&mut self, until: u64) {
        let mut next_tick = self.now + 10;
        loop {
            let event = self.queue.peek().map(|Reverse((t, _))| *t);
            let at = event.filter(|t| *t <= next_tick).unwrap_or(next_tick);
            if at > until {
                self.now = until;
                return;
            }
            self.now = at;
            if event == Some(at) {
                let Reverse((_, seq)) = self.queue.pop().unwrap();
                let (from, to, message) = self.events.remove(&seq).unwrap();
                if let Some(engine) = self.engines[usize::from(to)].as_mut() {
                    let out = engine.handle(from, message, at);
                    self.dispatch(to, out);
                }
            } else {
                next_tick += 10;
                for i in 0..self.engines.len() {
                    if let Some(engine) = self.engines[i].as_mut() {
                        let out = engine.tick(at);
                        self.dispatch(i as u16, out);
                    }
                }
            }
        }
    }

    fn top(&self) -> u64 {
        self.all.borrow().keys().next_back().copied().unwrap_or(0)
    }

    fn lowest_honest(&self) -> u64 {
        (0..self.disks.len())
            .filter(|i| self.equivocator != Some(*i as u16))
            .map(|i| {
                self.disks[i]
                    .log
                    .borrow()
                    .last()
                    .map_or(0, |(_, b, _)| b.height)
            })
            .min()
            .unwrap()
    }

    fn round_like(&mut self) -> Round {
        match self.rng.range(0, 3) {
            0 => self.rng.range(0, 20),
            1 => self.rng.range(0, 3_000),
            2 => Round::MAX - self.rng.range(0, 3),
            _ => self.rng.next(),
        }
    }

    fn certificate_like(&mut self) -> QuorumCert {
        let genuine = if self.certificates.is_empty() {
            QuorumCert::genesis(self.chain)
        } else {
            let pick = self.rng.range(0, self.certificates.len() as u64 - 1);
            self.certificates[pick as usize].clone()
        };
        match self.rng.range(0, 3) {
            0 => QuorumCert {
                round: self.round_like(),
                ..genuine
            },
            1 => QuorumCert {
                block: Hash::digest("forged", &self.rng.next().to_le_bytes()),
                ..genuine
            },
            2 => {
                let mut forged = genuine;
                forged.votes.reverse();
                forged
            }
            _ => genuine,
        }
    }

    fn timeout_cert_like(&mut self) -> TimeoutCert {
        let high_qc = self.certificate_like();
        TimeoutCert {
            round: self.round_like(),
            entries: Vec::new(),
            high_qc,
        }
    }

    /// Validly signed nonsense from validator `from`, sent directly to everyone.
    fn nonsense(&mut self, from: u16) {
        let key = self.keys[usize::from(from)].clone();
        let chain = self.chain;
        for _ in 0..40 {
            let round = self.round_like();
            let message = match self.rng.range(0, 6) {
                0 => {
                    let block = Hash::digest("vote", &self.rng.next().to_le_bytes());
                    let kind = match self.rng.range(0, 2) {
                        0 => VoteKind::Optimistic,
                        1 => VoteKind::Normal,
                        _ => VoteKind::Fallback,
                    };
                    Message::Vote(Vote::sign(block, round, kind, from, &key, &chain))
                }
                1 => {
                    let qc = self.certificate_like();
                    Message::Timeout(Timeout::signed(round, qc, from, &key, &chain))
                }
                2 => {
                    let justify = self.certificate_like();
                    let block = Block {
                        round,
                        height: self.rng.range(0, 4_000),
                        parent: justify.block,
                        proposer: from,
                        voters: vec![from],
                        payload: self.rng.next(),
                    };
                    let tc = self.rng.chance(500).then(|| self.timeout_cert_like());
                    let justify = self.rng.chance(800).then_some(justify);
                    Message::Proposal(Proposal::sign(block, justify, tc, &key, &chain))
                }
                3 => Message::Sync {
                    high_qc: self.certificate_like(),
                    last_tc: Some(self.timeout_cert_like()),
                },
                4 => Message::BlockRequest(Hash::digest("request", &round.to_le_bytes())),
                5 if !self.proposals.is_empty() => {
                    let pick = self.rng.range(0, self.proposals.len() as u64 - 1);
                    let mut stolen = self.proposals[pick as usize].clone();
                    stolen.tc = Some(self.timeout_cert_like());
                    Message::BlockResponse(stolen)
                }
                _ => {
                    let qc = self.certificate_like();
                    Message::Timeout(Timeout::signed(Round::MAX, qc, from, &key, &chain))
                }
            };
            for to in 0..self.disks.len() as u16 {
                if to != from {
                    self.send(from, to, message.clone());
                }
            }
        }
    }

    /// One random fault.
    fn strike(&mut self) {
        let n = self.disks.len() as u16;
        match self.rng.range(0, 7) {
            0 => {
                let victim = self.rng.range(0, u64::from(n) - 1) as u16;
                self.crash(victim);
            }
            1 => {
                for i in 0..n {
                    self.crash(i);
                }
                self.queue.clear();
                self.events.clear();
            }
            2 => {
                for i in 0..n {
                    if self.engines[usize::from(i)].is_none() {
                        self.boot(i);
                    }
                }
            }
            3 => {
                for g in 0..self.groups.len() {
                    self.groups[g] = self.rng.range(0, 2) as u8;
                }
            }
            4 => self.groups.fill(0),
            5 => self.loss = self.rng.range(0, 300),
            6 => self.delay = (self.rng.range(1, 50), self.rng.range(50, 900)),
            _ => {
                let i = self.rng.range(0, u64::from(n) - 1) as u16;
                if self.engines[usize::from(i)].is_some() {
                    self.crash(i);
                    self.boot(i);
                }
            }
        }
    }

    /// Everything back to normal: the chain must then make progress again. Validators too far
    /// behind for block requests sync the committed chain, as a node with `--follow` does.
    fn heal(&mut self) {
        self.groups.fill(0);
        self.loss = 0;
        self.delay = (5, 60);
        let longest = (0..self.disks.len())
            .filter(|i| self.equivocator != Some(*i as u16))
            .max_by_key(|i| self.disks[*i].log.borrow().len())
            .unwrap();
        let chain = self.disks[longest].log.borrow().clone();
        for i in 0..self.disks.len() {
            if self.disks[i].log.borrow().len() + 100 < chain.len() {
                *self.disks[i].log.borrow_mut() = chain.clone();
                self.crash(i as u16);
            }
        }
        for i in 0..self.disks.len() as u16 {
            if self.engines[usize::from(i)].is_none() {
                self.boot(i);
            }
        }
    }
}

fn scenario(n: usize, seed: u64, equivocator: Option<u16>, strikes: u64) {
    run_scenario(n, seed, equivocator, strikes, false);
}

fn run_scenario(n: usize, seed: u64, equivocator: Option<u16>, strikes: u64, nonsense: bool) {
    let mut chaos = Chaos::new(n, seed, equivocator);
    let mut when = chaos.now;
    for _ in 0..strikes {
        when += chaos.rng.range(50, 1_500);
        chaos.run(when);
        chaos.strike();
        if let (true, Some(attacker)) = (nonsense, equivocator) {
            chaos.nonsense(attacker);
        }
    }
    chaos.heal();
    let target = chaos.top() + 3;
    let deadline = chaos.now + 300_000;
    while chaos.lowest_honest() < target {
        assert!(
            chaos.now < deadline,
            "seed {seed}: no progress after healing, heights up to {} and lowest {}",
            chaos.top(),
            chaos.lowest_honest()
        );
        chaos.heal();
        let step = chaos.now + 1_000;
        chaos.run(step);
    }
}

fn seeds() -> u64 {
    std::env::var("QUBITS_CHAOS_SEEDS").map_or(16, |s| s.parse().unwrap())
}

#[test]
fn four_validators_survive_random_faults() {
    for seed in 0..seeds() {
        scenario(4, seed, None, 40);
    }
}

#[test]
fn seven_validators_survive_random_faults() {
    for seed in 0..seeds() / 2 {
        scenario(7, seed + 1_000, None, 40);
    }
}

#[test]
fn an_equivocating_leader_changes_nothing_under_random_faults() {
    for seed in 0..seeds() {
        scenario(4, seed + 2_000, Some((seed % 4) as u16), 40);
    }
}

#[test]
fn a_validator_sending_signed_nonsense_changes_nothing() {
    for seed in 0..seeds() {
        run_scenario(4, seed + 3_000, Some((seed % 4) as u16), 40, true);
    }
}
