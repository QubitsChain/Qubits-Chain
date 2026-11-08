use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;

use qubits_consensus::*;
use qubits_crypto::{SchemeId, SecretKey};
use qubits_types::Hash;

type Payload = u64;
type Log = Rc<RefCell<Vec<(Hash, Block<Payload>, QuorumCert)>>>;

struct TestApp(Log);

impl App<Payload> for TestApp {
    fn propose(&mut self, _: &Hash, height: u64, _: Round, _: u64) -> Payload {
        height
    }
    fn verify(&mut self, _: &Hash, _: &Block<Payload>, _: u64) -> bool {
        true
    }
    fn commit(&mut self, chain: &[Final<'_, Payload>], proof: &FinalityProof) {
        let mut log = self.0.borrow_mut();
        for f in chain {
            log.push((f.id, f.block.clone(), proof.qc.clone()));
        }
    }
}

struct Validator {
    engine: Option<Engine<Payload, TestApp>>,
    log: Log,
    safety: SafetyState,
    blocks: BTreeMap<(u64, Hash), Proposal<Payload>>,
}

struct Net {
    keys: Vec<SecretKey>,
    validators: ValidatorSet,
    chain: Hash,
    now: u64,
    nodes: Vec<Validator>,
    queue: VecDeque<(u16, u16, Message<Payload>)>,
    cut: Option<u16>,
}

impl Net {
    fn new(n: u8) -> Net {
        let keys: Vec<SecretKey> = (0..n)
            .map(|i| SecretKey::from_seed(SchemeId::MlDsa65, &[i + 1; 32]).unwrap())
            .collect();
        let validators =
            ValidatorSet::new(keys.iter().map(|k| k.public_key().clone()).collect()).unwrap();
        let mut net = Net {
            keys,
            validators,
            chain: Hash([7; 32]),
            now: 1_000,
            nodes: Vec::new(),
            queue: VecDeque::new(),
            cut: None,
        };
        for _ in 0..n {
            net.nodes.push(Validator {
                engine: None,
                log: Rc::default(),
                safety: SafetyState::default(),
                blocks: BTreeMap::new(),
            });
        }
        for i in 0..n {
            net.boot(u16::from(i));
        }
        net
    }

    fn boot(&mut self, i: u16) {
        let index = usize::from(i);
        let cfg = Config {
            me: i,
            key: self.keys[index].clone(),
            validators: self.validators.clone(),
            chain: self.chain,
            round_timeout_ms: 1_000,
            min_block_interval_ms: 1,
        };
        let node = &self.nodes[index];
        let log = node.log.borrow();
        let tip = log.last().cloned();
        let recent = log
            .iter()
            .rev()
            .take(REPUTATION_WINDOW)
            .rev()
            .map(|(_, b, _)| Recent::of(b))
            .collect();
        drop(log);
        let height = tip.as_ref().map_or(0, |(_, b, _)| b.height);
        let mut start: Start<Payload> = match tip {
            Some((id, block, qc)) => Start {
                committed: id,
                committed_height: block.height,
                committed_round: block.round,
                high_qc: qc,
                safety: node.safety.clone(),
                recent,
                blocks: Vec::new(),
            },
            None => Start {
                safety: node.safety.clone(),
                ..Start::genesis(self.chain)
            },
        };
        start.blocks = node
            .blocks
            .iter()
            .filter(|((h, _), _)| *h > height)
            .map(|(_, p)| p.clone())
            .collect();
        let (engine, out) = Engine::new(cfg, TestApp(node.log.clone()), start, self.now);
        self.nodes[index].engine = Some(engine);
        self.dispatch(i, out);
    }

    fn down(&mut self, i: u16) {
        self.nodes[usize::from(i)].engine = None;
    }

    fn dispatch(&mut self, from: u16, outputs: Vec<Output<Payload>>) {
        for output in outputs {
            match output {
                Output::PersistSafety(state) => self.nodes[usize::from(from)].safety = state,
                Output::PersistBlock(p) => {
                    let key = (p.block.height, p.block.id());
                    self.nodes[usize::from(from)].blocks.insert(key, p);
                }
                Output::Send(to, m) => self.send(from, to, m),
                Output::Broadcast(m) => {
                    for to in 0..self.nodes.len() as u16 {
                        if to != from {
                            self.send(from, to, m.clone());
                        }
                    }
                }
                Output::Committed { .. } => {}
            }
        }
    }

    fn send(&mut self, from: u16, to: u16, message: Message<Payload>) {
        if self.cut != Some(from) && self.cut != Some(to) {
            self.queue.push_back((from, to, message));
        }
    }

    fn deliver_one(&mut self) -> bool {
        let Some((from, to, message)) = self.queue.pop_front() else {
            return false;
        };
        self.now += 1;
        if let Some(engine) = self.nodes[usize::from(to)].engine.as_mut() {
            let out = engine.handle(from, message, self.now);
            self.dispatch(to, out);
        }
        true
    }

    fn tick(&mut self) {
        self.now += 5;
        for i in 0..self.nodes.len() as u16 {
            if let Some(engine) = self.nodes[usize::from(i)].engine.as_mut() {
                let out = engine.tick(self.now);
                self.dispatch(i, out);
            }
        }
    }

    fn step(&mut self) {
        if !self.deliver_one() {
            self.tick();
        }
    }

    fn heights(&self) -> Vec<u64> {
        self.nodes
            .iter()
            .map(|n| n.log.borrow().last().map_or(0, |(_, b, _)| b.height))
            .collect()
    }

    fn run_until(&mut self, what: &str, done: impl Fn(&Net) -> bool) {
        for _ in 0..500_000 {
            if done(self) {
                return;
            }
            self.step();
        }
        panic!("{what} did not happen; heights {:?}", self.heights());
    }

    fn assert_same_chains(&self) {
        for a in &self.nodes {
            for b in &self.nodes {
                for (x, y) in a.log.borrow().iter().zip(b.log.borrow().iter()) {
                    assert_eq!(x.0, y.0, "conflicting blocks at height {}", x.1.height);
                }
            }
        }
    }
}

#[test]
fn a_restart_cannot_fork_a_committed_block() {
    let mut net = Net::new(4);
    net.run_until("one validator ahead", |n| {
        let h = n.heights();
        let max = *h.iter().max().unwrap();
        max >= 4 && h.iter().filter(|x| **x == max).count() == 1
    });
    let heights = net.heights();
    let ahead = heights
        .iter()
        .position(|h| *h == *heights.iter().max().unwrap())
        .unwrap() as u16;
    let (x, x_height) = {
        let log = net.nodes[usize::from(ahead)].log.borrow();
        let last = log.last().unwrap();
        (last.0, last.1.height)
    };

    net.cut = Some(ahead);
    net.queue.retain(|(f, t, _)| *f != ahead && *t != ahead);
    while net.deliver_one() {}
    for i in (0..4).filter(|i| *i != ahead) {
        net.down(i);
    }
    for i in (0..4).filter(|i| *i != ahead) {
        net.boot(i);
    }

    net.run_until("the others reaching that height", |n| {
        n.heights()
            .iter()
            .enumerate()
            .all(|(i, h)| i as u16 == ahead || *h >= x_height)
    });
    for i in (0..4).filter(|i| *i != ahead) {
        let log = net.nodes[usize::from(i)].log.borrow();
        let (id, _, _) = log.iter().find(|(_, b, _)| b.height == x_height).unwrap();
        assert_eq!(*id, x, "validator {i} committed a conflicting block");
    }
    net.assert_same_chains();
}

#[test]
fn the_chain_survives_every_validator_restarting_at_once() {
    let mut net = Net::new(4);
    net.run_until("some blocks", |n| n.heights().iter().all(|h| *h >= 3));
    for _ in 0..3 {
        net.step();
    }
    let before = *net.heights().iter().max().unwrap();
    net.queue.clear();
    for i in 0..4 {
        net.down(i);
    }
    for i in 0..4 {
        net.boot(i);
    }
    net.run_until("progress after the restart", |n| {
        n.heights().iter().all(|h| *h > before + 3)
    });
    net.assert_same_chains();
}

#[test]
fn repeated_restarts_stay_safe_and_live() {
    let mut net = Net::new(4);
    let mut target = 0;
    for pass in 0..30u64 {
        for _ in 0..(37 + pass * 13) {
            net.step();
        }
        let victim = (pass % 4) as u16;
        net.down(victim);
        for _ in 0..(5 + pass * 3) {
            net.step();
        }
        net.boot(victim);
        target = target.max(*net.heights().iter().min().unwrap());
        net.assert_same_chains();
    }
    net.run_until("progress", |n| n.heights().iter().all(|h| *h > target + 3));
    net.assert_same_chains();
}
