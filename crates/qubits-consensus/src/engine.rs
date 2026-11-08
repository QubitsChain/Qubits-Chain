use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use borsh::{BorshDeserialize, BorshSerialize};
use qubits_crypto::{SecretKey, Signature};
use qubits_types::Hash;

use crate::types::{
    Block, FinalityProof, Message, Proposal, QuorumCert, Round, Timeout, TimeoutCert,
    ValidatorIndex, ValidatorSet, Vote, VoteKind,
};

pub trait App<P> {
    fn propose(&mut self, parent: &Hash, height: u64, round: Round, now_ms: u64) -> P;

    fn verify(&mut self, id: &Hash, block: &Block<P>, now_ms: u64) -> bool;

    fn commit(&mut self, chain: &[Final<'_, P>], proof: &FinalityProof);

    fn has_work(&self, _parent: &Hash) -> bool {
        true
    }
}

pub struct Final<'a, P> {
    pub id: Hash,
    pub block: &'a Block<P>,
}

pub struct Config {
    pub me: ValidatorIndex,
    pub key: SecretKey,
    pub validators: ValidatorSet,
    pub chain: Hash,
    pub round_timeout_ms: u64,
    pub min_block_interval_ms: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SafetyState {
    /// highest round with a normal or fallback vote
    pub voted_round: Round,
    /// latest optimistic vote: a normal vote in that round may only repeat it
    pub optimistic: Option<(Round, Hash)>,
    /// highest round timed out in, no voting there or below
    pub timeout_round: Round,
    /// a restart must not report a lower QC, or a TC could skip a final block
    pub high_qc: Option<QuorumCert>,
}

impl SafetyState {
    fn last_round(&self) -> Round {
        self.voted_round
            .max(self.optimistic.map_or(0, |(round, _)| round))
            .max(self.timeout_round)
    }

    fn voted_in(&self, round: Round) -> bool {
        self.voted_round >= round || self.optimistic.is_some_and(|(r, _)| r >= round)
    }
}

#[derive(Clone, Debug)]
pub struct Start<P> {
    pub committed: Hash,
    pub committed_height: u64,
    pub committed_round: Round,
    pub high_qc: QuorumCert,
    pub safety: SafetyState,
    pub recent: Vec<Recent>,
    pub blocks: Vec<Proposal<P>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recent {
    pub id: Hash,
    pub parent: Hash,
    pub height: u64,
    pub round: Round,
    pub proposer: ValidatorIndex,
    pub voters: Vec<ValidatorIndex>,
}

impl Recent {
    pub fn of<P: BorshSerialize>(block: &Block<P>) -> Self {
        Recent {
            id: block.id(),
            parent: block.parent,
            height: block.height,
            round: block.round,
            proposer: block.proposer,
            voters: block.voters.clone(),
        }
    }
}

impl<P> Start<P> {
    pub fn genesis(chain: Hash) -> Self {
        Start {
            committed: chain,
            committed_height: 0,
            committed_round: 0,
            high_qc: QuorumCert::genesis(chain),
            safety: SafetyState::default(),
            recent: Vec::new(),
            blocks: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output<P> {
    /// must be durable before acting on any later output
    PersistSafety(SafetyState),
    /// must be durable too; hand back in `Start::blocks` after a restart
    PersistBlock(Proposal<P>),
    Send(ValidatorIndex, Message<P>),
    Broadcast(Message<P>),
    Committed {
        id: Hash,
        height: u64,
    },
}

pub const REPUTATION_WINDOW: usize = 10;
const IDLE_POLL_MS: u64 = 20;
pub const SYNC_BATCH: usize = 64;
const BLOCK_RETENTION: u64 = 256;
const MAX_WAITING_BYTES: usize = 64 * 1024 * 1024;
const SERVE_BYTES_PER_SECOND: usize = 32 * 1024 * 1024;
const VOTE_WINDOW: Round = 64;
const MAX_VERIFIED: usize = 10_000;

struct Waiting<P> {
    from: ValidatorIndex,
    id: Hash,
    size: usize,
    proposal: Proposal<P>,
}

#[derive(Clone, Copy)]
struct Meta {
    round: Round,
    height: u64,
    parent: Hash,
}

pub struct Engine<P, A> {
    cfg: Config,
    app: A,
    now: u64,

    meta: HashMap<Hash, Meta>,
    participation: HashMap<Hash, (ValidatorIndex, Vec<ValidatorIndex>)>,
    blocks: HashMap<Hash, Proposal<P>>,
    committed: Hash,
    committed_height: u64,
    committed_round: Round,

    round: Round,
    safety: SafetyState,
    high_qc: QuorumCert,
    last_tc: Option<TimeoutCert>,
    proposed_in: Round,
    mine: Option<(Round, Hash)>,
    voted: Option<(Round, Hash)>,
    last_block_ms: Option<u64>,
    proposal_due: Option<u64>,
    normal_due: Option<u64>,
    deadline: u64,

    votes: BTreeMap<(Round, VoteKind, Hash), BTreeMap<ValidatorIndex, Signature>>,
    heard: BTreeMap<ValidatorIndex, Round>,
    timeouts: BTreeMap<Round, BTreeMap<ValidatorIndex, Timeout>>,
    timeout_round: BTreeMap<ValidatorIndex, Round>,
    arrived: BTreeMap<Round, Vec<Hash>>,
    waiting: BTreeMap<Hash, Vec<Waiting<P>>>,
    waiting_bytes: BTreeMap<ValidatorIndex, usize>,
    seen: BTreeMap<(Round, ValidatorIndex, bool), Hash>,
    refused: HashSet<Hash>,
    served: BTreeMap<ValidatorIndex, (u64, usize)>,
    requested: HashSet<Hash>,
    fetching: BTreeMap<Hash, (u64, ValidatorIndex)>,
    verified: HashSet<Hash>,
    replaying: bool,

    inbox: VecDeque<(ValidatorIndex, Message<P>)>,
    out: Vec<Output<P>>,
}

impl<P, A> Engine<P, A>
where
    P: Clone + BorshSerialize,
    A: App<P>,
{
    pub fn new(cfg: Config, app: A, start: Start<P>, now_ms: u64) -> (Self, Vec<Output<P>>) {
        assert_eq!(
            cfg.validators.key(cfg.me),
            Some(cfg.key.public_key()),
            "config key must be validator `me`"
        );
        let mut meta = HashMap::new();
        let mut participation = HashMap::new();
        for r in &start.recent {
            meta.insert(
                r.id,
                Meta {
                    round: r.round,
                    height: r.height,
                    parent: r.parent,
                },
            );
            participation.insert(r.id, (r.proposer, r.voters.clone()));
        }
        meta.entry(start.committed).or_insert(Meta {
            round: start.committed_round,
            height: start.committed_height,
            parent: Hash::ZERO,
        });
        let high_qc = match start.safety.high_qc.clone() {
            Some(qc) if qc.round > start.high_qc.round => qc,
            _ => start.high_qc,
        };
        let mut engine = Engine {
            now: now_ms,
            meta,
            participation,
            blocks: HashMap::new(),
            committed: start.committed,
            committed_height: start.committed_height,
            committed_round: start.committed_round,
            round: high_qc.round,
            safety: start.safety,
            high_qc,
            last_tc: None,
            proposed_in: 0,
            mine: None,
            voted: None,
            last_block_ms: None,
            proposal_due: None,
            normal_due: None,
            deadline: 0,
            votes: BTreeMap::new(),
            heard: BTreeMap::new(),
            timeouts: BTreeMap::new(),
            timeout_round: BTreeMap::new(),
            arrived: BTreeMap::new(),
            waiting: BTreeMap::new(),
            waiting_bytes: BTreeMap::new(),
            seen: BTreeMap::new(),
            refused: HashSet::new(),
            served: BTreeMap::new(),
            requested: HashSet::new(),
            fetching: BTreeMap::new(),
            verified: HashSet::new(),
            replaying: true,
            inbox: VecDeque::new(),
            out: Vec::new(),
            cfg,
            app,
        };
        let me = engine.cfg.me;
        for proposal in start.blocks {
            engine.on_proposal(me, proposal);
            engine.drain();
        }
        engine.replaying = false;
        if !engine.meta.contains_key(&engine.high_qc.block) {
            let holder = Self::holder(&engine.high_qc, me);
            engine.request(engine.high_qc.block, holder);
        }
        let first = (engine.high_qc.round + 1)
            .max(engine.safety.last_round())
            .max(engine.round);
        engine.deadline = 0;
        engine.advance_round(first);
        engine.drain();
        let out = std::mem::take(&mut engine.out);
        (engine, out)
    }

    pub fn round(&self) -> Round {
        self.round
    }

    pub fn committed(&self) -> (Hash, u64) {
        (self.committed, self.committed_height)
    }

    pub fn high_qc(&self) -> &QuorumCert {
        &self.high_qc
    }

    pub fn app(&self) -> &A {
        &self.app
    }

    pub fn app_mut(&mut self) -> &mut A {
        &mut self.app
    }

    pub fn into_app(self) -> A {
        self.app
    }

    pub fn next_deadline(&self) -> u64 {
        [
            self.proposal_due,
            self.normal_due,
            self.fetching.values().map(|(at, _)| *at).min(),
        ]
        .into_iter()
        .flatten()
        .fold(self.deadline, u64::min)
    }

    pub fn handle(&mut self, from: ValidatorIndex, msg: Message<P>, now_ms: u64) -> Vec<Output<P>> {
        self.now = self.now.max(now_ms);
        if usize::from(from) < self.cfg.validators.len() {
            self.inbox.push_back((from, msg));
            self.drain();
        }
        std::mem::take(&mut self.out)
    }

    pub fn tick(&mut self, now_ms: u64) -> Vec<Output<P>> {
        self.now = self.now.max(now_ms);
        if self.proposal_due.is_some_and(|due| self.now >= due) {
            self.proposal_due = None;
            self.try_propose();
            self.drain();
        }
        if self.normal_due.is_some_and(|due| self.now >= due) {
            self.normal_due = None;
            self.normal_propose();
            self.drain();
        }
        self.fetch_due();
        if self.now >= self.deadline {
            if self.idle() {
                self.deadline = self.now + self.timeout_ms();
            } else {
                self.local_timeout();
                self.drain();
            }
        }
        std::mem::take(&mut self.out)
    }

    fn drain(&mut self) {
        while let Some((from, msg)) = self.inbox.pop_front() {
            match msg {
                Message::Proposal(p) => self.on_proposal(from, p),
                Message::Certify {
                    block,
                    justify,
                    signature,
                } => self.on_certify(from, block, justify, signature),
                Message::BlockResponse(p) => self.on_proposal(from, p),
                Message::Vote(v) => self.on_vote(from, v),
                Message::Timeout(t) => self.on_timeout(t),
                Message::Sync { high_qc, last_tc } => self.on_sync(high_qc, last_tc),
                Message::BlockRequest(id) => self.answer_block_request(from, id),
            }
        }
    }

    fn answer_block_request(&mut self, from: ValidatorIndex, id: Hash) {
        let second = self.now / 1000;
        let served = self.served.entry(from).or_insert((second, 0));
        if served.0 != second {
            *served = (second, 0);
        }
        let mut chain = Vec::new();
        let mut cursor = id;
        while chain.len() < SYNC_BATCH && served.1 < SERVE_BYTES_PER_SECOND {
            let Some(p) = self.blocks.get(&cursor) else {
                break;
            };
            served.1 += encoded_size(p);
            chain.push(p.clone());
            cursor = p.block.parent;
        }
        for p in chain.into_iter().rev() {
            self.send(from, Message::BlockResponse(p));
        }
    }

    fn send(&mut self, to: ValidatorIndex, msg: Message<P>) {
        if to == self.cfg.me {
            self.inbox.push_back((to, msg));
        } else {
            self.out.push(Output::Send(to, msg));
        }
    }

    fn broadcast(&mut self, msg: Message<P>) {
        self.inbox.push_back((self.cfg.me, msg.clone()));
        self.out.push(Output::Broadcast(msg));
    }

    fn request(&mut self, id: Hash, from: ValidatorIndex) {
        if !self.meta.contains_key(&id) && self.requested.insert(id) {
            self.send(from, Message::BlockRequest(id));
        }
    }

    /// Certificates and children often beat a block here, because votes are smaller and take
    /// other paths. Only ask for it once it is overdue.
    fn fetch(&mut self, id: Hash, from: ValidatorIndex) {
        if !self.meta.contains_key(&id) && !self.requested.contains(&id) {
            let at = self.now + self.grace_ms();
            self.fetching.entry(id).or_insert((at, from));
        }
    }

    fn fetch_due(&mut self) {
        let now = self.now;
        let due: Vec<(Hash, ValidatorIndex)> = self
            .fetching
            .iter()
            .filter(|(_, (at, _))| *at <= now)
            .map(|(id, (_, from))| (*id, *from))
            .collect();
        for (id, from) in due {
            self.fetching.remove(&id);
            self.request(id, from);
        }
    }

    fn grace_ms(&self) -> u64 {
        self.cfg.round_timeout_ms / 4
    }

    fn qc_valid(&mut self, qc: &QuorumCert) -> bool {
        let digest = qc.digest();
        if self.verified.contains(&digest) {
            return true;
        }
        let ok = qc.verify(&self.cfg.validators, &self.cfg.chain);
        if ok {
            if self.verified.len() >= MAX_VERIFIED {
                self.verified.clear();
            }
            self.verified.insert(digest);
        }
        ok
    }

    fn process_qc(&mut self, qc: &QuorumCert) {
        if qc.round > self.high_qc.round {
            self.high_qc = qc.clone();
        }
        if !self.meta.contains_key(&qc.block) {
            self.fetch(qc.block, Self::holder(qc, self.cfg.me));
        }
        self.try_commit();
        self.advance_round(qc.round + 1);
        self.vote_for_arrived();
    }

    fn process_tc(&mut self, tc: TimeoutCert) {
        let round = tc.round;
        let high_qc = tc.high_qc.clone();
        if self
            .last_tc
            .as_ref()
            .is_none_or(|last| tc.round > last.round)
        {
            self.last_tc = Some(tc);
        }
        self.process_qc(&high_qc);
        self.advance_round(round + 1);
        self.try_propose();
    }

    /// Ancestors of a certified block are certified, so the highest two rounds in a row below
    /// the highest certificate make the lower of the two final.
    fn try_commit(&mut self) {
        let mut path = Vec::new();
        let mut cursor = self.high_qc.block;
        loop {
            let Some(block) = self.meta.get(&cursor).copied() else {
                return;
            };
            if block.height <= self.committed_height {
                return;
            }
            path.push(cursor);
            let Some(parent) = self.meta.get(&block.parent).copied() else {
                return;
            };
            if block.round == parent.round + 1 {
                if parent.height > self.committed_height {
                    path.reverse();
                    self.commit(block.parent, &path);
                }
                return;
            }
            cursor = block.parent;
        }
    }

    fn commit(&mut self, target: Hash, path: &[Hash]) {
        let target_meta = self.meta[&target];
        let mut chain = Vec::new();
        let mut cursor = target;
        while cursor != self.committed {
            let m = self.meta[&cursor];
            assert!(
                m.height > self.committed_height,
                "safety violation: block {cursor} conflicts with committed block {}",
                self.committed
            );
            chain.push(cursor);
            cursor = m.parent;
        }
        chain.reverse();
        let proof = FinalityProof {
            tip: target,
            path: path
                .iter()
                .map(|id| self.blocks[id].block.header())
                .collect(),
            qc: self.high_qc.clone(),
        };
        let finals: Vec<Final<'_, P>> = chain
            .into_iter()
            .map(|id| Final {
                id,
                block: &self.blocks[&id].block,
            })
            .collect();
        self.app.commit(&finals, &proof);
        for f in &finals {
            self.out.push(Output::Committed {
                id: f.id,
                height: f.block.height,
            });
        }
        drop(finals);
        self.committed = target;
        self.committed_height = target_meta.height;
        self.committed_round = target_meta.round;
        let (height, round) = (self.committed_height, self.committed_round);
        self.seen.retain(|(r, _, _), _| *r > round);
        self.refused.clear();
        let bytes = &mut self.waiting_bytes;
        self.waiting.retain(|_, children| {
            children.retain(|w| {
                let keep = w.proposal.block.height > height;
                if !keep {
                    release(bytes, w);
                }
                keep
            });
            !children.is_empty()
        });
        let keep_above = self.committed_height.saturating_sub(BLOCK_RETENTION);
        let committed = self.committed;
        let meta = &mut self.meta;
        let participation = &mut self.participation;
        self.blocks.retain(|id, p| {
            let keep = p.block.height > keep_above;
            if !keep && *id != committed {
                meta.remove(id);
                participation.remove(id);
            }
            keep
        });
    }

    fn leader(&self, round: Round, parent: &Hash) -> ValidatorIndex {
        let validators = &self.cfg.validators;
        let mut active = std::collections::BTreeSet::new();
        let mut cursor = *parent;
        for _ in 0..REPUTATION_WINDOW {
            let Some(m) = self.meta.get(&cursor) else {
                break;
            };
            if let Some((proposer, voters)) = self.participation.get(&cursor) {
                active.insert(*proposer);
                active.extend(voters.iter().copied());
            }
            cursor = m.parent;
        }
        if active.len() < validators.quorum() {
            return validators.leader(round);
        }
        let candidates: Vec<ValidatorIndex> = active.into_iter().collect();
        candidates[(round % candidates.len() as u64) as usize]
    }

    fn idle(&self) -> bool {
        self.waiting.is_empty()
            && self.high_qc.round + 1 >= self.round
            && !self.app.has_work(&self.high_qc.block)
    }

    fn holder(qc: &QuorumCert, fallback: ValidatorIndex) -> ValidatorIndex {
        qc.votes.first().map_or(fallback, |(i, _)| *i)
    }

    fn timeout_ms(&self) -> u64 {
        let failed = self.round.saturating_sub(self.high_qc.round + 1).min(6) as u32;
        self.cfg.round_timeout_ms * 3u64.pow(failed) / 2u64.pow(failed)
    }

    fn advance_round(&mut self, round: Round) {
        if round <= self.round && self.deadline != 0 {
            return;
        }
        self.round = self.round.max(round);
        self.deadline = self.now + self.timeout_ms();
        self.normal_due = None;
        let keep_from = self.round.saturating_sub(1);
        self.votes.retain(|(r, _, _), _| *r >= keep_from);
        self.timeouts.retain(|r, _| *r >= self.round);
        self.arrived.retain(|r, _| *r >= self.round);
        self.try_propose();
        self.arm_normal();
        self.vote_for_arrived();
    }

    /// What this validator may propose right now, if anything.
    fn slot(&self) -> Option<(Hash, Round, Option<TimeoutCert>)> {
        let me = self.cfg.me;
        // the next round's leader doesn't wait for the certificate of the block it just voted for
        if let Some((round, id)) = self.voted
            && round == self.round
            && self.leader(round + 1, &id) == me
        {
            return Some((id, round + 1, None));
        }
        if self.safety.voted_in(self.round) || self.safety.timeout_round >= self.round {
            return None;
        }
        let parent = self.high_qc.block;
        if self.leader(self.round, &parent) != me {
            return None;
        }
        if self.high_qc.round + 1 == self.round {
            return Some((parent, self.round, None));
        }
        match &self.last_tc {
            Some(tc) if tc.round + 1 == self.round => Some((parent, self.round, Some(tc.clone()))),
            _ => None,
        }
    }

    fn build(&mut self, parent: Hash, round: Round) -> Option<Block<P>> {
        let height = self.meta.get(&parent)?.height + 1;
        let payload = self.app.propose(&parent, height, round, self.now);
        let recent = self.high_qc.round.saturating_sub(2);
        let voters = self
            .heard
            .iter()
            .filter(|(_, r)| **r >= recent)
            .map(|(i, _)| *i)
            .collect();
        self.proposed_in = round;
        self.last_block_ms = Some(self.now);
        Some(Block {
            round,
            height,
            parent,
            proposer: self.cfg.me,
            voters,
            payload,
        })
    }

    fn try_propose(&mut self) {
        if self.replaying {
            return;
        }
        let Some((parent, round, tc)) = self.slot() else {
            return;
        };
        if self.proposed_in >= round {
            return;
        }
        if let Some(last) = self.last_block_ms {
            let earliest = last + self.cfg.min_block_interval_ms;
            if self.now < earliest {
                self.proposal_due = Some(earliest);
                return;
            }
        }
        // after a timeout we need a block anyway, to carry the TC
        if tc.is_none() && !self.app.has_work(&parent) {
            self.proposal_due = Some(self.now + self.cfg.min_block_interval_ms.max(IDLE_POLL_MS));
            return;
        }
        let Some(block) = self.build(parent, round) else {
            self.fetch(parent, Self::holder(&self.high_qc, self.cfg.me));
            return;
        };
        self.mine = Some((round, block.id()));
        let proposal = match tc {
            Some(tc) => Proposal::sign(
                block,
                Some(self.high_qc.clone()),
                Some(tc),
                &self.cfg.key,
                &self.cfg.chain,
            ),
            None => Proposal::optimistic(block, &self.cfg.key, &self.cfg.chain),
        };
        self.broadcast(Message::Proposal(proposal));
        self.arm_normal();
    }

    /// The certificate is 2f+1 signatures of 3.3 KB each, so unlike the paper's protocol we only
    /// send it when the optimistic path didn't get this round certified in time.
    fn arm_normal(&mut self) {
        let round = self.round;
        if self.high_qc.round + 1 != round || !matches!(self.mine, Some((r, _)) if r == round) {
            return;
        }
        let parent = self.mine.and_then(|(_, id)| self.blocks.get(&id));
        let stale = parent.is_some_and(|p| p.block.parent != self.high_qc.block);
        let timed_out = self.safety.timeout_round + 1 >= round && self.safety.timeout_round != 0;
        let wait = if stale || timed_out {
            0
        } else {
            self.grace_ms()
        };
        self.normal_due = Some(self.now + wait);
    }

    fn normal_propose(&mut self) {
        let (round, parent) = (self.round, self.high_qc.block);
        if self.high_qc.round + 1 != round || self.leader(round, &parent) != self.cfg.me {
            return;
        }
        let mine = self
            .mine
            .filter(|(r, _)| *r == round)
            .and_then(|(_, id)| self.blocks.get(&id))
            .map(|p| p.block.clone())
            .filter(|block| block.parent == parent);
        let sent = mine.is_some();
        let Some(block) = mine.or_else(|| self.build(parent, round)) else {
            return;
        };
        let justify = Some(self.high_qc.clone());
        let id = block.id();
        let proposal = Proposal::sign(block, justify, None, &self.cfg.key, &self.cfg.chain);
        if sent {
            // already sent with the block
            self.inbox
                .push_back((self.cfg.me, Message::Proposal(proposal.clone())));
            self.out.push(Output::Broadcast(Message::Certify {
                block: id,
                justify: self.high_qc.clone(),
                signature: proposal.signature,
            }));
        } else {
            self.broadcast(Message::Proposal(proposal));
        }
    }

    fn on_certify(
        &mut self,
        from: ValidatorIndex,
        id: Hash,
        justify: QuorumCert,
        signature: Signature,
    ) {
        let Some(block) = self.blocks.get(&id).map(|p| p.block.clone()) else {
            if self.qc_valid(&justify) {
                self.process_qc(&justify);
            }
            self.fetch(id, from);
            return;
        };
        self.on_proposal(
            from,
            Proposal {
                block,
                justify: Some(justify),
                tc: None,
                signature,
            },
        );
    }

    fn local_timeout(&mut self) {
        let qc_is_new = self
            .safety
            .high_qc
            .as_ref()
            .is_none_or(|qc| qc.round < self.high_qc.round);
        if self.safety.timeout_round < self.round || qc_is_new {
            self.safety.timeout_round = self.safety.timeout_round.max(self.round);
            self.safety.high_qc = Some(self.high_qc.clone());
            self.out.push(Output::PersistSafety(self.safety.clone()));
        }
        let timeout = Timeout::signed(
            self.round,
            self.high_qc.clone(),
            self.cfg.me,
            &self.cfg.key,
            &self.cfg.chain,
        );
        self.broadcast(Message::Timeout(timeout));
        self.requested.clear();
        self.fetching.clear();
        let mut missing: Vec<Hash> = self.waiting.keys().copied().collect();
        if !self.meta.contains_key(&self.high_qc.block) {
            missing.push(self.high_qc.block);
        }
        for id in missing {
            self.out.push(Output::Broadcast(Message::BlockRequest(id)));
            self.requested.insert(id);
        }
        self.deadline = self.now + self.timeout_ms();
    }

    fn on_proposal(&mut self, from: ValidatorIndex, p: Proposal<P>) {
        let id = p.block.id();
        let solicited = self.replaying || self.requested.contains(&id);
        let known = self.meta.contains_key(&id);
        if (known && p.justify.is_none()) || (self.refused.contains(&id) && !solicited) {
            return;
        }
        let b = &p.block;
        let shaped = match (&p.justify, &p.tc) {
            (None, None) => true,
            (None, Some(_)) => false,
            (Some(qc), None) => qc.block == b.parent && qc.round.checked_add(1) == Some(b.round),
            (Some(qc), Some(tc)) => {
                qc.block == b.parent
                    && qc.round < b.round
                    && tc.round.checked_add(1) == Some(b.round)
                    && qc.round >= tc.max_high_qc_round()
            }
        };
        if !shaped
            || b.height <= self.committed_height
            || b.round <= self.committed_round
            || !p.signature_valid(&id, &self.cfg.validators, &self.cfg.chain)
        {
            return;
        }
        if let Some(tc) = &p.tc
            && !tc.verify(&self.cfg.validators, &self.cfg.chain)
        {
            return;
        }
        if let Some(qc) = &p.justify {
            if !self.qc_valid(qc) {
                return;
            }
            self.process_qc(&qc.clone());
        }
        if let Some(tc) = p.tc.clone() {
            self.process_tc(tc);
        }
        if known {
            self.try_vote(&id, &p);
            return;
        }
        let b = &p.block;
        if b.round > self.round.saturating_add(VOTE_WINDOW) {
            return;
        }
        // equivocating leader: one block per kind of proposal, unless a QC made us fetch another
        let key = (b.round, b.proposer, p.justify.is_some());
        if *self.seen.entry(key).or_insert(id) != id && !solicited {
            return;
        }

        let Some(parent) = self.meta.get(&b.parent).copied() else {
            let parent_id = b.parent;
            self.park(from, id, p);
            if solicited {
                self.request(parent_id, from);
            } else {
                self.fetch(parent_id, from);
            }
            return;
        };
        let n = self.cfg.validators.len();
        let structurally_ok = b.height == parent.height + 1
            && b.round > parent.round
            && b.voters.is_sorted_by(|a, b| a < b)
            && b.voters.last().is_none_or(|v| usize::from(*v) < n)
            && b.proposer == self.leader(b.round, &b.parent);
        if !structurally_ok || !self.app.verify(&id, b, self.now) {
            self.refused.insert(id);
            return;
        }
        self.participation
            .insert(id, (b.proposer, b.voters.clone()));
        self.meta.insert(
            id,
            Meta {
                round: b.round,
                height: b.height,
                parent: b.parent,
            },
        );
        self.requested.remove(&id);
        self.fetching.remove(&id);
        self.last_block_ms = Some(self.now.max(self.last_block_ms.unwrap_or(0)));
        self.arrived.entry(b.round).or_default().push(id);
        self.blocks.insert(id, p.clone());
        if !self.replaying {
            self.out.push(Output::PersistBlock(p.clone()));
        }

        self.try_commit();
        self.try_vote(&id, &p);
        self.try_propose();
        if let Some(children) = self.waiting.remove(&id) {
            for w in children {
                release(&mut self.waiting_bytes, &w);
                self.inbox
                    .push_back((w.from, Message::BlockResponse(w.proposal)));
            }
        }
    }

    fn park(&mut self, from: ValidatorIndex, id: Hash, proposal: Proposal<P>) {
        let size = encoded_size(&proposal);
        let held = self.waiting_bytes.entry(from).or_default();
        if *held + size > MAX_WAITING_BYTES {
            return;
        }
        let children = self.waiting.entry(proposal.block.parent).or_default();
        if children.iter().all(|w| w.id != id) {
            *held += size;
            children.push(Waiting {
                from,
                id,
                size,
                proposal,
            });
        }
    }

    /// The voting rules of Pipelined Moonshot, figure 3 of the paper. Every clause is used by its
    /// safety proof; change one only with the proof open.
    fn vote_kind(&self, id: &Hash, p: &Proposal<P>) -> Option<VoteKind> {
        let (s, v) = (&self.safety, p.block.round);
        if v != self.round || s.timeout_round >= v {
            return None;
        }
        match (&p.justify, &p.tc) {
            (None, None) => {
                // no timeout for the round before either: then this round's optimistic quorum
                // and a TC for the round before can't both exist
                let clean = s.timeout_round == 0 || s.timeout_round + 1 < v;
                let locked = self.high_qc.round + 1 == v && self.high_qc.block == p.block.parent;
                (clean && locked && !s.voted_in(v)).then_some(VoteKind::Optimistic)
            }
            (Some(_), None) => {
                let conflicts = s.optimistic.is_some_and(|(r, opt)| r == v && opt != *id);
                (s.voted_round < v && !conflicts).then_some(VoteKind::Normal)
            }
            (Some(qc), Some(tc)) => (s.voted_round < v && qc.round >= tc.max_high_qc_round())
                .then_some(VoteKind::Fallback),
            (None, Some(_)) => None,
        }
    }

    fn try_vote(&mut self, id: &Hash, p: &Proposal<P>) {
        if let Some(kind) = self.vote_kind(id, p).filter(|_| !self.replaying) {
            self.cast_vote(*id, kind);
        }
    }

    fn vote_for_arrived(&mut self) {
        if self.replaying {
            return;
        }
        let Some(ids) = self.arrived.get(&self.round).cloned() else {
            return;
        };
        for id in ids {
            let kind = self.blocks.get(&id).and_then(|p| self.vote_kind(&id, p));
            if let Some(kind) = kind {
                self.cast_vote(id, kind);
            }
        }
    }

    fn cast_vote(&mut self, id: Hash, kind: VoteKind) {
        let round = self.round;
        match kind {
            VoteKind::Optimistic => self.safety.optimistic = Some((round, id)),
            VoteKind::Normal | VoteKind::Fallback => self.safety.voted_round = round,
        }
        self.safety.high_qc = Some(self.high_qc.clone());
        self.out.push(Output::PersistSafety(self.safety.clone()));
        let vote = Vote::sign(id, round, kind, self.cfg.me, &self.cfg.key, &self.cfg.chain);
        self.broadcast(Message::Vote(vote));
        self.voted = Some((round, id));
        self.try_propose();
    }

    fn on_vote(&mut self, from: ValidatorIndex, v: Vote) {
        // not verified yet, could be anything
        if v.round > self.round.saturating_add(VOTE_WINDOW) {
            return;
        }
        if from == v.voter {
            let last = self.heard.entry(from).or_default();
            *last = v.round.max(*last);
        }
        if v.round <= self.high_qc.round {
            return;
        }
        let quorum = self.cfg.validators.quorum();
        if self
            .votes
            .get(&(v.round, v.kind, v.block))
            .is_some_and(|entry| entry.len() >= quorum)
        {
            return;
        }
        let already_voted = self
            .votes
            .range((v.round, v.kind, Hash::ZERO)..=(v.round, v.kind, Hash([0xff; 32])))
            .any(|(_, entry)| entry.contains_key(&v.voter));
        if already_voted || !v.verify(&self.cfg.validators, &self.cfg.chain) {
            return;
        }
        let entry = self.votes.entry((v.round, v.kind, v.block)).or_default();
        entry.insert(v.voter, v.signature);
        if entry.len() == quorum {
            let qc = QuorumCert {
                block: v.block,
                round: v.round,
                kind: v.kind,
                votes: entry.iter().map(|(i, s)| (*i, s.clone())).collect(),
            };
            self.verified.insert(qc.digest());
            self.process_qc(&qc);
        }
    }

    fn on_timeout(&mut self, t: Timeout) {
        if !t.verify(&self.cfg.validators, &self.cfg.chain) || !self.qc_valid(&t.high_qc) {
            return;
        }
        self.process_qc(&t.high_qc.clone());
        if t.round < self.round {
            if t.voter != self.cfg.me {
                let sync = Message::Sync {
                    high_qc: self.high_qc.clone(),
                    last_tc: self.last_tc.clone(),
                };
                self.send(t.voter, sync);
            }
            return;
        }
        let round = t.round;
        // newest per validator only, so rounds can't be used to fill memory
        match self.timeout_round.insert(t.voter, round) {
            Some(held) if held > round => {
                self.timeout_round.insert(t.voter, held);
                return;
            }
            Some(held) if held < round => {
                if let Some(entry) = self.timeouts.get_mut(&held) {
                    entry.remove(&t.voter);
                    if entry.is_empty() {
                        self.timeouts.remove(&held);
                    }
                }
            }
            _ => {}
        }
        let entry = self.timeouts.entry(round).or_default();
        entry.insert(t.voter, t);
        let count = entry.len();
        if count >= self.cfg.validators.quorum()
            && self.last_tc.as_ref().is_none_or(|tc| tc.round < round)
        {
            let timeouts = &self.timeouts[&round];
            let entries = timeouts
                .values()
                .map(|t| (t.voter, t.high_qc.round, t.signature.clone()))
                .collect();
            let high_qc = timeouts
                .values()
                .map(|t| &t.high_qc)
                .max_by_key(|qc| qc.round)
                .expect("a quorum is not empty")
                .clone();
            let tc = TimeoutCert {
                round,
                entries,
                high_qc,
            };
            // no need to send it: f+1 timeouts make every honest validator time out too, so all
            // of them can build this
            self.process_tc(tc);
        }
        self.join_timeouts();
    }

    /// Restarts lose TCs, so rounds can drift apart with no certificate to bring them together.
    /// f+1 timeouts at or past a round include an honest validator, so that round is safe to join.
    fn join_timeouts(&mut self) {
        let mut rounds: Vec<Round> = self.timeout_round.values().copied().collect();
        rounds.sort_unstable_by(|a, b| b.cmp(a));
        let Some(&target) = rounds.get(self.cfg.validators.max_faulty()) else {
            return;
        };
        if target >= self.round && self.safety.timeout_round < target {
            self.advance_round(target);
            self.local_timeout();
        }
    }

    fn on_sync(&mut self, high_qc: QuorumCert, last_tc: Option<TimeoutCert>) {
        if self.qc_valid(&high_qc) {
            self.process_qc(&high_qc);
        }
        if let Some(tc) = last_tc
            && self
                .last_tc
                .as_ref()
                .is_none_or(|last| tc.round > last.round)
            && tc.verify(&self.cfg.validators, &self.cfg.chain)
        {
            self.process_tc(tc);
        }
    }
}

fn encoded_size<P: BorshSerialize>(proposal: &Proposal<P>) -> usize {
    borsh::object_length(proposal).expect("in-memory encoding cannot fail")
}

fn release<P>(bytes: &mut BTreeMap<ValidatorIndex, usize>, waiting: &Waiting<P>) {
    if let Some(held) = bytes.get_mut(&waiting.from) {
        *held = held.saturating_sub(waiting.size);
    }
}

#[cfg(test)]
mod tests {
    use qubits_crypto::SchemeId;

    use super::*;

    struct Accepting;

    impl App<u8> for Accepting {
        fn propose(&mut self, _: &Hash, _: u64, _: Round, _: u64) -> u8 {
            0
        }
        fn verify(&mut self, _: &Hash, _: &Block<u8>, _: u64) -> bool {
            true
        }
        fn commit(&mut self, _: &[Final<'_, u8>], _: &FinalityProof) {}
    }

    const CHAIN: Hash = Hash([7; 32]);

    fn keys() -> Vec<SecretKey> {
        (0..4u8)
            .map(|i| SecretKey::from_seed(SchemeId::MlDsa65, &[i + 1; 32]).unwrap())
            .collect()
    }

    fn engine(keys: &[SecretKey], me: usize) -> Engine<u8, Accepting> {
        let validators =
            ValidatorSet::new(keys.iter().map(|k| k.public_key().clone()).collect()).unwrap();
        let cfg = Config {
            me: me as ValidatorIndex,
            key: keys[me].clone(),
            validators,
            chain: CHAIN,
            round_timeout_ms: 1_000,
            min_block_interval_ms: 0,
        };
        Engine::new(cfg, Accepting, Start::genesis(CHAIN), 0).0
    }

    fn proposal(keys: &[SecretKey], proposer: usize, round: Round, payload: u8) -> Proposal<u8> {
        let block = Block {
            round,
            height: 1,
            parent: CHAIN,
            proposer: proposer as ValidatorIndex,
            voters: vec![],
            payload,
        };
        Proposal::optimistic(block, &keys[proposer], &CHAIN)
    }

    #[test]
    fn extreme_rounds_from_the_network_are_harmless() {
        let k = keys();
        let mut e = engine(&k, 0);
        let vote = Vote::sign(
            Hash([1; 32]),
            Round::MAX,
            VoteKind::Normal,
            1,
            &k[1],
            &CHAIN,
        );
        e.handle(1, Message::Vote(vote), 1);
        let tc = TimeoutCert {
            round: Round::MAX,
            entries: vec![],
            high_qc: QuorumCert::genesis(CHAIN),
        };
        let block = proposal(&k, 1, 1, 0).block;
        let forged = Proposal::sign(
            block,
            Some(QuorumCert::genesis(CHAIN)),
            Some(tc),
            &k[1],
            &CHAIN,
        );
        e.handle(1, Message::Proposal(forged), 2);
        assert_eq!(e.round(), 1);
        assert!(e.votes.is_empty());
    }

    #[test]
    fn votes_are_stored_only_after_they_verify() {
        let k = keys();
        let mut e = engine(&k, 2);
        let mut vote = Vote::sign(Hash([1; 32]), 1, VoteKind::Normal, 1, &k[1], &CHAIN);
        vote.voter = 3;
        e.handle(3, Message::Vote(vote), 1);
        assert!(
            e.votes.is_empty(),
            "no entry for a vote that does not verify"
        );
    }

    #[test]
    fn a_validator_counts_once_per_round_whatever_block_it_votes_for() {
        let k = keys();
        let mut e = engine(&k, 2);
        for (i, block) in [[1; 32], [2; 32], [3; 32]].into_iter().enumerate() {
            let vote = Vote::sign(Hash(block), 1, VoteKind::Normal, 1, &k[1], &CHAIN);
            e.handle(1, Message::Vote(vote), i as u64 + 1);
        }
        assert_eq!(e.votes.len(), 1);
    }

    #[test]
    fn only_the_newest_timeout_of_each_validator_is_kept() {
        let k = keys();
        let mut e = engine(&k, 0);
        for round in [50, 60, 55, 1_000_000] {
            let t = Timeout::signed(round, QuorumCert::genesis(CHAIN), 3, &k[3], &CHAIN);
            e.handle(3, Message::Timeout(t), 1);
        }
        assert_eq!(e.timeouts.len(), 1);
        assert_eq!(e.timeouts[&1_000_000].len(), 1);
    }

    #[test]
    fn rounds_follow_f_plus_one_timeouts_and_no_fewer() {
        let k = keys();
        let mut e = engine(&k, 0);
        let timeout = |round, voter: usize| {
            Message::Timeout(Timeout::signed(
                round,
                QuorumCert::genesis(CHAIN),
                voter as ValidatorIndex,
                &k[voter],
                &CHAIN,
            ))
        };
        e.handle(1, timeout(60, 1), 1);
        assert_eq!(e.round(), 1, "one validator can't move anyone");
        e.handle(2, timeout(50, 2), 2);
        assert_eq!(e.round(), 50, "two are f+1: follow the lower of them");
    }

    #[test]
    fn an_equivocating_leader_gets_one_block_per_round() {
        let k = keys();
        let mut e = engine(&k, 0);
        let leader = usize::from(e.leader(1, &CHAIN));
        let first = proposal(&k, leader, 1, 1);
        e.handle(
            leader as ValidatorIndex,
            Message::Proposal(first.clone()),
            1,
        );
        for payload in 2..20 {
            let other = proposal(&k, leader, 1, payload);
            e.handle(leader as ValidatorIndex, Message::Proposal(other), 2);
        }
        assert_eq!(e.blocks.len(), 1);
        assert!(e.blocks.contains_key(&first.block.id()));

        let wanted = proposal(&k, leader, 1, 2);
        e.requested.insert(wanted.block.id());
        e.handle(1, Message::BlockResponse(wanted.clone()), 3);
        assert!(e.blocks.contains_key(&wanted.block.id()));
    }

    #[test]
    fn blocks_waiting_for_a_parent_are_bounded_per_sender() {
        let k = keys();
        let mut e = engine(&k, 0);
        let mut blocks = 0;
        for i in 0..2_000u32 {
            let mut p = proposal(&k, 1, 1, 0);
            p.block.height = 2 + u64::from(i);
            e.park(1, p.block.id(), p);
            blocks += 1;
        }
        let held: usize = e.waiting.values().map(Vec::len).sum();
        assert_eq!(held, blocks, "small blocks fit the budget");
        assert!(e.waiting_bytes[&1] <= MAX_WAITING_BYTES);

        let budget = e.waiting_bytes[&1];
        e.waiting_bytes.insert(1, MAX_WAITING_BYTES);
        let mut p = proposal(&k, 1, 1, 0);
        p.block.height = 1_000_000;
        e.park(1, p.block.id(), p);
        assert_eq!(e.waiting.values().map(Vec::len).sum::<usize>(), blocks);
        e.waiting_bytes.insert(1, budget);

        let settled = e.waiting.remove(&CHAIN).unwrap();
        for w in &settled {
            release(&mut e.waiting_bytes, w);
        }
        assert_eq!(e.waiting_bytes[&1], 0);
    }

    // one test per voting rule clause; chaos runs rarely reach these orderings

    const VALIDATORS: u64 = 4;

    fn block_at(round: Round, height: u64, parent: Hash, payload: u8) -> Block<u8> {
        Block {
            round,
            height,
            parent,
            proposer: (round % VALIDATORS) as ValidatorIndex,
            voters: vec![],
            payload,
        }
    }

    fn optimistic(k: &[SecretKey], block: Block<u8>) -> Message<u8> {
        let key = &k[usize::from(block.proposer)];
        Message::Proposal(Proposal::optimistic(block, key, &CHAIN))
    }

    fn normal(k: &[SecretKey], block: Block<u8>, justify: QuorumCert) -> Message<u8> {
        let key = &k[usize::from(block.proposer)];
        Message::Proposal(Proposal::sign(block, Some(justify), None, key, &CHAIN))
    }

    fn certify(k: &[SecretKey], block: Hash, round: Round, kind: VoteKind) -> QuorumCert {
        let votes = (1..4u16)
            .map(|i| {
                let vote = Vote::sign(block, round, kind, i, &k[usize::from(i)], &CHAIN);
                (i, vote.signature)
            })
            .collect();
        QuorumCert {
            block,
            round,
            kind,
            votes,
        }
    }

    fn timeout_cert(k: &[SecretKey], round: Round, high_qc: QuorumCert) -> TimeoutCert {
        let entries = (1..4u16)
            .map(|i| {
                let key = &k[usize::from(i)];
                let timeout = Timeout::signed(round, high_qc.clone(), i, key, &CHAIN);
                (i, high_qc.round, timeout.signature)
            })
            .collect();
        TimeoutCert {
            round,
            entries,
            high_qc,
        }
    }

    fn sync(high_qc: QuorumCert) -> Message<u8> {
        Message::Sync {
            high_qc,
            last_tc: None,
        }
    }

    fn votes(outputs: &[Output<u8>]) -> Vec<(Hash, Round, VoteKind)> {
        outputs
            .iter()
            .filter_map(|o| match o {
                Output::Broadcast(Message::Vote(v)) => Some((v.block, v.round, v.kind)),
                _ => None,
            })
            .collect()
    }

    /// Validator 0 in round 2, holding the certificate of round 1's block.
    fn in_round_two(k: &[SecretKey]) -> (Engine<u8, Accepting>, Block<u8>, QuorumCert) {
        let mut e = engine(k, 0);
        let first = block_at(1, 1, CHAIN, 1);
        let out = e.handle(1, optimistic(k, first.clone()), 1);
        assert_eq!(votes(&out), [(first.id(), 1, VoteKind::Optimistic)]);
        let qc = certify(k, first.id(), 1, VoteKind::Optimistic);
        e.handle(1, sync(qc.clone()), 2);
        assert_eq!(e.round(), 2);
        (e, first, qc)
    }

    #[test]
    fn an_optimistic_vote_waits_for_the_parents_certificate() {
        let k = keys();
        let mut e = engine(&k, 0);
        let first = block_at(1, 1, CHAIN, 1);
        e.handle(1, optimistic(&k, first.clone()), 1);
        let second = block_at(2, 2, first.id(), 2);
        let out = e.handle(2, optimistic(&k, second.clone()), 2);
        assert!(votes(&out).is_empty(), "no certificate for round 1 yet");

        let qc = certify(&k, first.id(), 1, VoteKind::Optimistic);
        let out = e.handle(1, sync(qc), 3);
        assert_eq!(votes(&out), [(second.id(), 2, VoteKind::Optimistic)]);
    }

    #[test]
    fn an_optimistic_vote_needs_the_certificate_of_exactly_the_round_before() {
        let k = keys();
        let (mut e, first, qc) = in_round_two(&k);
        let tc = timeout_cert(&k, 2, qc);
        e.handle(
            2,
            Message::Sync {
                high_qc: tc.high_qc.clone(),
                last_tc: Some(tc),
            },
            3,
        );
        assert_eq!(e.round(), 3);
        let skipping = block_at(3, 2, first.id(), 3);
        let out = e.handle(3, optimistic(&k, skipping), 4);
        assert!(votes(&out).is_empty(), "round 2 has no certificate");
    }

    #[test]
    fn no_optimistic_vote_after_timing_out_in_the_round_before() {
        let k = keys();
        let mut e = engine(&k, 0);
        let first = block_at(1, 1, CHAIN, 1);
        e.handle(1, optimistic(&k, first.clone()), 1);
        // round 1 times out here while the certificate is still on its way
        let timed_out = e.tick(5_000);
        assert!(
            timed_out
                .iter()
                .any(|o| matches!(o, Output::Broadcast(Message::Timeout(t)) if t.round == 1))
        );
        let qc = certify(&k, first.id(), 1, VoteKind::Normal);
        e.handle(1, sync(qc.clone()), 5_001);
        assert_eq!(e.round(), 2);

        let second = block_at(2, 2, first.id(), 2);
        let out = e.handle(2, optimistic(&k, second.clone()), 5_002);
        assert!(
            votes(&out).is_empty(),
            "a TC for round 1 and an optimistic quorum in round 2 must not both exist"
        );
        let out = e.handle(2, normal(&k, second.clone(), qc), 5_003);
        assert_eq!(votes(&out), [(second.id(), 2, VoteKind::Normal)]);
    }

    #[test]
    fn no_vote_after_timing_out_in_the_same_round() {
        let k = keys();
        let (mut e, first, qc) = in_round_two(&k);
        e.tick(5_000);
        let second = block_at(2, 2, first.id(), 2);
        let out = e.handle(2, normal(&k, second, qc), 5_001);
        assert!(votes(&out).is_empty());
    }

    #[test]
    fn a_normal_vote_may_repeat_an_optimistic_one_but_not_contradict_it() {
        let k = keys();
        let (mut e, first, qc) = in_round_two(&k);
        let second = block_at(2, 2, first.id(), 2);
        let out = e.handle(2, optimistic(&k, second.clone()), 3);
        assert_eq!(votes(&out), [(second.id(), 2, VoteKind::Optimistic)]);

        let rival = block_at(2, 2, first.id(), 3);
        let out = e.handle(2, normal(&k, rival, qc.clone()), 4);
        assert!(votes(&out).is_empty(), "already voted for another block");

        let out = e.handle(2, normal(&k, second.clone(), qc.clone()), 5);
        assert_eq!(
            votes(&out),
            [(second.id(), 2, VoteKind::Normal)],
            "the same block again, so optimistic and normal voters can form one quorum"
        );
        let out = e.handle(2, normal(&k, second, qc), 6);
        assert!(votes(&out).is_empty(), "one normal vote per round");
    }

    #[test]
    fn a_fallback_vote_needs_a_tc_and_the_highest_certificate_in_it() {
        let k = keys();
        let (mut e, first, qc) = in_round_two(&k);
        let second = block_at(2, 2, first.id(), 2);
        let second_qc = certify(&k, second.id(), 2, VoteKind::Optimistic);
        let tc = timeout_cert(&k, 2, second_qc.clone());
        e.handle(3, optimistic(&k, second.clone()), 3);

        let stale = block_at(3, 2, first.id(), 3);
        let key = &k[usize::from(stale.proposer)];
        let stale = Proposal::sign(stale, Some(qc), Some(tc.clone()), key, &CHAIN);
        let out = e.handle(3, Message::Proposal(stale), 4);
        assert!(votes(&out).is_empty(), "skips what round 2 certified");

        let good = block_at(3, 3, second.id(), 4);
        let id = good.id();
        let key = &k[usize::from(good.proposer)];
        let good = Proposal::sign(good, Some(second_qc), Some(tc), key, &CHAIN);
        let out = e.handle(3, Message::Proposal(good), 5);
        assert_eq!(votes(&out), [(id, 3, VoteKind::Fallback)]);
    }

    #[test]
    fn a_fallback_vote_is_allowed_after_an_optimistic_vote_in_the_same_round() {
        let k = keys();
        let (mut e, first, qc) = in_round_two(&k);
        let second = block_at(2, 2, first.id(), 2);
        e.handle(2, optimistic(&k, second), 3);

        // another leader's chain: a TC for round 1 means no optimistic quorum exists for round 2
        let tc = timeout_cert(&k, 1, qc.clone());
        let rival = block_at(2, 2, first.id(), 9);
        let id = rival.id();
        let key = &k[usize::from(rival.proposer)];
        let rival = Proposal::sign(rival, Some(qc), Some(tc), key, &CHAIN);
        let out = e.handle(2, Message::Proposal(rival), 4);
        assert_eq!(votes(&out), [(id, 2, VoteKind::Fallback)]);
    }

    #[test]
    fn a_restart_remembers_what_it_voted_for() {
        let k = keys();
        let (mut e, first, qc) = in_round_two(&k);
        let second = block_at(2, 2, first.id(), 2);
        let out = e.handle(2, optimistic(&k, second.clone()), 3);
        let safety = out
            .iter()
            .rev()
            .find_map(|o| match o {
                Output::PersistSafety(s) => Some(s.clone()),
                _ => None,
            })
            .expect("a vote is written down before it leaves");
        assert_eq!(safety.optimistic, Some((2, second.id())));
        assert_eq!(safety.high_qc.as_ref(), Some(&qc));

        let validators =
            ValidatorSet::new(k.iter().map(|k| k.public_key().clone()).collect()).unwrap();
        let cfg = Config {
            me: 0,
            key: k[0].clone(),
            validators,
            chain: CHAIN,
            round_timeout_ms: 1_000,
            min_block_interval_ms: 0,
        };
        let first_proposal = Proposal::optimistic(first.clone(), &k[1], &CHAIN);
        let start = Start {
            safety,
            blocks: vec![first_proposal],
            ..Start::genesis(CHAIN)
        };
        let (mut e, _) = Engine::new(cfg, Accepting, start, 10);
        assert_eq!(e.round(), 2);
        let rival = block_at(2, 2, first.id(), 3);
        let out = e.handle(2, optimistic(&k, rival.clone()), 11);
        assert!(votes(&out).is_empty(), "already voted in this round");
        let out = e.handle(2, normal(&k, rival, qc.clone()), 12);
        assert!(votes(&out).is_empty(), "and for another block");
        let out = e.handle(2, normal(&k, second.clone(), qc), 13);
        assert_eq!(votes(&out), [(second.id(), 2, VoteKind::Normal)]);
    }

    #[test]
    fn the_leader_proposes_on_the_block_it_just_voted_for() {
        let k = keys();
        let mut e = engine(&k, 0);
        let first = block_at(3, 1, CHAIN, 1);
        let tc = timeout_cert(&k, 2, QuorumCert::genesis(CHAIN));
        let genesis = QuorumCert::genesis(CHAIN);
        let key = &k[usize::from(first.proposer)];
        let first = Proposal::sign(first, Some(genesis), Some(tc), key, &CHAIN);
        let id = first.block.id();
        let out = e.handle(3, Message::Proposal(first), 1);
        assert_eq!(votes(&out), [(id, 3, VoteKind::Fallback)]);
        assert_eq!(e.round(), 3, "still waiting for the certificate of round 3");
        let next = out.iter().find_map(|o| match o {
            Output::Broadcast(Message::Proposal(p)) => Some(p),
            _ => None,
        });
        let next = next.expect("validator 0 leads round 4 and doesn't wait");
        assert_eq!((next.block.round, next.block.parent), (4, id));
        assert!(next.justify.is_none(), "and sends no certificate");
    }

    #[test]
    fn a_restart_reports_the_highest_certificate_it_ever_saw() {
        let k = keys();
        let (e, first, qc) = in_round_two(&k);
        drop(e);
        // crashed right after persisting that certificate, before anything was committed
        let safety = SafetyState {
            high_qc: Some(qc.clone()),
            ..SafetyState::default()
        };
        let validators =
            ValidatorSet::new(k.iter().map(|k| k.public_key().clone()).collect()).unwrap();
        let cfg = Config {
            me: 0,
            key: k[0].clone(),
            validators,
            chain: CHAIN,
            round_timeout_ms: 1_000,
            min_block_interval_ms: 0,
        };
        let start = Start {
            safety,
            blocks: vec![Proposal::optimistic(first, &k[1], &CHAIN)],
            ..Start::genesis(CHAIN)
        };
        let (mut e, _) = Engine::new(cfg, Accepting, start, 10);
        assert_eq!(e.round(), 2);
        let out = e.tick(5_000);
        let reported = out.iter().find_map(|o| match o {
            Output::Broadcast(Message::Timeout(t)) => Some(t.high_qc.round),
            _ => None,
        });
        assert_eq!(
            reported,
            Some(1),
            "a lower lock could let a TC skip a final block"
        );
    }

    #[test]
    fn a_timeout_is_written_down_and_survives_a_restart() {
        let k = keys();
        let (mut e, first, qc) = in_round_two(&k);
        let out = e.tick(5_000);
        let safety = out
            .iter()
            .find_map(|o| match o {
                Output::PersistSafety(s) => Some(s.clone()),
                _ => None,
            })
            .expect("the timeout is persisted before it is sent");
        assert_eq!(safety.timeout_round, 2);

        let validators =
            ValidatorSet::new(k.iter().map(|k| k.public_key().clone()).collect()).unwrap();
        let cfg = Config {
            me: 0,
            key: k[0].clone(),
            validators,
            chain: CHAIN,
            round_timeout_ms: 1_000,
            min_block_interval_ms: 0,
        };
        let start = Start {
            safety,
            blocks: vec![Proposal::optimistic(first.clone(), &k[1], &CHAIN)],
            ..Start::genesis(CHAIN)
        };
        let (mut e, _) = Engine::new(cfg, Accepting, start, 5_001);
        let second = block_at(2, 2, first.id(), 2);
        let out = e.handle(2, normal(&k, second, qc), 5_002);
        assert!(
            votes(&out).is_empty(),
            "timed out in round 2 before the restart"
        );
    }
}
