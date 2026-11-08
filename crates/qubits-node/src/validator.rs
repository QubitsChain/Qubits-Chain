use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use borsh::{BorshDeserialize, BorshSerialize};
use qubits_consensus::shards::{self, Assembler, Shard};
use qubits_consensus::{
    Config, Engine, Message, Output, Proposal, REPUTATION_WINDOW, Recent, Round, SafetyState,
    Start, ValidatorIndex, ValidatorSet,
};
use qubits_crypto::{PublicKey, SecretKey};
use qubits_execution::read_validators;
use qubits_types::{BlockPayload, Hash, SignedTransaction};

use crate::app::{ChainApp, ConsensusTip, EpochInfo, META_TIP};
use crate::metrics::Traffic;
use crate::network::{Inbox, NetMessage, Transport};
use crate::sync::{Follower, SyncError};
use crate::{Node, NodeError, now_ms};

const META_SAFETY: &[u8] = b"consensus_safety";
const RETIRED_FOR_MS: u64 = 60_000;
const STATUS_EVERY_MS: u64 = 10_000;
const INTAKE_QUEUE: usize = 1024;
const KEEP_UP_EVERY_MS: u64 = 2_000;
const STUCK_CHECKS: u64 = 5;
/// Peers keep 256 blocks to serve; sync over HTTP well before falling out of that window.
const MAX_CONSENSUS_LAG: u64 = 128;

#[derive(Clone, Copy, Debug)]
pub struct Timing {
    pub round_timeout_ms: u64,
    pub min_block_interval_ms: u64,
    pub tx_ttl_ms: u64,
    pub regossip_ms: u64,
}

impl Timing {
    pub const DEFAULT: Timing = Timing {
        round_timeout_ms: 1_500,
        min_block_interval_ms: 100,
        tx_ttl_ms: 10 * 60 * 1_000,
        regossip_ms: 3_000,
    };
}

impl Default for Timing {
    fn default() -> Self {
        Timing::DEFAULT
    }
}

#[derive(BorshSerialize, BorshDeserialize)]
struct SafetyRecord {
    epoch: u64,
    state: SafetyState,
}

struct Intake {
    queue: Option<SyncSender<SignedTransaction>>,
    thread: Option<JoinHandle<()>>,
}

impl Intake {
    fn start(node: Arc<Node>) -> Intake {
        let (queue, gossiped) = sync_channel::<SignedTransaction>(INTAKE_QUEUE);
        let thread = std::thread::Builder::new()
            .name("tx-intake".into())
            .spawn(move || {
                while let Ok(tx) = gossiped.recv() {
                    let _ = node.accept(tx, now_ms());
                }
            })
            .expect("spawning a thread cannot fail");
        Intake {
            queue: Some(queue),
            thread: Some(thread),
        }
    }

    fn push(&self, tx: SignedTransaction) {
        let full = self
            .queue
            .as_ref()
            .is_some_and(|queue| matches!(queue.try_send(tx), Err(TrySendError::Full(_))));
        if full {
            tracing::debug!("dropping a gossiped transaction: too many waiting");
        }
    }
}

impl Drop for Intake {
    fn drop(&mut self) {
        self.queue = None;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn pending_key(epoch: u64, height: u64, id: &Hash) -> Vec<u8> {
    [epoch.to_be_bytes().as_slice(), &height.to_be_bytes(), &id.0].concat()
}

fn describe(message: &Message<BlockPayload>) -> (&'static str, Round) {
    match message {
        Message::Proposal(p) => ("proposal", p.block.round),
        Message::Certify { justify, .. } => ("certify", justify.round + 1),
        Message::BlockResponse(p) => ("block", p.block.round),
        Message::Vote(v) => ("vote", v.round),
        Message::Timeout(t) => ("timeout", t.round),
        Message::Sync { high_qc, .. } => ("sync", high_qc.round),
        Message::BlockRequest(_) => ("block-request", 0),
    }
}

fn short(key: &PublicKey) -> String {
    hex::encode(&key.as_raw()[..6])
}

/// Watches the follow sources from its own thread: HTTP must never hold up consensus.
struct KeepingUp {
    follower: Arc<Mutex<Follower>>,
    remote: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    last_check: u64,
    last_head: u64,
    stuck_checks: u64,
}

impl KeepingUp {
    fn start(follower: Follower) -> KeepingUp {
        let follower = Arc::new(Mutex::new(follower));
        let remote = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (watched, height, stopped) = (follower.clone(), remote.clone(), stop.clone());
        let thread = std::thread::Builder::new()
            .name("keep-up".into())
            .spawn(move || {
                while !stopped.load(Ordering::Relaxed) {
                    if let Ok(top) = crate::lock(&watched).remote_height() {
                        height.store(top, Ordering::Relaxed);
                    }
                    for _ in 0..KEEP_UP_EVERY_MS / 100 {
                        if !stopped.load(Ordering::Relaxed) {
                            std::thread::sleep(Duration::from_millis(100));
                        }
                    }
                }
            })
            .expect("spawning a thread cannot fail");
        KeepingUp {
            follower,
            remote,
            stop,
            thread: Some(thread),
            last_check: now_ms(),
            last_head: 0,
            stuck_checks: 0,
        }
    }

    fn remote(&self) -> u64 {
        self.remote.load(Ordering::Relaxed)
    }

    /// Behind and not moving: an idle chain sends us nothing to catch up from.
    fn stuck(&mut self, head: u64, behind: u64) -> bool {
        self.stuck_checks = if behind > 0 && head == self.last_head {
            self.stuck_checks + 1
        } else {
            0
        };
        self.last_head = head;
        self.stuck_checks >= STUCK_CHECKS
    }

    fn sync(&self, far: bool) -> Result<(), SyncError> {
        let mut follower = crate::lock(&self.follower);
        if far {
            follower.catch_up(2, Duration::from_secs(300))
        } else {
            follower.step().map(|_| ())
        }
    }
}

impl Drop for KeepingUp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct EpochEngine {
    epoch: u64,
    engine: Engine<BlockPayload, ChainApp>,
    validators: ValidatorSet,
    me: ValidatorIndex,
    assembler: Assembler,
}

pub struct Validator {
    node: Arc<Node>,
    key: SecretKey,
    timing: Timing,
    last_housekeeping: u64,
    last_status: u64,
    reported: Traffic,
    keeping_up: Option<KeepingUp>,
    transport: Arc<dyn Transport>,
    intake: Intake,
    current: Option<EpochEngine>,
    retired: Option<(EpochEngine, u64)>,
}

pub(crate) fn current_validators(node: &Node) -> Result<ValidatorSet, NodeError> {
    let set = read_validators(node.store()).map_err(|e| NodeError::Storage(e.to_string()))?;
    ValidatorSet::new(set.keys()).map_err(NodeError::Config)
}

impl Validator {
    pub fn start(
        node: Arc<Node>,
        key: SecretKey,
        transport: Arc<dyn Transport>,
        timing: Timing,
    ) -> Result<Validator, NodeError> {
        node.set_gossip(transport.clone());
        let intake = Intake::start(node.clone());
        let mut validator = Validator {
            node,
            key,
            timing,
            last_housekeeping: now_ms(),
            last_status: now_ms(),
            reported: Traffic::default(),
            keeping_up: None,
            transport,
            intake,
            current: None,
            retired: None,
        };
        let outputs = validator.open_epoch()?.ok_or_else(|| {
            NodeError::Config("this key is not in the current validator set".into())
        })?;
        validator.act(outputs, true)?;
        Ok(validator)
    }

    fn open_epoch(&mut self) -> Result<Option<Vec<Output<BlockPayload>>>, NodeError> {
        let store = self.node.store_arc();
        let epoch =
            EpochInfo::read(&store, self.node.genesis_hash()).map_err(NodeError::Storage)?;
        let validators = current_validators(&self.node)?;
        let Some(me) = validators.index_of(self.key.public_key()) else {
            return Ok(None);
        };
        let tip: Option<ConsensusTip> = match store.get_meta(META_TIP)? {
            Some(bytes) => {
                Some(borsh::from_slice(&bytes).map_err(|e| NodeError::Storage(e.to_string()))?)
            }
            None => None,
        };
        let safety = match store.get_meta(META_SAFETY)? {
            Some(bytes) => {
                let record: SafetyRecord =
                    borsh::from_slice(&bytes).map_err(|e| NodeError::Storage(e.to_string()))?;
                if record.epoch == epoch.epoch {
                    record.state
                } else {
                    SafetyState::default()
                }
            }
            None => SafetyState::default(),
        };
        let mut blocks = Vec::new();
        for (key, bytes) in store.pending_blocks()? {
            if key.starts_with(&epoch.epoch.to_be_bytes()) {
                let proposal: Proposal<BlockPayload> =
                    borsh::from_slice(&bytes).map_err(|e| NodeError::Storage(e.to_string()))?;
                blocks.push(proposal);
            }
        }
        let start = match &tip {
            Some(t) if t.height > epoch.start_height => {
                let first = t
                    .height
                    .saturating_sub(REPUTATION_WINDOW as u64 - 1)
                    .max(epoch.start_height + 1);
                let mut recent = Vec::new();
                for height in first..=t.height {
                    if let Some(block) = self.node.block(height)? {
                        recent.push(Recent::of(&block));
                    }
                }
                Start {
                    committed: t.id,
                    committed_height: t.height,
                    committed_round: t.round,
                    high_qc: t.qc.clone(),
                    safety,
                    recent,
                    blocks,
                }
            }
            _ => Start {
                committed_height: epoch.start_height,
                safety,
                blocks,
                ..Start::genesis(epoch.start)
            },
        };
        let app = ChainApp::new(
            store,
            self.node.genesis().clone(),
            self.node.mempool(),
            self.node.signatures(),
            tip.as_ref(),
            self.node.keep_versions_shared(),
            self.node.feed().heads(),
        );
        let cfg = Config {
            me,
            key: self.key.clone(),
            validators: validators.clone(),
            chain: epoch.start,
            round_timeout_ms: self.timing.round_timeout_ms,
            min_block_interval_ms: self.timing.min_block_interval_ms,
        };
        let (engine, outputs) = Engine::new(cfg, app, start, now_ms());
        tracing::info!(
            epoch = epoch.epoch,
            validators = validators.len(),
            index = me,
            "consensus epoch started"
        );
        self.current = Some(EpochEngine {
            epoch: epoch.epoch,
            engine,
            assembler: Assembler::new(validators.len(), me),
            validators,
            me,
        });
        Ok(Some(outputs))
    }

    fn after_engine_call(&mut self) -> Result<(), NodeError> {
        let ended = self
            .current
            .as_mut()
            .and_then(|c| c.engine.app_mut().take_epoch_end());
        if ended.is_none() {
            return Ok(());
        }
        let mut old = self.current.take().expect("checked above");
        old.engine.app_mut().retire();
        self.retired = Some((old, now_ms()));
        match self.open_epoch()? {
            Some(outputs) => self.act(outputs, true),
            None => {
                tracing::warn!("this key is no longer a validator; consensus stopped");
                Ok(())
            }
        }
    }

    pub fn index(&self) -> Option<ValidatorIndex> {
        self.current.as_ref().map(|c| c.me)
    }

    pub fn epoch(&self) -> Option<u64> {
        self.current.as_ref().map(|c| c.epoch)
    }

    pub fn handle(&mut self, from: &PublicKey, bytes: &[u8]) -> Result<(), NodeError> {
        self.node.metrics().received(bytes.len());
        match NetMessage::decode(bytes) {
            Some(NetMessage::Consensus { epoch, message }) => {
                let (kind, round) = describe(&message);
                tracing::debug!(
                    from = %short(from),
                    kind,
                    round,
                    epoch,
                    bytes = bytes.len(),
                    "received"
                );
                let now = now_ms();
                if let Some(current) = self.current.as_mut()
                    && current.epoch == epoch
                {
                    if let Some(index) = current.validators.index_of(from) {
                        let outputs = current.engine.handle(index, message, now);
                        self.act(outputs, true)?;
                        return self.after_engine_call();
                    }
                } else if let Some((retired, _)) = self.retired.as_mut()
                    && retired.epoch == epoch
                    && let Some(index) = retired.validators.index_of(from)
                {
                    let outputs = retired.engine.handle(index, message, now);
                    self.act(outputs, false)?;
                }
                Ok(())
            }
            Some(NetMessage::Transaction(tx)) => {
                tracing::debug!(
                    from = %short(from),
                    kind = "transaction",
                    bytes = bytes.len(),
                    "received"
                );
                self.intake.push(tx);
                Ok(())
            }
            Some(NetMessage::Shard { epoch, shard }) => self.on_shard(from, bytes, epoch, shard),
            None => {
                tracing::debug!("dropping undecodable message");
                Ok(())
            }
        }
    }

    fn on_shard(
        &mut self,
        from: &PublicKey,
        bytes: &[u8],
        epoch: u64,
        shard: Shard,
    ) -> Result<(), NodeError> {
        let engine = match (self.current.as_mut(), self.retired.as_mut()) {
            (Some(current), _) if current.epoch == epoch => current,
            (_, Some((retired, _))) if retired.epoch == epoch => retired,
            _ => return Ok(()),
        };
        let Some(sender) = engine.validators.index_of(from) else {
            return Ok(());
        };
        let proposer = engine.validators.key(shard.proposer).cloned();
        let round = engine.engine.round();
        let received = engine.assembler.add(sender, shard, round);
        if received.relay {
            let peers = self.transport.connected() as u64;
            self.node.metrics().sent(peers, peers * bytes.len() as u64);
            self.transport.broadcast(bytes.to_vec());
        }
        let (Some(message), Some(proposer)) = (received.message, proposer) else {
            return Ok(());
        };
        self.node.metrics().shards_rebuilt();
        // only a proposal: a shard can hold anything its sender likes, shards inside shards too
        match NetMessage::decode(&message) {
            Some(NetMessage::Consensus {
                message: Message::Proposal(_),
                ..
            }) => self.handle(&proposer, &message),
            _ => Ok(()),
        }
    }

    pub fn tick(&mut self) -> Result<(), NodeError> {
        let now = now_ms();
        if now >= self.last_status + STATUS_EVERY_MS {
            self.last_status = now;
            self.log_status();
        }
        self.keep_up(now)?;
        let (round, epoch) = self
            .current
            .as_ref()
            .map_or((0, 0), |c| (c.engine.round(), c.epoch));
        let peers = self.transport.connected() as u64;
        self.node.metrics().consensus(round, epoch, peers);
        if now >= self.last_housekeeping + self.timing.regossip_ms {
            self.last_housekeeping = now;
            self.node.expire_mempool(now, self.timing.tx_ttl_ms);
            for tx in self.node.waiting_since(now, self.timing.regossip_ms, 64) {
                self.transport
                    .broadcast(NetMessage::Transaction(tx).encode());
            }
        }
        if self
            .retired
            .as_ref()
            .is_some_and(|(_, since)| now > since + RETIRED_FOR_MS)
        {
            self.retired = None;
        }
        if let Some((retired, _)) = self.retired.as_mut() {
            let outputs = retired.engine.tick(now);
            self.act(outputs, false)?;
        }
        if let Some(current) = self.current.as_mut() {
            current.assembler.forget_before(current.engine.round());
            let outputs = current.engine.tick(now);
            self.act(outputs, true)?;
            self.after_engine_call()?;
        }
        Ok(())
    }

    /// With sources to follow, syncs when consensus can't help: this key left the validator
    /// set, or the others no longer keep the blocks it misses.
    pub fn follow(&mut self, follower: Follower) {
        self.keeping_up = Some(KeepingUp::start(follower));
    }

    fn keep_up(&mut self, now: u64) -> Result<(), NodeError> {
        let Some(keeping_up) = self.keeping_up.as_mut() else {
            return Ok(());
        };
        if now < keeping_up.last_check + KEEP_UP_EVERY_MS {
            return Ok(());
        }
        keeping_up.last_check = now;
        let head = self.node.head()?.height;
        let behind = keeping_up.remote().saturating_sub(head);
        let stuck = keeping_up.stuck(head, behind);
        let far = behind > MAX_CONSENSUS_LAG;
        let member = self.current.is_some();
        if behind == 0 || (member && !far && !stuck) {
            return Ok(());
        }
        tracing::warn!(behind, "syncing from the follow sources");
        if let Err(e) = keeping_up.sync(far) {
            tracing::warn!(error = %e, "sync failed");
            return Ok(());
        }
        self.node.metrics().synced();
        if self.node.head()?.height == head {
            return Ok(());
        }
        self.current = None;
        if let Some(outputs) = self.open_epoch()? {
            self.act(outputs, true)?;
        }
        Ok(())
    }

    fn log_status(&mut self) {
        let total = self.node.metrics().traffic();
        let traffic = total.since(self.reported);
        self.reported = total;
        let height = self.node.head().map_or(0, |head| head.height);
        tracing::info!(
            height,
            round = self.current.as_ref().map_or(0, |c| c.engine.round()),
            epoch = self.current.as_ref().map_or(0, |c| c.epoch),
            peers = self.transport.connected(),
            mempool = self.node.mempool_len(),
            in_msgs = traffic.messages_in,
            in_kb = traffic.bytes_in / 1024,
            out_msgs = traffic.messages_out,
            out_kb = traffic.bytes_out / 1024,
            "status"
        );
    }

    fn act(&mut self, outputs: Vec<Output<BlockPayload>>, current: bool) -> Result<(), NodeError> {
        let source = if current {
            self.current.as_ref()
        } else {
            self.retired.as_ref().map(|(e, _)| e)
        };
        let Some(source) = source else { return Ok(()) };
        let epoch = source.epoch;
        for output in outputs {
            match output {
                // has to hit disk before the vote goes out
                Output::PersistSafety(state) if current => {
                    let record = SafetyRecord { epoch, state };
                    let bytes = borsh::to_vec(&record).expect("encoding cannot fail");
                    self.node.store().put_meta(META_SAFETY, &bytes)?;
                }
                Output::PersistSafety(_) => {}
                // same: a QC's block must survive every validator restarting at once
                Output::PersistBlock(proposal) if current => {
                    let key = pending_key(epoch, proposal.block.height, &proposal.block.id());
                    let bytes = borsh::to_vec(&proposal).expect("encoding cannot fail");
                    self.node.store().put_pending_block(&key, &bytes)?;
                }
                Output::PersistBlock(_) => {}
                Output::Send(to, message) => {
                    if let Some(key) = source.validators.key(to) {
                        let (kind, round) = describe(&message);
                        let bytes = NetMessage::Consensus { epoch, message }.encode();
                        tracing::debug!(
                            to = %short(key),
                            kind,
                            round,
                            epoch,
                            bytes = bytes.len(),
                            "sent"
                        );
                        self.node.metrics().sent(1, bytes.len() as u64);
                        self.transport.send(key, bytes);
                    }
                }
                Output::Broadcast(message) => {
                    let (kind, round) = describe(&message);
                    let proposal = matches!(message, Message::Proposal(_));
                    let bytes = NetMessage::Consensus { epoch, message }.encode();
                    let n = source.validators.len();
                    if proposal && shards::worthwhile(bytes.len(), n) {
                        self.spread(&source.validators, source.me, epoch, round, &bytes);
                        continue;
                    }
                    let peers = self.transport.connected() as u64;
                    tracing::debug!(
                        to = "all",
                        kind,
                        round,
                        epoch,
                        bytes = bytes.len(),
                        peers,
                        "sent"
                    );
                    self.node.metrics().sent(peers, peers * bytes.len() as u64);
                    self.transport.broadcast(bytes);
                }
                Output::Committed { height, .. } => {
                    if current {
                        let below = pending_key(epoch, height + 1, &Hash::ZERO);
                        self.node.store().delete_pending_blocks_before(&below)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn spread(
        &self,
        validators: &ValidatorSet,
        me: ValidatorIndex,
        epoch: u64,
        round: Round,
        bytes: &[u8],
    ) {
        tracing::debug!(round, bytes = bytes.len(), "spreading as shards");
        for shard in shards::split(bytes, round, me, validators.len()) {
            let to = shard.index;
            let encoded = NetMessage::Shard { epoch, shard }.encode();
            let peers = self.transport.connected() as u64;
            if to == me {
                self.node
                    .metrics()
                    .sent(peers, peers * encoded.len() as u64);
                self.transport.broadcast(encoded);
            } else if let Some(key) = validators.key(to) {
                self.node.metrics().sent(1, encoded.len() as u64);
                self.transport.send(key, encoded);
            }
        }
    }

    fn wait_ms(&self) -> u64 {
        let deadline = self
            .current
            .as_ref()
            .map_or(u64::MAX, |c| c.engine.next_deadline());
        deadline.saturating_sub(now_ms()).max(1)
    }

    fn deadline_passed(&self) -> bool {
        self.current
            .as_ref()
            .is_some_and(|c| c.engine.next_deadline() <= now_ms())
    }

    pub fn spawn(mut self, inbox: Inbox) -> ValidatorHandle {
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let name = format!(
            "validator-{}",
            hex::encode(&self.key.public_key().as_raw()[..4])
        );
        let thread = std::thread::Builder::new()
            .name(name)
            .spawn(move || {
                while !stopped.load(Ordering::Relaxed) {
                    let wait = Duration::from_millis(self.wait_ms().min(50));
                    let result = match inbox.recv_timeout(wait) {
                        Ok((from, bytes)) => self.handle(&from, &bytes),
                        Err(RecvTimeoutError::Timeout) => self.tick(),
                        Err(RecvTimeoutError::Disconnected) => return,
                    };
                    let result = result.and_then(|()| {
                        if self.deadline_passed() {
                            self.tick()
                        } else {
                            Ok(())
                        }
                    });
                    if let Err(e) = result {
                        // on purpose: the hook in main exits and a supervisor restarts us
                        panic!("validator stopped: {e}");
                    }
                }
            })
            .expect("spawning a thread cannot fail");
        ValidatorHandle {
            stop,
            thread: Some(thread),
        }
    }
}

pub struct ValidatorHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ValidatorHandle {
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for ValidatorHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub fn spawn_standby(
    node: Arc<Node>,
    key: SecretKey,
    transport: Arc<dyn Transport>,
    timing: Timing,
    mut follower: crate::sync::Follower,
    inbox: Inbox,
) -> ValidatorHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let thread = std::thread::Builder::new()
        .name("standby".into())
        .spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                let member = current_validators(&node)
                    .map(|set| set.index_of(key.public_key()).is_some())
                    .unwrap_or(false);
                if member {
                    match Validator::start(node.clone(), key.clone(), transport.clone(), timing) {
                        Ok(mut validator) => {
                            tracing::info!("joined the validator set");
                            validator.follow(follower);
                            let handle = validator.spawn(inbox);
                            while !stopped.load(Ordering::Relaxed) {
                                std::thread::sleep(Duration::from_millis(50));
                            }
                            handle.stop();
                            return;
                        }
                        Err(e) => tracing::warn!(error = %e, "could not start the validator"),
                    }
                }
                if let Err(e) = follower.step() {
                    tracing::debug!(error = %e, "standby sync failed");
                }
                while inbox.try_recv().is_ok() {}
                std::thread::sleep(Duration::from_millis(100));
            }
        })
        .expect("spawning a thread cannot fail");
    ValidatorHandle {
        stop,
        thread: Some(thread),
    }
}
