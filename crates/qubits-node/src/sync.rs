use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use qubits_consensus::ValidatorSet;
use qubits_execution::{BlockEnv, execute_block_cached};
use qubits_state::{CommittedBlock, PutBlock, StateChunk};
use qubits_types::rpc::{
    EpochSummary, EpochsResponse, RawBlockResponse, SnapshotResponse, StatusResponse,
};
use qubits_types::{Genesis, Hash, SignedTransaction};
use serde::de::DeserializeOwned;

use crate::app::{
    ConsensusTip, EpochInfo, META_EPOCH, META_EPOCHS, META_FINALITY, META_TIP, PROOF_EVERY,
    finality_key, reconfigures, write_committed,
};
use crate::rpc::DEFAULT_CHUNK_BYTES;
use crate::{ChainBlock, FinalityProof, Node, NodeError, now_ms};

const REFORWARD_MS: u64 = 3_000;
/// A fresh node this far behind takes the state instead of replaying every block.
pub const SNAPSHOT_IF_BEHIND: u64 = 1_000;

const MAX_REPLY_BYTES: u64 = 64 * 1024 * 1024;
const UNREACHABLE_AFTER: Duration = Duration::from_secs(30);
const STATUS_EVERY_MS: u64 = 10_000;

#[derive(Clone, Debug)]
pub struct EpochView {
    pub validators: ValidatorSet,
    pub chain: Hash,
}

/// How many of `blocks` are proven final. Proofs that fail are cleared, so what's left can be
/// stored. A block is final if it or anything linked above it has a proof; a block that changes
/// the validators needs its own, since the next one is signed by others.
pub fn committed_prefix(
    parent: &Hash,
    parent_height: u64,
    blocks: &[ChainBlock],
    proofs: &mut [Option<FinalityProof>],
    epoch: &EpochView,
) -> Result<usize, String> {
    let mut view = epoch.clone();
    let mut previous = *parent;
    let mut proven = 0;
    for (i, block) in blocks.iter().enumerate() {
        let id = block.id();
        if block.height != parent_height + 1 + i as u64 {
            return Err(format!(
                "expected height {}, got {}",
                parent_height + 1 + i as u64,
                block.height
            ));
        }
        if block.parent != previous {
            return Err(format!(
                "block {} does not extend the previous block",
                block.height
            ));
        }
        if let Some(slot) = proofs.get_mut(i)
            && let Some(proof) = slot
        {
            if proof.tip == id && proof.verify(block.round, &view.validators, &view.chain) {
                proven = i + 1;
            } else {
                *slot = None;
            }
        }
        if crate::app::reconfigures(block) {
            if proven < i + 1 {
                break;
            }
            let keys = block
                .payload
                .transactions
                .iter()
                .filter_map(|tx| match &tx.tx.payload {
                    qubits_types::Payload::SetValidators { validators } => {
                        Some(qubits_types::validator_keys(validators))
                    }
                    _ => None,
                })
                .next_back()
                .expect("reconfigures() found one");
            view = EpochView {
                validators: ValidatorSet::new(keys)?,
                chain: id,
            };
        }
        previous = id;
    }
    Ok(proven)
}

/// The block that ended an epoch, with its proof, as a source hands it over.
#[derive(Clone, Debug)]
pub struct EpochProof {
    pub summary: EpochSummary,
    pub block: ChainBlock,
    pub proof: FinalityProof,
}

/// Verifies a snapshot's pivot block from genesis: each epoch's last block is certified by the
/// set before it, and hands over the next set. Returns the epoch the pivot belongs to and the
/// epochs after genesis up to it.
pub fn checked_pivot(
    genesis: &Genesis,
    epochs: &[EpochProof],
    block: &ChainBlock,
    proof: &FinalityProof,
) -> Result<(EpochInfo, Vec<EpochInfo>), String> {
    let (views, infos) = epoch_views(genesis, epochs)?;
    let id = block.id();
    if proof.tip != id || block.payload.check_tx_root().is_err() {
        return Err("the pivot block and its proof do not match".into());
    }
    let signed_by = infos
        .iter()
        .rposition(|e| e.start_height < block.height)
        .ok_or("the pivot is genesis")?;
    let view = &views[signed_by];
    if !proof.verify(block.round, &view.validators, &view.chain) {
        return Err("the pivot's proof fails".into());
    }
    let current = infos
        .iter()
        .rposition(|e| e.start_height <= block.height)
        .expect("genesis is below every block");
    if reconfigures(block) && infos[current].start_height != block.height {
        return Err("the pivot changes the validators but no epoch starts there".into());
    }
    Ok((infos[current].clone(), infos[1..=current].to_vec()))
}

/// The validator set of every epoch, from the genesis set through the blocks that ended each
/// epoch, each certified by the set before it.
pub fn epoch_views(
    genesis: &Genesis,
    epochs: &[EpochProof],
) -> Result<(Vec<EpochView>, Vec<EpochInfo>), String> {
    let mut views = vec![EpochView {
        validators: ValidatorSet::new(qubits_types::validator_keys(&genesis.validators))?,
        chain: genesis.hash(),
    }];
    let mut infos = vec![EpochInfo::genesis(genesis.hash())];
    for (i, e) in epochs.iter().enumerate() {
        let id = e.block.id();
        let number = i as u64 + 1;
        if e.summary.epoch != number
            || e.summary.start != id
            || e.summary.start_height != e.block.height
            || e.block.height <= infos[i].start_height
            || !reconfigures(&e.block)
            || e.block.payload.check_tx_root().is_err()
            || e.proof.tip != id
        {
            return Err(format!("epoch {number} does not check out"));
        }
        let view = &views[i];
        if !e.proof.verify(e.block.round, &view.validators, &view.chain) {
            return Err(format!(
                "epoch {number}: the proof of its first block fails"
            ));
        }
        let keys = e
            .block
            .payload
            .transactions
            .iter()
            .filter_map(|tx| match &tx.tx.payload {
                qubits_types::Payload::SetValidators { validators } => {
                    Some(qubits_types::validator_keys(validators))
                }
                _ => None,
            })
            .next_back()
            .expect("reconfigures() found one");
        views.push(EpochView {
            validators: ValidatorSet::new(keys)?,
            chain: id,
        });
        infos.push(EpochInfo {
            epoch: number,
            start: id,
            start_height: e.block.height,
        });
    }
    Ok((views, infos))
}

/// The set and chain id a block extending the current head is certified by.
pub(crate) fn current_view(node: &Node) -> Result<EpochView, SyncError> {
    let epoch = EpochInfo::read(node.store(), node.genesis_hash())
        .map_err(|e| SyncError::Node(NodeError::Storage(e)))?;
    let validators = crate::validator::current_validators(node)?;
    Ok(EpochView {
        validators,
        chain: epoch.start,
    })
}

/// Executes and commits what `committed_prefix` proves of `blocks`, on top of the head.
pub(crate) fn apply_proven(
    node: &Node,
    parent: &Hash,
    parent_height: u64,
    blocks: &[ChainBlock],
    proofs: &mut [Option<FinalityProof>],
) -> Result<usize, SyncError> {
    let view = current_view(node)?;
    let proven = committed_prefix(parent, parent_height, blocks, proofs, &view)
        .map_err(SyncError::Invalid)?;

    // each block's tip record gets the certificate of the next proof, from its own epoch
    let mut certificates = Vec::with_capacity(proven);
    let mut certificate = None;
    for proof in proofs[..proven].iter().rev() {
        if let Some(proof) = proof {
            certificate = Some(proof.qc.clone());
        }
        certificates.push(certificate.clone());
    }
    certificates.reverse();

    let genesis = node.genesis();
    for (i, block) in blocks[..proven].iter().enumerate() {
        let payload = &block.payload;
        payload
            .check_tx_root()
            .map_err(|e| SyncError::Invalid(e.to_string()))?;
        let env = BlockEnv {
            genesis_hash: node.genesis_hash(),
            height: block.height,
            timestamp_ms: payload.timestamp_ms,
            params: genesis.params.clone(),
        };
        let signatures = node.signatures();
        let executed = execute_block_cached(node.store(), env, &payload.transactions, &signatures)
            .map_err(|e| SyncError::Invalid(format!("block {}: {e}", block.height)))?;
        let qc = certificates[i]
            .as_ref()
            .expect("everything proven has a proof at or above it");
        write_committed(
            node.store(),
            &node.mempool(),
            block,
            &executed,
            node.keep_versions(),
            qc,
            proofs[i].as_ref(),
        )
        .map_err(SyncError::Invalid)?;
        node.feed().announce(block.height);
    }
    Ok(proven)
}

#[derive(Debug)]
pub enum SyncError {
    Source(String),
    Invalid(String),
    Node(NodeError),
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::Source(e) => write!(f, "source: {e}"),
            SyncError::Invalid(e) => write!(f, "invalid data from source: {e}"),
            SyncError::Node(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SyncError {}

impl From<NodeError> for SyncError {
    fn from(e: NodeError) -> Self {
        SyncError::Node(e)
    }
}

pub struct Follower {
    node: Arc<Node>,
    sources: Vec<String>,
    agent: ureq::Agent,
    next_source: usize,
    snapshot_if_behind: u64,
}

fn decode<T: borsh::BorshDeserialize>(what: &str, hex_text: &str) -> Result<T, SyncError> {
    let bytes =
        hex::decode(hex_text).map_err(|_| SyncError::Invalid(format!("{what} is not hex")))?;
    borsh::from_slice(&bytes).map_err(|e| SyncError::Invalid(format!("{what}: {e}")))
}

impl Follower {
    pub fn new(node: Arc<Node>, sources: Vec<String>) -> Result<Follower, NodeError> {
        if sources.is_empty() {
            return Err(NodeError::Config("no sources to follow".into()));
        }
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(60)))
            .build()
            .into();
        let sources = sources
            .into_iter()
            .map(|s| s.trim_end_matches('/').to_owned())
            .collect();
        Ok(Follower {
            node,
            sources,
            agent,
            next_source: 0,
            snapshot_if_behind: SNAPSHOT_IF_BEHIND,
        })
    }

    pub fn snapshot_if_behind(mut self, blocks: u64) -> Follower {
        self.snapshot_if_behind = blocks;
        self
    }

    fn get_bytes(&self, source: &str, path: &str) -> Result<Vec<u8>, SyncError> {
        let url = format!("{source}{path}");
        let mut resp = self
            .agent
            .get(&url)
            .call()
            .map_err(|e| SyncError::Source(format!("{url}: {e}")))?;
        if !resp.status().is_success() {
            return Err(SyncError::Source(format!(
                "{url}: HTTP {}",
                resp.status().as_u16()
            )));
        }
        resp.body_mut()
            .with_config()
            .limit(MAX_REPLY_BYTES)
            .read_to_vec()
            .map_err(|e| SyncError::Source(e.to_string()))
    }

    /// `None` when the source has nothing to offer there (404 or 503).
    fn get_optional<T: DeserializeOwned>(
        &self,
        source: &str,
        path: &str,
    ) -> Result<Option<T>, SyncError> {
        let url = format!("{source}{path}");
        let mut resp = self
            .agent
            .get(&url)
            .call()
            .map_err(|e| SyncError::Source(format!("{url}: {e}")))?;
        match resp.status().as_u16() {
            404 | 503 => return Ok(None),
            code if !resp.status().is_success() => {
                return Err(SyncError::Source(format!("{url}: HTTP {code}")));
            }
            _ => {}
        }
        let body = resp
            .body_mut()
            .with_config()
            .limit(MAX_REPLY_BYTES)
            .read_to_string()
            .map_err(|e| SyncError::Source(e.to_string()))?;
        serde_json::from_str(&body)
            .map(Some)
            .map_err(|e| SyncError::Source(format!("{url}: {e}")))
    }

    /// Takes the state at the source's snapshot height instead of replaying history. Only a node
    /// with nothing past genesis can. `Ok(None)` when the source offers no snapshot.
    fn snapshot(&mut self, source: &str) -> Result<Option<u64>, SyncError> {
        let Some(snap): Option<SnapshotResponse> =
            self.get_optional(source, "/v1/state/snapshot")?
        else {
            return Ok(None);
        };
        let invalid = |what: &str| SyncError::Invalid(what.to_string());
        let epochs: EpochsResponse = self.get(source, "/v1/epochs")?;
        let mut proofs = Vec::new();
        for summary in epochs.epochs.into_iter().filter(|e| e.epoch > 0) {
            let raw: RawBlockResponse =
                self.get(source, &format!("/v1/blocks/{}/raw", summary.start_height))?;
            let finality = raw
                .finality
                .ok_or_else(|| invalid("an epoch's first block comes without a proof"))?;
            proofs.push(EpochProof {
                summary,
                block: decode("block", &raw.block)?,
                proof: decode("finality proof", &finality)?,
            });
        }
        let block: ChainBlock = decode("block", &snap.block)?;
        let proof: FinalityProof = decode("finality proof", &snap.finality)?;
        if block.height != snap.height || block.payload.state_root != snap.state_root {
            return Err(invalid("the snapshot block does not match its summary"));
        }
        let (current, later) = checked_pivot(self.node.genesis(), &proofs, &block, &proof)
            .map_err(SyncError::Invalid)?;

        let height = block.height;
        tracing::info!(height, "taking the state from a snapshot");
        let store = self.node.store();
        let mut restore = store
            .begin_restore(height, block.payload.state_root)
            .map_err(NodeError::from)?;
        let mut from = Some([0u8; 32]);
        let (mut leaves, mut chunks) = (0usize, 0usize);
        while let Some(start) = from {
            let path = format!(
                "/v1/state/ranges?height={height}&from={}&bytes={DEFAULT_CHUNK_BYTES}",
                hex::encode(start)
            );
            let bytes = self.get_bytes(source, &path)?;
            let chunk: StateChunk = borsh::from_slice(&bytes)
                .map_err(|e| SyncError::Invalid(format!("state chunk: {e}")))?;
            leaves += chunk.leaves.len();
            chunks += 1;
            from = chunk.next();
            restore
                .add_chunk(chunk)
                .map_err(|e| SyncError::Invalid(format!("state chunk: {}", e.0)))?;
            if chunks.is_multiple_of(50) {
                tracing::info!(leaves, "restoring the state");
            }
        }

        let id = block.id();
        let bytes = borsh::to_vec(&block).expect("encoding cannot fail");
        let tx_ids: Vec<Hash> = block
            .payload
            .transactions
            .iter()
            .map(SignedTransaction::id)
            .collect();
        let tip = ConsensusTip {
            id,
            height,
            round: block.round,
            qc: proof.qc.clone(),
            timestamp_ms: block.payload.timestamp_ms,
        };
        let encode = |value: &dyn Fn() -> Vec<u8>| value();
        let proof_key = finality_key(height);
        let meta = [
            (
                META_TIP,
                encode(&|| borsh::to_vec(&tip).expect("encoding cannot fail")),
            ),
            (
                META_FINALITY,
                encode(&|| borsh::to_vec(&(height, &proof)).expect("encoding cannot fail")),
            ),
            (
                proof_key.as_slice(),
                encode(&|| borsh::to_vec(&proof).expect("encoding cannot fail")),
            ),
            (
                META_EPOCH,
                encode(&|| borsh::to_vec(&current).expect("encoding cannot fail")),
            ),
            (
                META_EPOCHS,
                encode(&|| borsh::to_vec(&later).expect("encoding cannot fail")),
            ),
        ];
        let addresses = crate::index::of_payload(&block);
        let committed = CommittedBlock {
            height,
            state_root: block.payload.state_root,
            bytes: &bytes,
            tx_ids: &tx_ids,
            addresses: &addresses,
            receipts: &[],
            meta: &meta,
        };
        store
            .finish_restore(restore, &committed)
            .map_err(|e| SyncError::Invalid(format!("snapshot: {}", e.0)))?;
        // the next node to join from here walks the same epochs, and these are the only blocks
        // from below the pivot that it needs
        for e in proofs.iter().filter(|e| e.block.height < height) {
            let put = PutBlock {
                bytes: borsh::to_vec(&e.block).expect("encoding cannot fail"),
                tx_ids: e
                    .block
                    .payload
                    .transactions
                    .iter()
                    .map(SignedTransaction::id)
                    .collect(),
                addresses: crate::index::of_payload(&e.block),
                meta: vec![(
                    finality_key(e.block.height),
                    borsh::to_vec(&e.proof).expect("encoding cannot fail"),
                )],
            };
            store
                .put_blocks(e.block.height, &[put])
                .map_err(|e| SyncError::Invalid(format!("snapshot: {}", e.0)))?;
        }
        self.node.metrics().snapshot_synced();
        tracing::info!(height, leaves, chunks, "state restored from a snapshot");
        Ok(Some(height))
    }

    fn get<T: DeserializeOwned>(&self, source: &str, path: &str) -> Result<T, SyncError> {
        let url = format!("{source}{path}");
        let mut resp = self
            .agent
            .get(&url)
            .call()
            .map_err(|e| SyncError::Source(format!("{url}: {e}")))?;
        if !resp.status().is_success() {
            return Err(SyncError::Source(format!(
                "{url}: HTTP {}",
                resp.status().as_u16()
            )));
        }
        let body = resp
            .body_mut()
            .with_config()
            .limit(MAX_REPLY_BYTES)
            .read_to_string()
            .map_err(|e| SyncError::Source(e.to_string()))?;
        serde_json::from_str(&body).map_err(|e| SyncError::Source(format!("{url}: {e}")))
    }

    pub fn remote_height(&mut self) -> Result<u64, SyncError> {
        self.remote_status().map(|s| s.height)
    }

    fn remote_status(&mut self) -> Result<StatusResponse, SyncError> {
        let source = self.sources[self.next_source % self.sources.len()].clone();
        let status: StatusResponse = self
            .get(&source, "/v1/status")
            .inspect_err(|_| self.next_source += 1)?;
        if status.genesis_hash != self.node.genesis_hash() {
            self.next_source += 1;
            return Err(SyncError::Invalid(format!(
                "{source} follows a different chain"
            )));
        }
        Ok(status)
    }

    pub fn step(&mut self) -> Result<u64, SyncError> {
        self.step_until(None)
    }

    /// One pass that gives up once `timeout` is over.
    pub fn step_within(&mut self, timeout: Duration) -> Result<u64, SyncError> {
        self.step_until(Some(Instant::now() + timeout))
    }

    fn step_until(&mut self, deadline: Option<Instant>) -> Result<u64, SyncError> {
        let result = self.try_step(deadline);
        if result.is_err() {
            self.next_source += 1;
        }
        result
    }

    fn try_step(&mut self, deadline: Option<Instant>) -> Result<u64, SyncError> {
        let status = self.remote_status()?;
        let remote = status.height;
        let source = self.sources[self.next_source % self.sources.len()].clone();
        let head = self.node.head()?;
        if remote <= head.height {
            return Ok(0);
        }
        if head.height == 0
            && (remote > self.snapshot_if_behind || status.blocks_from > 1)
            && let Some(height) = self.snapshot(&source)?
        {
            return Ok(height);
        }
        if status.blocks_from > head.height + 1 {
            return Err(SyncError::Source(format!(
                "{source} keeps blocks only from {} and this node is at {}: re-initialize it \
                 to join from a snapshot",
                status.blocks_from, head.height
            )));
        }
        let end = remote.min((head.height / PROOF_EVERY + 1) * PROOF_EVERY);
        let mut blocks = Vec::new();
        let mut proofs = Vec::new();
        for height in head.height + 1..=end {
            if deadline.is_some_and(|d| Instant::now() > d) {
                return Err(SyncError::Source(format!("{source} is too slow")));
            }
            let query = if height == end { "?prove=true" } else { "" };
            let raw: RawBlockResponse =
                self.get(&source, &format!("/v1/blocks/{height}/raw{query}"))?;
            blocks.push(decode::<ChainBlock>("block", &raw.block)?);
            proofs.push(match raw.finality {
                Some(f) => Some(decode::<FinalityProof>("finality proof", &f)?),
                None => None,
            });
        }
        let proven = apply_proven(&self.node, &head.hash, head.height, &blocks, &mut proofs)?;
        Ok(proven as u64)
    }

    pub fn catch_up(&mut self, max_lag: u64, timeout: Duration) -> Result<(), SyncError> {
        let deadline = Instant::now() + timeout;
        let mut last_answer = Instant::now();
        loop {
            if Instant::now() > deadline {
                return Err(SyncError::Source("timed out catching up".into()));
            }
            let remote = match self.remote_height() {
                Ok(remote) => remote,
                Err(SyncError::Node(e)) => return Err(SyncError::Node(e)),
                Err(e) if last_answer.elapsed() > UNREACHABLE_AFTER => return Err(e),
                Err(e) => {
                    tracing::debug!(error = %e, "source did not answer");
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
            };
            last_answer = Instant::now();
            if remote <= self.node.head()?.height + max_lag {
                return Ok(());
            }
            match self.step_until(Some(deadline)) {
                Ok(0) => std::thread::sleep(Duration::from_millis(200)),
                Ok(_) => {}
                Err(SyncError::Node(e)) => return Err(SyncError::Node(e)),
                Err(e) => tracing::warn!(error = %e, "sync pass failed"),
            }
        }
    }

    /// Catching up on the validator thread, where consensus waits for it. Every pass has to bring
    /// blocks and all of it ends by `timeout`, so a source claiming blocks it doesn't serve costs
    /// one pass.
    pub fn keep_pace(&mut self, max_lag: u64, timeout: Duration) -> Result<(), SyncError> {
        let deadline = Instant::now() + timeout;
        loop {
            let remote = self.remote_height()?;
            if remote <= self.node.head()?.height + max_lag {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(SyncError::Source("timed out catching up".into()));
            }
            if self.step_until(Some(deadline))? == 0 {
                return Err(SyncError::Source(
                    "the source claims blocks it doesn't serve".into(),
                ));
            }
        }
    }

    pub fn spawn(mut self, every: Duration) -> FollowerHandle {
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = std::thread::Builder::new()
            .name("follower".into())
            .spawn(move || {
                let mut last_reforward = now_ms();
                let mut last_status = now_ms();
                while !stopped.load(Ordering::Relaxed) {
                    let now = now_ms();
                    if now >= last_reforward + REFORWARD_MS {
                        last_reforward = now;
                        self.node
                            .expire_mempool(now, crate::Timing::DEFAULT.tx_ttl_ms);
                        self.node.reforward(now, REFORWARD_MS);
                    }
                    if now >= last_status + STATUS_EVERY_MS {
                        last_status = now;
                        if let Ok(head) = self.node.head() {
                            tracing::info!(
                                height = head.height,
                                mempool = self.node.mempool_len(),
                                "following the chain"
                            );
                        }
                    }
                    match self.step() {
                        Ok(n) if n > 0 => continue,
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "sync pass failed"),
                    }
                    std::thread::sleep(every);
                }
            })
            .expect("spawning a thread cannot fail");
        FollowerHandle {
            stop,
            thread: Some(thread),
        }
    }
}

pub struct FollowerHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for FollowerHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
