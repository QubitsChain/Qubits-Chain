#![forbid(unsafe_code)]

mod app;
pub mod era;
pub mod history;
pub mod index;
mod mempool;
mod metrics;
pub mod network;
pub mod p2p;
pub mod rpc;
pub mod sync;
mod validator;
pub mod ws;

use std::fmt;
use std::path::Path;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use qubits_execution::{BlockEnv, Executor, Simulated, TxError, genesis_writes, simulate};
use qubits_state::Store;
use qubits_types::rpc::ViewRequest;
use qubits_types::{Address, Genesis, Hash, SignedTransaction};

pub use app::{ChainBlock, ConsensusTip, EpochInfo, PROOF_EVERY, reconfigures};
use mempool::Mempool;
pub use mempool::{MAX_MEMPOOL_TRANSACTIONS, MAX_PER_SENDER};
use network::{NetMessage, Transport};
pub use qubits_consensus::FinalityProof;
pub use validator::{Timing, Validator, ValidatorHandle, spawn_standby};

pub const MAX_CLOCK_DRIFT_MS: u64 = 10_000;
const FORWARD_QUEUE: usize = 1024;
const FORWARD_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum NodeError {
    Storage(String),
    Config(String),
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeError::Storage(e) => write!(f, "storage: {e}"),
            NodeError::Config(e) => write!(f, "configuration: {e}"),
        }
    }
}

impl std::error::Error for NodeError {}

impl From<qubits_state::Error> for NodeError {
    fn from(e: qubits_state::Error) -> Self {
        NodeError::Storage(e.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitError {
    Invalid(TxError),
    Duplicate,
    MempoolFull,
}

impl fmt::Display for SubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubmitError::Invalid(e) => write!(f, "{e}"),
            SubmitError::Duplicate => write!(f, "transaction already known"),
            SubmitError::MempoolFull => write!(f, "mempool is full, try again later"),
        }
    }
}

impl std::error::Error for SubmitError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    pub height: u64,
    pub hash: Hash,
    pub timestamp_ms: u64,
    pub state_root: Hash,
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // a poisoned lock only holds plain data
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub struct Node {
    store: Arc<Store>,
    genesis: Genesis,
    genesis_hash: Hash,
    mempool: Arc<Mutex<Mempool>>,
    signatures: Arc<qubits_types::SignatureCache>,
    gossip: Mutex<Option<Arc<dyn Transport>>>,
    forward: Mutex<Option<SyncSender<SignedTransaction>>>,
    keep_versions: Arc<std::sync::atomic::AtomicU64>,
    era_length: std::sync::atomic::AtomicU64,
    submits: Arc<tokio::sync::Semaphore>,
    metrics: metrics::Metrics,
    feed: ws::Feed,
}

impl Node {
    pub fn init(data_dir: &Path, genesis: &Genesis) -> Result<(), NodeError> {
        genesis
            .validate()
            .map_err(|e| NodeError::Config(format!("genesis: {e}")))?;
        let store = Store::open(data_dir)?;
        if store.latest_height()?.is_some() {
            return Err(NodeError::Config(format!(
                "{} already holds a chain",
                data_dir.display()
            )));
        }
        let prepared = store.prepare(0, &genesis_writes(genesis))?;
        store.commit_genesis(genesis, prepared)?;
        Ok(())
    }

    pub fn open(data_dir: &Path) -> Result<Node, NodeError> {
        let store = Store::open(data_dir)?;
        let genesis = store.genesis()?.ok_or_else(|| {
            NodeError::Config(format!(
                "{} is not initialized; run `qubits-node init` first",
                data_dir.display()
            ))
        })?;
        if store.address_index_version()? != Some(index::VERSION) {
            let blocks = store.rebuild_address_index(index::VERSION, |_, bytes| {
                let block: ChainBlock = borsh::from_slice(bytes).map_err(|e| e.to_string())?;
                index::of_block(&store, &block)
            })?;
            tracing::info!(blocks, "indexed transactions by address");
        }
        if store.token_index_version()? != Some(index::TOKEN_VERSION) {
            let blocks = store.rebuild_token_index(index::TOKEN_VERSION, |_, bytes| {
                let block: ChainBlock = borsh::from_slice(bytes).map_err(|e| e.to_string())?;
                index::tokens_of_block(&store, &block)
            })?;
            tracing::info!(blocks, "indexed tokens by holder");
        }
        Ok(Node {
            store: Arc::new(store),
            genesis_hash: genesis.hash(),
            genesis,
            mempool: Arc::new(Mutex::new(Mempool::default())),
            signatures: Arc::default(),
            gossip: Mutex::new(None),
            forward: Mutex::new(None),
            keep_versions: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            era_length: std::sync::atomic::AtomicU64::new(history::CHECKPOINT_EVERY),
            submits: Arc::new(tokio::sync::Semaphore::new(rpc::MAX_CONCURRENT_SUBMITS)),
            metrics: metrics::Metrics::default(),
            feed: ws::Feed::default(),
        })
    }

    pub(crate) fn feed(&self) -> &ws::Feed {
        &self.feed
    }

    /// How many WebSocket connections may be open at once.
    pub fn set_ws_limit(&self, limit: usize) {
        self.feed.set_limit(limit);
    }

    pub fn ws_connections(&self) -> usize {
        self.feed.connections()
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub(crate) fn store_arc(&self) -> Arc<Store> {
        self.store.clone()
    }

    pub(crate) fn metrics(&self) -> &metrics::Metrics {
        &self.metrics
    }

    pub(crate) fn submits(&self) -> Arc<tokio::sync::Semaphore> {
        self.submits.clone()
    }

    pub(crate) fn mempool(&self) -> Arc<Mutex<Mempool>> {
        self.mempool.clone()
    }

    pub(crate) fn set_gossip(&self, transport: Arc<dyn Transport>) {
        *lock(&self.gossip) = Some(transport);
    }

    pub fn set_keep_versions(&self, versions: u64) {
        self.keep_versions
            .store(versions, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn keep_versions(&self) -> u64 {
        self.keep_versions
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn keep_versions_shared(&self) -> Arc<std::sync::atomic::AtomicU64> {
        self.keep_versions.clone()
    }

    pub fn forward_to(&self, apis: Vec<String>) {
        let (queue, transactions) = sync_channel::<SignedTransaction>(FORWARD_QUEUE);
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(FORWARD_TIMEOUT))
            .build()
            .into();
        std::thread::Builder::new()
            .name("tx-forward".into())
            .spawn(move || {
                while let Ok(stx) = transactions.recv() {
                    let body = qubits_types::rpc::SubmitRequest {
                        transaction: hex::encode(stx.encode()),
                    };
                    for api in &apis {
                        let url = format!("{}/v1/transactions", api.trim_end_matches('/'));
                        if let Err(e) = agent.post(&url).send_json(&body) {
                            tracing::warn!(%url, error = %e, "could not forward transaction");
                        }
                    }
                }
            })
            .expect("spawning a thread cannot fail");
        *lock(&self.forward) = Some(queue);
    }

    pub fn genesis(&self) -> &Genesis {
        &self.genesis
    }

    pub fn genesis_hash(&self) -> Hash {
        self.genesis_hash
    }

    pub(crate) fn signatures(&self) -> Arc<qubits_types::SignatureCache> {
        self.signatures.clone()
    }

    pub fn validators(&self) -> Result<qubits_types::ValidatorSet, NodeError> {
        qubits_execution::read_validators(self.store())
            .map_err(|e| NodeError::Storage(e.to_string()))
    }

    pub fn block(&self, height: u64) -> Result<Option<ChainBlock>, NodeError> {
        match self.store.block(height)? {
            Some(bytes) => borsh::from_slice(&bytes)
                .map(Some)
                .map_err(|e| NodeError::Storage(format!("corrupt block {height}: {e}"))),
            None => Ok(None),
        }
    }

    /// Blocks per era file; proofs at era ends are kept forever. Only tests change it.
    pub fn era_length(&self) -> u64 {
        self.era_length.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn set_era_length(&self, length: u64) -> Result<(), NodeError> {
        if length == 0 || !length.is_multiple_of(PROOF_EVERY) {
            return Err(NodeError::Config(format!(
                "the era length must be a multiple of {PROOF_EVERY}"
            )));
        }
        self.era_length
            .store(length, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Complete eras this node can hand out: every block held and the proof at the end kept.
    pub fn eras(&self) -> Result<Vec<u64>, NodeError> {
        let length = self.era_length();
        let head = self.head()?.height;
        let from = self.store.blocks_from()?;
        let mut eras = Vec::new();
        for index in 0..head / length {
            let (first, last) = era::range(index, length);
            if first >= from.max(1) && self.stored_proof(last)?.is_some() {
                eras.push(index);
            }
        }
        Ok(eras)
    }

    pub fn epochs(&self) -> Result<Vec<EpochInfo>, NodeError> {
        EpochInfo::list(self.store(), self.genesis_hash).map_err(NodeError::Storage)
    }

    /// The newest height a joining node can take the state from: it has a proof kept and its
    /// state is still here. Pruned nodes keeping fewer than `PROOF_EVERY` versions have none.
    pub fn snapshot_height(&self) -> Result<Option<u64>, NodeError> {
        let head = self.head()?.height;
        let pruned = self.store.pruned_before()?;
        let epoch_start = self.epochs()?.last().map_or(0, |e| e.start_height);
        let regular = head - head % PROOF_EVERY;
        let candidate = regular.max(epoch_start);
        if candidate == 0 || candidate < pruned || self.stored_proof(candidate)?.is_none() {
            return Ok(None);
        }
        Ok(Some(candidate))
    }

    /// The proof kept for exactly this height, if any.
    pub fn stored_proof(&self, height: u64) -> Result<Option<FinalityProof>, NodeError> {
        match self.store.get_meta(&app::finality_key(height))? {
            Some(bytes) => borsh::from_slice(&bytes)
                .map(Some)
                .map_err(|e| NodeError::Storage(format!("corrupt proof at {height}: {e}"))),
            None => Ok(None),
        }
    }

    /// Proves `height` final from the next proof kept above it. `None` while the block is
    /// missing or newer than the last proof written.
    pub fn finality_proof(&self, height: u64) -> Result<Option<FinalityProof>, NodeError> {
        let Some(block) = self.block(height)? else {
            return Ok(None);
        };
        let Some(bytes) = self.store.get_meta(app::META_FINALITY)? else {
            return Ok(None);
        };
        let (tip, tip_proof): (u64, FinalityProof) = borsh::from_slice(&bytes)
            .map_err(|e| NodeError::Storage(format!("corrupt tip proof: {e}")))?;
        let mut path = Vec::new();
        for h in height..=tip {
            let kept = if h == tip {
                Some(tip_proof.clone())
            } else {
                self.stored_proof(h)?
            };
            if let Some(proof) = kept {
                path.extend(proof.path);
                return Ok(Some(FinalityProof {
                    tip: block.id(),
                    path,
                    qc: proof.qc,
                }));
            }
            let next = self
                .block(h + 1)?
                .ok_or_else(|| NodeError::Storage(format!("block {} missing", h + 1)))?;
            path.push(next.header());
        }
        Ok(None)
    }

    pub fn head(&self) -> Result<Head, NodeError> {
        let height = self.store.latest_height()?.unwrap_or(0);
        let state_root = self.store.state_root(height)?;
        if height == 0 {
            return Ok(Head {
                height,
                hash: self.genesis_hash,
                timestamp_ms: self.genesis.timestamp_ms,
                state_root,
            });
        }
        let block = self
            .block(height)?
            .ok_or_else(|| NodeError::Storage(format!("block {height} missing")))?;
        Ok(Head {
            height,
            hash: block.id(),
            timestamp_ms: block.payload.timestamp_ms,
            state_root,
        })
    }

    pub fn mempool_len(&self) -> usize {
        lock(&self.mempool).len()
    }

    pub fn pending_transaction(&self, id: &Hash) -> Option<SignedTransaction> {
        lock(&self.mempool).get(id).cloned()
    }

    pub(crate) fn expire_mempool(&self, now_ms: u64, ttl_ms: u64) {
        let expired = lock(&self.mempool).expire(now_ms, ttl_ms);
        if expired > 0 {
            tracing::info!(expired, "dropped expired transactions");
        }
    }

    pub(crate) fn waiting_since(
        &self,
        now_ms: u64,
        age_ms: u64,
        limit: usize,
    ) -> Vec<SignedTransaction> {
        lock(&self.mempool).waiting_since(now_ms, age_ms, limit)
    }

    pub(crate) fn reforward(&self, now_ms: u64, age_ms: u64) {
        let waiting = self.waiting_since(now_ms, age_ms, 64);
        if !waiting.is_empty() {
            self.forward(waiting);
        }
    }

    fn forward(&self, transactions: Vec<SignedTransaction>) {
        if let Some(queue) = lock(&self.forward).as_ref() {
            for stx in transactions {
                let _ = queue.try_send(stx);
            }
        }
    }

    pub fn submit(&self, stx: SignedTransaction, now_ms: u64) -> Result<Hash, SubmitError> {
        let id = self.accept(stx.clone(), now_ms)?;
        tracing::info!(
            %id,
            sender = %stx.tx.sender,
            nonce = stx.tx.nonce,
            fee = %stx.tx.fee,
            bytes = stx.encode().len(),
            "transaction received"
        );
        let gossip = lock(&self.gossip).clone();
        if let Some(gossip) = gossip {
            gossip.broadcast(NetMessage::Transaction(stx.clone()).encode());
        }
        self.forward(vec![stx]);
        Ok(id)
    }

    fn admission(mempool: &Mempool, id: &Hash, stx: &SignedTransaction) -> Result<(), SubmitError> {
        if mempool.contains(id) {
            return Err(SubmitError::Duplicate);
        }
        if mempool.len() >= MAX_MEMPOOL_TRANSACTIONS
            || mempool.sender_count(&stx.tx.sender) >= MAX_PER_SENDER
        {
            return Err(SubmitError::MempoolFull);
        }
        Ok(())
    }

    pub fn accept(&self, stx: SignedTransaction, now_ms: u64) -> Result<Hash, SubmitError> {
        let id = stx.id();
        let storage = |e: NodeError| SubmitError::Invalid(TxError::Storage(e.to_string()));
        let earlier: Vec<SignedTransaction> = {
            let mempool = lock(&self.mempool);
            Self::admission(&mempool, &id, &stx)?;
            mempool.by_sender(&stx.tx.sender).cloned().collect()
        };
        let included = self.store.tx_location(&id);
        if included.map_err(|e| storage(e.into()))?.is_some() {
            return Err(SubmitError::Duplicate);
        }
        let head = self.head().map_err(storage)?;
        let env = BlockEnv {
            genesis_hash: self.genesis_hash,
            height: head.height + 1,
            timestamp_ms: now_ms.max(head.timestamp_ms + 1),
            params: self.genesis.params.clone(),
        };
        let mut executor = Executor::new(self.store.as_ref(), env)
            .with_signatures(&self.signatures)
            .without_contracts();
        for earlier in &earlier {
            let _ = executor.apply_verified(earlier);
        }
        executor.apply(&stx).map_err(SubmitError::Invalid)?;
        let mut mempool = lock(&self.mempool);
        Self::admission(&mempool, &id, &stx)?;
        mempool.insert(stx, now_ms);
        Ok(id)
    }
}

impl Node {
    /// Runs a contract function against the latest state and keeps nothing.
    pub fn simulate(
        &self,
        request: &ViewRequest,
        contract: &Address,
        now_ms: u64,
    ) -> Result<Simulated, TxError> {
        let head = self.head().map_err(|e| TxError::Storage(e.to_string()))?;
        let env = BlockEnv {
            genesis_hash: self.genesis_hash,
            height: head.height + 1,
            timestamp_ms: now_ms.max(head.timestamp_ms + 1),
            params: self.genesis.params.clone(),
        };
        simulate(
            self.store.as_ref(),
            env,
            &request.caller.unwrap_or(Address([0; 32])),
            contract,
            &request.function,
            &request.args,
            request.amount,
        )
    }
}

pub async fn serve(node: Arc<Node>, listener: tokio::net::TcpListener) -> std::io::Result<()> {
    tokio::spawn(ws::publish(node.clone()));
    axum::serve(listener, rpc::router(node)).await
}
