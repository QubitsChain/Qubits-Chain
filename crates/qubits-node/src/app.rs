use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use borsh::{BorshDeserialize, BorshSerialize};
use qubits_consensus::{App, Block, Final, FinalityProof, Header, QuorumCert, Round};
use qubits_execution::{BlockEnv, Executed, Executor, TxError};
use qubits_state::{CommittedBlock, Overlay, Store, WriteSet};
use qubits_types::limits::MAX_BLOCK_BYTES;
use qubits_types::{
    Address, BlockPayload, Genesis, Hash, Receipt, SignatureCache, SignedTransaction, receipt_root,
    tx_root,
};

use crate::mempool::Mempool;
use crate::{MAX_CLOCK_DRIFT_MS, lock};

pub type ChainBlock = Block<BlockPayload>;

/// A proof is 2f+1 signatures of 3.3 KB each. Blocks link by hash, so every block doesn't need
/// its own: these and the tip's are enough, and any height can be proven from the next one kept.
pub const PROOF_EVERY: u64 = 64;

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ConsensusTip {
    pub id: Hash,
    pub height: u64,
    pub round: Round,
    pub qc: QuorumCert,
    pub timestamp_ms: u64,
}

pub(crate) const META_TIP: &[u8] = b"consensus_tip";
pub(crate) const META_FINALITY: &[u8] = b"consensus_finality";
pub(crate) const META_EPOCH: &[u8] = b"consensus_epoch";
/// every epoch after the first, in order; a joining node walks them to reach the current set
pub(crate) const META_EPOCHS: &[u8] = b"consensus_epochs";

pub(crate) fn finality_key(height: u64) -> Vec<u8> {
    [b"finality/".as_slice(), &height.to_be_bytes()].concat()
}

fn keeps_proof(block: &ChainBlock) -> bool {
    block.height.is_multiple_of(PROOF_EVERY) || reconfigures(block)
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EpochInfo {
    pub epoch: u64,
    pub start: Hash,
    pub start_height: u64,
}

impl EpochInfo {
    pub(crate) fn genesis(genesis_hash: Hash) -> Self {
        EpochInfo {
            epoch: 0,
            start: genesis_hash,
            start_height: 0,
        }
    }

    pub fn read(store: &Store, genesis_hash: Hash) -> Result<EpochInfo, String> {
        match store.get_meta(META_EPOCH).map_err(|e| e.to_string())? {
            Some(bytes) => borsh::from_slice(&bytes).map_err(|e| e.to_string()),
            None => Ok(EpochInfo::genesis(genesis_hash)),
        }
    }

    pub fn list(store: &Store, genesis_hash: Hash) -> Result<Vec<EpochInfo>, String> {
        let mut epochs = vec![EpochInfo::genesis(genesis_hash)];
        if let Some(bytes) = store.get_meta(META_EPOCHS).map_err(|e| e.to_string())? {
            let later: Vec<EpochInfo> = borsh::from_slice(&bytes).map_err(|e| e.to_string())?;
            epochs.extend(later);
        }
        Ok(epochs)
    }
}

pub fn reconfigures(block: &ChainBlock) -> bool {
    block
        .payload
        .transactions
        .iter()
        .any(|tx| matches!(tx.tx.payload, qubits_types::Payload::SetValidators { .. }))
}

pub(crate) fn write_committed(
    store: &Store,
    mempool: &Mutex<Mempool>,
    block: &ChainBlock,
    executed: &Executed,
    keep_versions: u64,
    qc: &QuorumCert,
    proof: Option<&FinalityProof>,
) -> Result<(), String> {
    let id = block.id();
    let prepared = store
        .prepare(block.height, &executed.writes)
        .map_err(|e| e.to_string())?;
    if prepared.root() != block.payload.state_root {
        return Err(format!(
            "state root of block {} does not match execution",
            block.height
        ));
    }
    let bytes = borsh::to_vec(block).expect("encoding cannot fail");
    let tx_ids: Vec<Hash> = block
        .payload
        .transactions
        .iter()
        .map(SignedTransaction::id)
        .collect();
    if receipt_root(&executed.receipts) != block.payload.receipt_root {
        return Err(format!(
            "receipts of block {} do not match its receipt root",
            block.height
        ));
    }
    let kept_receipts: Vec<(Hash, Vec<u8>)> = tx_ids
        .iter()
        .zip(&executed.receipts)
        .filter(|(_, receipt)| **receipt != Receipt::default())
        .map(|(id, receipt)| {
            let bytes = borsh::to_vec(receipt).expect("encoding cannot fail");
            (*id, bytes)
        })
        .collect();
    let tip = ConsensusTip {
        id,
        height: block.height,
        round: block.round,
        qc: qc.clone(),
        timestamp_ms: block.payload.timestamp_ms,
    };
    let proof_key = finality_key(block.height);
    let mut meta = vec![(META_TIP, borsh::to_vec(&tip).expect("encoding cannot fail"))];
    if let Some(proof) = proof {
        let tip_proof = borsh::to_vec(&(block.height, proof)).expect("encoding cannot fail");
        meta.push((META_FINALITY, tip_proof));
        if keeps_proof(block) {
            let kept = borsh::to_vec(proof).expect("encoding cannot fail");
            meta.push((proof_key.as_slice(), kept));
        }
    }
    if reconfigures(block) {
        let set_bytes = executed
            .writes
            .get(&qubits_execution::keys::validators())
            .cloned()
            .flatten()
            .ok_or("a validator change wrote no validator set")?;
        let set: qubits_types::ValidatorSet =
            borsh::from_slice(&set_bytes).map_err(|e| e.to_string())?;
        let epoch = EpochInfo {
            epoch: set.epoch,
            start: id,
            start_height: block.height,
        };
        meta.push((
            META_EPOCH,
            borsh::to_vec(&epoch).expect("encoding cannot fail"),
        ));
        let mut all = EpochInfo::list(store, Hash::ZERO)?;
        all.remove(0);
        all.push(epoch);
        meta.push((
            META_EPOCHS,
            borsh::to_vec(&all).expect("encoding cannot fail"),
        ));
    }
    let addresses: Vec<Vec<Address>> = block
        .payload
        .transactions
        .iter()
        .zip(&executed.receipts)
        .map(|(tx, receipt)| crate::index::addresses(tx, Some(receipt)))
        .collect();
    let committed = CommittedBlock {
        height: block.height,
        state_root: block.payload.state_root,
        bytes: &bytes,
        tx_ids: &tx_ids,
        addresses: &addresses,
        receipts: &kept_receipts,
        meta: &meta,
    };
    store
        .commit_block(&committed, prepared)
        .map_err(|e| e.to_string())?;

    // only these senders' nonces moved: read them before taking the lock consensus shares
    let nonces: HashMap<Address, u64> = block
        .payload
        .transactions
        .iter()
        .map(|tx| tx.tx.sender)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .filter_map(|sender| {
            let account = qubits_execution::read_account(store, &sender).ok()??;
            Some((sender, account.nonce))
        })
        .collect();
    let mut mempool = lock(mempool);
    for tx_id in &tx_ids {
        mempool.remove(tx_id);
    }
    if !nonces.is_empty() {
        let stale: Vec<Hash> = mempool
            .iter()
            .filter(|tx| nonces.get(&tx.tx.sender).is_some_and(|n| *n > tx.tx.nonce))
            .map(SignedTransaction::id)
            .collect();
        for tx_id in &stale {
            mempool.remove(tx_id);
        }
    }
    drop(mempool);
    tracing::info!(
        height = block.height,
        round = block.round,
        txs = tx_ids.len(),
        kb = bytes.len() / 1024,
        %id,
        "committed block"
    );
    if keep_versions > 0 && block.height > keep_versions {
        store
            .prune(block.height - keep_versions)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

struct Executing {
    included: Vec<SignedTransaction>,
    writes: WriteSet,
    receipts: Vec<Receipt>,
    state_root: Hash,
    failed: Vec<Hash>,
}

struct Speculative {
    parent: Hash,
    height: u64,
    timestamp_ms: u64,
    executed: Executed,
    has_transactions: bool,
    reconfigures: bool,
    tx_ids: Vec<Hash>,
}

pub struct ChainApp {
    store: Arc<Store>,
    genesis: Genesis,
    mempool: Arc<Mutex<Mempool>>,
    signatures: Arc<SignatureCache>,
    committed: Hash,
    committed_height: u64,
    committed_timestamp: u64,
    pending: HashMap<Hash, Speculative>,
    keep_versions: Arc<std::sync::atomic::AtomicU64>,
    heads: Arc<tokio::sync::watch::Sender<u64>>,
    epoch_end: Option<(Hash, u64)>,
    retired: bool,
}

impl ChainApp {
    pub(crate) fn new(
        store: Arc<Store>,
        genesis: Genesis,
        mempool: Arc<Mutex<Mempool>>,
        signatures: Arc<SignatureCache>,
        tip: Option<&ConsensusTip>,
        keep_versions: Arc<std::sync::atomic::AtomicU64>,
        heads: Arc<tokio::sync::watch::Sender<u64>>,
    ) -> Self {
        let (committed, committed_height, committed_timestamp) = match tip {
            Some(t) => (t.id, t.height, t.timestamp_ms),
            None => (genesis.hash(), 0, genesis.timestamp_ms),
        };
        ChainApp {
            store,
            genesis,
            mempool,
            signatures,
            committed,
            committed_height,
            committed_timestamp,
            pending: HashMap::new(),
            keep_versions,
            heads,
            epoch_end: None,
            retired: false,
        }
    }

    pub(crate) fn retire(&mut self) {
        self.retired = true;
        self.pending.clear();
    }

    pub(crate) fn take_epoch_end(&mut self) -> Option<(Hash, u64)> {
        let end = self.epoch_end.take()?;
        self.pending.clear();
        Some(end)
    }

    fn reconfiguration_pending(&self, parent: &Hash) -> bool {
        let mut cursor = *parent;
        while cursor != self.committed {
            match self.pending.get(&cursor) {
                Some(spec) if spec.reconfigures => return true,
                Some(spec) => cursor = spec.parent,
                None => return false,
            }
        }
        false
    }

    fn uncommitted_tx_ids(&self, parent: &Hash) -> std::collections::HashSet<Hash> {
        let mut ids = std::collections::HashSet::new();
        let mut cursor = *parent;
        while cursor != self.committed {
            let Some(spec) = self.pending.get(&cursor) else {
                break;
            };
            ids.extend(spec.tx_ids.iter().copied());
            cursor = spec.parent;
        }
        ids
    }

    fn layers(&self, parent: &Hash) -> Option<Vec<&WriteSet>> {
        let mut layers = Vec::new();
        let mut cursor = *parent;
        while cursor != self.committed {
            let spec = self.pending.get(&cursor)?;
            layers.push(&spec.executed.writes);
            cursor = spec.parent;
        }
        layers.reverse();
        Some(layers)
    }

    fn parent_timestamp(&self, parent: &Hash) -> Option<u64> {
        if *parent == self.committed {
            Some(self.committed_timestamp)
        } else {
            self.pending.get(parent).map(|s| s.timestamp_ms)
        }
    }

    fn env(&self, height: u64, timestamp_ms: u64) -> BlockEnv {
        BlockEnv {
            genesis_hash: self.genesis.hash(),
            height,
            timestamp_ms,
            params: self.genesis.params.clone(),
        }
    }

    fn execute(
        &self,
        parent: &Hash,
        height: u64,
        timestamp_ms: u64,
        transactions: Vec<SignedTransaction>,
        strict: bool,
    ) -> Result<Executing, String> {
        let layers = self.layers(parent).ok_or("unknown parent")?;
        let overlay = Overlay::new(self.store.as_ref(), layers.clone());
        let mut executor = Executor::new(&overlay, self.env(height, timestamp_ms))
            .with_signatures(&self.signatures);
        executor
            .prewarm(&transactions)
            .map_err(|e| format!("storage: {e}"))?;
        let max = self.genesis.params.max_block_transactions as usize;
        let mut included = Vec::new();
        let mut failed = Vec::new();
        let mut bytes = 0;
        for tx in transactions {
            if included.len() == max {
                if strict {
                    return Err("too many transactions".into());
                }
                break;
            }
            let size = tx.encode().len();
            if bytes + size > MAX_BLOCK_BYTES {
                if strict {
                    return Err("block too large".into());
                }
                continue;
            }
            match executor.apply(&tx) {
                Ok(()) => {
                    bytes += size;
                    included.push(tx);
                }
                Err(TxError::Storage(e)) => return Err(format!("storage: {e}")),
                Err(e) if strict => return Err(format!("transaction {} fails: {e}", tx.id())),
                // it stays in the mempool for a later block
                Err(TxError::BlockGasFull | TxError::ValidatorsChanging) => {}
                Err(_) => failed.push(tx.id()),
            }
        }
        let Executed { writes, receipts } = executor.into_executed();
        let mut chain = layers;
        chain.push(&writes);
        let state_root = self
            .store
            .speculative_root(&chain)
            .map_err(|e| e.to_string())?;
        Ok(Executing {
            included,
            writes,
            receipts,
            state_root,
            failed,
        })
    }
}

impl App<BlockPayload> for ChainApp {
    fn propose(&mut self, parent: &Hash, height: u64, _round: Round, now_ms: u64) -> BlockPayload {
        if self.retired {
            return BlockPayload {
                timestamp_ms: now_ms,
                transactions: vec![],
                tx_root: Hash::ZERO,
                state_root: Hash::ZERO,
                receipt_root: Hash::ZERO,
            };
        }
        let timestamp_ms = now_ms.max(self.parent_timestamp(parent).unwrap_or(0) + 1);
        let candidates: Vec<SignedTransaction> = if self.reconfiguration_pending(parent) {
            Vec::new()
        } else {
            // these aren't failing, just not final yet
            let included = self.uncommitted_tx_ids(parent);
            let room = self.genesis.params.max_block_transactions as usize;
            lock(&self.mempool)
                .iter()
                .filter(|tx| !included.contains(&tx.id()))
                .take(room.saturating_mul(2))
                .cloned()
                .collect()
        };
        match self.execute(parent, height, timestamp_ms, candidates, false) {
            Ok(done) => {
                let mut mempool = lock(&self.mempool);
                for id in &done.failed {
                    mempool.remove(id);
                }
                drop(mempool);
                BlockPayload {
                    timestamp_ms,
                    tx_root: tx_root(&done.included),
                    transactions: done.included,
                    state_root: done.state_root,
                    receipt_root: receipt_root(&done.receipts),
                }
            }
            Err(e) => {
                // propose something others refuse rather than stall
                tracing::error!(error = %e, "could not build a block");
                BlockPayload {
                    timestamp_ms,
                    transactions: vec![],
                    tx_root: Hash::ZERO,
                    state_root: Hash::ZERO,
                    receipt_root: Hash::ZERO,
                }
            }
        }
    }

    fn verify(&mut self, id: &Hash, block: &ChainBlock, now_ms: u64) -> bool {
        if self.retired {
            return false;
        }
        let payload = &block.payload;
        let Some(parent_ts) = self.parent_timestamp(&block.parent) else {
            return false;
        };
        if payload.timestamp_ms <= parent_ts || payload.timestamp_ms > now_ms + MAX_CLOCK_DRIFT_MS {
            tracing::debug!(%id, "refusing block: bad timestamp");
            return false;
        }
        if payload.check_tx_root().is_err() {
            return false;
        }
        if !payload.transactions.is_empty() && self.reconfiguration_pending(&block.parent) {
            tracing::debug!(%id, "refusing block: transactions after a validator change");
            return false;
        }
        match self.execute(
            &block.parent,
            block.height,
            payload.timestamp_ms,
            payload.transactions.clone(),
            true,
        ) {
            Ok(done)
                if done.state_root == payload.state_root
                    && receipt_root(&done.receipts) == payload.receipt_root =>
            {
                self.pending.insert(
                    *id,
                    Speculative {
                        parent: block.parent,
                        height: block.height,
                        timestamp_ms: payload.timestamp_ms,
                        executed: Executed {
                            writes: done.writes,
                            receipts: done.receipts,
                        },
                        has_transactions: !payload.transactions.is_empty(),
                        reconfigures: reconfigures(block),
                        tx_ids: payload
                            .transactions
                            .iter()
                            .map(SignedTransaction::id)
                            .collect(),
                    },
                );
                true
            }
            Ok(_) => {
                tracing::warn!(%id, "refusing block: its roots do not match execution");
                false
            }
            Err(e) => {
                tracing::warn!(%id, error = %e, "refusing block");
                false
            }
        }
    }

    fn has_work(&self, parent: &Hash) -> bool {
        if self.retired {
            return false;
        }
        if lock(&self.mempool).len() > 0 || self.reconfiguration_pending(parent) {
            return true;
        }
        let mut cursor = *parent;
        while cursor != self.committed {
            match self.pending.get(&cursor) {
                Some(spec) if spec.has_transactions => return true,
                Some(spec) => cursor = spec.parent,
                None => return true, // unknown history: keep going
            }
        }
        false
    }

    fn commit(&mut self, chain: &[Final<'_, BlockPayload>], proof: &FinalityProof) {
        if self.retired {
            return;
        }
        if self.epoch_end.is_some() {
            return;
        }
        // blocks after a validator change aren't stored, the proof leads through them
        let stored = chain
            .iter()
            .position(|f| reconfigures(f.block))
            .map_or(chain.len(), |end| end + 1);
        let headers: Vec<Header> = chain.iter().map(|f| f.block.header()).collect();
        let keep = self
            .keep_versions
            .load(std::sync::atomic::Ordering::Relaxed);
        for (i, f) in chain[..stored].iter().enumerate() {
            let spec = self
                .pending
                .remove(&f.id)
                .expect("consensus commits only verified blocks");
            let own = (i + 1 == stored || keeps_proof(f.block)).then(|| FinalityProof {
                tip: f.id,
                path: headers[i + 1..]
                    .iter()
                    .chain(&proof.path)
                    .cloned()
                    .collect(),
                qc: proof.qc.clone(),
            });
            write_committed(
                &self.store,
                &self.mempool,
                f.block,
                &spec.executed,
                keep,
                &proof.qc,
                own.as_ref(),
            )
            .expect("database failure while committing");
            self.heads.send_replace(f.block.height);
            self.committed = f.id;
            self.committed_height = f.block.height;
            self.committed_timestamp = f.block.payload.timestamp_ms;
            let height = f.block.height;
            self.pending.retain(|_, s| s.height > height);
            if spec.reconfigures {
                self.epoch_end = Some((f.id, height));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use qubits_crypto::{SchemeId, SecretKey};
    use qubits_types::{ChainParams, GenesisAccount};

    use super::*;

    #[test]
    fn a_block_lying_about_its_receipts_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let validator = SecretKey::from_seed(SchemeId::MlDsa65, &[1; 32]).unwrap();
        let genesis = Genesis {
            chain_id: "receipts".into(),
            timestamp_ms: 1,
            params: ChainParams {
                min_fee_per_byte: 1,
                max_block_transactions: 10,
            },
            validators: vec![qubits_types::Validator::self_paid(
                validator.public_key().clone(),
            )],
            accounts: vec![GenesisAccount {
                address: Address([1; 32]),
                balance: 1,
            }],
        };
        let writes = qubits_execution::genesis_writes(&genesis);
        let prepared = store.prepare(0, &writes).unwrap();
        store.commit_genesis(&genesis, prepared).unwrap();
        let parent = genesis.hash();
        let mut app = ChainApp::new(
            store,
            genesis,
            Arc::new(Mutex::new(Mempool::default())),
            Arc::new(SignatureCache::default()),
            None,
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
            Arc::new(tokio::sync::watch::Sender::new(0)),
        );
        let payload = app.propose(&parent, 1, 1, 1_000);
        let mut block = Block {
            round: 1,
            height: 1,
            parent,
            proposer: 0,
            voters: Vec::new(),
            payload,
        };
        let id = Hash([9; 32]);
        assert!(app.verify(&id, &block, 1_000), "the honest block");
        app.pending.clear();
        block.payload.receipt_root = Hash([7; 32]);
        assert!(!app.verify(&id, &block, 1_000), "the same block, lying");
    }
}
