use std::path::Path;
use std::sync::Arc;

use borsh::{BorshDeserialize, BorshSerialize};
use jmt::proof::{SparseMerkleProof, SparseMerkleRangeProof};
use jmt::restore::{JellyfishMerkleRestore, StateSnapshotReceiver};
use jmt::storage::{LeafNode, Node, NodeBatch, NodeKey, TreeReader, TreeUpdateBatch, TreeWriter};
use jmt::{JellyfishMerkleTree, KeyHash, OwnedValue, RootHash, SimpleHasher, Version};
use qubits_types::{Genesis, Hash};
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DB, Direction, IteratorMode, Options, WriteBatch,
    WriteOptions,
};

use crate::{Error, StateReader, WriteSet};

const CF_NODES: &str = "jmt_nodes";
const CF_VALUES: &str = "jmt_values";
const CF_BLOCKS: &str = "blocks";
const CF_TX_INDEX: &str = "tx_index";
const CF_RECEIPTS: &str = "receipts";
const CF_META: &str = "meta";
const CF_PENDING_BLOCKS: &str = "pending_blocks";
const CF_STALE_NODES: &str = "jmt_stale_nodes";
const CF_STALE_VALUES: &str = "jmt_stale_values";
const COLUMN_FAMILIES: [&str; 9] = [
    CF_NODES,
    CF_VALUES,
    CF_BLOCKS,
    CF_TX_INDEX,
    CF_RECEIPTS,
    CF_META,
    CF_PENDING_BLOCKS,
    CF_STALE_NODES,
    CF_STALE_VALUES,
];
const META_PRUNED_BEFORE: &[u8] = b"pruned_before";
const META_BLOCKS_FROM: &[u8] = b"blocks_from";

const META_GENESIS: &[u8] = b"genesis";
const META_LATEST_HEIGHT: &[u8] = b"latest_height";

pub struct Blake3Hasher(blake3::Hasher);

impl SimpleHasher for Blake3Hasher {
    fn new() -> Self {
        Blake3Hasher(blake3::Hasher::new_derive_key(
            "qubits.sh 2026-11 state tree",
        ))
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> [u8; 32] {
        *self.0.finalize().as_bytes()
    }
}

type Tree<'a> = JellyfishMerkleTree<'a, Reader<'a>, Blake3Hasher>;

pub type StateProof = SparseMerkleProof<Blake3Hasher>;

pub type StateRangeProof = SparseMerkleRangeProof<Blake3Hasher>;

/// Soft limit on a chunk: the leaf that crosses it is still included.
pub const MAX_CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// A run of leaves in key-hash order, with a proof that nothing is missing up to the last one.
/// Chunks taken from the first key on rebuild the whole tree, see `Restore`.
#[derive(Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct StateChunk {
    pub leaves: Vec<([u8; 32], Vec<u8>)>,
    pub proof: Option<StateRangeProof>,
    pub done: bool,
}

impl StateChunk {
    /// Where the next chunk starts, or `None` after the last leaf.
    pub fn next(&self) -> Option<[u8; 32]> {
        if self.done {
            return None;
        }
        let mut next = self.leaves.last()?.0;
        for byte in next.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                return Some(next);
            }
        }
        None
    }
}

fn err(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}

fn key_hash(key: &[u8]) -> KeyHash {
    KeyHash::with::<Blake3Hasher>(key)
}

fn meta_key(key: &[u8]) -> Vec<u8> {
    [b"node/".as_slice(), key].concat()
}

pub type PendingBlock = (Vec<u8>, Vec<u8>);

/// A block put back below the ones held, with its index entries and any meta to keep with it.
pub struct PutBlock {
    pub bytes: Vec<u8>,
    pub tx_ids: Vec<Hash>,
    pub meta: Vec<(Vec<u8>, Vec<u8>)>,
}

pub struct CommittedBlock<'a> {
    pub height: u64,
    pub state_root: Hash,
    pub bytes: &'a [u8],
    pub tx_ids: &'a [Hash],
    /// Only the transactions that have something to say: most are plain transfers.
    pub receipts: &'a [(Hash, Vec<u8>)],
    pub meta: &'a [(&'a [u8], Vec<u8>)],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TxLocation {
    pub height: u64,
    pub index: u32,
}

pub struct PreparedState {
    version: Version,
    root: Hash,
    batch: TreeUpdateBatch,
}

impl PreparedState {
    pub fn root(&self) -> Hash {
        self.root
    }

    pub fn version(&self) -> u64 {
        self.version
    }
}

pub struct Store {
    db: Arc<DB>,
}

struct Reader<'a> {
    db: &'a DB,
}

/// Writes the restored tree straight into the database; nothing below the restored version
/// exists, so there is nothing to keep consistent until the final, synced write.
struct Sink {
    db: Arc<DB>,
}

impl TreeWriter for Sink {
    fn write_node_batch(&self, node_batch: &NodeBatch) -> anyhow::Result<()> {
        let cf = |name| {
            self.db
                .cf_handle(name)
                .expect("column family created at open")
        };
        let mut batch = WriteBatch::default();
        for (key, node) in node_batch.nodes() {
            batch.put_cf(cf(CF_NODES), borsh::to_vec(key)?, borsh::to_vec(node)?);
        }
        for ((version, hash), value) in node_batch.values() {
            batch.put_cf(
                cf(CF_VALUES),
                value_key(*hash, *version),
                borsh::to_vec(value)?,
            );
        }
        self.db.write(batch)?;
        Ok(())
    }
}

/// What to do with a block while trimming history.
pub enum Verdict {
    Keep,
    Delete {
        tx_ids: Vec<Hash>,
        meta: Vec<Vec<u8>>,
    },
    /// this block and everything after it stay
    Stop,
}

/// Rebuilds the state of one version from chunks, each checked against the root as it comes.
/// A lying source fails at its first bad chunk, and nothing counts until `finish`.
pub struct Restore {
    inner: JellyfishMerkleRestore<Blake3Hasher>,
    version: Version,
    root: Hash,
}

impl Restore {
    pub fn add_chunk(&mut self, chunk: StateChunk) -> Result<(), Error> {
        let leaves = chunk
            .leaves
            .into_iter()
            .map(|(hash, value)| (KeyHash(hash), value))
            .collect();
        let proof = chunk.proof.ok_or_else(|| err("chunk without a proof"))?;
        self.inner.add_chunk(leaves, proof).map_err(err)
    }
}

impl Reader<'_> {
    fn cf(&self, name: &str) -> &ColumnFamily {
        self.db
            .cf_handle(name)
            .expect("column family created at open")
    }
}

impl TreeReader for Reader<'_> {
    fn get_node_option(&self, node_key: &NodeKey) -> anyhow::Result<Option<Node>> {
        let key = borsh::to_vec(node_key)?;
        match self.db.get_cf(self.cf(CF_NODES), key)? {
            Some(bytes) => Ok(Some(borsh::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> anyhow::Result<Option<OwnedValue>> {
        // keyed by key_hash || BE version, so a reverse seek finds the newest at or below it
        let seek = value_key(key_hash, max_version);
        let mut iter = self.db.iterator_cf(
            self.cf(CF_VALUES),
            IteratorMode::From(&seek, Direction::Reverse),
        );
        match iter.next() {
            Some(item) => {
                let (k, v) = item?;
                if k[..32] != key_hash.0 {
                    return Ok(None);
                }
                Ok(borsh::from_slice::<Option<OwnedValue>>(&v)?)
            }
            None => Ok(None),
        }
    }

    fn get_rightmost_leaf(&self) -> anyhow::Result<Option<(NodeKey, LeafNode)>> {
        anyhow::bail!("state tree restoration is not supported")
    }
}

fn value_key(key_hash: KeyHash, version: Version) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[..32].copy_from_slice(&key_hash.0);
    out[32..].copy_from_slice(&version.to_be_bytes());
    out
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, Error> {
        let mut options = Options::default();
        options.create_if_missing(true);
        options.create_missing_column_families(true);
        let cfs = COLUMN_FAMILIES.map(|name| ColumnFamilyDescriptor::new(name, Options::default()));
        let db = DB::open_cf_descriptors(&options, path, cfs).map_err(err)?;
        Ok(Store { db: Arc::new(db) })
    }

    fn cf(&self, name: &str) -> &ColumnFamily {
        self.db
            .cf_handle(name)
            .expect("column family created at open")
    }

    fn reader(&self) -> Reader<'_> {
        Reader { db: &self.db }
    }

    pub fn latest_height(&self) -> Result<Option<u64>, Error> {
        match self
            .db
            .get_cf(self.cf(CF_META), META_LATEST_HEIGHT)
            .map_err(err)?
        {
            Some(bytes) => Ok(Some(u64::from_be_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| err("corrupt latest height"))?,
            ))),
            None => Ok(None),
        }
    }

    pub fn genesis(&self) -> Result<Option<Genesis>, Error> {
        match self
            .db
            .get_cf(self.cf(CF_META), META_GENESIS)
            .map_err(err)?
        {
            Some(bytes) => Ok(Some(borsh::from_slice(&bytes).map_err(err)?)),
            None => Ok(None),
        }
    }

    pub fn prepare(&self, version: u64, writes: &WriteSet) -> Result<PreparedState, Error> {
        let expected = match self.latest_height()? {
            None => 0,
            Some(h) => h + 1,
        };
        if version != expected {
            return Err(err(format!(
                "cannot prepare version {version}, next is {expected}"
            )));
        }
        let reader = self.reader();
        let tree: Tree<'_> = JellyfishMerkleTree::new(&reader);
        let (root, batch) = tree
            .put_value_set(
                writes.iter().map(|(k, v)| (key_hash(k), v.clone())),
                version,
            )
            .map_err(err)?;
        Ok(PreparedState {
            version,
            root: Hash(root.0),
            batch,
        })
    }

    fn write_tree(&self, batch: &mut WriteBatch, prepared: &PreparedState) -> Result<(), Error> {
        let node_batch = &prepared.batch.node_batch;
        for (key, node) in node_batch.nodes() {
            batch.put_cf(
                self.cf(CF_NODES),
                borsh::to_vec(key).map_err(err)?,
                borsh::to_vec(node).map_err(err)?,
            );
        }
        for stale in &prepared.batch.stale_node_index_batch {
            let mut key = stale.stale_since_version.to_be_bytes().to_vec();
            key.extend(borsh::to_vec(&stale.node_key).map_err(err)?);
            batch.put_cf(self.cf(CF_STALE_NODES), key, []);
        }
        for ((version, hash), value) in node_batch.values() {
            if *version > 0
                && let Some(previous) = self.latest_value_version(*hash, version - 1)?
            {
                let mut key = version.to_be_bytes().to_vec();
                key.extend_from_slice(&hash.0);
                key.extend_from_slice(&previous.to_be_bytes());
                batch.put_cf(self.cf(CF_STALE_VALUES), key, []);
            }
            batch.put_cf(
                self.cf(CF_VALUES),
                value_key(*hash, *version),
                borsh::to_vec(value).map_err(err)?,
            );
        }
        batch.put_cf(
            self.cf(CF_META),
            META_LATEST_HEIGHT,
            prepared.version.to_be_bytes(),
        );
        Ok(())
    }

    fn write(&self, batch: WriteBatch) -> Result<(), Error> {
        let mut options = WriteOptions::default();
        options.set_sync(true);
        self.db.write_opt(batch, &options).map_err(err)
    }

    pub fn commit_genesis(&self, genesis: &Genesis, prepared: PreparedState) -> Result<(), Error> {
        if self.latest_height()?.is_some() {
            return Err(err("database is already initialized"));
        }
        if prepared.version != 0 {
            return Err(err("genesis state must be version 0"));
        }
        let mut batch = WriteBatch::default();
        self.write_tree(&mut batch, &prepared)?;
        batch.put_cf(
            self.cf(CF_META),
            META_GENESIS,
            borsh::to_vec(genesis).map_err(err)?,
        );
        self.write(batch)
    }

    pub fn commit_block(
        &self,
        block: &CommittedBlock<'_>,
        prepared: PreparedState,
    ) -> Result<(), Error> {
        if block.height != prepared.version {
            return Err(err("block height does not match prepared state"));
        }
        if block.state_root != prepared.root {
            return Err(err("block state root does not match prepared state"));
        }
        if self.latest_height()? != Some(block.height - 1) {
            return Err(err(format!("block {} is not the next block", block.height)));
        }
        let mut batch = WriteBatch::default();
        self.write_tree(&mut batch, &prepared)?;
        batch.put_cf(self.cf(CF_BLOCKS), block.height.to_be_bytes(), block.bytes);
        for (index, id) in block.tx_ids.iter().enumerate() {
            let location = TxLocation {
                height: block.height,
                index: index as u32,
            };
            batch.put_cf(
                self.cf(CF_TX_INDEX),
                id.0,
                borsh::to_vec(&location).map_err(err)?,
            );
        }
        for (id, receipt) in block.receipts {
            batch.put_cf(self.cf(CF_RECEIPTS), id.0, receipt);
        }
        for (key, value) in block.meta {
            batch.put_cf(self.cf(CF_META), meta_key(key), value);
        }
        self.write(batch)
    }

    pub fn put_meta(&self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        let mut batch = WriteBatch::default();
        batch.put_cf(self.cf(CF_META), meta_key(key), value);
        self.write(batch)
    }

    pub fn put_pending_block(&self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        let mut batch = WriteBatch::default();
        batch.put_cf(self.cf(CF_PENDING_BLOCKS), key, value);
        self.write(batch)
    }

    pub fn pending_blocks(&self) -> Result<Vec<PendingBlock>, Error> {
        self.db
            .iterator_cf(self.cf(CF_PENDING_BLOCKS), IteratorMode::Start)
            .map(|item| {
                let (key, value) = item.map_err(err)?;
                Ok((key.to_vec(), value.to_vec()))
            })
            .collect()
    }

    pub fn delete_pending_blocks_before(&self, key: &[u8]) -> Result<(), Error> {
        let mut batch = WriteBatch::default();
        batch.delete_range_cf(self.cf(CF_PENDING_BLOCKS), [].as_slice(), key);
        self.write(batch)
    }

    pub fn get_meta(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.db.get_cf(self.cf(CF_META), meta_key(key)).map_err(err)
    }

    pub fn speculative_root(&self, chain: &[&WriteSet]) -> Result<Hash, Error> {
        let base = self
            .latest_height()?
            .ok_or_else(|| err("database is not initialized"))?;
        if chain.is_empty() {
            return self.state_root(base);
        }
        let reader = self.reader();
        let tree: Tree<'_> = JellyfishMerkleTree::new(&reader);
        let sets = chain
            .iter()
            .map(|writes| {
                writes
                    .iter()
                    .map(|(k, v)| (key_hash(k), v.clone()))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let (roots, _) = tree.put_value_sets(sets, base + 1).map_err(err)?;
        Ok(Hash(roots.last().expect("one root per set").0))
    }

    fn latest_value_version(
        &self,
        hash: KeyHash,
        max_version: Version,
    ) -> Result<Option<Version>, Error> {
        let seek = value_key(hash, max_version);
        let mut iter = self.db.iterator_cf(
            self.cf(CF_VALUES),
            IteratorMode::From(&seek, Direction::Reverse),
        );
        match iter.next() {
            Some(item) => {
                let (k, _) = item.map_err(err)?;
                if k[..32] != hash.0 {
                    return Ok(None);
                }
                Ok(Some(u64::from_be_bytes(
                    k[32..40].try_into().expect("value keys are 40 bytes"),
                )))
            }
            None => Ok(None),
        }
    }

    pub fn pruned_before(&self) -> Result<u64, Error> {
        match self
            .db
            .get_cf(self.cf(CF_META), META_PRUNED_BEFORE)
            .map_err(err)?
        {
            Some(bytes) => Ok(u64::from_be_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| err("corrupt prune marker"))?,
            )),
            None => Ok(0),
        }
    }

    /// Walks the oldest held blocks, below `below` and at most `limit` of them, and drops the
    /// ones `decide` gives up. `blocks_from` moves past everything looked at, kept or not.
    pub fn prune_history(
        &self,
        below: u64,
        limit: usize,
        mut decide: impl FnMut(u64, &[u8]) -> Result<Verdict, String>,
    ) -> Result<u64, Error> {
        let from = self.blocks_from()?;
        let mut batch = WriteBatch::default();
        let mut deleted = 0;
        let mut height = from;
        let mut looked = 0;
        while height < below && looked < limit {
            if let Some(bytes) = self.block(height)? {
                match decide(height, &bytes).map_err(err)? {
                    Verdict::Stop => break,
                    Verdict::Keep => {}
                    Verdict::Delete { tx_ids, meta } => {
                        batch.delete_cf(self.cf(CF_BLOCKS), height.to_be_bytes());
                        for id in tx_ids {
                            batch.delete_cf(self.cf(CF_TX_INDEX), id.0);
                            batch.delete_cf(self.cf(CF_RECEIPTS), id.0);
                        }
                        for key in meta {
                            batch.delete_cf(self.cf(CF_META), meta_key(&key));
                        }
                        deleted += 1;
                    }
                }
            }
            height += 1;
            looked += 1;
        }
        if height > from {
            batch.put_cf(self.cf(CF_META), META_BLOCKS_FROM, height.to_be_bytes());
            self.write(batch)?;
        }
        Ok(deleted)
    }

    /// Writes blocks below `blocks_from` back, as they were, without moving the marker:
    /// `set_blocks_from` does that once the whole run links up.
    pub fn put_blocks(&self, first: u64, blocks: &[PutBlock]) -> Result<(), Error> {
        let from = self.blocks_from()?;
        if first + blocks.len() as u64 > from {
            return Err(err("only blocks below the ones held can be put back"));
        }
        let mut batch = WriteBatch::default();
        for (i, block) in blocks.iter().enumerate() {
            let height = first + i as u64;
            batch.put_cf(self.cf(CF_BLOCKS), height.to_be_bytes(), &block.bytes);
            for (key, value) in &block.meta {
                batch.put_cf(self.cf(CF_META), meta_key(key), value);
            }
            for (index, id) in block.tx_ids.iter().enumerate() {
                let location = TxLocation {
                    height,
                    index: index as u32,
                };
                batch.put_cf(
                    self.cf(CF_TX_INDEX),
                    id.0,
                    borsh::to_vec(&location).map_err(err)?,
                );
            }
        }
        self.write(batch)
    }

    pub fn set_blocks_from(&self, height: u64) -> Result<(), Error> {
        let mut batch = WriteBatch::default();
        batch.put_cf(self.cf(CF_META), META_BLOCKS_FROM, height.to_be_bytes());
        self.write(batch)
    }

    /// Undoes a put-back that didn't link up: blocks in `from..to`, below the ones held, and
    /// the meta keys written with them. Index entries of blocks that never linked lead nowhere
    /// and are left alone.
    pub fn delete_blocks(&self, from: u64, to: u64, meta: &[Vec<u8>]) -> Result<(), Error> {
        if to > self.blocks_from()? {
            return Err(err(
                "only blocks below the ones held can be deleted this way",
            ));
        }
        let mut batch = WriteBatch::default();
        for height in from..to {
            batch.delete_cf(self.cf(CF_BLOCKS), height.to_be_bytes());
        }
        for key in meta {
            batch.delete_cf(self.cf(CF_META), meta_key(key));
        }
        self.write(batch)
    }

    /// The oldest block held in full: 1 for a chain with its whole history, else the snapshot it
    /// started from or where trimming got to. Genesis is state, not a block.
    pub fn blocks_from(&self) -> Result<u64, Error> {
        match self
            .db
            .get_cf(self.cf(CF_META), META_BLOCKS_FROM)
            .map_err(err)?
        {
            Some(bytes) => Ok(u64::from_be_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| err("corrupt snapshot marker"))?,
            )
            .max(1)),
            None => Ok(1),
        }
    }

    fn check_not_pruned(&self, version: u64) -> Result<(), Error> {
        let pruned = self.pruned_before()?;
        if version < pruned {
            return Err(err(format!(
                "state at version {version} was pruned (kept from {pruned})"
            )));
        }
        Ok(())
    }

    pub fn prune(&self, keep_from: u64) -> Result<usize, Error> {
        let latest = self.latest_height()?.unwrap_or(0);
        let keep_from = keep_from.min(latest);
        if keep_from <= self.pruned_before()? {
            return Ok(0);
        }
        let mut batch = WriteBatch::default();
        let mut deleted = 0;
        let limit = (keep_from + 1).to_be_bytes();
        for item in self
            .db
            .iterator_cf(self.cf(CF_STALE_NODES), IteratorMode::Start)
        {
            let (k, _) = item.map_err(err)?;
            if k[..8] >= limit[..] {
                break;
            }
            batch.delete_cf(self.cf(CF_NODES), &k[8..]);
            batch.delete_cf(self.cf(CF_STALE_NODES), &k);
            deleted += 1;
        }
        for item in self
            .db
            .iterator_cf(self.cf(CF_STALE_VALUES), IteratorMode::Start)
        {
            let (k, _) = item.map_err(err)?;
            if k[..8] >= limit[..] {
                break;
            }
            let hash = KeyHash(k[8..40].try_into().expect("stale value keys are 48 bytes"));
            let old_version =
                u64::from_be_bytes(k[40..48].try_into().expect("stale value keys are 48 bytes"));
            batch.delete_cf(self.cf(CF_VALUES), value_key(hash, old_version));
            batch.delete_cf(self.cf(CF_STALE_VALUES), &k);
            deleted += 1;
        }
        batch.put_cf(
            self.cf(CF_META),
            META_PRUNED_BEFORE,
            keep_from.to_be_bytes(),
        );
        self.write(batch)?;
        Ok(deleted)
    }

    /// Leaves of `version` from `from` on, in key-hash order, up to about `max_bytes`.
    pub fn state_chunk(
        &self,
        version: u64,
        from: Option<[u8; 32]>,
        max_bytes: usize,
    ) -> Result<StateChunk, Error> {
        self.check_not_pruned(version)?;
        let latest = self
            .latest_height()?
            .ok_or_else(|| err("database is not initialized"))?;
        if version > latest {
            return Err(err(format!("no state at version {version} yet")));
        }
        let max_bytes = max_bytes.min(MAX_CHUNK_BYTES);
        let mut leaves = Vec::new();
        let mut bytes = 0;
        let mut cursor = from;
        let mut done = true;
        while let Some(hash) = cursor {
            let Some(next) = self.next_key_hash(hash)? else {
                break;
            };
            if bytes >= max_bytes {
                done = false;
                break;
            }
            if let Some(version) = self.latest_value_version(next, version)?
                && let Some(value) = self.value(next, version)?
            {
                bytes += 32 + value.len();
                leaves.push((next.0, value));
            }
            cursor = StateChunk {
                leaves: vec![(next.0, Vec::new())],
                proof: None,
                done: false,
            }
            .next();
        }
        if from.is_none() && leaves.is_empty() {
            return Err(err("empty state"));
        }
        let proof = match leaves.last() {
            Some((hash, _)) => {
                let reader = self.reader();
                let tree: Tree<'_> = JellyfishMerkleTree::new(&reader);
                Some(tree.get_range_proof(KeyHash(*hash), version).map_err(err)?)
            }
            None => None,
        };
        Ok(StateChunk {
            leaves,
            proof,
            done,
        })
    }

    /// The first key hash at or after `from` that has any value, at any version.
    fn next_key_hash(&self, from: [u8; 32]) -> Result<Option<KeyHash>, Error> {
        let seek = value_key(KeyHash(from), 0);
        let mut iter = self.db.iterator_cf(
            self.cf(CF_VALUES),
            IteratorMode::From(&seek, Direction::Forward),
        );
        match iter.next() {
            Some(item) => {
                let (k, _) = item.map_err(err)?;
                Ok(Some(KeyHash(
                    k[..32].try_into().expect("value keys are 40 bytes"),
                )))
            }
            None => Ok(None),
        }
    }

    fn value(&self, hash: KeyHash, version: Version) -> Result<Option<OwnedValue>, Error> {
        match self
            .db
            .get_cf(self.cf(CF_VALUES), value_key(hash, version))
            .map_err(err)?
        {
            Some(bytes) => borsh::from_slice::<Option<OwnedValue>>(&bytes).map_err(err),
            None => Ok(None),
        }
    }

    /// Starts rebuilding `version` with the state root `root`. Only a chain that has nothing past
    /// genesis can do this: the node is joining, not catching up.
    pub fn begin_restore(&self, version: u64, root: Hash) -> Result<Restore, Error> {
        if self.latest_height()? != Some(0) {
            return Err(err("a snapshot can only be restored into a fresh chain"));
        }
        if version == 0 {
            return Err(err("nothing to restore at genesis"));
        }
        let sink = Arc::new(Sink {
            db: self.db.clone(),
        });
        let inner =
            JellyfishMerkleRestore::new_overwrite(sink, version, RootHash(root.0)).map_err(err)?;
        Ok(Restore {
            inner,
            version,
            root,
        })
    }

    /// Makes the restored state the chain's head, with its block and metadata, in one write.
    /// Everything between genesis and `version` is marked pruned.
    pub fn finish_restore(
        &self,
        restore: Restore,
        block: &CommittedBlock<'_>,
    ) -> Result<(), Error> {
        let Restore {
            inner,
            version,
            root,
        } = restore;
        if block.height != version || block.state_root != root {
            return Err(err("restored block does not match the snapshot"));
        }
        inner.finish().map_err(err)?;
        let reader = self.reader();
        let tree: Tree<'_> = JellyfishMerkleTree::new(&reader);
        let RootHash(rebuilt) = tree.get_root_hash(version).map_err(err)?;
        if rebuilt != root.0 {
            return Err(err("restored state root does not match"));
        }
        if self.latest_height()? != Some(0) {
            return Err(err("the chain moved while restoring"));
        }
        let mut batch = WriteBatch::default();
        batch.put_cf(self.cf(CF_META), META_LATEST_HEIGHT, version.to_be_bytes());
        batch.put_cf(self.cf(CF_META), META_PRUNED_BEFORE, version.to_be_bytes());
        batch.put_cf(self.cf(CF_META), META_BLOCKS_FROM, version.to_be_bytes());
        batch.put_cf(self.cf(CF_BLOCKS), block.height.to_be_bytes(), block.bytes);
        for (index, id) in block.tx_ids.iter().enumerate() {
            let location = TxLocation {
                height: block.height,
                index: index as u32,
            };
            batch.put_cf(
                self.cf(CF_TX_INDEX),
                id.0,
                borsh::to_vec(&location).map_err(err)?,
            );
        }
        for (key, value) in block.meta {
            batch.put_cf(self.cf(CF_META), meta_key(key), value);
        }
        self.write(batch)
    }

    pub fn tree_size(&self) -> Result<(usize, usize), Error> {
        let count = |cf| {
            self.db
                .iterator_cf(self.cf(cf), IteratorMode::Start)
                .count()
        };
        Ok((count(CF_NODES), count(CF_VALUES)))
    }

    pub fn state_root(&self, version: u64) -> Result<Hash, Error> {
        self.check_not_pruned(version)?;
        let reader = self.reader();
        let tree: Tree<'_> = JellyfishMerkleTree::new(&reader);
        let RootHash(root) = tree.get_root_hash(version).map_err(err)?;
        Ok(Hash(root))
    }

    pub fn get_at(&self, version: u64, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.check_not_pruned(version)?;
        self.reader()
            .get_value_option(version, key_hash(key))
            .map_err(err)
    }

    pub fn get_with_proof(
        &self,
        version: u64,
        key: &[u8],
    ) -> Result<(Option<Vec<u8>>, StateProof), Error> {
        self.check_not_pruned(version)?;
        let reader = self.reader();
        let tree: Tree<'_> = JellyfishMerkleTree::new(&reader);
        tree.get_with_proof(key_hash(key), version).map_err(err)
    }

    pub fn verify_proof(
        root: Hash,
        key: &[u8],
        value: Option<&[u8]>,
        proof: &StateProof,
    ) -> Result<(), Error> {
        proof
            .verify(RootHash(root.0), key_hash(key), value)
            .map_err(err)
    }

    pub fn block(&self, height: u64) -> Result<Option<Vec<u8>>, Error> {
        self.db
            .get_cf(self.cf(CF_BLOCKS), height.to_be_bytes())
            .map_err(err)
    }

    pub fn receipt(&self, id: &Hash) -> Result<Option<Vec<u8>>, Error> {
        self.db.get_cf(self.cf(CF_RECEIPTS), id.0).map_err(err)
    }

    pub fn tx_location(&self, id: &Hash) -> Result<Option<TxLocation>, Error> {
        match self.db.get_cf(self.cf(CF_TX_INDEX), id.0).map_err(err)? {
            Some(bytes) => Ok(Some(borsh::from_slice(&bytes).map_err(err)?)),
            None => Ok(None),
        }
    }
}

impl StateReader for Store {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        match self.latest_height()? {
            Some(version) => self.get_at(version, key),
            None => Ok(None),
        }
    }
}
