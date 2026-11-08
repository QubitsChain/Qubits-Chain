//! Era files: the blocks of one era, ending in a kept proof, with the epoch chain before them.
//! Anyone can check one against the genesis file alone, so history can live anywhere: an
//! archive node hands them out, and a node that dropped its history takes them back.
//!
//! Layout, all borsh: `Header`, then `Vec<EraEpoch>`, then `count` times a `ChainBlock` and
//! an `Option<FinalityProof>`. Blocks are streamed, never all in memory.

use std::io::{self, Read, Write};

use borsh::{BorshDeserialize, BorshSerialize};
use qubits_consensus::ValidatorSet;
use qubits_types::rpc::EpochSummary;
use qubits_types::{Genesis, Hash, SignedTransaction};

use qubits_state::PutBlock;

use crate::app::{PROOF_EVERY, finality_key, reconfigures};
use crate::sync::{EpochProof, EpochView, apply_proven, epoch_views};
use crate::{ChainBlock, FinalityProof, Node, NodeError};

pub const MAGIC: [u8; 4] = *b"QERA";
pub const VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Header {
    pub magic: [u8; 4],
    pub version: u8,
    pub genesis_hash: Hash,
    pub first_height: u64,
    pub count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EraEpoch {
    pub epoch: u64,
    pub block: ChainBlock,
    pub proof: FinalityProof,
}

/// Era `index` holds heights `index * length + 1 ..= (index + 1) * length`.
pub fn range(index: u64, length: u64) -> (u64, u64) {
    (index * length + 1, (index + 1) * length)
}

pub fn file_name(chain_id: &str, genesis: &Hash, index: u64) -> String {
    format!("{chain_id}-{}-{index:05}.era", &hex::encode(genesis.0)[..8])
}

/// The beginning of era `index` up to `to`: what a node that started from a snapshot at `to`
/// needs before the complete eras below.
pub fn partial_file_name(chain_id: &str, genesis: &Hash, index: u64, to: u64) -> String {
    format!(
        "{chain_id}-{}-{index:05}-to-{to}.era",
        &hex::encode(genesis.0)[..8]
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    pub first_height: u64,
    pub last_height: u64,
    pub blocks: u64,
    pub transactions: u64,
    pub proofs: u64,
}

fn invalid(what: impl ToString) -> String {
    what.to_string()
}

/// Writes heights `first..=last` of `node` as an era file. The last block must have a kept
/// proof: era ends and epoch ends do.
pub fn write<W: Write>(node: &Node, first: u64, last: u64, mut out: W) -> Result<(), NodeError> {
    if first == 0 || last < first {
        return Err(NodeError::Config("empty era".into()));
    }
    let store = node.store();
    if store.blocks_from()? > first {
        return Err(NodeError::Config(format!(
            "blocks before {} are not kept on this node",
            store.blocks_from()?
        )));
    }
    if node.stored_proof(last)?.is_none() {
        return Err(NodeError::Config(format!(
            "block {last} has no kept proof; eras end on one"
        )));
    }
    let mut epochs = Vec::new();
    for info in node.epochs()?.into_iter().filter(|e| e.epoch > 0) {
        if info.start_height >= first {
            break;
        }
        let block = node.block(info.start_height)?.ok_or_else(|| {
            NodeError::Storage(format!("epoch block {} missing", info.start_height))
        })?;
        let proof = node.stored_proof(info.start_height)?.ok_or_else(|| {
            NodeError::Storage(format!("epoch proof {} missing", info.start_height))
        })?;
        epochs.push(EraEpoch {
            epoch: info.epoch,
            block,
            proof,
        });
    }
    let header = Header {
        magic: MAGIC,
        version: VERSION,
        genesis_hash: node.genesis_hash(),
        first_height: first,
        count: u32::try_from(last - first + 1)
            .map_err(|_| NodeError::Config("era too long".into()))?,
    };
    let io_err = |e: io::Error| NodeError::Storage(format!("writing the era: {e}"));
    out.write_all(&borsh::to_vec(&header).expect("encoding cannot fail"))
        .map_err(io_err)?;
    out.write_all(&borsh::to_vec(&epochs).expect("encoding cannot fail"))
        .map_err(io_err)?;
    for height in first..=last {
        let bytes = store
            .block(height)?
            .ok_or_else(|| NodeError::Storage(format!("block {height} missing")))?;
        out.write_all(&bytes).map_err(io_err)?;
        let proof = node.stored_proof(height)?;
        out.write_all(&borsh::to_vec(&proof).expect("encoding cannot fail"))
            .map_err(io_err)?;
    }
    out.flush().map_err(io_err)
}

/// Reads an era file one block at a time.
pub struct Reader<R: Read> {
    reader: R,
    pub header: Header,
    pub epochs: Vec<EraEpoch>,
    left: u32,
}

impl<R: Read> Reader<R> {
    pub fn open(mut reader: R) -> Result<Self, String> {
        let header = Header::deserialize_reader(&mut reader).map_err(|e| format!("header: {e}"))?;
        if header.magic != MAGIC {
            return Err("not an era file".into());
        }
        if header.version != VERSION {
            return Err(format!(
                "era file version {} is not supported",
                header.version
            ));
        }
        if header.count == 0 || header.first_height == 0 {
            return Err("empty era".into());
        }
        let epochs =
            Vec::<EraEpoch>::deserialize_reader(&mut reader).map_err(|e| format!("epochs: {e}"))?;
        Ok(Reader {
            reader,
            left: header.count,
            header,
            epochs,
        })
    }

    pub fn last_height(&self) -> u64 {
        self.header.first_height + u64::from(self.header.count) - 1
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<(ChainBlock, Option<FinalityProof>)>, String> {
        if self.left == 0 {
            return Ok(None);
        }
        self.left -= 1;
        let block =
            ChainBlock::deserialize_reader(&mut self.reader).map_err(|e| format!("block: {e}"))?;
        let proof = Option::<FinalityProof>::deserialize_reader(&mut self.reader)
            .map_err(|e| format!("proof: {e}"))?;
        Ok(Some((block, proof)))
    }

    fn epoch_proofs(&self) -> Vec<EpochProof> {
        self.epochs
            .iter()
            .map(|e| EpochProof {
                summary: EpochSummary {
                    epoch: e.epoch,
                    start: e.block.id(),
                    start_height: e.block.height,
                },
                block: e.block.clone(),
                proof: e.proof.clone(),
            })
            .collect()
    }
}

/// Walks a file's blocks in order: hash links, tx roots, and every proof against the validator
/// set in force, which the file's epoch chain and its own reconfigurations determine.
struct Checker {
    view: EpochView,
    next_height: u64,
    previous: Option<Hash>,
    pub last_proven: bool,
}

impl Checker {
    fn start<R: Read>(genesis: &Genesis, reader: &Reader<R>) -> Result<Checker, String> {
        if reader.header.genesis_hash != genesis.hash() {
            return Err("another chain's era".into());
        }
        let (views, infos) = epoch_views(genesis, &reader.epoch_proofs())?;
        let first = reader.header.first_height;
        let at = infos
            .iter()
            .rposition(|e| e.start_height < first)
            .ok_or("the era starts at genesis")?;
        if infos.len() != at + 1 {
            return Err("epochs after the era's start included".into());
        }
        Ok(Checker {
            view: views[at].clone(),
            next_height: first,
            previous: None,
            last_proven: false,
        })
    }

    fn check(&mut self, block: &ChainBlock, proof: Option<&FinalityProof>) -> Result<Hash, String> {
        let height = self.next_height;
        let id = block.id();
        if block.height != height {
            return Err(format!("expected block {height}, found {}", block.height));
        }
        if let Some(parent) = self.previous
            && block.parent != parent
        {
            return Err(format!("block {height} does not extend the previous block"));
        }
        block
            .payload
            .check_tx_root()
            .map_err(|e| format!("block {height}: {e}"))?;
        self.last_proven = false;
        if let Some(proof) = proof {
            if proof.tip != id
                || !proof.verify(block.round, &self.view.validators, &self.view.chain)
            {
                return Err(format!("the proof of block {height} fails"));
            }
            self.last_proven = true;
        }
        if reconfigures(block) {
            if !self.last_proven {
                return Err(format!(
                    "block {height} changes the validators and needs its own proof"
                ));
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
            self.view = EpochView {
                validators: ValidatorSet::new(keys)?,
                chain: id,
            };
        }
        self.next_height += 1;
        self.previous = Some(id);
        Ok(id)
    }
}

/// Checks a file from the genesis set up: blocks link by hash, every block that changes the
/// validators and the last block carry a proof that verifies with the set in force.
pub fn verify<R: Read>(genesis: &Genesis, mut reader: Reader<R>) -> Result<Summary, String> {
    let mut checker = Checker::start(genesis, &reader)?;
    let mut summary = Summary {
        first_height: reader.header.first_height,
        last_height: reader.last_height(),
        blocks: 0,
        transactions: 0,
        proofs: 0,
    };
    while let Some((block, proof)) = reader.next()? {
        checker.check(&block, proof.as_ref())?;
        summary.blocks += 1;
        summary.transactions += block.payload.transactions.len() as u64;
        summary.proofs += u64::from(proof.is_some());
    }
    if !checker.last_proven {
        return Err("the last block has no proof".into());
    }
    Ok(summary)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Imported {
    /// executed on top of the head
    Appended(Summary),
    /// put back below the blocks held, linked by hash to them
    Restored(Summary),
}

/// Takes an era file into `node`: appended and executed when it starts right after the head,
/// or put back below the oldest block held when it reaches up to it. Either way the blocks
/// end up linked by hash to blocks this node already trusts.
pub fn import<R: Read>(node: &Node, mut reader: Reader<R>) -> Result<Imported, String> {
    if reader.header.genesis_hash != node.genesis_hash() {
        return Err("another chain's era".into());
    }
    let head = node.head().map_err(invalid)?;
    let from = node.store().blocks_from().map_err(invalid)?;
    let first = reader.header.first_height;
    let last = reader.last_height();
    if first == head.height + 1 {
        return append(node, &mut reader, head.hash, head.height).map(Imported::Appended);
    }
    if first < from && last + 1 >= from {
        return restore(node, &mut reader, from).map(Imported::Restored);
    }
    if last <= head.height && first >= from {
        return Err(format!("blocks {first}..={last} are already here"));
    }
    Err(format!(
        "era {first}..={last} fits neither after the head ({}) nor under the oldest block held \
         ({from}): import eras in order",
        head.height
    ))
}

fn append<R: Read>(
    node: &Node,
    reader: &mut Reader<R>,
    mut parent: Hash,
    mut parent_height: u64,
) -> Result<Summary, String> {
    let first = reader.header.first_height;
    let mut summary = Summary {
        first_height: first,
        last_height: reader.last_height(),
        blocks: 0,
        transactions: 0,
        proofs: 0,
    };
    let mut blocks = Vec::new();
    let mut proofs = Vec::new();
    loop {
        let next = reader.next()?;
        let done = next.is_none();
        if let Some((block, proof)) = next {
            if block.height != first + summary.blocks + blocks.len() as u64 {
                return Err(format!("block {} out of place", block.height));
            }
            summary.transactions += block.payload.transactions.len() as u64;
            summary.proofs += u64::from(proof.is_some());
            blocks.push(block);
            proofs.push(proof);
        }
        let flush = done
            || proofs.last().is_some_and(Option::is_some)
            || blocks.len() >= PROOF_EVERY as usize;
        if flush && !blocks.is_empty() {
            let proven = apply_proven(node, &parent, parent_height, &blocks, &mut proofs)
                .map_err(|e| e.to_string())?;
            if proven == 0 && done {
                return Err("the era's last blocks are not provably final".into());
            }
            if proven > 0 {
                let last = &blocks[proven - 1];
                parent = last.id();
                parent_height = last.height;
                summary.blocks += proven as u64;
                blocks.drain(..proven);
                proofs.drain(..proven);
            }
        }
        if done {
            if !blocks.is_empty() {
                return Err("the era's last blocks are not provably final".into());
            }
            return Ok(summary);
        }
    }
}

fn restore<R: Read>(node: &Node, reader: &mut Reader<R>, from: u64) -> Result<Summary, String> {
    let store = node.store();
    let first = reader.header.first_height;
    let mut checker = Checker::start(node.genesis(), reader)?;
    let mut summary = Summary {
        first_height: first,
        last_height: reader.last_height(),
        blocks: 0,
        transactions: 0,
        proofs: 0,
    };
    let mut pending: Vec<PutBlock> = Vec::new();
    let mut pending_from = first;
    let mut written_meta: Vec<Vec<u8>> = Vec::new();
    let undo = |written: &[Vec<u8>], reason: String| -> String {
        let _ = store.delete_blocks(first, from, written);
        reason
    };
    let mut linked = false;
    let mut last: Option<Hash> = None;
    while let Some((block, proof)) = reader.next()? {
        let height = block.height;
        let id = checker
            .check(&block, proof.as_ref())
            .map_err(|e| undo(&written_meta, e))?;
        last = Some(id);
        summary.blocks += 1;
        summary.transactions += block.payload.transactions.len() as u64;
        summary.proofs += u64::from(proof.is_some());
        if height >= from {
            // overlapping what is held: the ids must agree, and that links the whole file
            if !linked {
                let held = node.block(height).map_err(invalid)?;
                if held.map(|b| b.id()) != Some(id) {
                    return Err(undo(
                        &written_meta,
                        format!("block {height} is not the one this node holds"),
                    ));
                }
                linked = true;
            }
            continue;
        }
        let tx_ids = block
            .payload
            .transactions
            .iter()
            .map(SignedTransaction::id)
            .collect();
        // proofs come back with the blocks, so this node can hand the era out in turn
        let meta = match proof {
            Some(proof) => {
                let key = finality_key(height);
                written_meta.push(key.clone());
                vec![(key, borsh::to_vec(&proof).expect("encoding cannot fail"))]
            }
            None => Vec::new(),
        };
        pending.push(PutBlock {
            bytes: borsh::to_vec(&block).expect("encoding cannot fail"),
            tx_ids,
            meta,
        });
        if pending.len() >= PROOF_EVERY as usize {
            store
                .put_blocks(pending_from, &pending)
                .map_err(|e| undo(&written_meta, e.to_string()))?;
            pending_from += pending.len() as u64;
            pending.clear();
        }
    }
    if !pending.is_empty() {
        store
            .put_blocks(pending_from, &pending)
            .map_err(|e| undo(&written_meta, e.to_string()))?;
    }
    if !linked {
        // the file ends right under the oldest block held
        let held = node.block(from).map_err(invalid)?;
        if held.map(|b| b.parent) != last {
            return Err(undo(
                &written_meta,
                format!("the era does not link to block {from}"),
            ));
        }
    }
    store
        .set_blocks_from(first)
        .map_err(|e| undo(&written_meta, e.to_string()))?;
    Ok(summary)
}
