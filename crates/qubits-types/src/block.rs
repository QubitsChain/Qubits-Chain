use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::hash::{Hash, context};
use crate::{Error, SignedTransaction};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct BlockPayload {
    pub timestamp_ms: u64,
    pub transactions: Vec<SignedTransaction>,
    pub tx_root: Hash,
    pub state_root: Hash,
    /// What became of each transaction: state alone can't say why a call did nothing.
    pub receipt_root: Hash,
}

impl BlockPayload {
    pub fn check_tx_root(&self) -> Result<(), Error> {
        if tx_root(&self.transactions) == self.tx_root {
            Ok(())
        } else {
            Err(Error::Decode("tx_root does not match transactions".into()))
        }
    }
}

pub fn tx_root(transactions: &[SignedTransaction]) -> Hash {
    let leaves = transactions
        .iter()
        .map(|tx| Hash::digest(context::TX_ROOT_LEAF, &tx.encode()))
        .collect();
    merkle(leaves, context::TX_ROOT_NODE)
}

pub(crate) fn merkle(mut level: Vec<Hash>, node: &str) -> Hash {
    if level.is_empty() {
        return Hash::ZERO;
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [left, right] => {
                    let mut buf = [0u8; 64];
                    buf[..32].copy_from_slice(&left.0);
                    buf[32..].copy_from_slice(&right.0);
                    Hash::digest(node, &buf)
                }
                [single] => *single,
                _ => unreachable!("chunks(2) yields one or two items"),
            })
            .collect();
    }
    level[0]
}
