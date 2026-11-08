#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

#[cfg(feature = "rocksdb")]
mod store;

#[cfg(feature = "rocksdb")]
pub use store::{
    Blake3Hasher, CommittedBlock, MAX_CHUNK_BYTES, PendingBlock, PreparedState, PutBlock, Restore,
    StateChunk, StateProof, StateRangeProof, Store, TxLocation, Verdict,
};

pub type WriteSet = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "state storage error: {}", self.0)
    }
}

impl std::error::Error for Error {}

pub trait StateReader {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryState {
    entries: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl MemoryState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply(&mut self, writes: &WriteSet) {
        for (key, value) in writes {
            match value {
                Some(v) => self.entries.insert(key.clone(), v.clone()),
                None => self.entries.remove(key),
            };
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl StateReader for MemoryState {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.entries.get(key).cloned())
    }
}

pub struct Overlay<'a, S: StateReader + ?Sized> {
    base: &'a S,
    layers: Vec<&'a WriteSet>,
}

impl<'a, S: StateReader + ?Sized> Overlay<'a, S> {
    pub fn new(base: &'a S, layers: Vec<&'a WriteSet>) -> Self {
        Overlay { base, layers }
    }
}

impl<S: StateReader + ?Sized> StateReader for Overlay<'_, S> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        for layer in self.layers.iter().rev() {
            if let Some(value) = layer.get(key) {
                return Ok(value.clone());
            }
        }
        self.base.get(key)
    }
}

impl<T: StateReader + ?Sized> StateReader for &T {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        (**self).get(key)
    }
}
