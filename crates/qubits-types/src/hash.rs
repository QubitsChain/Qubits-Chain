use core::fmt;
use core::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Error;

#[derive(
    Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, BorshSerialize, BorshDeserialize,
)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub const ZERO: Hash = Hash([0; 32]);

    pub fn digest(context: &str, data: &[u8]) -> Hash {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(data);
        Hash(*hasher.finalize().as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub(crate) mod context {
    pub const ADDRESS: &str = "qubits.sh 2026-11 address";
    pub const TX_ID: &str = "qubits.sh 2026-11 transaction id";
    pub const GENESIS: &str = "qubits.sh 2026-11 genesis";
    pub const GOVERNANCE: &str = "qubits.sh 2026-11 validator governance";
    pub const REWARDS: &str = "qubits.sh 2026-11 validator rewards";
    pub const TX_ROOT_LEAF: &str = "qubits.sh 2026-11 tx root leaf";
    pub const TX_ROOT_NODE: &str = "qubits.sh 2026-11 tx root node";
    pub const SIGNATURE_CACHE: &str = "qubits.sh 2026-11 signature cache";
    pub const CONTRACT_ADDRESS: &str = "qubits.sh 2026-11 contract address";
    pub const CONTRACT_CODE: &str = "qubits.sh 2026-11 contract code";
    pub const CONTRACT_HASH: &str = "qubits.sh 2026-11 contract hash";
    pub const RECEIPT_ROOT_LEAF: &str = "qubits.sh 2026-11 receipt root leaf";
    pub const RECEIPT_ROOT_NODE: &str = "qubits.sh 2026-11 receipt root node";
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({self})")
    }
}

impl FromStr for Hash {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).map_err(|_| Error::InvalidHash)?;
        Ok(Hash(out))
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        <String as Deserialize>::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
