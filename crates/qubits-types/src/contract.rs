use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::hash::{Hash, context};
use crate::{Address, block};

pub mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        hex::decode(String::deserialize(d)?).map_err(D::Error::custom)
    }
}

/// What is stored for a deployed contract. The code lives once under its hash.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Contract {
    pub code: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Event {
    pub contract: Address,
    #[serde(with = "hex_serde")]
    pub topic: Vec<u8>,
    #[serde(with = "hex_serde")]
    pub data: Vec<u8>,
}

/// How a transaction ended. Anything but `Done` undid the contract's work and still paid.
/// No text from the VM goes in here: receipts are hashed into the block.
#[derive(
    Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    #[default]
    Done,
    Reverted {
        #[serde(with = "hex_serde")]
        reason: Vec<u8>,
    },
    OutOfGas,
    Trapped,
    /// The code is not a usable contract, or has no such function.
    Invalid,
}

#[derive(
    Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct Receipt {
    pub outcome: Outcome,
    pub gas_used: u64,
    #[serde(with = "hex_serde")]
    pub output: Vec<u8>,
    pub events: Vec<Event>,
    /// The address a deployment created.
    pub contract: Option<Address>,
}

pub fn contract_address(deployer: &Address, nonce: u64) -> Address {
    let mut seed = [0u8; 40];
    seed[..32].copy_from_slice(deployer.as_bytes());
    seed[32..].copy_from_slice(&nonce.to_le_bytes());
    Address(Hash::digest(context::CONTRACT_ADDRESS, &seed).0)
}

pub fn code_hash(code: &[u8]) -> Hash {
    Hash::digest(context::CONTRACT_CODE, code)
}

/// The hash a contract gets from the `hash` host call.
pub fn contract_hash(data: &[u8]) -> Hash {
    Hash::digest(context::CONTRACT_HASH, data)
}

pub fn receipt_root(receipts: &[Receipt]) -> Hash {
    let leaves = receipts
        .iter()
        .map(|r| {
            let bytes = borsh::to_vec(r).expect("in-memory encoding cannot fail");
            Hash::digest(context::RECEIPT_ROOT_LEAF, &bytes)
        })
        .collect();
    block::merkle(leaves, context::RECEIPT_ROOT_NODE)
}
