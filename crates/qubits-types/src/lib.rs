#![forbid(unsafe_code)]

mod account;
mod address;
mod block;
pub mod client;
mod contract;
mod error;
mod genesis;
mod hash;
pub mod rpc;
mod signatures;
mod transaction;

pub use account::{
    Account, Amount, AssetId, AuthPolicy, DelayedAction, NATIVE_DECIMALS, PendingAction,
    RewardAccount, RewardTotals, Validator, ValidatorSet, VaultPolicy, amount_serde,
    governance_address, rewards_address, validator_keys,
};
pub use address::Address;
pub use block::{BlockPayload, tx_root};
pub use contract::{
    Contract, Event, Outcome, Receipt, code_hash, contract_address, contract_hash, hex_serde,
    receipt_root,
};
pub use error::Error;
pub use genesis::{ChainParams, Genesis, GenesisAccount};
pub use hash::Hash;
pub use signatures::SignatureCache;
pub use transaction::{KeySignature, Payload, Role, SignedTransaction, Transaction};

pub use qubits_crypto as crypto;

pub mod limits {
    pub const MAX_AUTH_KEYS: usize = 16;
    pub const MAX_PENDING_ACTIONS: usize = 16;
    pub const MAX_VAULT_DELAY_MS: u64 = 365 * 24 * 60 * 60 * 1000;
    pub const MAX_TX_BYTES: usize = 288 * 1024;
    // fees escape the vault delay, so this caps what a stolen owner key can burn
    pub const MAX_FEE_MULTIPLE: u128 = 8;
    pub const MAX_CHAIN_ID_LEN: usize = 64;
    pub const MAX_VALIDATORS: usize = 50;
    pub const MAX_BLOCK_BYTES: usize = 8 * 1024 * 1024;
    // leaves room in MAX_TX_BYTES for a quorum of 50 validators' signatures on the deployment
    pub const MAX_CODE_BYTES: usize = 160 * 1024;
    pub const MAX_ARGS_BYTES: usize = 16 * 1024;
    pub const MAX_FUNCTION_NAME: usize = 64;
    pub const MAX_CALL_DEPTH: usize = 8;
    /// Gas one byte's worth of fee buys.
    pub const GAS_PER_BYTE: u64 = 16;
    pub const MAX_TX_GAS: u64 = 5_000_000;
    /// What the gas limits in a block may add up to, so a block stays far below the block time.
    pub const MAX_BLOCK_GAS: u64 = 10_000_000;
}
