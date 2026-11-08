use serde::{Deserialize, Serialize};

use crate::account::amount_serde;
use crate::{
    Address, Amount, AssetId, AuthPolicy, Hash, PendingAction, Receipt, SignedTransaction,
    VaultPolicy, hex_serde,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResponse {
    pub chain_id: String,
    pub genesis_hash: Hash,
    pub height: u64,
    pub latest_hash: Hash,
    pub latest_timestamp_ms: u64,
    pub state_root: Hash,
    pub min_fee_per_byte: u64,
    pub mempool_size: usize,
    /// state below this height is gone (pruned, or never here after a snapshot)
    #[serde(default)]
    pub state_from: u64,
    /// the oldest block held in full; below it only checkpoints and epoch ends, if anything
    #[serde(default)]
    pub blocks_from: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalanceView {
    pub asset: AssetId,
    #[serde(with = "amount_serde")]
    pub amount: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountResponse {
    pub address: Address,
    pub exists: bool,
    pub nonce: u64,
    pub auth: Option<AuthPolicy>,
    pub vault: Option<VaultPolicy>,
    pub balances: Vec<BalanceView>,
    pub pending: Vec<PendingAction>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitRequest {
    pub transaction: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitResponse {
    pub id: Hash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxStatus {
    Pending,
    Included,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionResponse {
    pub id: Hash,
    pub status: TxStatus,
    pub block_height: Option<u64>,
    #[serde(default)]
    pub block_timestamp_ms: Option<u64>,
    pub index: Option<u32>,
    pub transaction: SignedTransaction,
    /// What a contract transaction did; plain transactions have none.
    #[serde(default)]
    pub receipt: Option<Receipt>,
}

/// Included transactions that name an address, newest first. See
/// `/v1/accounts/{address}/transactions`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountTransactionsResponse {
    pub address: Address,
    pub transactions: Vec<TransactionResponse>,
    /// Pass as `before` for the page after this one; none once the oldest held is given.
    pub next: Option<String>,
    /// The list is complete from this block on; older history was dropped or never held.
    pub blocks_from: u64,
}

/// Every deployed contract, oldest first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractsResponse {
    pub contracts: Vec<Address>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractResponse {
    pub address: Address,
    pub code: Hash,
    pub code_size: usize,
    #[serde(with = "amount_serde")]
    pub balance: Amount,
}

/// `contract.function(args)` against the latest state, for free. Nothing it does is kept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewRequest {
    pub function: String,
    #[serde(with = "hex_serde")]
    pub args: Vec<u8>,
    /// Run as this account, to see what a call of its would do. Nobody by default.
    #[serde(default)]
    pub caller: Option<Address>,
    /// Native tokens going along, from the caller.
    #[serde(default, with = "amount_serde")]
    pub amount: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewResponse {
    #[serde(flatten)]
    pub receipt: Receipt,
    /// The caller's native balance after the call, before any fee.
    #[serde(with = "amount_serde")]
    pub balance_after: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockResponse {
    pub hash: Hash,
    pub height: u64,
    pub round: u64,
    pub parent: Hash,
    pub proposer: u16,
    pub timestamp_ms: u64,
    pub tx_root: Hash,
    pub state_root: Hash,
    pub receipt_root: Hash,
    pub voters: Vec<u16>,
    pub transaction_ids: Vec<Hash>,
    pub transactions: Vec<SignedTransaction>,
}

/// A block as `/v1/ws` announces it: a `BlockResponse` without the transactions, which can come
/// to megabytes. `/v1/blocks/{height}` has them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockSummary {
    pub hash: Hash,
    pub height: u64,
    pub round: u64,
    pub parent: Hash,
    pub proposer: u16,
    pub timestamp_ms: u64,
    pub tx_root: Hash,
    pub state_root: Hash,
    pub receipt_root: Hash,
    pub voters: Vec<u16>,
    pub transaction_ids: Vec<Hash>,
}

/// What a client sends over `/v1/ws`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum WsRequest {
    SubscribeBlocks,
    UnsubscribeBlocks,
    WatchTransaction { id: Hash },
    UnwatchTransaction { id: Hash },
}

/// What `/v1/ws` sends. `Transaction` is always an included one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsEvent {
    Block(Box<BlockSummary>),
    Transaction(Box<TransactionResponse>),
    Error { error: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochSummary {
    pub epoch: u64,
    pub start: Hash,
    pub start_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochsResponse {
    pub epochs: Vec<EpochSummary>,
}

/// Complete eras of `length` blocks this node hands out at `/v1/eras/{index}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasResponse {
    pub length: u64,
    pub eras: Vec<u64>,
}

/// A state a new node can start from: the block (borsh, hex) and its finality proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotResponse {
    pub height: u64,
    pub state_root: Hash,
    pub block: String,
    pub finality: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawBlockResponse {
    pub height: u64,
    pub block: String,
    pub finality: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountProofResponse {
    pub height: u64,
    pub block_hash: Hash,
    pub state_root: Hash,
    pub account: Option<String>,
    pub proof: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorsResponse {
    pub epoch: u64,
    pub epoch_start: Hash,
    pub epoch_start_height: u64,
    pub validators: Vec<crate::Validator>,
    pub quorum: usize,
    pub governance: Address,
}

/// What a payout address can claim. `seated` says whether it is still earning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardResponse {
    pub payout: Address,
    pub seated: bool,
    #[serde(with = "amount_serde")]
    pub claimable: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardsResponse {
    pub pool: Address,
    #[serde(with = "amount_serde")]
    pub balance: Amount,
    #[serde(with = "amount_serde")]
    pub per_validator: Amount,
    #[serde(with = "amount_serde")]
    pub carry: Amount,
    pub validators: Vec<RewardResponse>,
}
