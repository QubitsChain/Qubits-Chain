use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use qubits_execution::{TxError, keys, read_account, read_contracts};
use qubits_state::StateReader;
use qubits_types::limits::{MAX_ARGS_BYTES, MAX_FUNCTION_NAME, MAX_TX_BYTES};
use qubits_types::rpc::{
    AccountProofResponse, AccountResponse, BalanceView, BlockResponse, ContractResponse,
    ContractsResponse, EpochSummary, EpochsResponse, ErasResponse, ErrorResponse, RawBlockResponse,
    RewardResponse, RewardsResponse, SnapshotResponse, StatusResponse, SubmitRequest,
    SubmitResponse, TransactionResponse, TxStatus, ValidatorsResponse, ViewRequest, ViewResponse,
};
use qubits_types::{Address, AssetId, Contract, Hash, Receipt, SignedTransaction};
use tower_http::cors::CorsLayer;

use crate::{ChainBlock, Node, NodeError, SubmitError, now_ms};

type Shared = Arc<Node>;

pub const MAX_CONCURRENT_SUBMITS: usize = 32;
pub const DEFAULT_CHUNK_BYTES: usize = 2 * 1024 * 1024;
pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(ErrorResponse { error: self.1 })).into_response()
    }
}

impl From<NodeError> for ApiError {
    fn from(e: NodeError) -> Self {
        tracing::error!(error = %e, "request failed");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

impl From<qubits_state::Error> for ApiError {
    fn from(e: qubits_state::Error) -> Self {
        NodeError::from(e).into()
    }
}

fn bad_request(msg: impl ToString) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.to_string())
}

fn not_found(msg: impl ToString) -> ApiError {
    ApiError(StatusCode::NOT_FOUND, msg.to_string())
}

type ApiResult<T> = Result<Json<T>, ApiError>;

pub fn router(node: Shared) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/v1/status", get(status))
        .route("/v1/accounts/{address}", get(account))
        .route("/v1/blocks/latest", get(latest_block))
        .route("/v1/blocks/{height}", get(block))
        .route("/v1/blocks/{height}/raw", get(raw_block))
        .route("/v1/validators", get(validators))
        .route("/v1/epochs", get(epochs))
        .route("/v1/state/snapshot", get(snapshot))
        .route("/v1/state/ranges", get(state_ranges))
        .route("/v1/eras", get(eras))
        .route("/v1/eras/{index}", get(era_file))
        .route("/v1/proofs/accounts/{address}", get(account_proof))
        .route("/v1/contracts", get(contracts))
        .route("/v1/contracts/{address}", get(contract))
        .route(
            "/v1/contracts/{address}/view",
            axum::routing::post(view_contract),
        )
        .route("/v1/transactions", axum::routing::post(submit))
        .route("/v1/transactions/{id}", get(transaction))
        .route("/v1/rewards", get(rewards))
        .route("/v1/rewards/{address}", get(reward))
        .route("/v1/ws", get(crate::ws::upgrade))
        // hex doubles the size
        .layer(DefaultBodyLimit::max(2 * MAX_TX_BYTES + 1024))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(CorsLayer::permissive())
        .with_state(node)
}

async fn health(State(node): State<Shared>) -> Result<String, ApiError> {
    Ok(format!("ok {}\n", node.head()?.height))
}

async fn metrics(State(node): State<Shared>) -> Result<String, ApiError> {
    let height = node.head()?.height;
    let connections = node.feed().connections();
    Ok(node
        .metrics()
        .render(height, node.mempool_len(), connections))
}

async fn status(State(node): State<Shared>) -> ApiResult<StatusResponse> {
    let head = node.head()?;
    Ok(Json(StatusResponse {
        chain_id: node.genesis().chain_id.clone(),
        genesis_hash: node.genesis_hash(),
        height: head.height,
        latest_hash: head.hash,
        latest_timestamp_ms: head.timestamp_ms,
        state_root: head.state_root,
        min_fee_per_byte: node.genesis().params.min_fee_per_byte,
        mempool_size: node.mempool_len(),
        state_from: node.store().pruned_before()?,
        blocks_from: node.store().blocks_from()?,
    }))
}

async fn account(
    State(node): State<Shared>,
    Path(address): Path<String>,
) -> ApiResult<AccountResponse> {
    let address: Address = address.parse().map_err(bad_request)?;
    let account = read_account(node.store(), &address).map_err(|e| match e {
        TxError::Storage(msg) => ApiError::from(NodeError::Storage(msg)),
        other => bad_request(other),
    })?;
    let exists = account.is_some();
    let account = account.unwrap_or_default();
    Ok(Json(AccountResponse {
        address,
        exists,
        nonce: account.nonce,
        auth: account.auth,
        vault: account.vault,
        balances: account
            .balances
            .into_iter()
            .map(|(asset, amount)| BalanceView { asset, amount })
            .collect(),
        pending: account.pending,
    }))
}

fn block_response(block: ChainBlock) -> BlockResponse {
    BlockResponse {
        hash: block.id(),
        height: block.height,
        round: block.round,
        parent: block.parent,
        proposer: block.proposer,
        timestamp_ms: block.payload.timestamp_ms,
        tx_root: block.payload.tx_root,
        receipt_root: block.payload.receipt_root,
        state_root: block.payload.state_root,
        voters: block.voters.clone(),
        transaction_ids: block
            .payload
            .transactions
            .iter()
            .map(SignedTransaction::id)
            .collect(),
        transactions: block.payload.transactions,
    }
}

fn missing_block(node: &Node, height: u64) -> ApiError {
    match node.store().blocks_from() {
        Ok(from) if height < from => not_found(format!(
            "history before block {from} is not kept on this node"
        )),
        _ => not_found("no block at that height"),
    }
}

async fn block(State(node): State<Shared>, Path(height): Path<u64>) -> ApiResult<BlockResponse> {
    let block = node
        .block(height)?
        .ok_or_else(|| missing_block(&node, height))?;
    Ok(Json(block_response(block)))
}

async fn latest_block(State(node): State<Shared>) -> ApiResult<BlockResponse> {
    let height = node.head()?.height;
    let block = node
        .block(height)?
        .ok_or_else(|| not_found("no blocks yet"))?;
    Ok(Json(block_response(block)))
}

async fn validators(State(node): State<Shared>) -> ApiResult<ValidatorsResponse> {
    let set = node.validators()?;
    let epoch =
        crate::EpochInfo::read(node.store(), node.genesis_hash()).map_err(NodeError::Storage)?;
    Ok(Json(ValidatorsResponse {
        epoch: epoch.epoch,
        epoch_start: epoch.start,
        epoch_start_height: epoch.start_height,
        quorum: set.quorum(),
        validators: set.validators,
        governance: qubits_types::governance_address(),
    }))
}

fn state_failure(e: TxError) -> ApiError {
    match e {
        TxError::Storage(msg) => NodeError::Storage(msg).into(),
        other => bad_request(other),
    }
}

fn reward_of(node: &Node, payout: Address, seated: bool) -> Result<RewardResponse, ApiError> {
    let claimable = qubits_execution::claimable(node.store(), &payout).map_err(state_failure)?;
    Ok(RewardResponse {
        payout,
        seated,
        claimable,
    })
}

async fn reward(
    State(node): State<Shared>,
    Path(address): Path<String>,
) -> ApiResult<RewardResponse> {
    let payout: Address = address.parse().map_err(bad_request)?;
    let seated = node.validators()?.pays(&payout);
    Ok(Json(reward_of(&node, payout, seated)?))
}

async fn rewards(State(node): State<Shared>) -> ApiResult<RewardsResponse> {
    let totals = qubits_execution::read_reward_totals(node.store()).map_err(state_failure)?;
    let pool = qubits_types::rewards_address();
    let balance = read_account(node.store(), &pool)
        .map_err(state_failure)?
        .map_or(0, |account| account.balance(AssetId::NATIVE));
    let validators = node
        .validators()?
        .validators
        .iter()
        .map(|v| reward_of(&node, v.payout, true))
        .collect::<Result<_, _>>()?;
    Ok(Json(RewardsResponse {
        pool,
        balance,
        per_validator: totals.per_validator,
        carry: totals.carry,
        validators,
    }))
}

async fn epochs(State(node): State<Shared>) -> ApiResult<EpochsResponse> {
    let epochs = node
        .epochs()?
        .into_iter()
        .map(|e| EpochSummary {
            epoch: e.epoch,
            start: e.start,
            start_height: e.start_height,
        })
        .collect();
    Ok(Json(EpochsResponse { epochs }))
}

async fn snapshot(State(node): State<Shared>) -> ApiResult<SnapshotResponse> {
    let unavailable = || {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "no snapshot to serve".into(),
        )
    };
    let height = node.snapshot_height()?.ok_or_else(unavailable)?;
    let block = node.block(height)?.ok_or_else(unavailable)?;
    let proof = node.stored_proof(height)?.ok_or_else(unavailable)?;
    Ok(Json(SnapshotResponse {
        height,
        state_root: block.payload.state_root,
        block: hex::encode(borsh::to_vec(&block).expect("encoding cannot fail")),
        finality: hex::encode(borsh::to_vec(&proof).expect("encoding cannot fail")),
    }))
}

async fn eras(State(node): State<Shared>) -> ApiResult<ErasResponse> {
    Ok(Json(ErasResponse {
        length: node.era_length(),
        eras: node.eras()?,
    }))
}

struct ChannelWriter(tokio::sync::mpsc::Sender<Result<axum::body::Bytes, std::io::Error>>);

impl std::io::Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .blocking_send(Ok(axum::body::Bytes::copy_from_slice(buf)))
            .map_err(|_| std::io::Error::other("the download stopped"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(serde::Deserialize)]
struct EraQuery {
    /// end the file at this height instead of the era's end: the part of the current era a
    /// node that started from a snapshot needs
    to: Option<u64>,
}

/// One era, streamed as it is read, so a file of any size costs little memory.
async fn era_file(
    State(node): State<Shared>,
    Path(index): Path<u64>,
    axum::extract::Query(query): axum::extract::Query<EraQuery>,
) -> Result<Response, ApiError> {
    let (first, mut last) = crate::era::range(index, node.era_length());
    let mut name = crate::era::file_name(&node.genesis().chain_id, &node.genesis_hash(), index);
    match query.to {
        None if !node.eras()?.contains(&index) => {
            return Err(not_found(
                "that era is not complete or not kept on this node",
            ));
        }
        None => {}
        Some(to) => {
            let held = first >= node.store().blocks_from()?.max(1) && to <= node.head()?.height;
            if !(first..=last).contains(&to) || !held || node.stored_proof(to)?.is_none() {
                return Err(not_found(
                    "that part of the era is not here, or its last block has no kept proof",
                ));
            }
            last = to;
            name = crate::era::partial_file_name(
                &node.genesis().chain_id,
                &node.genesis_hash(),
                index,
                to,
            );
        }
    }
    let (sender, receiver) = tokio::sync::mpsc::channel(8);
    tokio::task::spawn_blocking(move || {
        let mut out = std::io::BufWriter::with_capacity(256 * 1024, ChannelWriter(sender));
        if let Err(e) = crate::era::write(&node, first, last, &mut out) {
            tracing::warn!(error = %e, index, "could not stream an era");
        }
    });
    let body = axum::body::Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(receiver));
    Ok((
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/octet-stream".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
        ],
        body,
    )
        .into_response())
}

#[derive(serde::Deserialize)]
struct RangesQuery {
    height: u64,
    from: Option<String>,
    bytes: Option<usize>,
}

/// Leaves of the state at a height, from a key hash on, as borsh: for joining nodes.
async fn state_ranges(
    State(node): State<Shared>,
    axum::extract::Query(query): axum::extract::Query<RangesQuery>,
) -> Result<Response, ApiError> {
    let from = match query.from {
        Some(text) => hex::decode(text)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| bad_request("from must be 32 bytes of hex"))?,
        None => [0; 32],
    };
    let bytes = query.bytes.unwrap_or(DEFAULT_CHUNK_BYTES);
    let chunk = node
        .store()
        .state_chunk(query.height, Some(from), bytes)
        .map_err(|e| not_found(e.0))?;
    let body = borsh::to_vec(&chunk).expect("encoding cannot fail");
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        body,
    )
        .into_response())
}

#[derive(serde::Deserialize)]
struct RawQuery {
    #[serde(default)]
    prove: bool,
}

async fn raw_block(
    State(node): State<Shared>,
    Path(height): Path<u64>,
    axum::extract::Query(query): axum::extract::Query<RawQuery>,
) -> ApiResult<RawBlockResponse> {
    let bytes = node
        .store()
        .block(height)?
        .ok_or_else(|| missing_block(&node, height))?;
    let proof = match node.stored_proof(height)? {
        Some(proof) => Some(proof),
        None if query.prove => node.finality_proof(height)?,
        None => None,
    };
    Ok(Json(RawBlockResponse {
        height,
        block: hex::encode(bytes),
        finality: proof.map(|p| hex::encode(borsh::to_vec(&p).expect("encoding cannot fail"))),
    }))
}

#[derive(serde::Deserialize)]
struct ProofQuery {
    height: Option<u64>,
}

async fn account_proof(
    State(node): State<Shared>,
    Path(address): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ProofQuery>,
) -> ApiResult<AccountProofResponse> {
    let address: Address = address.parse().map_err(bad_request)?;
    let head = node.head()?;
    let height = query.height.unwrap_or(head.height);
    if height > head.height {
        return Err(not_found("that height is not committed yet"));
    }
    let block_hash = if height == 0 {
        node.genesis_hash()
    } else {
        node.block(height)?
            .ok_or_else(|| not_found("no block at that height"))?
            .id()
    };
    let key = qubits_execution::keys::account(&address);
    let state_root = node
        .store()
        .state_root(height)
        .map_err(|_| not_found("state at that height was pruned"))?;
    let (value, proof) = node.store().get_with_proof(height, &key)?;
    Ok(Json(AccountProofResponse {
        height,
        block_hash,
        state_root,
        account: value.map(hex::encode),
        proof: hex::encode(borsh::to_vec(&proof).expect("encoding cannot fail")),
    }))
}

async fn transaction(
    State(node): State<Shared>,
    Path(id): Path<String>,
) -> ApiResult<TransactionResponse> {
    let id: Hash = id.parse().map_err(bad_request)?;
    if let Some(response) = included(&node, &id)? {
        return Ok(Json(response));
    }
    match node.pending_transaction(&id) {
        Some(transaction) => Ok(Json(TransactionResponse {
            id,
            status: TxStatus::Pending,
            block_height: None,
            index: None,
            transaction,
            receipt: None,
        })),
        None => Err(not_found("unknown transaction")),
    }
}

/// A transaction that made it into a block, with what it did.
pub(crate) fn included(node: &Node, id: &Hash) -> Result<Option<TransactionResponse>, ApiError> {
    let Some(location) = node.store().tx_location(id)? else {
        return Ok(None);
    };
    let block = node
        .block(location.height)?
        .ok_or_else(|| NodeError::Storage(format!("block {} missing", location.height)))?;
    let transaction = block
        .payload
        .transactions
        .get(location.index as usize)
        .cloned()
        .ok_or_else(|| NodeError::Storage("transaction index out of range".into()))?;
    Ok(Some(TransactionResponse {
        id: *id,
        status: TxStatus::Included,
        block_height: Some(location.height),
        index: Some(location.index),
        transaction,
        receipt: receipt(node, id)?,
    }))
}

fn receipt(node: &Node, id: &Hash) -> Result<Option<Receipt>, ApiError> {
    let Some(bytes) = node.store().receipt(id)? else {
        return Ok(None);
    };
    let receipt = borsh::from_slice(&bytes)
        .map_err(|e| NodeError::Storage(format!("corrupt receipt {id}: {e}")))?;
    Ok(Some(receipt))
}

async fn contracts(State(node): State<Shared>) -> ApiResult<ContractsResponse> {
    let contracts = read_contracts(node.store()).map_err(|e| NodeError::Storage(e.to_string()))?;
    Ok(Json(ContractsResponse { contracts }))
}

async fn contract(
    State(node): State<Shared>,
    Path(address): Path<String>,
) -> ApiResult<ContractResponse> {
    let address: Address = address.parse().map_err(bad_request)?;
    let store = node.store();
    let Some(record) = store.get(&keys::contract(&address))? else {
        return Err(not_found("no contract at that address"));
    };
    let contract: Contract = borsh::from_slice(&record)
        .map_err(|e| NodeError::Storage(format!("corrupt contract {address}: {e}")))?;
    let code = store
        .get(&keys::code(&contract.code))?
        .ok_or_else(|| NodeError::Storage(format!("code of {address} missing")))?;
    let account = read_account(store, &address).map_err(|e| NodeError::Storage(e.to_string()))?;
    Ok(Json(ContractResponse {
        address,
        code: contract.code,
        code_size: code.len(),
        balance: account.map_or(0, |a| a.balance(AssetId::NATIVE)),
    }))
}

async fn view_contract(
    State(node): State<Shared>,
    Path(address): Path<String>,
    Json(request): Json<ViewRequest>,
) -> ApiResult<ViewResponse> {
    let address: Address = address.parse().map_err(bad_request)?;
    if request.args.len() > MAX_ARGS_BYTES || request.function.len() > MAX_FUNCTION_NAME {
        return Err(bad_request("the call is too large"));
    }
    // runs code for free, so it waits in the same line as submissions
    let permit = node.submits().acquire_owned().await;
    let permit = permit.map_err(|e| ApiError(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        node.simulate(&request, &address, now_ms())
    })
    .await
    .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    match result {
        Ok(simulated) => Ok(Json(ViewResponse {
            receipt: simulated.receipt,
            balance_after: simulated.balance_after,
        })),
        Err(TxError::NotAContract) => Err(not_found(TxError::NotAContract)),
        Err(TxError::Storage(e)) => Err(NodeError::Storage(e).into()),
        Err(e) => Err(bad_request(e)),
    }
}

async fn submit(
    State(node): State<Shared>,
    Json(request): Json<SubmitRequest>,
) -> Result<(StatusCode, Json<SubmitResponse>), ApiError> {
    let bytes = hex::decode(request.transaction.trim())
        .map_err(|_| bad_request("transaction is not hex"))?;
    let stx = SignedTransaction::decode(&bytes).map_err(bad_request)?;
    // after the body, so slow clients can't sit on the permits
    let permit = node.submits().acquire_owned().await;
    let permit = permit.map_err(|e| ApiError(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        node.submit(stx, now_ms())
    })
    .await
    .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    match result {
        Ok(id) => Ok((StatusCode::ACCEPTED, Json(SubmitResponse { id }))),
        Err(SubmitError::MempoolFull) => Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            SubmitError::MempoolFull.to_string(),
        )),
        Err(SubmitError::Invalid(TxError::Storage(e))) => Err(NodeError::Storage(e).into()),
        Err(SubmitError::Duplicate) => Err(ApiError(
            StatusCode::CONFLICT,
            SubmitError::Duplicate.to_string(),
        )),
        Err(e) => Err(bad_request(e)),
    }
}
