//! `/v1/ws`: blocks, transaction results and transactions naming an address, pushed as they are
//! committed.
//!
//! Consensus only moves a number (`Feed::announce`), so nothing here can slow it down. One task
//! turns new heights into messages, once each, and every connection shares them. Slow clients
//! are dropped rather than waited for, and they must then catch up over the HTTP API.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use qubits_types::rpc::{BlockSummary, ErrorResponse, WsEvent, WsRequest};
use qubits_types::{Address, Hash, SignedTransaction};
use tokio::sync::{broadcast, watch};
use tokio::time::{Instant, timeout};

use crate::{ChainBlock, Node, rpc};

/// Connections open at once, unless `--ws-limit` says otherwise.
pub const MAX_CONNECTIONS: usize = 1024;
/// Transactions one connection may wait for.
pub const MAX_WATCHED: usize = 64;
/// Addresses one connection may watch.
pub const MAX_WATCHED_ADDRESSES: usize = 16;
/// Blocks kept for a connection. One that falls further behind is closed.
pub const MAX_BEHIND: usize = 64;
const MAX_REQUEST_BYTES: usize = 1024;
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Well under the 60 s after which proxies usually drop a quiet connection.
const PING_EVERY: Duration = Duration::from_secs(30);
/// "Try again later", in the registry of WebSocket close codes.
const CLOSE_BEHIND: u16 = 1013;

struct Published {
    height: u64,
    text: Utf8Bytes,
    transactions: Vec<Hash>,
    /// What each transaction is listed under, as in the address index.
    named: Vec<Vec<Address>>,
}

pub struct Feed {
    heads: Arc<watch::Sender<u64>>,
    blocks: broadcast::Sender<Arc<Published>>,
    open: Arc<AtomicUsize>,
    limit: AtomicUsize,
}

impl Default for Feed {
    fn default() -> Self {
        Feed {
            heads: Arc::new(watch::Sender::new(0)),
            blocks: broadcast::Sender::new(MAX_BEHIND),
            open: Arc::default(),
            limit: AtomicUsize::new(MAX_CONNECTIONS),
        }
    }
}

impl Feed {
    pub(crate) fn heads(&self) -> Arc<watch::Sender<u64>> {
        self.heads.clone()
    }

    /// Says a block is stored. It only moves a number, so consensus never waits for a client.
    pub(crate) fn announce(&self, height: u64) {
        self.heads.send_replace(height);
    }

    pub(crate) fn set_limit(&self, limit: usize) {
        self.limit.store(limit, Ordering::Relaxed);
    }

    pub(crate) fn connections(&self) -> usize {
        self.open.load(Ordering::Relaxed)
    }

    fn slot(&self) -> Option<Slot> {
        let limit = self.limit.load(Ordering::Relaxed);
        self.open
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |open| {
                (open < limit).then_some(open + 1)
            })
            .ok()?;
        Some(Slot(self.open.clone()))
    }
}

struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn message(event: &WsEvent) -> Message {
    Message::text(serde_json::to_string(event).expect("encoding cannot fail"))
}

fn error(text: impl Into<String>) -> Message {
    message(&WsEvent::Error { error: text.into() })
}

fn published(node: &Node, block: ChainBlock) -> Published {
    let named = crate::index::of_block(node.store(), &block).unwrap_or_else(|e| {
        tracing::error!(height = block.height, error = %e, "receipts missing from the feed");
        crate::index::of_payload(&block)
    });
    let height = block.height;
    let transactions: Vec<Hash> = block
        .payload
        .transactions
        .iter()
        .map(SignedTransaction::id)
        .collect();
    let event = WsEvent::Block(Box::new(BlockSummary {
        hash: block.id(),
        height: block.height,
        round: block.round,
        parent: block.parent,
        proposer: block.proposer,
        timestamp_ms: block.payload.timestamp_ms,
        tx_root: block.payload.tx_root,
        state_root: block.payload.state_root,
        receipt_root: block.payload.receipt_root,
        voters: block.voters,
        transaction_ids: transactions.clone(),
    }));
    Published {
        height,
        text: serde_json::to_string(&event)
            .expect("encoding cannot fail")
            .into(),
        transactions,
        named,
    }
}

/// Runs for as long as the server does. It sends every block in order, so a client that keeps up
/// misses none, and it costs nothing while nobody is connected.
pub(crate) async fn publish(node: Arc<Node>) {
    let feed = node.feed();
    let mut heads = feed.heads.subscribe();
    let mut next = match node.head() {
        Ok(head) => head.height + 1,
        Err(e) => {
            tracing::error!(error = %e, "no feed of blocks");
            return;
        }
    };
    while heads.changed().await.is_ok() {
        let head = *heads.borrow_and_update();
        if feed.blocks.receiver_count() > 0 {
            // a snapshot leaves no blocks below it
            let first = node
                .store()
                .blocks_from()
                .map_or(next, |from| from.max(next));
            for height in first..=head {
                match node.block(height) {
                    Ok(Some(block)) => {
                        let _ = feed.blocks.send(Arc::new(published(&node, block)));
                    }
                    Ok(None) => {}
                    Err(e) => tracing::error!(height, error = %e, "block missing from the feed"),
                }
                tokio::task::yield_now().await;
            }
        }
        next = head + 1;
    }
}

pub async fn upgrade(State(node): State<Arc<Node>>, upgrade: WebSocketUpgrade) -> Response {
    let Some(slot) = node.feed().slot() else {
        let error = ErrorResponse {
            error: "too many WebSocket connections".into(),
        };
        return (StatusCode::SERVICE_UNAVAILABLE, Json(error)).into_response();
    };
    upgrade
        .max_message_size(MAX_REQUEST_BYTES)
        .max_frame_size(MAX_REQUEST_BYTES)
        .on_upgrade(move |socket| connection(node, socket, slot))
}

#[derive(Default)]
struct Client {
    blocks: bool,
    watched: HashSet<Hash>,
    addresses: HashSet<Address>,
}

impl Client {
    fn on_block(&mut self, node: &Node, block: &Published) -> Vec<Message> {
        let mut out = Vec::new();
        if self.blocks {
            out.push(Message::Text(block.text.clone()));
        }
        for id in &block.transactions {
            if self.watched.contains(id) {
                out.extend(self.included(node, *id));
            }
        }
        let matched: Vec<(Address, u32)> = block
            .named
            .iter()
            .enumerate()
            .flat_map(|(index, named)| {
                named
                    .iter()
                    .filter(|a| self.addresses.contains(a))
                    .map(move |a| (*a, index as u32))
            })
            .collect();
        if !matched.is_empty() {
            out.extend(self.named(node, block.height, &matched));
        }
        out
    }

    /// The block is read once, however many of its transactions name a watched address.
    fn named(&self, node: &Node, height: u64, matched: &[(Address, u32)]) -> Vec<Message> {
        let Ok(Some(block)) = node.block(height) else {
            return vec![error("could not read the block")];
        };
        matched
            .iter()
            .filter_map(
                |(address, index)| match rpc::response_at(node, &block, *index) {
                    Ok(Some(transaction)) => Some(message(&WsEvent::AddressTransaction {
                        address: *address,
                        transaction: Box::new(transaction),
                    })),
                    Ok(None) => None,
                    Err(_) => Some(error("could not read the transaction")),
                },
            )
            .collect()
    }

    /// Stops watching once it can say what became of the transaction.
    fn included(&mut self, node: &Node, id: Hash) -> Option<Message> {
        match rpc::included(node, &id) {
            Ok(Some(response)) => {
                self.watched.remove(&id);
                Some(message(&WsEvent::Transaction(Box::new(response))))
            }
            Ok(None) => None,
            Err(_) => Some(error("could not read the transaction")),
        }
    }

    fn on_request(&mut self, node: &Node, text: &str) -> Vec<Message> {
        let request = match serde_json::from_str(text) {
            Ok(request) => request,
            Err(e) => return vec![error(format!("bad request: {e}"))],
        };
        match request {
            WsRequest::SubscribeBlocks => self.blocks = true,
            WsRequest::UnsubscribeBlocks => self.blocks = false,
            WsRequest::UnwatchTransaction { id } => {
                self.watched.remove(&id);
            }
            WsRequest::WatchAddress { address } => {
                if self.addresses.len() >= MAX_WATCHED_ADDRESSES
                    && !self.addresses.contains(&address)
                {
                    return vec![error("watching too many addresses")];
                }
                // only what comes next: the past is at /v1/accounts/{address}/transactions
                self.addresses.insert(address);
            }
            WsRequest::UnwatchAddress { address } => {
                self.addresses.remove(&address);
            }
            WsRequest::WatchTransaction { id } => {
                if self.watched.len() >= MAX_WATCHED && !self.watched.contains(&id) {
                    return vec![error("watching too many transactions")];
                }
                self.watched.insert(id);
                // this connection hears of anything later, so only the past needs a look
                return self.included(node, id).into_iter().collect();
            }
        }
        Vec::new()
    }
}

async fn connection(node: Arc<Node>, mut socket: WebSocket, _slot: Slot) {
    let mut blocks = node.feed().blocks.subscribe();
    let mut client = Client::default();
    let mut ping = tokio::time::interval_at(Instant::now() + PING_EVERY, PING_EVERY);
    let mut heard = true;
    loop {
        let out = tokio::select! {
            block = blocks.recv() => match block {
                Ok(block) => client.on_block(&node, &block),
                Err(broadcast::error::RecvError::Lagged(_)) => vec![Message::Close(Some(CloseFrame {
                    code: CLOSE_BEHIND,
                    reason: "fell behind".into(),
                }))],
                Err(broadcast::error::RecvError::Closed) => return,
            },
            received = socket.recv() => match received {
                Some(Err(_)) | None => return,
                Some(Ok(Message::Text(text))) => {
                    heard = true;
                    client.on_request(&node, &text)
                }
                Some(Ok(Message::Binary(_))) => {
                    heard = true;
                    vec![error("requests are JSON text")]
                }
                // includes a close: the next read answers it, then ends the connection
                Some(Ok(_)) => {
                    heard = true;
                    Vec::new()
                }
            },
            _ = ping.tick() => {
                if !heard {
                    return;
                }
                heard = false;
                vec![Message::Ping(Bytes::new())]
            }
        };
        for outgoing in out {
            let closing = matches!(outgoing, Message::Close(_));
            match timeout(SEND_TIMEOUT, socket.send(outgoing)).await {
                Ok(Ok(())) if !closing => {}
                _ => return,
            }
        }
    }
}
