use std::sync::Arc;
use std::time::{Duration, Instant};

use qubits_crypto::{SchemeId, SecretKey};
use qubits_execution::{TxError, min_fee, read_account};
use qubits_node::network::{LocalHub, NoPeers};
use qubits_node::{Node, NodeError, SubmitError, Timing, Validator, ValidatorHandle, now_ms};
use qubits_types::rpc::*;
use qubits_types::*;

const CHAIN: &str = "qubits-devnet";
const TIMING: Timing = Timing {
    round_timeout_ms: 1_000,
    min_block_interval_ms: 50,
    ..Timing::DEFAULT
};

fn key(seed: u8) -> SecretKey {
    SecretKey::from_seed(SchemeId::MlDsa65, &[seed; 32]).unwrap()
}

fn validator_key(i: usize) -> SecretKey {
    key(200 + i as u8)
}

fn alice() -> SecretKey {
    key(1)
}

fn addr(sk: &SecretKey) -> Address {
    AuthPolicy::single(sk.public_key().clone()).address()
}

fn genesis_time() -> u64 {
    static TIME: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *TIME.get_or_init(|| now_ms() - 1_000)
}

fn genesis(validators: usize) -> Genesis {
    Genesis {
        chain_id: CHAIN.into(),
        timestamp_ms: genesis_time(),
        params: ChainParams {
            min_fee_per_byte: 1,
            max_block_transactions: 100,
        },
        validators: (0..validators)
            .map(|i| qubits_types::Validator::self_paid(validator_key(i).public_key().clone()))
            .collect(),
        accounts: vec![GenesisAccount {
            address: addr(&alice()),
            balance: 100_000_000,
        }],
    }
}

fn tx(sk: &SecretKey, nonce: u64, reveal: bool, payload: Payload) -> SignedTransaction {
    tx_on(&genesis(1), sk, nonce, reveal, payload)
}

fn tx_on(
    g: &Genesis,
    sk: &SecretKey,
    nonce: u64,
    reveal: bool,
    payload: Payload,
) -> SignedTransaction {
    let policy = AuthPolicy::single(sk.public_key().clone());
    let reveal = reveal.then(|| policy.clone());
    let mut t = Transaction {
        genesis_hash: g.hash(),
        sender: policy.address(),
        nonce,
        fee: 0,
        valid_until_ms: u64::MAX,
        role: Role::Owner,
        payload,
    };
    let draft = SignedTransaction::sign(t.clone(), &policy, reveal.clone(), &[sk]).unwrap();
    t.fee = min_fee(&genesis(1).params, draft.encode().len());
    SignedTransaction::sign(t, &policy, reveal, &[sk]).unwrap()
}

fn pay(to: Address, amount: Amount) -> Payload {
    Payload::Transfer {
        to,
        asset: AssetId::NATIVE,
        amount,
    }
}

fn balance(node: &Node, address: &Address) -> Amount {
    read_account(node.store(), address)
        .unwrap()
        .unwrap_or_default()
        .balance(AssetId::NATIVE)
}

fn wait_for(what: &str, timeout_ms: u64, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

struct Cluster {
    nodes: Vec<Arc<Node>>,
    handles: Vec<Option<ValidatorHandle>>,
    hub: LocalHub,
    _dirs: Vec<tempfile::TempDir>,
}

impl Cluster {
    fn start(n: usize) -> Cluster {
        let g = genesis(n);
        let keys: Vec<_> = (0..n)
            .map(|i| validator_key(i).public_key().clone())
            .collect();
        let (hub, inboxes) = LocalHub::new(&keys);
        let mut nodes = Vec::new();
        let mut handles = Vec::new();
        let mut dirs = Vec::new();
        for (i, inbox) in inboxes.into_iter().enumerate() {
            let dir = tempfile::tempdir().unwrap();
            Node::init(dir.path(), &g).unwrap();
            let node = Arc::new(Node::open(dir.path()).unwrap());
            let transport = Arc::new(hub.transport(&keys[i]));
            let validator =
                Validator::start(node.clone(), validator_key(i), transport, TIMING).unwrap();
            handles.push(Some(validator.spawn(inbox)));
            nodes.push(node);
            dirs.push(dir);
        }
        Cluster {
            nodes,
            handles,
            hub,
            _dirs: dirs,
        }
    }

    fn heights(&self) -> Vec<u64> {
        self.nodes
            .iter()
            .map(|n| n.head().unwrap().height)
            .collect()
    }

    fn assert_agree(&self, among: &[usize]) {
        let common = among
            .iter()
            .map(|&i| self.nodes[i].head().unwrap().height)
            .min()
            .unwrap();
        assert!(common > 0);
        for h in 1..=common {
            let reference = self.nodes[among[0]].store().block(h).unwrap().unwrap();
            let root = self.nodes[among[0]].store().state_root(h).unwrap();
            for &i in &among[1..] {
                assert_eq!(
                    self.nodes[i].store().block(h).unwrap().unwrap(),
                    reference,
                    "block {h} differs on node {i}"
                );
                assert_eq!(
                    self.nodes[i].store().state_root(h).unwrap(),
                    root,
                    "state {h} differs on node {i}"
                );
            }
        }
    }
}

type KeepOpen = std::sync::mpsc::Sender<qubits_node::network::Envelope>;

fn single_validator() -> (tempfile::TempDir, Arc<Node>, ValidatorHandle, KeepOpen) {
    let dir = tempfile::tempdir().unwrap();
    Node::init(dir.path(), &genesis(1)).unwrap();
    let node = Arc::new(Node::open(dir.path()).unwrap());
    let validator =
        Validator::start(node.clone(), validator_key(0), Arc::new(NoPeers), TIMING).unwrap();
    let (keep_open, inbox) = std::sync::mpsc::channel();
    let handle = validator.spawn(inbox);
    (dir, node, handle, keep_open)
}

#[test]
fn init_and_open_checks() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        matches!(Node::open(dir.path()), Err(NodeError::Config(_))),
        "not initialized"
    );
    let g = genesis(1);
    Node::init(dir.path(), &g).unwrap();
    assert!(
        matches!(Node::init(dir.path(), &g), Err(NodeError::Config(_))),
        "twice"
    );

    let node = Arc::new(Node::open(dir.path()).unwrap());
    let head = node.head().unwrap();
    assert_eq!((head.height, head.hash), (0, g.hash()));
    assert_eq!(balance(&node, &addr(&alice())), 100_000_000);
    let not_validator = Validator::start(node, key(99), Arc::new(NoPeers), TIMING);
    assert!(matches!(not_validator, Err(NodeError::Config(_))));

    let mut bad = genesis(1);
    bad.validators.clear();
    assert!(Node::init(tempfile::tempdir().unwrap().path(), &bad).is_err());
}

#[test]
fn single_validator_commits_transactions_in_order() {
    let (_dir, node, _handle, _open) = single_validator();
    let bob = addr(&key(2));
    let txs = [
        tx(&alice(), 0, true, pay(bob, 10)),
        tx(&alice(), 1, false, pay(bob, 20)),
        tx(&alice(), 2, false, pay(bob, 30)),
    ];
    for t in &txs {
        node.submit(t.clone(), now_ms()).unwrap();
    }
    wait_for("transfers", 10_000, || balance(&node, &bob) == 60);
    assert_eq!(node.mempool_len(), 0);

    let loc = node.store().tx_location(&txs[2].id()).unwrap().unwrap();
    let block = node.block(loc.height).unwrap().unwrap();
    assert_eq!(block.payload.transactions[loc.index as usize], txs[2]);
    let proof = node.finality_proof(loc.height).unwrap().unwrap();
    assert_eq!(proof.tip, block.id(), "any final block can be proven");
    assert_eq!(proof.qc.votes.len(), 1);
    let head = node.head().unwrap();
    for h in 2..=head.height {
        let (prev, cur) = (
            node.block(h - 1).unwrap().unwrap(),
            node.block(h).unwrap().unwrap(),
        );
        assert_eq!(cur.parent, prev.id());
        assert!(cur.payload.timestamp_ms > prev.payload.timestamp_ms);
    }
}

#[test]
fn invalid_and_duplicate_submissions_are_refused() {
    let (_dir, node, _handle, _open) = single_validator();
    let bob = addr(&key(2));
    let unfunded = tx(&key(7), 0, true, pay(bob, 1));
    assert_eq!(
        node.submit(unfunded, now_ms()),
        Err(SubmitError::Invalid(TxError::UnknownSender))
    );
    let skipped = tx(&alice(), 1, true, pay(bob, 1));
    assert_eq!(
        node.submit(skipped, now_ms()),
        Err(SubmitError::Invalid(TxError::BadNonce { expected: 0 }))
    );

    let good = tx(&alice(), 0, true, pay(bob, 1));
    node.submit(good.clone(), now_ms()).unwrap();
    assert_eq!(
        node.submit(good.clone(), now_ms()),
        Err(SubmitError::Duplicate)
    );
    wait_for("inclusion", 10_000, || {
        node.store().tx_location(&good.id()).unwrap().is_some()
    });
    assert_eq!(
        node.submit(good, now_ms()),
        Err(SubmitError::Duplicate),
        "already included"
    );
}

#[test]
fn four_validators_agree_on_every_block() {
    let cluster = Cluster::start(4);
    let bob = addr(&key(2));
    for nonce in 0..5u64 {
        let via = &cluster.nodes[nonce as usize % 4];
        let stx = tx_on(&genesis(4), &alice(), nonce, nonce == 0, pay(bob, 100));
        via.submit(stx, now_ms()).unwrap();
        let expected = 100 * (u128::from(nonce) + 1);
        wait_for("transfer", 15_000, || {
            cluster.nodes.iter().all(|n| balance(n, &bob) == expected)
        });
    }
    cluster.assert_agree(&[0, 1, 2, 3]);

    let node = &cluster.nodes[0];
    let height = node.head().unwrap().height;
    let proposers: std::collections::BTreeSet<u16> = (1..=height)
        .map(|h| node.block(h).unwrap().unwrap().proposer)
        .collect();
    assert!(proposers.len() >= 3, "leaders rotate: {proposers:?}");
    let chain = node.genesis_hash();
    let set = qubits_consensus::ValidatorSet::new(validator_keys(&genesis(4).validators)).unwrap();
    for h in 1..=height {
        let (block, proof) = (
            node.block(h).unwrap().unwrap(),
            node.finality_proof(h).unwrap().unwrap(),
        );
        assert!(proof.qc.votes.len() >= 3, "block {h} has a quorum");
        assert!(proof.verify(block.round, &set, &chain), "block {h}");
    }
}

#[test]
fn chain_continues_with_one_validator_down() {
    let mut cluster = Cluster::start(4);
    let bob = addr(&key(2));
    cluster.nodes[0]
        .submit(tx_on(&genesis(4), &alice(), 0, true, pay(bob, 7)), now_ms())
        .unwrap();
    wait_for("first transfer", 15_000, || {
        cluster.nodes.iter().all(|n| balance(n, &bob) == 7)
    });

    cluster.hub.set_down(validator_key(3).public_key(), true);
    cluster.handles[3].take().unwrap().stop();
    let before = cluster.heights()[0];
    cluster.nodes[1]
        .submit(
            tx_on(&genesis(4), &alice(), 1, false, pay(bob, 7)),
            now_ms(),
        )
        .unwrap();
    wait_for("transfer with a validator down", 30_000, || {
        (0..3).all(|i| balance(&cluster.nodes[i], &bob) == 14)
    });
    assert!(cluster.heights()[0] > before);
    cluster.assert_agree(&[0, 1, 2]);
}

#[test]
fn validator_resumes_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    Node::init(dir.path(), &genesis(1)).unwrap();
    let bob = addr(&key(2));
    let (height, round) = {
        let node = Arc::new(Node::open(dir.path()).unwrap());
        let validator =
            Validator::start(node.clone(), validator_key(0), Arc::new(NoPeers), TIMING).unwrap();
        let (_keep, inbox) = std::sync::mpsc::channel();
        let handle = validator.spawn(inbox);
        node.submit(tx(&alice(), 0, true, pay(bob, 5)), now_ms())
            .unwrap();
        wait_for("first transfer", 10_000, || balance(&node, &bob) == 5);
        handle.stop();
        let head = node.head().unwrap();
        (head.height, node.block(head.height).unwrap().unwrap().round)
    };

    let node = Arc::new(Node::open(dir.path()).unwrap());
    assert_eq!(node.head().unwrap().height, height);
    let validator =
        Validator::start(node.clone(), validator_key(0), Arc::new(NoPeers), TIMING).unwrap();
    let (_keep, inbox) = std::sync::mpsc::channel();
    let _handle = validator.spawn(inbox);
    node.submit(tx(&alice(), 1, false, pay(bob, 5)), now_ms())
        .unwrap();
    wait_for("transfer after restart", 10_000, || {
        balance(&node, &bob) == 10
    });
    let next = node.block(height + 1).unwrap().unwrap();
    assert_eq!(next.parent, node.block(height).unwrap().unwrap().id());
    assert!(next.round > round, "rounds never repeat after a restart");
}

struct Server {
    base: String,
    node: Arc<Node>,
    _chain: (tempfile::TempDir, ValidatorHandle, KeepOpen),
}

fn start_server() -> Server {
    let (dir, node, handle, open) = single_validator();
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std_listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", std_listener.local_addr().unwrap());
    let served = node.clone();
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                let listener = tokio::net::TcpListener::from_std(std_listener).unwrap();
                qubits_node::serve(served, listener).await.unwrap();
            });
    });
    Server {
        base,
        node,
        _chain: (dir, handle, open),
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into()
}

fn get<T: serde::de::DeserializeOwned>(
    server: &Server,
    path: &str,
) -> (u16, Result<T, ErrorResponse>) {
    let mut resp = agent()
        .get(format!("{}{path}", server.base))
        .call()
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.body_mut().read_to_string().unwrap();
    if status < 300 {
        (status, Ok(serde_json::from_str(&body).unwrap()))
    } else {
        (status, Err(serde_json::from_str(&body).unwrap()))
    }
}

fn post_tx(server: &Server, stx: &SignedTransaction) -> (u16, String) {
    let body = SubmitRequest {
        transaction: hex::encode(stx.encode()),
    };
    let mut resp = agent()
        .post(format!("{}/v1/transactions", server.base))
        .send_json(&body)
        .unwrap();
    (
        resp.status().as_u16(),
        resp.body_mut().read_to_string().unwrap(),
    )
}

#[test]
fn http_api_end_to_end() {
    let server = start_server();
    let (code, status) = get::<StatusResponse>(&server, "/v1/status");
    assert_eq!(code, 200);
    assert_eq!(status.unwrap().chain_id, CHAIN);

    let alice_addr = addr(&alice());
    let (_, account) = get::<AccountResponse>(&server, &format!("/v1/accounts/{alice_addr}"));
    assert_eq!(
        account.unwrap().balances,
        vec![BalanceView {
            asset: AssetId::NATIVE,
            amount: 100_000_000
        }]
    );

    let bob = addr(&key(2));
    let stx = tx(&alice(), 0, true, pay(bob, 1234));
    let (code, body) = post_tx(&server, &stx);
    assert_eq!(code, 202, "{body}");

    let mut included = None;
    wait_for("inclusion", 10_000, || {
        if let (200, Ok(r)) =
            get::<TransactionResponse>(&server, &format!("/v1/transactions/{}", stx.id()))
            && r.status == TxStatus::Included
        {
            included = Some(r);
        }
        included.is_some()
    });
    let included = included.unwrap();
    assert_eq!(included.transaction, stx);
    let height = included.block_height.unwrap();

    let (_, block) = get::<BlockResponse>(&server, &format!("/v1/blocks/{height}"));
    let block = block.unwrap();
    assert_eq!(block.height, height);
    assert_eq!(block.transaction_ids, vec![stx.id()]);
    assert_eq!(block.proposer, 0);
    assert_eq!(block.tx_root, tx_root(std::slice::from_ref(&stx)));
    let (_, latest) = get::<BlockResponse>(&server, "/v1/blocks/latest");
    assert!(latest.unwrap().height >= height);

    let (_, bob_account) = get::<AccountResponse>(&server, &format!("/v1/accounts/{bob}"));
    assert_eq!(bob_account.unwrap().balances[0].amount, 1234);

    let (code, _) = post_tx(&server, &stx);
    assert_eq!(code, 409, "duplicate");
    let (code, body) = post_tx(&server, &tx(&key(9), 0, true, pay(bob, 1)));
    assert_eq!(code, 400);
    assert!(body.contains("sender account does not exist"), "{body}");
    let (code, _) = get::<AccountResponse>(&server, "/v1/accounts/not-an-address");
    assert_eq!(code, 400);
    let (code, _) =
        get::<TransactionResponse>(&server, &format!("/v1/transactions/{}", Hash([3; 32])));
    assert_eq!(code, 404);
    let (code, _) = get::<BlockResponse>(&server, "/v1/blocks/999999");
    assert_eq!(code, 404);
}

fn included(server: &Server, stx: &SignedTransaction) -> u64 {
    let mut height = None;
    wait_for("inclusion", 10_000, || {
        if let (200, Ok(r)) =
            get::<TransactionResponse>(server, &format!("/v1/transactions/{}", stx.id()))
        {
            height = r.block_height;
        }
        height.is_some()
    });
    height.unwrap()
}

fn history(server: &Server, who: &Address, query: &str) -> AccountTransactionsResponse {
    let (code, page) = get::<AccountTransactionsResponse>(
        server,
        &format!("/v1/accounts/{who}/transactions{query}"),
    );
    assert_eq!(code, 200);
    page.unwrap()
}

fn ids(page: &AccountTransactionsResponse) -> Vec<Hash> {
    page.transactions.iter().map(|t| t.id).collect()
}

#[test]
fn transactions_are_listed_by_address() {
    let server = start_server();
    let (bob_key, carol, dave) = (key(2), addr(&key(3)), addr(&key(4)));
    let bob = addr(&bob_key);
    let paid: Vec<SignedTransaction> = (0..3)
        .map(|n| tx(&alice(), n, n == 0, pay(bob, 1_000_000)))
        .collect();
    for stx in &paid {
        assert_eq!(post_tx(&server, stx).0, 202);
    }
    for stx in &paid {
        included(&server, stx);
    }
    let passed_on = tx(&bob_key, 0, true, pay(carol, 5));
    assert_eq!(post_tx(&server, &passed_on).0, 202);
    let height = included(&server, &passed_on);

    let bob_page = history(&server, &bob, "");
    let mut expected: Vec<Hash> = paid.iter().map(SignedTransaction::id).collect();
    expected.push(passed_on.id());
    expected.reverse();
    assert_eq!(ids(&bob_page), expected, "newest first, sent and received");
    assert_eq!(bob_page.next, None);
    assert_eq!(bob_page.blocks_from, 1);
    let newest = &bob_page.transactions[0];
    assert_eq!(newest.status, TxStatus::Included);
    assert_eq!(newest.block_height, Some(height));
    assert_eq!(newest.transaction, passed_on);
    let block_time = get::<BlockResponse>(&server, &format!("/v1/blocks/{height}"))
        .1
        .unwrap()
        .timestamp_ms;
    assert_eq!(newest.block_timestamp_ms, Some(block_time));

    assert_eq!(ids(&history(&server, &carol, "")), [passed_on.id()]);
    assert_eq!(ids(&history(&server, &addr(&alice()), "")), expected[1..]);
    let nobody = history(&server, &dave, "");
    assert!(nobody.transactions.is_empty());
    assert_eq!(nobody.next, None);

    // pages of two, each going on from the last
    let first = history(&server, &bob, "?limit=2");
    assert_eq!(ids(&first), expected[..2]);
    let next = first.next.expect("more to come");
    let second = history(&server, &bob, &format!("?limit=2&before={next}"));
    assert_eq!(ids(&second), expected[2..]);
    assert_eq!(second.next, None);

    for bad in [
        "/v1/accounts/not-an-address/transactions".to_string(),
        format!("/v1/accounts/{bob}/transactions?before=yesterday"),
        format!("/v1/accounts/{bob}/transactions?limit=lots"),
    ] {
        let (code, _) = get::<AccountTransactionsResponse>(&server, &bad);
        assert_eq!(code, 400, "{bad}");
    }
}

#[test]
fn fees_show_up_on_the_rewards_routes() {
    let server = start_server();
    let payout = qubits_types::Validator::self_paid(validator_key(0).public_key().clone()).payout;
    let (_, empty) = get::<RewardsResponse>(&server, "/v1/rewards");
    assert_eq!(empty.unwrap().balance, 0);

    let stx = tx(&alice(), 0, true, pay(addr(&key(2)), 1));
    assert_eq!(post_tx(&server, &stx).0, 202);
    wait_for("the fee", 10_000, || {
        get::<RewardsResponse>(&server, "/v1/rewards")
            .1
            .unwrap()
            .balance
            == stx.tx.fee
    });
    let (_, rewards) = get::<RewardsResponse>(&server, "/v1/rewards");
    let rewards = rewards.unwrap();
    assert_eq!(rewards.pool, rewards_address());
    assert_eq!(rewards.per_validator, stx.tx.fee);
    let mine = RewardResponse {
        payout,
        seated: true,
        claimable: stx.tx.fee,
    };
    assert_eq!(rewards.validators, vec![mine.clone()]);
    let (_, one) = get::<RewardResponse>(&server, &format!("/v1/rewards/{payout}"));
    assert_eq!(one.unwrap(), mine);
    let (_, set) = get::<ValidatorsResponse>(&server, "/v1/validators");
    assert_eq!(set.unwrap().validators[0].payout, payout);

    let stranger = addr(&key(9));
    let (_, nobody) = get::<RewardResponse>(&server, &format!("/v1/rewards/{stranger}"));
    assert_eq!(nobody.unwrap().claimable, 0);
    let (code, _) = get::<RewardResponse>(&server, "/v1/rewards/nonsense");
    assert_eq!(code, 400);
}

#[test]
fn idle_chain_makes_no_blocks_until_there_is_work() {
    let cluster = Cluster::start(4);
    std::thread::sleep(Duration::from_millis(1_500));
    assert_eq!(
        cluster.heights(),
        vec![0; 4],
        "no empty blocks on a fresh idle chain"
    );

    let bob = addr(&key(2));
    cluster.nodes[2]
        .submit(tx_on(&genesis(4), &alice(), 0, true, pay(bob, 3)), now_ms())
        .unwrap();
    wait_for("transfer", 15_000, || {
        cluster.nodes.iter().all(|n| balance(n, &bob) == 3)
    });

    wait_for("settling", 15_000, || {
        let h = cluster.heights();
        std::thread::sleep(Duration::from_millis(300));
        h == cluster.heights()
    });
    let settled = cluster.heights();
    std::thread::sleep(Duration::from_millis(1_500));
    assert_eq!(
        cluster.heights(),
        settled,
        "blocks were produced while idle"
    );
    assert!(
        settled[0] <= 6,
        "a single transfer took {} blocks",
        settled[0]
    );
    cluster.assert_agree(&[0, 1, 2, 3]);
}

#[derive(Default)]
struct Recorder(std::sync::Mutex<Vec<Vec<u8>>>);

impl qubits_node::network::Transport for Recorder {
    fn send(&self, _: &qubits_crypto::PublicKey, bytes: Vec<u8>) {
        self.0.lock().unwrap().push(bytes);
    }
    fn broadcast(&self, bytes: Vec<u8>) {
        self.0.lock().unwrap().push(bytes);
    }
}

#[test]
fn waiting_transactions_are_gossiped_again_then_expire() {
    let dir = tempfile::tempdir().unwrap();
    Node::init(dir.path(), &genesis(4)).unwrap();
    let node = Arc::new(Node::open(dir.path()).unwrap());
    let recorder = Arc::new(Recorder::default());
    let timing = Timing {
        regossip_ms: 200,
        tx_ttl_ms: 1_500,
        ..TIMING
    };
    let validator =
        Validator::start(node.clone(), validator_key(0), recorder.clone(), timing).unwrap();
    let (_keep, inbox) = std::sync::mpsc::channel();
    let _handle = validator.spawn(inbox);

    let stx = tx_on(&genesis(4), &alice(), 0, true, pay(addr(&key(2)), 1));
    node.accept(stx.clone(), now_ms()).unwrap();
    let gossiped = |r: &Recorder| {
        r.0.lock().unwrap().iter().any(|bytes| {
            matches!(qubits_node::network::NetMessage::decode(bytes), Some(qubits_node::network::NetMessage::Transaction(t)) if t == stx)
        })
    };
    wait_for("re-gossip", 5_000, || gossiped(&recorder));
    assert_eq!(node.mempool_len(), 1);
    wait_for("expiry", 5_000, || node.mempool_len() == 0);
}

#[test]
fn pruning_node_keeps_recent_state_and_all_blocks() {
    let (_dir, node, _handle, _open) = single_validator();
    node.set_keep_versions(2);
    let bob = addr(&key(2));
    for nonce in 0..6 {
        node.submit(tx(&alice(), nonce, nonce == 0, pay(bob, 1)), now_ms())
            .unwrap();
        wait_for("transfer", 10_000, || {
            balance(&node, &bob) == u128::from(nonce) + 1
        });
    }
    let head = node.head().unwrap();
    let pruned = node.store().pruned_before().unwrap();
    assert!(
        pruned > 0 && pruned + 2 >= head.height,
        "pruned before {pruned} at height {}",
        head.height
    );
    assert!(node.store().state_root(1).is_err(), "old state is gone");
    assert_eq!(
        node.store().state_root(head.height).unwrap(),
        head.state_root
    );
    for h in 1..=head.height {
        assert!(node.block(h).unwrap().is_some(), "block {h} is kept");
    }
}

#[test]
fn the_whole_network_can_restart_at_once() {
    let n = 4;
    let g = genesis(n);
    let keys: Vec<_> = (0..n)
        .map(|i| validator_key(i).public_key().clone())
        .collect();
    let dirs: Vec<_> = (0..n).map(|_| tempfile::tempdir().unwrap()).collect();
    let start = |dirs: &[tempfile::TempDir]| {
        let (hub, inboxes) = LocalHub::new(&keys);
        let mut nodes = Vec::new();
        let mut handles = Vec::new();
        for (i, inbox) in inboxes.into_iter().enumerate() {
            let node = Arc::new(Node::open(dirs[i].path()).unwrap());
            let transport = Arc::new(hub.transport(&keys[i]));
            let validator =
                Validator::start(node.clone(), validator_key(i), transport, TIMING).unwrap();
            handles.push(validator.spawn(inbox));
            nodes.push(node);
        }
        (nodes, handles)
    };
    for dir in &dirs {
        Node::init(dir.path(), &g).unwrap();
    }
    let bob = addr(&key(2));
    let (nodes, handles) = start(&dirs);
    for nonce in 0..3u64 {
        let stx = tx_on(&g, &alice(), nonce, nonce == 0, pay(bob, 1));
        nodes[0].submit(stx, now_ms()).unwrap();
        wait_for("transfer", 20_000, || {
            balance(&nodes[0], &bob) == u128::from(nonce) + 1
        });
    }
    for handle in handles {
        handle.stop();
    }
    drop(nodes);

    let (nodes, _handles) = start(&dirs);
    wait_for("everyone catching up after the restart", 30_000, || {
        nodes.iter().all(|node| balance(node, &bob) == 3)
    });
    let stx = tx_on(&g, &alice(), 3, false, pay(bob, 1));
    nodes[1].submit(stx, now_ms()).unwrap();
    wait_for("progress after the restart", 30_000, || {
        nodes.iter().all(|node| balance(node, &bob) == 4)
    });
    let height = nodes
        .iter()
        .map(|n| n.head().unwrap().height)
        .min()
        .unwrap();
    let first = nodes[0].block(height).unwrap().unwrap();
    for node in &nodes[1..] {
        assert_eq!(node.block(height).unwrap().unwrap(), first);
    }
}

type Socket = tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>;

fn ws_connect(server: &Server) -> Result<Socket, tungstenite::Error> {
    let url = format!("{}/v1/ws", server.base.replace("http://", "ws://"));
    let (socket, _) = tungstenite::connect(url)?;
    if let tungstenite::stream::MaybeTlsStream::Plain(stream) = socket.get_ref() {
        stream
            .set_read_timeout(Some(Duration::from_secs(40)))
            .unwrap();
    }
    Ok(socket)
}

fn ws_send(socket: &mut Socket, request: &WsRequest) {
    let text = serde_json::to_string(request).unwrap();
    socket.send(tungstenite::Message::text(text)).unwrap();
}

fn ws_read(socket: &mut Socket) -> WsEvent {
    loop {
        match socket.read().unwrap() {
            tungstenite::Message::Text(text) => return serde_json::from_str(&text).unwrap(),
            tungstenite::Message::Ping(_) | tungstenite::Message::Pong(_) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
}

/// Requests are handled in order, so the answer to a bad one means the earlier ones were.
fn ws_settle(socket: &mut Socket) {
    socket
        .send(tungstenite::Message::text("not a request"))
        .unwrap();
    assert!(matches!(ws_read(socket), WsEvent::Error { .. }));
}

fn named(socket: &mut Socket) -> (Address, Hash, TransactionResponse) {
    match ws_read(socket) {
        WsEvent::AddressTransaction {
            address,
            transaction,
        } => (address, transaction.id, *transaction),
        other => panic!("expected a transaction naming the address: {other:?}"),
    }
}

#[test]
fn websocket_tells_a_watched_address_of_its_transactions() {
    let server = start_server();
    let mut socket = ws_connect(&server).unwrap();
    let (bob_key, carol) = (key(2), addr(&key(3)));
    let bob = addr(&bob_key);
    ws_send(&mut socket, &WsRequest::WatchAddress { address: bob });
    ws_settle(&mut socket);

    let paid = tx(&alice(), 0, true, pay(bob, 1_000_000));
    assert_eq!(post_tx(&server, &paid).0, 202);
    let (address, id, pushed) = named(&mut socket);
    assert_eq!((address, id), (bob, paid.id()));
    let path = format!("/v1/transactions/{}", paid.id());
    assert_eq!(
        pushed,
        get::<TransactionResponse>(&server, &path).1.unwrap()
    );

    // a transaction that doesn't name bob says nothing, so the next event is the one he sends
    let other = tx(&alice(), 1, false, pay(carol, 5));
    assert_eq!(post_tx(&server, &other).0, 202);
    included(&server, &other);
    let sent = tx(&bob_key, 0, true, pay(carol, 7));
    assert_eq!(post_tx(&server, &sent).0, 202);
    assert_eq!(named(&mut socket).1, sent.id());

    // unwatched, bob hears nothing more: the next event is carol's, from a later block
    ws_send(&mut socket, &WsRequest::UnwatchAddress { address: bob });
    ws_send(&mut socket, &WsRequest::WatchAddress { address: carol });
    ws_settle(&mut socket);
    let to_bob = tx(&alice(), 2, false, pay(bob, 1));
    assert_eq!(post_tx(&server, &to_bob).0, 202);
    included(&server, &to_bob);
    let to_carol = tx(&alice(), 3, false, pay(carol, 1));
    assert_eq!(post_tx(&server, &to_carol).0, 202);
    let (address, id, _) = named(&mut socket);
    assert_eq!((address, id), (carol, to_carol.id()));

    for i in 0..15u8 {
        ws_send(
            &mut socket,
            &WsRequest::WatchAddress {
                address: Address([i; 32]),
            },
        );
    }
    ws_send(
        &mut socket,
        &WsRequest::WatchAddress {
            address: Address([200; 32]),
        },
    );
    match ws_read(&mut socket) {
        WsEvent::Error { error } => assert_eq!(error, "watching too many addresses"),
        other => panic!("expected the limit: {other:?}"),
    }
}

#[test]
fn websocket_pushes_blocks_and_what_became_of_a_transaction() {
    let server = start_server();
    let mut socket = ws_connect(&server).unwrap();
    let stx = tx(&alice(), 0, true, pay(addr(&key(2)), 1234));
    ws_send(&mut socket, &WsRequest::SubscribeBlocks);
    ws_send(&mut socket, &WsRequest::WatchTransaction { id: stx.id() });
    ws_settle(&mut socket);

    let (code, body) = post_tx(&server, &stx);
    assert_eq!(code, 202, "{body}");
    let block = loop {
        match ws_read(&mut socket) {
            WsEvent::Block(block) if !block.transaction_ids.is_empty() => break block,
            WsEvent::Block(_) => {}
            other => panic!("the block comes first: {other:?}"),
        }
    };
    assert_eq!(block.transaction_ids, vec![stx.id()]);
    let WsEvent::Transaction(pushed) = ws_read(&mut socket) else {
        panic!("expected the transaction");
    };

    let path = format!("/v1/transactions/{}", stx.id());
    let (_, asked) = get::<TransactionResponse>(&server, &path);
    assert_eq!(*pushed, asked.unwrap());
    assert_eq!(pushed.status, TxStatus::Included);

    let (_, full) = get::<BlockResponse>(&server, &format!("/v1/blocks/{}", block.height));
    let full = full.unwrap();
    assert_eq!(full.hash, block.hash);
    assert_eq!(full.state_root, block.state_root);
    assert_eq!(full.transaction_ids, block.transaction_ids);

    let mut late = ws_connect(&server).unwrap();
    ws_send(&mut late, &WsRequest::WatchTransaction { id: stx.id() });
    let WsEvent::Transaction(pushed) = ws_read(&mut late) else {
        panic!("expected the transaction");
    };
    assert_eq!(pushed.block_height, Some(block.height));
    ws_settle(&mut late);

    let next = tx(&alice(), 1, false, pay(addr(&key(2)), 1));
    let other = tx(&alice(), 2, false, pay(addr(&key(2)), 1));
    ws_send(&mut late, &WsRequest::WatchTransaction { id: next.id() });
    ws_send(&mut late, &WsRequest::UnwatchTransaction { id: next.id() });
    ws_send(&mut late, &WsRequest::WatchTransaction { id: other.id() });
    ws_send(&mut socket, &WsRequest::UnsubscribeBlocks);
    ws_settle(&mut late);
    ws_settle(&mut socket);
    assert_eq!(post_tx(&server, &next).0, 202);
    assert_eq!(post_tx(&server, &other).0, 202);
    let WsEvent::Transaction(pushed) = ws_read(&mut late) else {
        panic!("expected the transaction");
    };
    assert_eq!(pushed.id, other.id());
    wait_for("both transfers", 10_000, || {
        block.height < server.node.head().unwrap().height
            && balance(&server.node, &addr(&key(2))) == 1236
    });
    ws_settle(&mut socket);
}

#[test]
fn websocket_requests_and_connections_are_limited() {
    let server = start_server();
    let mut socket = ws_connect(&server).unwrap();

    socket
        .send(tungstenite::Message::binary(vec![1, 2, 3]))
        .unwrap();
    assert!(matches!(ws_read(&mut socket), WsEvent::Error { .. }));

    for seed in 0..qubits_node::ws::MAX_WATCHED as u8 {
        let id = Hash([seed; 32]);
        ws_send(&mut socket, &WsRequest::WatchTransaction { id });
    }
    ws_settle(&mut socket);
    let id = Hash([255; 32]);
    ws_send(&mut socket, &WsRequest::WatchTransaction { id });
    assert!(matches!(ws_read(&mut socket), WsEvent::Error { .. }));

    socket
        .send(tungstenite::Message::text("x".repeat(2048)))
        .unwrap();
    assert!(
        loop {
            match socket.read() {
                Ok(tungstenite::Message::Close(_)) | Err(_) => break true,
                Ok(tungstenite::Message::Ping(_)) => {}
                Ok(other) => panic!("unexpected {other:?}"),
            }
        },
        "the connection ends"
    );
    drop(socket);
    wait_for("the slot to free", 5_000, || {
        server.node.ws_connections() == 0
    });

    server.node.set_ws_limit(1);
    let mut first = ws_connect(&server).unwrap();
    match ws_connect(&server) {
        Err(tungstenite::Error::Http(response)) => assert_eq!(response.status().as_u16(), 503),
        other => panic!("expected 503, got {:?}", other.map(|_| ())),
    }
    let metrics = agent()
        .get(format!("{}/metrics", server.base))
        .call()
        .unwrap()
        .body_mut()
        .read_to_string()
        .unwrap();
    assert!(metrics.contains("qubits_ws_connections 1\n"), "{metrics}");
    first.close(None).unwrap();
    let ended = loop {
        if let Err(e) = first.read() {
            break e;
        }
    };
    assert!(
        matches!(ended, tungstenite::Error::ConnectionClosed),
        "a clean close: {ended:?}"
    );
    wait_for("the slot to free", 5_000, || {
        server.node.ws_connections() == 0
    });
    assert!(ws_connect(&server).is_ok());

    let response = agent()
        .get(format!("{}/v1/ws", server.base))
        .call()
        .unwrap();
    assert_eq!(response.status().as_u16(), 400);
}

/// Takes over 30 s: `cargo test -p qubits-node --test node -- --ignored websocket`
#[test]
#[ignore]
fn websocket_outlives_the_request_timeout_and_is_pinged() {
    let server = start_server();
    let mut socket = ws_connect(&server).unwrap();
    let started = Instant::now();
    assert!(matches!(
        socket.read().unwrap(),
        tungstenite::Message::Ping(_)
    ));
    assert!(started.elapsed() >= Duration::from_secs(29));
    std::thread::sleep(qubits_node::rpc::REQUEST_TIMEOUT.saturating_sub(started.elapsed()));

    let stx = tx(&alice(), 0, true, pay(addr(&key(2)), 1));
    ws_send(&mut socket, &WsRequest::WatchTransaction { id: stx.id() });
    ws_settle(&mut socket);
    assert_eq!(post_tx(&server, &stx).0, 202);
    assert!(matches!(ws_read(&mut socket), WsEvent::Transaction(_)));
}
