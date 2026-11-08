use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, Instant};

use qubits_consensus::ValidatorSet;
use qubits_crypto::{SchemeId, SecretKey};
use qubits_execution::{keys, min_fee, read_account};
use qubits_node::era;
use qubits_node::history::{HISTORY_MARGIN, prune_once};
use qubits_node::network::LocalHub;
use qubits_node::sync::{EpochProof, EpochView, Follower, checked_pivot, committed_prefix};
use qubits_node::{
    ChainBlock, FinalityProof, Node, PROOF_EVERY, Timing, Validator, ValidatorHandle, now_ms,
};
use qubits_state::{StateProof, Store};
use qubits_types::rpc::{
    AccountProofResponse, EpochSummary, EpochsResponse, ErasResponse, RawBlockResponse,
    SnapshotResponse, StatusResponse, WsEvent, WsRequest,
};
use qubits_types::*;

const CHAIN: &str = "qubits-sync-test";

fn key(seed: u8) -> SecretKey {
    SecretKey::from_seed(SchemeId::MlDsa65, &[seed; 32]).unwrap()
}

fn addr(sk: &SecretKey) -> Address {
    AuthPolicy::single(sk.public_key().clone()).address()
}

fn genesis() -> Genesis {
    Genesis {
        chain_id: CHAIN.into(),
        timestamp_ms: 1_700_000_000_000,
        params: ChainParams {
            min_fee_per_byte: 1,
            max_block_transactions: 100,
        },
        validators: (0..4)
            .map(|i| qubits_types::Validator::self_paid(key(120 + i).public_key().clone()))
            .collect(),
        accounts: vec![GenesisAccount {
            address: addr(&key(1)),
            balance: 10_000_000,
        }],
    }
}

fn transfer(nonce: u64, to: Address, amount: Amount) -> SignedTransaction {
    let sk = key(1);
    let policy = AuthPolicy::single(sk.public_key().clone());
    let reveal = (nonce == 0).then(|| policy.clone());
    let mut tx = Transaction {
        genesis_hash: genesis().hash(),
        sender: policy.address(),
        nonce,
        fee: 0,
        valid_until_ms: u64::MAX,
        role: Role::Owner,
        payload: Payload::Transfer {
            to,
            asset: AssetId::NATIVE,
            amount,
        },
    };
    let draft = SignedTransaction::sign(tx.clone(), &policy, reveal.clone(), &[&sk]).unwrap();
    tx.fee = min_fee(&genesis().params, draft.encode().len());
    SignedTransaction::sign(tx, &policy, reveal, &[&sk]).unwrap()
}

fn balance(node: &Node, who: &Address) -> Amount {
    read_account(node.store(), who)
        .unwrap()
        .map_or(0, |a| a.balance(AssetId::NATIVE))
}

fn wait_for(what: &str, timeout_ms: u64, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

struct Cluster {
    nodes: Vec<Arc<Node>>,
    url: String,
    _handles: Vec<ValidatorHandle>,
    _dirs: Vec<tempfile::TempDir>,
}

impl Cluster {
    fn start(g: &Genesis) -> Cluster {
        let keys: Vec<_> = (0..4).map(|i| key(120 + i).public_key().clone()).collect();
        let (hub, inboxes) = LocalHub::new(&keys);
        let timing = Timing {
            round_timeout_ms: 1_000,
            min_block_interval_ms: 50,
            ..Timing::DEFAULT
        };
        let (mut nodes, mut handles, mut dirs) = (Vec::new(), Vec::new(), Vec::new());
        for (i, inbox) in inboxes.into_iter().enumerate() {
            let dir = tempfile::tempdir().unwrap();
            Node::init(dir.path(), g).unwrap();
            let node = Arc::new(Node::open(dir.path()).unwrap());
            let validator = Validator::start(
                node.clone(),
                key(120 + i as u8),
                Arc::new(hub.transport(&keys[i])),
                timing,
            )
            .unwrap();
            handles.push(validator.spawn(inbox));
            nodes.push(node);
            dirs.push(dir);
        }
        let url = serve(nodes[0].clone());
        Cluster {
            nodes,
            url,
            _handles: handles,
            _dirs: dirs,
        }
    }
}

fn serve(node: Arc<Node>) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                qubits_node::serve(node, listener).await.unwrap();
            });
    });
    url
}

fn api_node(g: &Genesis) -> (tempfile::TempDir, Arc<Node>) {
    let dir = tempfile::tempdir().unwrap();
    Node::init(dir.path(), g).unwrap();
    let node = Arc::new(Node::open(dir.path()).unwrap());
    (dir, node)
}

fn get<T: serde::de::DeserializeOwned>(url: &str) -> T {
    let body = ureq::get(url)
        .call()
        .unwrap()
        .body_mut()
        .read_to_string()
        .unwrap();
    serde_json::from_str(&body).unwrap()
}

#[test]
fn api_node_replays_the_chain_to_identical_state() {
    let g = genesis();
    let cluster = Cluster::start(&g);
    let bob = addr(&key(2));
    for nonce in 0..3 {
        cluster.nodes[1]
            .submit(transfer(nonce, bob, 50), now_ms())
            .unwrap();
        let expected = 50 * (u128::from(nonce) + 1);
        wait_for("transfer", 15_000, || {
            cluster.nodes.iter().all(|n| balance(n, &bob) == expected)
        });
    }
    let tip = cluster.nodes[0].head().unwrap().height;

    let (_dir, api) = api_node(&g);
    let mut follower = Follower::new(api.clone(), vec![cluster.url.clone()]).unwrap();
    follower.catch_up(0, Duration::from_secs(30)).unwrap();

    assert_eq!(api.head().unwrap().height, tip);
    for h in 1..=tip {
        assert_eq!(
            api.store().block(h).unwrap(),
            cluster.nodes[0].store().block(h).unwrap()
        );
        assert_eq!(
            api.store().state_root(h).unwrap(),
            cluster.nodes[0].store().state_root(h).unwrap()
        );
    }
    assert_eq!(balance(&api, &bob), 150);
    assert_eq!(follower.step().unwrap(), 0, "nothing new");
}

#[test]
fn api_node_forwards_transactions_and_sees_them_committed() {
    let g = genesis();
    let cluster = Cluster::start(&g);
    let (_dir, api) = api_node(&g);
    api.forward_to(vec![cluster.url.clone()]);
    let _follower = Follower::new(api.clone(), vec![cluster.url.clone()])
        .unwrap()
        .spawn(Duration::from_millis(100));

    let bob = addr(&key(2));
    api.submit(transfer(0, bob, 9), now_ms()).unwrap();
    wait_for("forwarded transfer on the validators", 15_000, || {
        balance(&cluster.nodes[3], &bob) == 9
    });
    wait_for("transfer on the API node", 15_000, || {
        balance(&api, &bob) == 9
    });
    assert_eq!(
        api.mempool_len(),
        0,
        "included transaction left the API node's mempool"
    );
}

#[test]
fn an_api_node_pushes_the_blocks_it_follows() {
    let g = genesis();
    let cluster = Cluster::start(&g);
    let (_dir, api) = api_node(&g);
    let url = serve(api.clone()).replace("http://", "ws://");
    let (mut socket, _) = tungstenite::connect(format!("{url}/v1/ws")).unwrap();
    let request = serde_json::to_string(&WsRequest::SubscribeBlocks).unwrap();
    socket.send(tungstenite::Message::text(request)).unwrap();
    socket
        .send(tungstenite::Message::text(
            "settle: the answer proves it was read",
        ))
        .unwrap();
    let answer = socket.read().unwrap().into_text().unwrap();
    assert!(answer.contains("\"error\""), "{answer}");

    let bob = addr(&key(2));
    cluster.nodes[0]
        .submit(transfer(0, bob, 5), now_ms())
        .unwrap();
    let _follower = Follower::new(api.clone(), vec![cluster.url.clone()])
        .unwrap()
        .spawn(Duration::from_millis(100));
    wait_for("the block on the API node", 15_000, || {
        balance(&api, &bob) == 5
    });
    let text = socket.read().unwrap().into_text().unwrap();
    let WsEvent::Block(block) = serde_json::from_str(&text).unwrap() else {
        panic!("expected a block: {text}");
    };
    assert_eq!(block.hash, api.block(block.height).unwrap().unwrap().id());
}

#[test]
fn tampered_or_unproven_blocks_are_not_applied() {
    let g = genesis();
    let cluster = Cluster::start(&g);
    let bob = addr(&key(2));
    for nonce in 0..2 {
        cluster.nodes[0]
            .submit(transfer(nonce, bob, 1), now_ms())
            .unwrap();
        wait_for("transfer", 15_000, || {
            cluster
                .nodes
                .iter()
                .all(|n| balance(n, &bob) == u128::from(nonce) + 1)
        });
    }
    let source = &cluster.nodes[0];
    let tip = source.head().unwrap().height;
    let blocks: Vec<ChainBlock> = (1..=tip)
        .map(|h| source.block(h).unwrap().unwrap())
        .collect();
    let validators = ValidatorSet::new(validator_keys(&g.validators)).unwrap();
    let chain = source.genesis_hash();
    let raw: RawBlockResponse = get(&format!("{}/v1/blocks/{tip}/raw?prove=true", cluster.url));
    let finality: FinalityProof =
        borsh::from_slice(&hex::decode(raw.finality.expect("tip has a finality proof")).unwrap())
            .unwrap();
    let view = EpochView {
        validators: validators.clone(),
        chain,
    };
    let check = |blocks: &[ChainBlock], finality: Option<&FinalityProof>| {
        let mut proofs = vec![None; blocks.len()];
        if let Some(last) = proofs.last_mut() {
            *last = finality.cloned();
        }
        committed_prefix(&chain, 0, blocks, &mut proofs, &view)
    };

    assert_eq!(check(&blocks, Some(&finality)), Ok(blocks.len()));
    assert_eq!(
        check(&blocks, None),
        Ok(0),
        "nothing is final without a proof"
    );

    let mut edited = blocks.clone();
    edited[0].payload.timestamp_ms += 1;
    assert!(check(&edited, Some(&finality)).is_err());

    let mut gap = blocks.clone();
    gap.remove(1);
    assert!(check(&gap, Some(&finality)).is_err());

    let others =
        ValidatorSet::new((0..4).map(|i| key(150 + i).public_key().clone()).collect()).unwrap();
    let foreign = EpochView {
        validators: others,
        chain,
    };
    let mut proofs = vec![None; blocks.len()];
    *proofs.last_mut().unwrap() = Some(finality.clone());
    assert_eq!(
        committed_prefix(&chain, 0, &blocks, &mut proofs, &foreign),
        Ok(0),
        "another validator set proves nothing"
    );
    assert!(proofs.iter().all(Option::is_none), "and it isn't kept");

    let mut wrong_round = finality.clone();
    wrong_round.path.last_mut().unwrap().round += 1;
    assert_eq!(check(&blocks, Some(&wrong_round)), Ok(0));
    let mut wrong_tip = finality.clone();
    wrong_tip.tip = Hash([5; 32]);
    assert_eq!(check(&blocks, Some(&wrong_tip)), Ok(0));

    let mut other = genesis();
    other.chain_id = "another-chain".into();
    let (_dir, stranger) = api_node(&other);
    let err = Follower::new(stranger, vec![cluster.url.clone()])
        .unwrap()
        .step()
        .unwrap_err();
    assert!(err.to_string().contains("different chain"), "{err}");
}

#[test]
fn account_proofs_verify_against_certified_state_roots() {
    let g = genesis();
    let cluster = Cluster::start(&g);
    let bob = addr(&key(2));
    cluster.nodes[0]
        .submit(transfer(0, bob, 77), now_ms())
        .unwrap();
    wait_for("transfer", 15_000, || {
        cluster.nodes.iter().all(|n| balance(n, &bob) == 77)
    });
    let validators = ValidatorSet::new(validator_keys(&g.validators)).unwrap();
    let chain = cluster.nodes[0].genesis_hash();

    let proof: AccountProofResponse = get(&format!("{}/v1/proofs/accounts/{bob}", cluster.url));
    let raw: RawBlockResponse = get(&format!(
        "{}/v1/blocks/{}/raw?prove=true",
        cluster.url, proof.height
    ));
    let block: ChainBlock = borsh::from_slice(&hex::decode(raw.block).unwrap()).unwrap();
    let finality: FinalityProof =
        borsh::from_slice(&hex::decode(raw.finality.unwrap()).unwrap()).unwrap();
    assert_eq!(block.id(), proof.block_hash);
    assert!(finality.verify(block.round, &validators, &chain));
    assert_eq!(block.payload.state_root, proof.state_root);
    let account_bytes = hex::decode(proof.account.unwrap()).unwrap();
    let account: Account = borsh::from_slice(&account_bytes).unwrap();
    assert_eq!(account.balance(AssetId::NATIVE), 77);
    let merkle: StateProof = borsh::from_slice(&hex::decode(&proof.proof).unwrap()).unwrap();
    Store::verify_proof(
        proof.state_root,
        &keys::account(&bob),
        Some(&account_bytes),
        &merkle,
    )
    .unwrap();
    assert!(
        Store::verify_proof(
            proof.state_root,
            &keys::account(&bob),
            Some(b"forged"),
            &merkle
        )
        .is_err()
    );

    let nobody = addr(&key(99));
    let absent: AccountProofResponse = get(&format!("{}/v1/proofs/accounts/{nobody}", cluster.url));
    assert_eq!(absent.account, None);
    let merkle: StateProof = borsh::from_slice(&hex::decode(&absent.proof).unwrap()).unwrap();
    Store::verify_proof(absent.state_root, &keys::account(&nobody), None, &merkle).unwrap();
    let at_genesis: AccountProofResponse = get(&format!(
        "{}/v1/proofs/accounts/{bob}?height=0",
        cluster.url
    ));
    assert_eq!((at_genesis.height, at_genesis.account), (0, None));
    let future = ureq::get(&format!(
        "{}/v1/proofs/accounts/{bob}?height=999999",
        cluster.url
    ))
    .config()
    .http_status_as_error(false)
    .build()
    .call()
    .unwrap();
    assert_eq!(future.status().as_u16(), 404);
}

#[test]
fn a_validator_cut_off_from_consensus_syncs_over_http() {
    let g = genesis();
    let keys: Vec<_> = (0..4).map(|i| key(120 + i).public_key().clone()).collect();
    let (hub, inboxes) = LocalHub::new(&keys);
    let timing = Timing {
        round_timeout_ms: 1_000,
        min_block_interval_ms: 5,
        ..Timing::DEFAULT
    };
    let mut nodes = Vec::new();
    let mut validators = Vec::new();
    let mut dirs = Vec::new();
    for (i, public) in keys.iter().enumerate() {
        let dir = tempfile::tempdir().unwrap();
        Node::init(dir.path(), &g).unwrap();
        let node = Arc::new(Node::open(dir.path()).unwrap());
        let transport = Arc::new(hub.transport(public));
        validators
            .push(Validator::start(node.clone(), key(120 + i as u8), transport, timing).unwrap());
        nodes.push(node);
        dirs.push(dir);
    }
    let url = serve(nodes[0].clone());
    let behind_url = serve(nodes[3].clone());
    validators[3].follow(Follower::new(nodes[3].clone(), vec![url]).unwrap());
    let _handles: Vec<ValidatorHandle> = validators
        .into_iter()
        .zip(inboxes)
        .map(|(validator, inbox)| validator.spawn(inbox))
        .collect();

    hub.set_down(&keys[3], true);
    let bob = addr(&key(2));
    let mut nonce = 0;
    while nodes[0].head().unwrap().height < 150 {
        nodes[0].submit(transfer(nonce, bob, 1), now_ms()).unwrap();
        nonce += 1;
        wait_for("transfer", 15_000, || {
            balance(&nodes[0], &bob) == u128::from(nonce)
                && balance(&nodes[1], &bob) == u128::from(nonce)
        });
    }
    wait_for("the sync", 30_000, || nodes[3].head().unwrap().height > 100);
    // the counter moves once the sync pass returns, which is after the blocks land
    wait_for("the sync counter", 30_000, || {
        let metrics: String = ureq::get(format!("{behind_url}/metrics"))
            .call()
            .unwrap()
            .body_mut()
            .read_to_string()
            .unwrap();
        !metrics.contains("qubits_syncs_total 0")
    });

    hub.set_down(&keys[3], false);
    wait_for("it to rejoin", 30_000, || {
        balance(&nodes[3], &bob) == u128::from(nonce)
    });
    nodes[3].submit(transfer(nonce, bob, 1), now_ms()).unwrap();
    wait_for("a transfer through it", 15_000, || {
        nodes
            .iter()
            .all(|n| balance(n, &bob) == u128::from(nonce) + 1)
    });
}

/// Keeps the chain growing until a proof past genesis is kept.
fn grow(cluster: &Cluster, bob: &Address, nonce: &mut u64, height: u64) {
    while cluster.nodes[0].head().unwrap().height < height {
        cluster.nodes[(*nonce % 4) as usize]
            .submit(transfer(*nonce, *bob, 1), now_ms())
            .unwrap();
        *nonce += 1;
        let want = u128::from(*nonce);
        wait_for("transfer", 15_000, || {
            balance(&cluster.nodes[0], bob) == want
        });
    }
}

#[test]
fn a_new_node_joins_from_a_snapshot() {
    let g = genesis();
    let cluster = Cluster::start(&g);
    let bob = addr(&key(2));
    let mut nonce = 0;
    grow(&cluster, &bob, &mut nonce, PROOF_EVERY + 5);
    let tip = cluster.nodes[0].head().unwrap().height;

    let (_dir, joined) = api_node(&g);
    let mut follower = Follower::new(joined.clone(), vec![cluster.url.clone()])
        .unwrap()
        .snapshot_if_behind(10);
    follower.catch_up(0, Duration::from_secs(60)).unwrap();

    let head = joined.head().unwrap();
    assert!(head.height >= tip);
    assert_eq!(
        joined.block(head.height).unwrap(),
        cluster.nodes[0].block(head.height).unwrap()
    );
    let pivot = joined.store().pruned_before().unwrap();
    assert_eq!(joined.store().blocks_from().unwrap(), pivot);
    assert!(
        pivot >= PROOF_EVERY && pivot.is_multiple_of(PROOF_EVERY),
        "{pivot}"
    );
    assert!(
        joined.block(1).unwrap().is_none(),
        "no history below the snapshot"
    );
    assert!(joined.block(pivot).unwrap().is_some());
    assert_eq!(balance(&joined, &bob), u128::from(nonce));
    assert_eq!(joined.epochs().unwrap().len(), 1);

    let url = serve(joined.clone());
    let metrics = ureq::get(format!("{url}/metrics"))
        .call()
        .unwrap()
        .body_mut()
        .read_to_string()
        .unwrap();
    assert!(
        metrics.contains("qubits_snapshot_syncs_total 1"),
        "{metrics}"
    );
    assert!(matches!(
        ureq::get(format!("{url}/v1/blocks/1")).call(),
        Err(ureq::Error::StatusCode(404))
    ));

    cluster.nodes[1]
        .submit(transfer(nonce, bob, 1), now_ms())
        .unwrap();
    nonce += 1;
    wait_for("the next transfer", 15_000, || {
        let _ = follower.step();
        balance(&joined, &bob) == u128::from(nonce)
    });

    let proof: AccountProofResponse = get(&format!("{url}/v1/proofs/accounts/{bob}"));
    let account_bytes = hex::decode(proof.account.unwrap()).unwrap();
    let merkle: StateProof = borsh::from_slice(&hex::decode(&proof.proof).unwrap()).unwrap();
    Store::verify_proof(
        proof.state_root,
        &keys::account(&bob),
        Some(&account_bytes),
        &merkle,
    )
    .unwrap();
    assert_eq!(
        proof.state_root,
        cluster.nodes[0].store().state_root(proof.height).unwrap()
    );
}

#[test]
fn snapshot_pivots_from_a_lying_source_are_refused() {
    let g = genesis();
    let cluster = Cluster::start(&g);
    let bob = addr(&key(2));
    let mut nonce = 0;
    grow(&cluster, &bob, &mut nonce, PROOF_EVERY + 2);

    let snap: SnapshotResponse = get(&format!("{}/v1/state/snapshot", cluster.url));
    let epochs: EpochsResponse = get(&format!("{}/v1/epochs", cluster.url));
    assert_eq!(epochs.epochs.len(), 1);
    assert_eq!(snap.height, PROOF_EVERY);
    let block: ChainBlock = borsh::from_slice(&hex::decode(&snap.block).unwrap()).unwrap();
    let proof: FinalityProof = borsh::from_slice(&hex::decode(&snap.finality).unwrap()).unwrap();
    let (current, later) = checked_pivot(&g, &[], &block, &proof).unwrap();
    assert_eq!((current.epoch, later.len()), (0, 0));

    let mut edited = block.clone();
    edited.payload.timestamp_ms += 1;
    assert!(
        checked_pivot(&g, &[], &edited, &proof).is_err(),
        "edited block"
    );

    let raw: RawBlockResponse = get(&format!(
        "{}/v1/blocks/{}/raw?prove=true",
        cluster.url,
        snap.height - 1
    ));
    let other: FinalityProof =
        borsh::from_slice(&hex::decode(raw.finality.unwrap()).unwrap()).unwrap();
    assert!(
        checked_pivot(&g, &[], &block, &other).is_err(),
        "another block's proof"
    );

    let mut foreign = g.clone();
    foreign.validators = (0..4)
        .map(|i| qubits_types::Validator::self_paid(key(150 + i).public_key().clone()))
        .collect();
    assert!(
        checked_pivot(&foreign, &[], &block, &proof).is_err(),
        "other validators"
    );

    let invented = EpochProof {
        summary: EpochSummary {
            epoch: 1,
            start: block.id(),
            start_height: block.height,
        },
        block: block.clone(),
        proof: proof.clone(),
    };
    assert!(
        checked_pivot(&g, &[invented], &block, &proof).is_err(),
        "an epoch that never was"
    );
}

#[test]
fn old_blocks_are_dropped_and_the_node_stays_useful() {
    let g = genesis();
    let cluster = Cluster::start(&g);
    let bob = addr(&key(2));
    let mut nonce = 0;
    grow(&cluster, &bob, &mut nonce, HISTORY_MARGIN + 80);

    let (_dir_a, a) = api_node(&g);
    let mut a_follower = Follower::new(a.clone(), vec![cluster.url.clone()]).unwrap();
    a_follower.catch_up(0, Duration::from_secs(60)).unwrap();
    let (_dir_b, b) = api_node(&g);
    let url_a = serve(a.clone());
    let mut b_follower = Follower::new(b.clone(), vec![url_a.clone()]).unwrap();
    assert!(b_follower.step().unwrap() > 0);
    let behind = b.head().unwrap().height;
    assert!(behind > 0 && behind < HISTORY_MARGIN);

    let early_tx = a.block(5).unwrap().unwrap().payload.transactions[0].id();
    let head = a.head().unwrap().height;
    let below = head - HISTORY_MARGIN;
    let deleted = prune_once(&a, 0, HISTORY_MARGIN, 10_000).unwrap();
    assert_eq!(deleted, below - 1, "everything older than the margin");
    assert_eq!(a.store().blocks_from().unwrap(), below);
    assert!(a.block(5).unwrap().is_none());
    assert!(a.block(below).unwrap().is_some());
    assert!(a.store().tx_location(&early_tx).unwrap().is_none());
    assert_eq!(a.head().unwrap().height, head, "the head is untouched");
    assert_eq!(balance(&a, &bob), u128::from(nonce));

    let body = match ureq::get(format!("{url_a}/v1/blocks/5")).call() {
        Err(ureq::Error::StatusCode(404)) => "404".to_string(),
        other => panic!("{other:?}"),
    };
    assert_eq!(body, "404");
    let status: StatusResponse = get(&format!("{url_a}/v1/status"));
    assert_eq!(status.blocks_from, below);

    let err = b_follower.step().unwrap_err().to_string();
    assert!(err.contains("re-initialize"), "{err}");

    let (_dir_c, c) = api_node(&g);
    let mut c_follower = Follower::new(c.clone(), vec![url_a.clone()])
        .unwrap()
        .snapshot_if_behind(10);
    c_follower.catch_up(0, Duration::from_secs(60)).unwrap();
    assert!(c.store().blocks_from().unwrap() >= below);
    assert_eq!(balance(&c, &bob), u128::from(nonce));

    cluster.nodes[2]
        .submit(transfer(nonce, bob, 1), now_ms())
        .unwrap();
    nonce += 1;
    wait_for("the next transfer", 15_000, || {
        let _ = a_follower.step();
        balance(&a, &bob) == u128::from(nonce)
    });
    let proof: AccountProofResponse = get(&format!("{url_a}/v1/proofs/accounts/{bob}"));
    assert!(proof.height > head);
}

#[test]
fn era_files_carry_history_between_nodes() {
    const ERA: u64 = 64;
    let g = genesis();
    let cluster = Cluster::start(&g);
    let bob = addr(&key(2));
    let mut nonce = 0;
    grow(&cluster, &bob, &mut nonce, 3 * ERA + 10);

    let (_dir_a, a) = api_node(&g);
    a.set_era_length(ERA).unwrap();
    let mut a_follower = Follower::new(a.clone(), vec![cluster.url.clone()]).unwrap();
    a_follower.catch_up(0, Duration::from_secs(60)).unwrap();
    assert_eq!(a.eras().unwrap(), vec![0, 1, 2]);

    let mut files = Vec::new();
    let url_a = serve(a.clone());
    let offered: ErasResponse = get(&format!("{url_a}/v1/eras"));
    assert_eq!((offered.length, offered.eras.clone()), (ERA, vec![0, 1, 2]));
    for index in 0..3 {
        let (first, last) = era::range(index, ERA);
        let mut bytes = Vec::new();
        era::write(&a, first, last, &mut bytes).unwrap();
        let mut served = Vec::new();
        ureq::get(format!("{url_a}/v1/eras/{index}"))
            .call()
            .unwrap()
            .body_mut()
            .as_reader()
            .read_to_end(&mut served)
            .unwrap();
        assert_eq!(served, bytes, "era {index}");
        let summary = era::verify(&g, era::Reader::open(bytes.as_slice()).unwrap()).unwrap();
        assert_eq!((summary.first_height, summary.last_height), (first, last));
        assert_eq!(summary.blocks, ERA);
        files.push(bytes);
    }
    assert!(matches!(
        ureq::get(format!("{url_a}/v1/eras/3")).call(),
        Err(ureq::Error::StatusCode(404))
    ));

    for (index, at) in [(0, 400usize), (1, 9_000), (2, 60_000)] {
        let mut bad = files[index].clone();
        let at = at.min(bad.len() - 1);
        bad[at] ^= 1;
        let result = era::Reader::open(bad.as_slice()).and_then(|r| era::verify(&g, r));
        assert!(result.is_err(), "era {index} with byte {at} flipped");
    }
    let mut foreign = g.clone();
    foreign.validators = (0..4)
        .map(|i| qubits_types::Validator::self_paid(key(150 + i).public_key().clone()))
        .collect();
    assert!(era::verify(&foreign, era::Reader::open(files[0].as_slice()).unwrap()).is_err());

    let (_dir_b, b) = api_node(&g);
    for (index, file) in files.iter().enumerate() {
        let imported = era::import(&b, era::Reader::open(file.as_slice()).unwrap()).unwrap();
        assert!(
            matches!(imported, era::Imported::Appended(_)),
            "era {index}"
        );
    }
    assert_eq!(b.head().unwrap().height, 3 * ERA);
    assert_eq!(b.block(3 * ERA).unwrap(), a.block(3 * ERA).unwrap());
    assert_eq!(
        b.store().state_root(3 * ERA).unwrap(),
        a.store().state_root(3 * ERA).unwrap()
    );
    assert!(
        era::import(&b, era::Reader::open(files[1].as_slice()).unwrap()).is_err(),
        "again"
    );
    let mut b_follower = Follower::new(b.clone(), vec![cluster.url.clone()]).unwrap();
    b_follower.catch_up(0, Duration::from_secs(30)).unwrap();
    assert_eq!(balance(&b, &bob), u128::from(nonce));

    let (_dir_c, c) = api_node(&g);
    c.set_era_length(ERA).unwrap();
    let mut c_follower = Follower::new(c.clone(), vec![url_a.clone()])
        .unwrap()
        .snapshot_if_behind(10);
    c_follower.catch_up(0, Duration::from_secs(60)).unwrap();
    let pivot = c.store().blocks_from().unwrap();
    assert_eq!(pivot, 3 * ERA, "the newest multiple of 64");
    let early_tx = a.block(5).unwrap().unwrap().payload.transactions[0].id();
    assert!(c.store().tx_location(&early_tx).unwrap().is_none());
    assert!(
        era::import(&c, era::Reader::open(files[0].as_slice()).unwrap()).is_err(),
        "era 0 does not reach the blocks held"
    );
    for index in [2, 1, 0] {
        let imported =
            era::import(&c, era::Reader::open(files[index].as_slice()).unwrap()).unwrap();
        assert!(
            matches!(imported, era::Imported::Restored(_)),
            "era {index}"
        );
    }
    assert_eq!(c.store().blocks_from().unwrap(), 1);
    for h in [1, 5, ERA, 2 * ERA + 1, 3 * ERA] {
        assert_eq!(c.block(h).unwrap(), a.block(h).unwrap(), "block {h}");
    }
    assert_eq!(
        c.store().tx_location(&early_tx).unwrap().map(|l| l.height),
        Some(5)
    );
    assert_eq!(
        c.eras().unwrap(),
        vec![0, 1, 2],
        "and hands them out in turn"
    );

    let (_dir_d, d) = api_node(&g);
    let mut d_follower = Follower::new(d.clone(), vec![url_a.clone()])
        .unwrap()
        .snapshot_if_behind(10);
    d_follower.catch_up(0, Duration::from_secs(60)).unwrap();
    let mut forged = files[2].clone();
    let at = forged.len() - 2_000;
    forged[at] ^= 1;
    assert!(era::import(&d, era::Reader::open(forged.as_slice()).unwrap()).is_err());
    assert_eq!(d.store().blocks_from().unwrap(), 3 * ERA);
    assert!(
        d.block(2 * ERA + 5).unwrap().is_none(),
        "nothing left behind"
    );
}
