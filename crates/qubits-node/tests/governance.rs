use std::sync::Arc;
use std::time::{Duration, Instant};

use qubits_consensus::ValidatorSet as ConsensusSet;
use qubits_crypto::{SchemeId, SecretKey};
use qubits_execution::{min_fee, read_account, read_validators};
use qubits_node::history::prune_once;
use qubits_node::network::{LocalHub, NoPeers};
use qubits_node::sync::Follower;
use qubits_node::{
    EpochInfo, Node, PROOF_EVERY, Timing, Validator, ValidatorHandle, now_ms, reconfigures,
    spawn_standby,
};
use qubits_types::client::PartialTransaction;
use qubits_types::rpc::{AccountResponse, StatusResponse};
use qubits_types::*;

const CHAIN: &str = "qubits-governance-test";
const TIMING: Timing = Timing {
    round_timeout_ms: 1_000,
    min_block_interval_ms: 50,
    ..Timing::DEFAULT
};

fn key(seed: u8) -> SecretKey {
    SecretKey::from_seed(SchemeId::MlDsa65, &[seed; 32]).unwrap()
}

fn validator(i: u8) -> SecretKey {
    key(130 + i)
}

fn addr(sk: &SecretKey) -> Address {
    AuthPolicy::single(sk.public_key().clone()).address()
}

fn genesis(validators: &[u8]) -> Genesis {
    Genesis {
        chain_id: CHAIN.into(),
        timestamp_ms: now_ms() - 1_000,
        params: ChainParams {
            min_fee_per_byte: 1,
            max_block_transactions: 100,
        },
        validators: validators
            .iter()
            .map(|&i| qubits_types::Validator::self_paid(validator(i).public_key().clone()))
            .collect(),
        accounts: vec![
            GenesisAccount {
                address: addr(&key(1)),
                balance: 10_000_000,
            },
            GenesisAccount {
                address: governance_address(),
                balance: 10_000_000,
            },
        ],
    }
}

fn transfer(g: &Genesis, nonce: u64, to: Address, amount: Amount) -> SignedTransaction {
    let sk = key(1);
    let policy = AuthPolicy::single(sk.public_key().clone());
    let reveal = (nonce == 0).then(|| policy.clone());
    let mut tx = Transaction {
        genesis_hash: g.hash(),
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
    tx.fee = min_fee(&g.params, draft.encode().len());
    SignedTransaction::sign(tx, &policy, reveal, &[&sk]).unwrap()
}

fn set_validators(node: &Node, validators: &[u8], signers: &[u8]) -> SignedTransaction {
    let g = node.genesis();
    let status = StatusResponse {
        chain_id: g.chain_id.clone(),
        genesis_hash: node.genesis_hash(),
        height: 0,
        latest_hash: Hash::ZERO,
        latest_timestamp_ms: 0,
        state_root: Hash::ZERO,
        min_fee_per_byte: g.params.min_fee_per_byte,
        mempool_size: 0,
        state_from: 0,
        blocks_from: 0,
    };
    let account = read_account(node.store(), &governance_address())
        .unwrap()
        .unwrap();
    let account = AccountResponse {
        address: governance_address(),
        exists: true,
        nonce: account.nonce,
        auth: account.auth,
        vault: None,
        balances: vec![],
        pending: vec![],
    };
    let payload = Payload::SetValidators {
        validators: validators
            .iter()
            .map(|&i| qubits_types::Validator::self_paid(validator(i).public_key().clone()))
            .collect(),
    };
    let mut partial =
        PartialTransaction::new(&status, &account, Role::Owner, payload, None, u64::MAX).unwrap();
    for &i in signers {
        partial.sign(&validator(i)).unwrap();
    }
    partial.finish().unwrap()
}

fn balance(node: &Node, who: &Address) -> Amount {
    read_account(node.store(), who)
        .unwrap()
        .map_or(0, |a| a.balance(AssetId::NATIVE))
}

fn epoch(node: &Node) -> EpochInfo {
    EpochInfo::read(node.store(), node.genesis_hash()).unwrap()
}

fn wait_for(what: &str, timeout_ms: u64, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(25));
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

fn new_node(g: &Genesis) -> (tempfile::TempDir, Arc<Node>) {
    let dir = tempfile::tempdir().unwrap();
    Node::init(dir.path(), g).unwrap();
    let node = Arc::new(Node::open(dir.path()).unwrap());
    (dir, node)
}

#[test]
fn validators_replace_one_of_their_own_and_the_chain_carries_on() {
    let g = genesis(&[0, 1, 2, 3]);
    let members: Vec<_> = (0..5).map(|i| validator(i).public_key().clone()).collect();
    let (hub, inboxes) = LocalHub::new(&members);
    let mut inboxes = inboxes.into_iter();
    let (mut nodes, mut handles, mut dirs): (Vec<Arc<Node>>, Vec<ValidatorHandle>, Vec<_>) =
        (vec![], vec![], vec![]);
    for i in 0..4u8 {
        let (dir, node) = new_node(&g);
        let v = Validator::start(
            node.clone(),
            validator(i),
            Arc::new(hub.transport(&members[i as usize])),
            TIMING,
        )
        .unwrap();
        handles.push(v.spawn(inboxes.next().unwrap()));
        nodes.push(node);
        dirs.push(dir);
    }
    let url = serve(nodes[0].clone());

    let (dir4, node4) = new_node(&g);
    let follower = Follower::new(node4.clone(), vec![url.clone()]).unwrap();
    let standby = spawn_standby(
        node4.clone(),
        validator(4),
        Arc::new(hub.transport(&members[4])),
        TIMING,
        follower,
        inboxes.next().unwrap(),
    );
    assert!(
        Validator::start(node4.clone(), validator(4), Arc::new(NoPeers), TIMING).is_err(),
        "not a validator yet"
    );

    let bob = addr(&key(2));
    nodes[1].submit(transfer(&g, 0, bob, 10), now_ms()).unwrap();
    wait_for("first transfer", 15_000, || {
        nodes.iter().all(|n| balance(n, &bob) == 10)
    });

    let change = set_validators(&nodes[0], &[0, 1, 2, 4], &[0, 1, 2]);
    nodes[0].submit(change.clone(), now_ms()).unwrap();
    wait_for("the new epoch", 20_000, || {
        nodes.iter().all(|n| epoch(n).epoch == 1)
    });
    let boundary = epoch(&nodes[0]);
    for n in &nodes {
        assert_eq!(
            epoch(n),
            boundary,
            "every validator ends the epoch at the same block"
        );
    }
    let end_block = nodes[0].block(boundary.start_height).unwrap().unwrap();
    assert!(reconfigures(&end_block));
    assert_eq!(end_block.id(), boundary.start);
    let set = read_validators(nodes[0].store()).unwrap();
    assert_eq!(
        set.keys(),
        [0u8, 1, 2, 4].map(|i| validator(i).public_key().clone())
    );

    wait_for("validator 4 to reach the new epoch", 20_000, || {
        epoch(&node4).epoch == 1
    });

    nodes[2].submit(transfer(&g, 1, bob, 5), now_ms()).unwrap();
    let live = [&nodes[0], &nodes[1], &nodes[2], &node4];
    wait_for("transfer in the new epoch", 20_000, || {
        live.iter().all(|n| balance(n, &bob) == 15)
    });
    let head = nodes[0].head().unwrap().height;
    assert!(head > boundary.start_height);
    let new_set = ConsensusSet::new(set.keys()).unwrap();
    let old_set = ConsensusSet::new(qubits_types::validator_keys(&g.validators)).unwrap();
    for h in boundary.start_height + 1..=head {
        let proof = nodes[0].finality_proof(h).unwrap();
        let Some(proof) = proof else { continue };
        assert!(
            proof.qc.verify(&new_set, &boundary.start),
            "block {h} certified by the new set for this epoch"
        );
        assert!(
            !proof.qc.verify(&old_set, &node4.genesis_hash()),
            "old signatures don't carry over"
        );
    }
    let last_old = nodes[0].block(boundary.start_height).unwrap().unwrap();
    let proof = nodes[0]
        .stored_proof(boundary.start_height)
        .unwrap()
        .expect("the block that ends an epoch keeps its proof");
    assert!(proof.verify(last_old.round, &old_set, &node4.genesis_hash()));
    wait_for("validator 4 to store the new blocks", 20_000, || {
        node4.head().unwrap().height >= head
    });
    for h in 1..=head {
        assert_eq!(
            node4.store().block(h).unwrap(),
            nodes[0].store().block(h).unwrap(),
            "block {h}"
        );
    }
    let removed_height = nodes[3].head().unwrap().height;
    assert_eq!(removed_height, boundary.start_height);

    let (_api_dir, api) = new_node(&g);
    let mut api_follower = Follower::new(api.clone(), vec![url.clone()]).unwrap();
    api_follower.catch_up(0, Duration::from_secs(30)).unwrap();
    assert_eq!(api.head().unwrap().height, nodes[0].head().unwrap().height);
    assert_eq!(epoch(&api), boundary);
    assert_eq!(balance(&api, &bob), 15);

    let (_snap_dir, snap) = new_node(&g);
    let mut snap_follower = Follower::new(snap.clone(), vec![url.clone()])
        .unwrap()
        .snapshot_if_behind(1);
    snap_follower.catch_up(0, Duration::from_secs(30)).unwrap();
    let pivot = snap.store().pruned_before().unwrap();
    assert!(
        pivot >= boundary.start_height,
        "took the state, not the blocks"
    );
    assert_eq!(epoch(&snap), boundary);
    assert_eq!(snap.epochs().unwrap().len(), 2);
    assert_eq!(balance(&snap, &bob), 15);
    assert_eq!(
        read_validators(snap.store()).unwrap().keys(),
        set.keys(),
        "the restored state carries the new set"
    );

    let api_url = serve(api.clone());
    prune_once(&api, 0, 0, 10_000).unwrap();
    assert!(api.block(1).unwrap().is_none());
    assert!(api.block(boundary.start_height).unwrap().is_some());
    assert!(api.stored_proof(boundary.start_height).unwrap().is_some());
    assert_eq!(api.epochs().unwrap().len(), 2);
    let (_late_dir, late) = new_node(&g);
    let mut late_follower = Follower::new(late.clone(), vec![api_url])
        .unwrap()
        .snapshot_if_behind(1);
    late_follower.catch_up(0, Duration::from_secs(30)).unwrap();
    assert_eq!(epoch(&late), boundary);
    assert_eq!(balance(&late, &bob), 15);

    let target = boundary.start_height - boundary.start_height % PROOF_EVERY + PROOF_EVERY;
    let mut nonce = 2;
    while nodes[0].head().unwrap().height < target {
        nodes[0]
            .submit(transfer(&g, nonce, bob, 1), now_ms())
            .unwrap();
        nonce += 1;
        let want = 13 + u128::from(nonce);
        wait_for("a transfer", 15_000, || balance(&nodes[0], &bob) == want);
    }
    let (_above_dir, above) = new_node(&g);
    Follower::new(above.clone(), vec![url])
        .unwrap()
        .snapshot_if_behind(1)
        .catch_up(0, Duration::from_secs(30))
        .unwrap();
    assert!(above.store().pruned_before().unwrap() > boundary.start_height);
    let above_url = serve(above.clone());
    let (_next_dir, next) = new_node(&g);
    Follower::new(next.clone(), vec![above_url])
        .unwrap()
        .snapshot_if_behind(1)
        .catch_up(0, Duration::from_secs(30))
        .unwrap();
    assert_eq!(epoch(&next), boundary);
    assert_eq!(balance(&next, &bob), balance(&above, &bob));

    drop(standby);
    drop(handles);
    drop((dirs, dir4));
}

#[test]
fn validator_restarts_into_the_epoch_it_left() {
    let g = genesis(&[0]);
    let (_dir, node) = new_node(&g);
    let bob = addr(&key(2));
    {
        let (_keep, inbox) = std::sync::mpsc::channel();
        let handle = Validator::start(node.clone(), validator(0), Arc::new(NoPeers), TIMING)
            .unwrap()
            .spawn(inbox);
        node.submit(set_validators(&node, &[0], &[0]), now_ms())
            .unwrap();
        wait_for("epoch 1", 10_000, || epoch(&node).epoch == 1);
        node.submit(transfer(&g, 0, bob, 3), now_ms()).unwrap();
        wait_for("transfer in epoch 1", 10_000, || balance(&node, &bob) == 3);
        handle.stop();
    }
    let height = node.head().unwrap().height;
    let (_keep, inbox) = std::sync::mpsc::channel();
    let validator =
        Validator::start(node.clone(), validator(0), Arc::new(NoPeers), TIMING).unwrap();
    assert_eq!(validator.epoch(), Some(1));
    let _handle = validator.spawn(inbox);
    node.submit(transfer(&g, 1, bob, 3), now_ms()).unwrap();
    wait_for("transfer after restart", 10_000, || {
        balance(&node, &bob) == 6
    });
    assert!(node.head().unwrap().height > height);
    node.submit(set_validators(&node, &[0], &[0]), now_ms())
        .unwrap();
    wait_for("epoch 2", 10_000, || epoch(&node).epoch == 2);
}
