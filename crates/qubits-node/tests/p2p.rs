use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use qubits_crypto::{SchemeId, SecretKey};
use qubits_execution::{min_fee, read_account};
use qubits_node::p2p::{self, P2pConfig};
use qubits_node::{Node, Timing, Validator, ValidatorHandle, now_ms};
use qubits_types::*;

const CHAIN: &str = "qubits-p2p-test";

fn key(seed: u8) -> SecretKey {
    SecretKey::from_seed(SchemeId::MlDsa65, &[seed; 32]).unwrap()
}

fn addr(sk: &SecretKey) -> Address {
    AuthPolicy::single(sk.public_key().clone()).address()
}

const TEST_VALIDATORS: usize = 4;

fn genesis_time() -> u64 {
    static TIME: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *TIME.get_or_init(|| now_ms() - 1_000)
}

fn genesis(n: usize) -> Genesis {
    Genesis {
        chain_id: CHAIN.into(),
        timestamp_ms: genesis_time(),
        params: ChainParams {
            min_fee_per_byte: 1,
            max_block_transactions: 100,
        },
        validators: (0..n)
            .map(|i| qubits_types::Validator::self_paid(key(100 + i as u8).public_key().clone()))
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
        genesis_hash: genesis(TEST_VALIDATORS).hash(),
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
    tx.fee = min_fee(&genesis(1).params, draft.encode().len());
    SignedTransaction::sign(tx, &policy, reveal, &[&sk]).unwrap()
}

fn free_ports(n: usize) -> Vec<SocketAddr> {
    let listeners: Vec<_> = (0..n)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    listeners.iter().map(|l| l.local_addr().unwrap()).collect()
}

fn wait_for(what: &str, timeout_ms: u64, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn four_validators_reach_consensus_over_tcp() {
    let n = 4;
    let g = genesis(n);
    let ports = free_ports(n);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let mut nodes = Vec::new();
    let mut handles: Vec<ValidatorHandle> = Vec::new();
    let mut dirs = Vec::new();
    for i in 0..n {
        let dir = tempfile::tempdir().unwrap();
        Node::init(dir.path(), &g).unwrap();
        let node = Arc::new(Node::open(dir.path()).unwrap());
        let peers: BTreeMap<qubits_crypto::PublicKey, SocketAddr> = (0..n)
            .filter(|&j| j != i)
            .map(|j| (key(100 + j as u8).public_key().clone(), ports[j]))
            .collect();
        let config = P2pConfig {
            listen: ports[i],
            peers,
        };
        let (transport, inbox, _) = runtime
            .block_on(p2p::connect(&node, key(100 + i as u8), config))
            .unwrap();
        let timing = Timing {
            round_timeout_ms: 1_500,
            min_block_interval_ms: 50,
            ..Timing::DEFAULT
        };
        let validator =
            Validator::start(node.clone(), key(100 + i as u8), transport, timing).unwrap();
        handles.push(validator.spawn(inbox));
        nodes.push(node);
        dirs.push(dir);
    }

    let bob = addr(&key(2));
    for nonce in 0..3u64 {
        nodes[(nonce as usize + 1) % n]
            .submit(transfer(nonce, bob, 10), now_ms())
            .unwrap();
        let expected = 10 * (u128::from(nonce) + 1);
        wait_for("transfer", 20_000, || {
            nodes.iter().all(|node| {
                read_account(node.store(), &bob)
                    .unwrap()
                    .is_some_and(|a| a.balance(AssetId::NATIVE) == expected)
            })
        });
    }

    let common = nodes
        .iter()
        .map(|n| n.head().unwrap().height)
        .min()
        .unwrap();
    for h in 1..=common {
        let reference = nodes[0].store().block(h).unwrap().unwrap();
        for node in &nodes[1..] {
            assert_eq!(
                node.store().block(h).unwrap().unwrap(),
                reference,
                "block {h} differs"
            );
        }
    }
    let proposers: std::collections::BTreeSet<u16> = (1..=common)
        .map(|h| nodes[0].block(h).unwrap().unwrap().proposer)
        .collect();
    assert!(
        proposers.len() >= 3,
        "leaders rotate over the network: {proposers:?}"
    );
    drop(handles);
}
