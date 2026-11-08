//! Contracts on a running validator: what the rules in `qubits-execution` come to in a block.

use std::sync::Arc;
use std::time::{Duration, Instant};

use qubits_crypto::{SchemeId, SecretKey};
use qubits_node::network::NoPeers;
use qubits_node::{Node, Timing, Validator, now_ms};
use qubits_types::client::required_fee;
use qubits_types::limits::{MAX_BLOCK_GAS, MAX_TX_GAS};
use qubits_types::*;

fn key(seed: u8) -> SecretKey {
    SecretKey::from_seed(SchemeId::MlDsa65, &[seed; 32]).unwrap()
}

fn signed(
    genesis: &Genesis,
    sender: Address,
    signer: &SecretKey,
    reveal: bool,
    nonce: u64,
    payload: Payload,
) -> SignedTransaction {
    let policy = AuthPolicy::single(signer.public_key().clone());
    let reveal = reveal.then(|| policy.clone());
    let mut tx = Transaction {
        genesis_hash: genesis.hash(),
        sender,
        nonce,
        fee: 0,
        valid_until_ms: u64::MAX,
        role: Role::Owner,
        payload,
    };
    let draft = SignedTransaction::sign(tx.clone(), &policy, reveal.clone(), &[signer]).unwrap();
    tx.fee = required_fee(1, draft.encode().len(), tx.payload.gas_limit());
    SignedTransaction::sign(tx, &policy, reveal, &[signer]).unwrap()
}

fn wait_included(node: &Node, id: &Hash) -> u64 {
    let start = Instant::now();
    loop {
        if let Some(location) = node.store().tx_location(id).unwrap() {
            return location.height;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "{id} not included"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn gas_that_does_not_fit_waits_for_the_next_block() {
    let validator = key(200);
    let senders: Vec<SecretKey> = (1..=5).map(key).collect();
    let mut accounts: Vec<GenesisAccount> = senders
        .iter()
        .map(|sk| GenesisAccount {
            address: AuthPolicy::single(sk.public_key().clone()).address(),
            balance: 100_000_000,
        })
        .collect();
    accounts.push(GenesisAccount {
        address: governance_address(),
        balance: 100_000_000,
    });
    let genesis = Genesis {
        chain_id: "contracts".into(),
        timestamp_ms: now_ms() - 1_000,
        params: ChainParams {
            min_fee_per_byte: 1,
            max_block_transactions: 100,
        },
        validators: vec![qubits_types::Validator::self_paid(
            validator.public_key().clone(),
        )],
        accounts,
    };
    let dir = tempfile::tempdir().unwrap();
    Node::init(dir.path(), &genesis).unwrap();
    let node = Arc::new(Node::open(dir.path()).unwrap());
    let timing = Timing {
        round_timeout_ms: 1_000,
        min_block_interval_ms: 50,
        ..Timing::DEFAULT
    };
    let started = Validator::start(node.clone(), validator.clone(), Arc::new(NoPeers), timing);
    let (_keep_open, inbox) = std::sync::mpsc::channel();
    let _handle = started.unwrap().spawn(inbox);

    let spin = r#"(module (memory (export "memory") 1) (func (export "spin") (loop $l (br $l))))"#;
    let deploy = Payload::Deploy {
        code: wat::parse_str(spin).unwrap(),
        args: vec![],
        gas_limit: 1_000_000,
    };
    let stx = signed(&genesis, governance_address(), &validator, false, 0, deploy);
    let id = node.submit(stx, now_ms()).unwrap();
    wait_included(&node, &id);
    let contract = contract_address(&governance_address(), 0);

    // all of these are taken in without running anything: each would burn a whole block's share
    let start = Instant::now();
    let ids: Vec<Hash> = senders
        .iter()
        .map(|sk| {
            let call = Payload::Call {
                contract,
                function: "spin".into(),
                args: vec![],
                amount: 0,
                gas_limit: MAX_TX_GAS,
            };
            let sender = AuthPolicy::single(sk.public_key().clone()).address();
            node.submit(signed(&genesis, sender, sk, true, 0, call), now_ms())
                .unwrap()
        })
        .collect();
    const { assert!(MAX_BLOCK_GAS / MAX_TX_GAS == 2) };

    let heights: Vec<u64> = ids.iter().map(|id| wait_included(&node, id)).collect();
    let mut blocks = heights.clone();
    blocks.sort_unstable();
    blocks.dedup();
    assert!(
        blocks.len() >= 3,
        "five calls in {blocks:?}, two to a block"
    );
    for height in &blocks {
        let count = heights.iter().filter(|h| *h == height).count();
        assert!(count <= 2, "{count} calls in block {height}");
    }
    assert!(start.elapsed() < Duration::from_secs(20));

    for id in &ids {
        let bytes = node.store().receipt(id).unwrap().expect("kept");
        let receipt: Receipt = borsh::from_slice(&bytes).unwrap();
        assert_eq!(receipt.outcome, Outcome::OutOfGas);
        assert_eq!(receipt.gas_used, MAX_TX_GAS);
    }
}
