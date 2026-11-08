//! What gas buys, on a real database: each row is a contract doing one expensive thing until
//! its gas runs out. A row far above the others is a price that is too low, and what a full
//! block can be made to cost. Read the table when gas prices or the VM change:
//!
//! cargo test --release -p qubits-execution --test gas -- --ignored --nocapture

use std::time::Instant;

use qubits_crypto::{Domain, SchemeId, SecretKey};
use qubits_execution::{BlockEnv, genesis_writes, keys, view};
use qubits_state::{Store, WriteSet};
use qubits_types::limits::{MAX_BLOCK_GAS, MAX_CODE_BYTES, MAX_TX_GAS};
use qubits_types::*;

const STORED_KEYS: u32 = 200_000;

fn contract(n: u8) -> Address {
    Address([n; 32])
}

fn install(writes: &mut WriteSet, address: Address, code: &[u8]) {
    let hash = code_hash(code);
    let record = Contract { code: hash };
    writes.insert(keys::code(&hash), Some(code.to_vec()));
    writes.insert(
        keys::contract(&address),
        Some(borsh::to_vec(&record).unwrap()),
    );
}

const IMPORTS: &str = r#"
  (import "qubits" "get" (func $get (param i32 i32 i32 i32) (result i32)))
  (import "qubits" "emit" (func $emit (param i32 i32 i32 i32)))
  (import "qubits" "hash" (func $hash (param i32 i32 i32)))
  (import "qubits" "balance" (func $balance (param i32 i32)))
  (import "qubits" "input" (func $input (param i32)))
  (import "qubits" "output" (func $output (param i32 i32)))
  (import "qubits" "call" (func $call (param i32 i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 2)
  (data (i32.const 0) "\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa")
  (data (i32.const 40) "go")
  (data (i32.const 300) "\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb")
  (data (i32.const 400) "\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc\cc")
"#;

fn looped(body: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(module {IMPORTS}
  (func $f (param i64) (result i64) (i64.add (local.get 0) (i64.const 1)))
  (func (export "go")
    (local $i i32) (local $x i64)
    (loop $l
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      {body}
      (br $l))))"#
    ))
    .unwrap()
}

fn verifying(key: &SecretKey, scheme: u32) -> Vec<u8> {
    let escaped = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("\\{b:02x}")).collect() };
    let message = b"a message";
    let signature = key.sign(Domain::Message, message).unwrap();
    let (raw_key, raw_sig) = (key.public_key().as_raw(), signature.as_raw());
    wat::parse_str(format!(
        r#"(module
  (import "qubits" "verify" (func $verify (param i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 2)
  (data (i32.const 0) "{}")
  (data (i32.const 4000) "{}")
  (data (i32.const 8000) "{}")
  (func (export "go")
    (loop $l
      (if (call $verify (i32.const {scheme}) (i32.const 0) (i32.const {}) (i32.const 4000) (i32.const {})
            (i32.const 8000) (i32.const {}))
        (then unreachable))
      (br $l))))"#,
        escaped(raw_key),
        escaped(message),
        escaped(raw_sig),
        raw_key.len(),
        message.len(),
        raw_sig.len(),
    ))
    .unwrap()
}

/// Valid code as long as code may be, to price reading and translating it.
fn big_code() -> Vec<u8> {
    let mut text = String::from(r#"(module (memory (export "memory") 1) (func (export "go"))"#);
    let mut size = 0;
    let mut i = 0;
    while size < MAX_CODE_BYTES - 2_000 {
        text.push_str(&format!(
            "(func $f{i} (param i64) (result i64) (i64.add (i64.mul (local.get 0) (i64.const {i})) (i64.const 7)))"
        ));
        i += 1;
        if i % 1_000 == 0 {
            size = wat::parse_str(format!("{text})")).unwrap().len();
        }
    }
    text.push(')');
    wat::parse_str(text).unwrap()
}

#[test]
#[ignore = "a measurement, in release mode"]
fn gas_rate_of_the_slowest_work() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let genesis = Genesis {
        chain_id: "gas".into(),
        timestamp_ms: 1,
        params: ChainParams {
            min_fee_per_byte: 1,
            max_block_transactions: 50,
        },
        validators: vec![qubits_types::Validator::self_paid(
            SecretKey::from_seed(SchemeId::MlDsa65, &[1; 32])
                .unwrap()
                .public_key()
                .clone(),
        )],
        accounts: vec![],
    };
    let big = big_code();
    let roomy = wat::parse_str(r#"(module (memory (export "memory") 64) (func (export "go")))"#);
    let roomy = roomy.unwrap();
    let ml_dsa = SecretKey::from_seed(SchemeId::MlDsa65, &[2; 32]).unwrap();
    let slh_dsa = SecretKey::from_seed(SchemeId::SlhDsaSha2_192s, &[2; 72]).unwrap();
    let copy_into_memory = r#"(memory.fill (i32.const 100) (i32.const 1) (i32.const 60000))"#;
    let rows: Vec<(&str, Vec<u8>)> = vec![
        ("branch", looped("")),
        (
            "arithmetic",
            looped("(local.set $x (i64.mul (i64.add (local.get $x) (i64.const 3)) (i64.const 7)))"),
        ),
        (
            "memory load and store",
            looped("(i64.store (i32.const 64) (i64.add (i64.load (i32.const 64)) (i64.const 1)))"),
        ),
        ("memory.fill 60 KB", looped(copy_into_memory)),
        (
            "wasm function call",
            looped("(local.set $x (call $f (local.get $x)))"),
        ),
        (
            "storage read, present",
            looped(
                "(i32.store (i32.const 64) (i32.rem_u (i32.mul (local.get $i) (i32.const 7919)) (i32.const 200000)))
                 (drop (call $get (i32.const 64) (i32.const 4) (i32.const 128) (i32.const 32)))",
            ),
        ),
        (
            "storage read, absent",
            looped(
                "(i32.store (i32.const 64) (i32.add (local.get $i) (i32.const 300000)))
                 (drop (call $get (i32.const 64) (i32.const 4) (i32.const 128) (i32.const 32)))",
            ),
        ),
        (
            "account balance",
            looped("(call $balance (i32.const 0) (i32.const 128))"),
        ),
        (
            "hash of nothing",
            looped("(call $hash (i32.const 0) (i32.const 0) (i32.const 128))"),
        ),
        (
            "hash of 16 KB",
            looped("(call $hash (i32.const 0) (i32.const 16384) (i32.const 128))"),
        ),
        (
            "event",
            looped("(call $emit (i32.const 0) (i32.const 1) (i32.const 0) (i32.const 1))"),
        ),
        ("output", looped("(call $output (i32.const 0) (i32.const 1))")),
        (
            "failed call, no contract",
            looped(
                "(drop (call $call (i32.const 0) (i32.const 40) (i32.const 2) (i32.const 0) (i32.const 0) (i32.const 8192)))",
            ),
        ),
        (
            "call of the largest code",
            looped(
                "(drop (call $call (i32.const 300) (i32.const 40) (i32.const 2) (i32.const 0) (i32.const 0) (i32.const 8192)))",
            ),
        ),
        (
            "call of the largest memory",
            looped(
                "(drop (call $call (i32.const 400) (i32.const 40) (i32.const 2) (i32.const 0) (i32.const 0) (i32.const 8192)))",
            ),
        ),
        ("ML-DSA-65 signature", verifying(&ml_dsa, 1)),
        ("SLH-DSA signature", verifying(&slh_dsa, 2)),
    ];
    let mut writes = genesis_writes(&genesis);
    install(&mut writes, Address([0xbb; 32]), &big);
    install(&mut writes, Address([0xcc; 32]), &roomy);
    let mut filled: Vec<Address> = Vec::new();
    for (i, (_, code)) in rows.iter().enumerate() {
        let address = contract(i as u8 + 1);
        install(&mut writes, address, code);
        filled.push(address);
    }
    for key in 0..STORED_KEYS {
        for address in &filled {
            if address.0[0] == 6 {
                writes.insert(
                    keys::storage(address, &key.to_le_bytes()),
                    Some(vec![7; 32]),
                );
            }
        }
    }
    let prepared = store.prepare(0, &writes).unwrap();
    store.commit_genesis(&genesis, prepared).unwrap();
    let env = BlockEnv {
        genesis_hash: genesis.hash(),
        height: 1,
        timestamp_ms: 2,
        params: genesis.params.clone(),
    };
    println!(
        "{:<28} {:>11} {:>10} {:>8}   a block of {} gas",
        "work", "gas", "ms", "ns/gas", MAX_BLOCK_GAS
    );
    let mut worst: f64 = 0.0;
    for (i, (name, _)) in rows.iter().enumerate() {
        let start = Instant::now();
        let receipt = view(&store, env.clone(), &contract(i as u8 + 1), "go", &[]).unwrap();
        let ms = start.elapsed().as_secs_f64() * 1e3;
        let rate = ms * 1e6 / receipt.gas_used as f64;
        worst = worst.max(rate);
        println!(
            "{name:<28} {:>11} {ms:>10.2} {rate:>8.2}   {:>7.1} ms  {:?}",
            receipt.gas_used,
            rate * MAX_BLOCK_GAS as f64 / 1e6,
            receipt.outcome,
        );
    }
    let mut updates = WriteSet::new();
    let count = (MAX_BLOCK_GAS / qubits_vm::gas::WRITE) as u32;
    for key in 0..count {
        let address = contract(6);
        updates.insert(
            keys::storage(&address, &(key * 7).to_le_bytes()),
            Some(vec![9; 32]),
        );
    }
    let start = Instant::now();
    store.speculative_root(&[&updates]).unwrap();
    let ms = start.elapsed().as_secs_f64() * 1e3;
    println!(
        "{:<28} {:>11} {ms:>10.2} {:>8.2}   a block's writes, hashing the tree: {count}",
        "state root",
        count as u64 * qubits_vm::gas::WRITE,
        ms * 1e6 / (count as u64 * qubits_vm::gas::WRITE) as f64,
    );
    println!("worst {worst:.2} ns/gas, MAX_TX_GAS {MAX_TX_GAS}");
}

fn resident_kb() -> u64 {
    let pid = std::process::id().to_string();
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

/// Every call translates code. Whatever that keeps must not grow with the number of calls.
#[test]
#[ignore = "a measurement, in release mode"]
fn memory_does_not_grow_with_calls() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let genesis = Genesis {
        chain_id: "gas".into(),
        timestamp_ms: 1,
        params: ChainParams {
            min_fee_per_byte: 1,
            max_block_transactions: 50,
        },
        validators: vec![qubits_types::Validator::self_paid(
            SecretKey::from_seed(SchemeId::MlDsa65, &[1; 32])
                .unwrap()
                .public_key()
                .clone(),
        )],
        accounts: vec![],
    };
    let code = include_bytes!("../../../contracts/out/token.wasm");
    let mut writes = genesis_writes(&genesis);
    install(&mut writes, contract(1), code);
    let prepared = store.prepare(0, &writes).unwrap();
    store.commit_genesis(&genesis, prepared).unwrap();
    let env = BlockEnv {
        genesis_hash: genesis.hash(),
        height: 1,
        timestamp_ms: 2,
        params: genesis.params.clone(),
    };
    let args = [0u8; 32];
    let warm = 20_000;
    for _ in 0..warm {
        view(&store, env.clone(), &contract(1), "balance_of", &args).unwrap();
    }
    let before = resident_kb();
    let start = Instant::now();
    let calls = 200_000;
    for _ in 0..calls {
        view(&store, env.clone(), &contract(1), "balance_of", &args).unwrap();
    }
    let per_call = start.elapsed().as_secs_f64() * 1e6 / calls as f64;
    let after = resident_kb();
    println!(
        "{before} KB before, {after} KB after {calls} calls of {} byte code; {per_call:.1} us a call",
        code.len()
    );
    assert!(
        after < before + 20_000,
        "memory grew by {} KB",
        after - before
    );
}
