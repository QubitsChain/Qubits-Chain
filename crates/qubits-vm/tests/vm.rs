//! The sandbox on its own, with the simplest host there is. The numbers here are the point: gas
//! used goes into receipts and receipts into blocks, so if one changes, on any machine, nodes
//! running different builds disagree. A change here is a fork, and must be meant.

use std::collections::BTreeMap;

use qubits_types::{Address, Amount, Outcome, contract_hash};
use qubits_vm::{Called, Fatal, Finish, Host, Invocation, run};

const TOKEN: &[u8] = include_bytes!("../../../contracts/out/token.wasm");
const AMM: &[u8] = include_bytes!("../../../contracts/out/amm.wasm");

#[derive(Default)]
struct Memory {
    storage: BTreeMap<Vec<u8>, Vec<u8>>,
    events: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Host for Memory {
    fn height(&self) -> u64 {
        7
    }

    fn timestamp_ms(&self) -> u64 {
        1_000
    }

    fn balance(&mut self, _: &Address) -> Result<Amount, Fatal> {
        Ok(5)
    }

    fn read(&mut self, _: &Address, key: &[u8]) -> Result<Option<Vec<u8>>, Fatal> {
        Ok(self.storage.get(key).cloned())
    }

    fn write(&mut self, _: &Address, key: &[u8], value: Option<&[u8]>) -> Result<(), Fatal> {
        match value {
            Some(value) => self.storage.insert(key.to_vec(), value.to_vec()),
            None => self.storage.remove(key),
        };
        Ok(())
    }

    fn transfer(&mut self, _: &Address, _: &Address, _: Amount) -> Result<bool, Fatal> {
        Ok(true)
    }

    fn emit(&mut self, _: &Address, topic: Vec<u8>, data: Vec<u8>) {
        self.events.push((topic, data));
    }

    fn call(
        &mut self,
        _: &Address,
        _: &Address,
        _: &str,
        _: &[u8],
        _: Amount,
        gas: u64,
    ) -> Result<Called, Fatal> {
        Ok(Called {
            ok: true,
            output: vec![1],
            gas_left: gas,
        })
    }
}

const ALICE: Address = Address([1; 32]);
const BOB: Address = Address([2; 32]);
const GAS: u64 = 5_000_000;
const GOLDEN_GAS: [u64; 4] = [252_105, 190_562, 130_597, 130_952];
const GOLDEN_FINGERPRINT: &str = "bd0b2efd98a3152ecd1fbbd2076b0d21f08c1cac2b360863ee30c5ab07df9a65";
const GOLDEN_MARKET_GAS: [u64; 2] = [522_451, 385_760];
const GOLDEN_MARKET_FINGERPRINT: &str =
    "9d2b1b32fbe62df47bf533e503c41e13b33a96951ef25c27e028ae3b8fd1ca9c";
const GOLDEN_WORK: u64 = 290_478;
const GOLDEN_WRITES: u64 = 317;

fn call(host: &mut Memory, code: &[u8], function: &str, input: &[u8], caller: Address) -> Finish {
    let invocation = Invocation {
        code,
        function,
        input,
        contract: Address([9; 32]),
        caller,
        value: 0,
        gas: GAS,
    };
    run(invocation, host).unwrap()
}

/// Everything a run leaves behind, as one hash.
fn fingerprint(host: &Memory, finishes: &[&Finish]) -> String {
    let mut bytes = Vec::new();
    for (key, value) in &host.storage {
        bytes.extend_from_slice(key);
        bytes.extend_from_slice(value);
    }
    for (topic, data) in &host.events {
        bytes.extend_from_slice(topic);
        bytes.extend_from_slice(data);
    }
    for finish in finishes {
        bytes.extend_from_slice(&finish.output);
        bytes.extend_from_slice(&finish.gas_left.to_le_bytes());
    }
    contract_hash(&bytes).to_string()
}

#[test]
fn the_token_costs_exactly_this() {
    let mut host = Memory::default();
    let mut args = ALICE.0.to_vec();
    args.extend_from_slice(&1_000u128.to_le_bytes());
    for text in ["Test", "TST"] {
        args.extend_from_slice(&(text.len() as u32).to_le_bytes());
        args.extend_from_slice(text.as_bytes());
    }
    args.extend_from_slice(&6u64.to_le_bytes());
    let init = call(&mut host, TOKEN, "init", &args, ALICE);
    assert_eq!(init.outcome, Outcome::Done);

    let mut args = BOB.0.to_vec();
    args.extend_from_slice(&300u128.to_le_bytes());
    let transfer = call(&mut host, TOKEN, "transfer", &args, ALICE);
    assert_eq!(transfer.outcome, Outcome::Done);

    let balance = call(&mut host, TOKEN, "balance_of", &BOB.0, ALICE);
    assert_eq!(balance.output, 300u128.to_le_bytes());

    let mut args = ALICE.0.to_vec();
    args.extend_from_slice(&301u128.to_le_bytes());
    let too_much = call(&mut host, TOKEN, "transfer", &args, BOB);
    assert!(matches!(too_much.outcome, Outcome::Reverted { .. }));

    assert_eq!(
        [
            GAS - init.gas_left,
            GAS - transfer.gas_left,
            GAS - balance.gas_left,
            GAS - too_much.gas_left,
        ],
        GOLDEN_GAS,
    );
    assert_eq!(
        fingerprint(&host, &[&init, &transfer, &balance, &too_much]),
        GOLDEN_FINGERPRINT,
    );
}

/// Where the 128-bit multiplication and the long division run, in 64-bit wasm instructions.
#[test]
fn the_market_costs_exactly_this() {
    let (x, y) = (Address([3; 32]), Address([4; 32]));
    let mut host = Memory::default();
    let mut add = [x.0, y.0].concat();
    for amount in [(1u128 << 111) + 12_345, (1 << 110) - 6_789, 0, 0] {
        add.extend_from_slice(&amount.to_le_bytes());
    }
    add.extend_from_slice(&u64::MAX.to_le_bytes());
    let added = call(&mut host, AMM, "add_liquidity", &add, ALICE);
    assert_eq!(added.outcome, Outcome::Done);

    let mut swap = [x.0, y.0].concat();
    swap.extend_from_slice(&(1u128 << 100).to_le_bytes());
    swap.extend_from_slice(&0u128.to_le_bytes());
    swap.extend_from_slice(&u64::MAX.to_le_bytes());
    let swapped = call(&mut host, AMM, "swap", &swap, ALICE);
    assert_eq!(swapped.outcome, Outcome::Done);
    assert_eq!(
        swapped.output,
        631_616_343_015_536_765_749_889_438_610u128.to_le_bytes(),
        "worked out in unbounded integers"
    );
    assert_eq!(
        [GAS - added.gas_left, GAS - swapped.gas_left],
        GOLDEN_MARKET_GAS
    );
    assert_eq!(
        fingerprint(&host, &[&added, &swapped]),
        GOLDEN_MARKET_FINGERPRINT
    );
}

#[test]
fn instructions_cost_exactly_this() {
    let code = wat::parse_str(
        r#"(module
  (memory (export "memory") 2)
  (func $mix (param i64) (result i64)
    (i64.xor (i64.mul (local.get 0) (i64.const 0x9E3779B97F4A7C15)) (i64.shr_u (local.get 0) (i64.const 29))))
  (func (export "work")
    (local $i i32) (local $x i64)
    (local.set $x (i64.const 42))
    (block $done
      (loop $next
        (br_if $done (i32.eq (local.get $i) (i32.const 10000)))
        (local.set $x (call $mix (local.get $x)))
        (i64.store (i32.and (i32.mul (local.get $i) (i32.const 8)) (i32.const 65535)) (local.get $x))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $next)))
    (memory.fill (i32.const 70000) (i32.const 7) (i32.const 40000))
    (memory.copy (i32.const 72000) (i32.const 0) (i32.const 30000))
    (drop (memory.grow (i32.const 3)))))"#,
    )
    .unwrap();
    let mut host = Memory::default();
    let done = call(&mut host, &code, "work", &[], ALICE);
    assert_eq!(done.outcome, Outcome::Done);
    assert_eq!(GAS - done.gas_left, GOLDEN_WORK);
}

#[test]
fn running_out_of_gas_stops_at_the_same_place() {
    let code = wat::parse_str(
        r#"(module
  (import "qubits" "set" (func $set (param i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (func (export "work")
    (local $i i32)
    (loop $next
      (i32.store (i32.const 0) (local.get $i))
      (call $set (i32.const 0) (i32.const 4) (i32.const 0) (i32.const 4))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $next))))"#,
    )
    .unwrap();
    let mut host = Memory::default();
    let done = call(&mut host, &code, "work", &[], ALICE);
    assert_eq!(done.outcome, Outcome::OutOfGas);
    assert_eq!(host.storage.len() as u64, GOLDEN_WRITES);
}
