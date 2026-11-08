//! Contract tests under the chain's rules, with the built contracts from `contracts/out` and
//! hostile ones.

mod common;

use common::*;
use qubits_crypto::{Domain, SecretKey};
use qubits_execution::{
    BlockError, Executor, TxError, execute_block, keys, read_contracts, recovery_reserve, simulate,
    view,
};
use qubits_state::StateReader;
use qubits_types::limits::{GAS_PER_BYTE, MAX_BLOCK_GAS, MAX_CALL_DEPTH, MAX_TX_GAS};
use qubits_types::*;

#[test]
fn token_moves_between_accounts() {
    let (alice, bob) = (key(1), key(2));
    let (a, b) = (address(&alice), address(&bob));
    let mut chain = Chain::new(&[&alice, &bob]);
    let t = token(&mut chain, &a, 1_000);
    assert_eq!(holds(&chain, t, &a), 1_000);
    assert_eq!(chain.view_u128(t, "total_supply", vec![]), 1_000);

    let receipt = chain.done(&alice, t, "transfer", send_args(&b, 300), 0);
    assert_eq!(holds(&chain, t, &a), 700);
    assert_eq!(holds(&chain, t, &b), 300);
    assert_eq!(receipt.events.len(), 1);
    assert_eq!(receipt.events[0].contract, t);
    assert_eq!(receipt.events[0].topic, b"transfer");
    assert_eq!(
        receipt.events[0].data,
        pack(&[a.as_bytes(), b.as_bytes(), &300u128.to_le_bytes()])
    );
    assert!(receipt.gas_used > 0 && receipt.gas_used < GAS);
}

#[test]
fn token_rules_hold() {
    let (alice, bob, carol) = (key(1), key(2), key(3));
    let (a, b, c) = (address(&alice), address(&bob), address(&carol));
    let mut chain = Chain::new(&[&alice, &bob, &carol]);
    let t = token(&mut chain, &a, 100);

    let too_much = chain
        .call(&alice, t, "transfer", send_args(&b, 101), 0)
        .unwrap();
    reverted(&too_much, "balance too low");

    let stolen = chain
        .call(
            &carol,
            t,
            "transfer_from",
            pack(&[a.as_bytes(), c.as_bytes(), &5u128.to_le_bytes()]),
            0,
        )
        .unwrap();
    reverted(&stolen, "allowance too low");

    chain.done(&alice, t, "approve", send_args(&c, 30), 0);
    assert_eq!(
        chain.view_u128(t, "allowance", pack(&[a.as_bytes(), c.as_bytes()])),
        30
    );
    chain.done(
        &carol,
        t,
        "transfer_from",
        pack(&[a.as_bytes(), b.as_bytes(), &20u128.to_le_bytes()]),
        0,
    );
    assert_eq!(holds(&chain, t, &b), 20);
    assert_eq!(
        chain.view_u128(t, "allowance", pack(&[a.as_bytes(), c.as_bytes()])),
        10
    );

    let minted = chain
        .call(&bob, t, "mint", send_args(&b, 1_000), 0)
        .unwrap();
    reverted(&minted, "only the owner can do that");
    chain.done(&alice, t, "mint", send_args(&b, 1_000), 0);
    chain.done(&bob, t, "burn", 500u128.to_le_bytes().to_vec(), 0);
    assert_eq!(chain.view_u128(t, "total_supply", vec![]), 600);
    assert_eq!(chain.view(t, "owner", vec![]).output, a.as_bytes());
}

#[test]
fn a_token_says_what_it_is_and_minting_can_end() {
    let (alice, bob) = (key(1), key(2));
    let (a, b) = (address(&alice), address(&bob));
    let mut chain = Chain::new(&[&alice, &bob]);
    let t = chain.deploy(TOKEN, token_args(&a, 100, "Qubits Dollar", "qUSD"));
    assert_eq!(chain.view(t, "name", vec![]).output, b"Qubits Dollar");
    assert_eq!(chain.view(t, "symbol", vec![]).output, b"qUSD");
    assert_eq!(chain.view(t, "decimals", vec![]).output, 6u64.to_le_bytes());

    let taken = chain
        .call(&bob, t, "set_owner", b.as_bytes().to_vec(), 0)
        .unwrap();
    reverted(&taken, "only the owner can do that");
    chain.done(&alice, t, "set_owner", b.as_bytes().to_vec(), 0);
    let late = chain.call(&alice, t, "mint", send_args(&a, 1), 0).unwrap();
    reverted(&late, "only the owner can do that");
    chain.done(&bob, t, "mint", send_args(&b, 5), 0);

    chain.done(&bob, t, "set_owner", vec![0; 32], 0);
    let ended = chain.call(&bob, t, "mint", send_args(&b, 1), 0).unwrap();
    reverted(&ended, "only the owner can do that");
    assert_eq!(chain.view_u128(t, "total_supply", vec![]), 105);
}

fn open_args(
    payee: &Address,
    arbiter: &Address,
    asset: &Address,
    amount: u128,
    deadline: u64,
) -> Vec<u8> {
    pack(&[
        payee.as_bytes(),
        arbiter.as_bytes(),
        asset.as_bytes(),
        &amount.to_le_bytes(),
        &deadline.to_le_bytes(),
    ])
}

const NATIVE: Address = Address([0; 32]);

#[test]
fn escrow_settles_the_native_token() {
    let (payer, payee, arbiter) = (key(1), key(2), key(3));
    let (p, q, r) = (address(&payer), address(&payee), address(&arbiter));
    let mut chain = Chain::new(&[&payer, &payee, &arbiter]);
    let escrow = chain.deploy(ESCROW, vec![]);
    let deadline = chain.now + 10_000;
    let id = 0u64.to_le_bytes().to_vec();

    let short = chain
        .call(
            &payer,
            escrow,
            "open",
            open_args(&q, &r, &NATIVE, 500, deadline),
            499,
        )
        .unwrap();
    reverted(&short, "send the amount with the call");
    assert_eq!(
        chain.balance(&escrow),
        0,
        "what came with a failed call went back"
    );

    let opened = chain.done(
        &payer,
        escrow,
        "open",
        open_args(&q, &r, &NATIVE, 500, deadline),
        500,
    );
    assert_eq!(opened.output, id);
    assert_eq!(chain.balance(&escrow), 500);

    let taken = chain
        .call(&payee, escrow, "release", id.clone(), 0)
        .unwrap();
    reverted(&taken, "only the payer or the arbiter can release");

    let before = chain.balance(&q);
    chain.done(&arbiter, escrow, "release", id.clone(), 0);
    assert_eq!(chain.balance(&q), before + 500);
    assert_eq!(chain.balance(&escrow), 0);

    let twice = chain.call(&arbiter, escrow, "release", id, 0).unwrap();
    reverted(&twice, "no such deal");
    let _ = p;
}

#[test]
fn escrow_gives_the_payer_a_way_out_only_after_the_deadline() {
    let (payer, payee, arbiter) = (key(1), key(2), key(3));
    let (p, q, r) = (address(&payer), address(&payee), address(&arbiter));
    let mut chain = Chain::new(&[&payer, &payee, &arbiter]);
    let escrow = chain.deploy(ESCROW, vec![]);
    let deadline = chain.now + 10_000;
    chain.done(
        &payer,
        escrow,
        "open",
        open_args(&q, &r, &NATIVE, 500, deadline),
        500,
    );
    let id = 0u64.to_le_bytes().to_vec();

    let early = chain.call(&payer, escrow, "refund", id.clone(), 0).unwrap();
    assert!(matches!(early.outcome, Outcome::Reverted { .. }));
    assert_eq!(chain.balance(&escrow), 500);

    chain.now = deadline;
    let before = chain.balance(&p);
    let receipt = chain.done(&payer, escrow, "refund", id, 0);
    assert_eq!(chain.balance(&escrow), 0);
    let fees = before + 500 - chain.balance(&p);
    assert!(fees < 100_000, "the 500 came back, less the fee of {fees}");
    let _ = receipt;
}

#[test]
fn escrow_settles_a_token_through_a_call_between_contracts() {
    let (payer, payee, arbiter) = (key(1), key(2), key(3));
    let (p, q, r) = (address(&payer), address(&payee), address(&arbiter));
    let mut chain = Chain::new(&[&payer, &payee, &arbiter]);
    let t = token(&mut chain, &p, 1_000);
    let escrow = chain.deploy(ESCROW, vec![]);
    let deadline = chain.now + 10_000;

    let unapproved = chain
        .call(
            &payer,
            escrow,
            "open",
            open_args(&q, &r, &t, 400, deadline),
            0,
        )
        .unwrap();
    reverted(&unapproved, "token transfer failed");

    chain.done(&payer, t, "approve", send_args(&escrow, 400), 0);
    let opened = chain.done(
        &payer,
        escrow,
        "open",
        open_args(&q, &r, &t, 400, deadline),
        0,
    );
    assert_eq!(holds(&chain, t, &p), 600);
    assert_eq!(holds(&chain, t, &escrow), 400);
    assert_eq!(opened.events.len(), 2, "the token's event and the escrow's");

    chain.done(&payer, escrow, "release", 0u64.to_le_bytes().to_vec(), 0);
    assert_eq!(holds(&chain, t, &q), 400);
    assert_eq!(holds(&chain, t, &escrow), 0);
}

#[test]
fn only_governance_can_deploy() {
    let alice = key(1);
    let mut chain = Chain::new(&[&alice]);
    let payload = Payload::Deploy {
        code: TOKEN.to_vec(),
        args: vec![],
        gas_limit: GAS,
    };
    let stx = chain.from(&alice, payload);
    assert_eq!(chain.submit(stx), Err(TxError::NotGovernance));
}

#[test]
fn governance_can_do_nothing_else_new() {
    let alice = key(1);
    let mut chain = Chain::new(&[&alice]);
    let t = token(&mut chain, &address(&alice), 1);
    let council = AuthPolicy::single(chain.validator.public_key().clone());
    let payload = call_payload(t, "total_supply", vec![], 0, GAS);
    let stx = chain.signed(&chain.validator, governance_address(), &council, payload);
    assert_eq!(chain.submit(stx), Err(TxError::NotAllowedForGovernance));
}

#[test]
fn nobody_can_spend_from_a_contract_address() {
    let alice = key(1);
    let mut chain = Chain::new(&[&alice]);
    let contract = chain.deploy(&wasm(r#"(module (memory (export "memory") 1))"#), vec![]);
    let fund = chain.from(
        &alice,
        Payload::Transfer {
            to: contract,
            asset: AssetId::NATIVE,
            amount: 1_000_000,
        },
    );
    chain.submit(fund).unwrap();
    let stx = chain.signed(
        &alice,
        contract,
        &AuthPolicy::single(alice.public_key().clone()),
        Payload::Transfer {
            to: address(&alice),
            asset: AssetId::NATIVE,
            amount: 1,
        },
    );
    assert_eq!(chain.submit(stx), Err(TxError::RevealMismatch));
    assert_eq!(chain.balance(&contract), 1_000_000);
}

const WRITE_THEN_REVERT: &str = r#"(module
  (import "qubits" "revert" (func $revert (param i32 i32)))
  (import "qubits" "set" (func $set (param i32 i32 i32 i32)))
  (import "qubits" "emit" (func $emit (param i32 i32 i32 i32)))
  (import "qubits" "transfer" (func $transfer (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "key")
  (data (i32.const 8) "no")
  (func (export "bounce")
    (call $set (i32.const 0) (i32.const 3) (i32.const 0) (i32.const 3))
    (call $emit (i32.const 0) (i32.const 3) (i32.const 0) (i32.const 3))
    (call $revert (i32.const 8) (i32.const 2))))"#;

#[test]
fn a_revert_undoes_the_contract_but_the_fee_and_nonce_stand() {
    let alice = key(1);
    let a = address(&alice);
    let mut chain = Chain::new(&[&alice]);
    let contract = chain.deploy(&wasm(WRITE_THEN_REVERT), vec![]);
    let before = chain.balance(&a);
    let stx = chain.from(&alice, call_payload(contract, "bounce", vec![], 700, GAS));
    let fee = stx.tx.fee;
    let receipt = chain.submit(stx).unwrap();

    reverted(&receipt, "no");
    assert!(
        receipt.events.is_empty(),
        "events of a failed call are gone"
    );
    assert_eq!(chain.stored(contract, b"key"), None);
    assert_eq!(chain.balance(&contract), 0);
    assert_eq!(chain.account(&a).nonce, 1);
    let gas_left = GAS - receipt.gas_used;
    assert_eq!(
        chain.balance(&a),
        before - fee + u128::from(gas_left / GAS_PER_BYTE)
    );
}

#[test]
fn unused_gas_comes_back_and_used_gas_does_not() {
    let (alice, bob) = (key(1), key(2));
    let a = address(&alice);
    let mut chain = Chain::new(&[&alice]);
    let t = token(&mut chain, &a, 100);
    let before = chain.balance(&a);
    let stx = chain.from(
        &alice,
        call_payload(t, "transfer", send_args(&address(&bob), 1), 0, MAX_TX_GAS),
    );
    let fee = stx.tx.fee;
    let receipt = chain.submit(stx).unwrap();
    assert_eq!(receipt.outcome, Outcome::Done);
    let paid = before - chain.balance(&a);
    assert!(paid < fee, "most of the gas limit was not used");
    assert_eq!(
        paid,
        fee - u128::from((MAX_TX_GAS - receipt.gas_used) / GAS_PER_BYTE)
    );
}

#[test]
fn an_endless_loop_burns_its_gas_and_stops() {
    let alice = key(1);
    let a = address(&alice);
    let mut chain = Chain::new(&[&alice]);
    let spin = chain.deploy(
        &wasm(
            r#"(module
        (memory (export "memory") 1)
        (func (export "spin") (loop $l (br $l))))"#,
        ),
        vec![],
    );
    let before = chain.balance(&a);
    let stx = chain.from(&alice, call_payload(spin, "spin", vec![], 0, GAS));
    let fee = stx.tx.fee;
    let receipt = chain.submit(stx).unwrap();
    assert_eq!(receipt.outcome, Outcome::OutOfGas);
    assert_eq!(receipt.gas_used, GAS);
    assert_eq!(chain.balance(&a), before - fee, "nothing refunded");
}

#[test]
fn the_fee_must_cover_the_gas_limit() {
    let alice = key(1);
    let mut chain = Chain::new(&[&alice]);
    let t = token(&mut chain, &address(&alice), 1);
    let policy = AuthPolicy::single(alice.public_key().clone());
    let payload = call_payload(t, "total_supply", vec![], 0, GAS);
    let stx = chain.signed_with_fee(&alice, address(&alice), &policy, payload, Some(5_000));
    assert!(matches!(chain.submit(stx), Err(TxError::FeeTooLow { .. })));

    let payload = call_payload(t, "total_supply", vec![], 0, MAX_TX_GAS + 1);
    let stx = chain.from(&alice, payload);
    assert_eq!(chain.submit(stx), Err(TxError::GasTooHigh));
}

#[test]
fn calling_what_is_not_there_is_refused_before_it_costs_anything() {
    let alice = key(1);
    let mut chain = Chain::new(&[&alice]);
    let t = token(&mut chain, &address(&alice), 1);
    let nothing = Address([9; 32]);
    assert_eq!(
        chain.call(&alice, nothing, "x", vec![], 0),
        Err(TxError::NotAContract)
    );
    assert_eq!(
        chain.call(&alice, t, "init", vec![], 0),
        Err(TxError::NotCallable)
    );
    let missing = chain
        .call(&alice, t, "no_such_function", vec![], 0)
        .unwrap();
    assert_eq!(missing.outcome, Outcome::Invalid);
}

#[test]
fn a_failed_deployment_leaves_no_contract() {
    let mut chain = Chain::new(&[]);
    let bad_init = wasm(
        r#"(module
        (memory (export "memory") 1)
        (func (export "init") unreachable))"#,
    );
    let address_next = contract_address(&governance_address(), 0);
    let receipt = chain
        .submit(chain.deploy_tx(&bad_init, vec![], GAS))
        .unwrap();
    assert_eq!(receipt.outcome, Outcome::Trapped);
    assert_eq!(receipt.contract, None);
    assert_eq!(
        chain.state.get(&keys::contract(&address_next)).unwrap(),
        None
    );
    assert_eq!(
        chain.state.get(&keys::code(&code_hash(&bad_init))).unwrap(),
        None
    );

    let garbage = chain
        .submit(chain.deploy_tx(b"not wasm", vec![], GAS))
        .unwrap();
    assert_eq!(garbage.outcome, Outcome::Invalid);

    let cheap = chain.submit(chain.deploy_tx(TOKEN, vec![], 1_000)).unwrap();
    assert_eq!(cheap.outcome, Outcome::OutOfGas, "state costs gas");
}

#[test]
fn the_chain_knows_every_contract_and_no_failed_one() {
    let alice = key(1);
    let mut chain = Chain::new(&[&alice]);
    assert_eq!(read_contracts(&chain.state).unwrap(), Vec::<Address>::new());
    let t = token(&mut chain, &address(&alice), 1);
    let refused =
        wasm(r#"(module (memory (export "memory") 1) (func (export "init") unreachable))"#);
    let receipt = chain
        .submit(chain.deploy_tx(&refused, vec![], GAS))
        .unwrap();
    assert_eq!(receipt.outcome, Outcome::Trapped);
    let escrow = chain.deploy(ESCROW, vec![]);
    assert_eq!(read_contracts(&chain.state).unwrap(), [t, escrow]);
}

fn vault(chain: &mut Chain, owner: &SecretKey, recovery: &AuthPolicy) {
    let policy = VaultPolicy {
        delay_ms: DELAY,
        recovery: Some(recovery.clone()),
    };
    let stx = chain.from(
        owner,
        Payload::SetVault {
            vault: Some(policy),
        },
    );
    chain.submit(stx).unwrap();
}

#[test]
fn a_stolen_vault_key_cannot_move_tokens_through_a_contract() {
    let (owner, thief, recovery, relayer) = (key(1), key(2), key(3), key(4));
    let (a, t_addr) = (address(&owner), address(&thief));
    let recovery_policy = AuthPolicy::single(recovery.public_key().clone());
    let mut chain = Chain::new(&[&owner, &relayer]);
    let t = token(&mut chain, &a, 1_000);
    vault(&mut chain, &owner, &recovery_policy);

    let receipt = chain.done(&owner, t, "transfer", send_args(&t_addr, 1_000), 0);
    assert_eq!(receipt, Receipt::default(), "it only went into the queue");
    assert_eq!(holds(&chain, t, &a), 1_000, "nothing moved");
    assert_eq!(chain.account(&a).pending.len(), 1);

    let exec = chain.from(&relayer, Payload::ExecutePending { account: a, id: 0 });
    assert!(matches!(
        chain.submit(exec),
        Err(TxError::PendingLocked { .. })
    ));

    let mut cancel = Transaction {
        genesis_hash: chain.genesis_hash,
        sender: a,
        nonce: chain.account(&a).nonce,
        fee: 10_000,
        valid_until_ms: u64::MAX,
        role: Role::Recovery,
        payload: Payload::CancelPending { id: 0 },
    };
    cancel.fee = 16_000;
    let stx = SignedTransaction::sign(cancel, &recovery_policy, None, &[&recovery]).unwrap();
    chain.submit(stx).unwrap();
    chain.now += DELAY;
    let exec = chain.from(&relayer, Payload::ExecutePending { account: a, id: 0 });
    assert_eq!(chain.submit(exec), Err(TxError::PendingNotFound));
    assert_eq!(holds(&chain, t, &a), 1_000);
}

#[test]
fn a_vault_call_runs_after_the_delay_as_the_vault() {
    let (owner, bob, recovery, relayer) = (key(1), key(2), key(3), key(4));
    let (a, b) = (address(&owner), address(&bob));
    let recovery_policy = AuthPolicy::single(recovery.public_key().clone());
    let mut chain = Chain::new(&[&owner, &relayer]);
    let t = token(&mut chain, &a, 1_000);
    vault(&mut chain, &owner, &recovery_policy);
    chain.done(&owner, t, "transfer", send_args(&b, 250), 0);

    chain.now += DELAY;
    let relayer_before = chain.balance(&address(&relayer));
    let exec = chain.from(&relayer, Payload::ExecutePending { account: a, id: 0 });
    let fee = exec.tx.fee;
    let receipt = chain.submit(exec).unwrap();
    assert_eq!(receipt.outcome, Outcome::Done);
    assert_eq!(holds(&chain, t, &a), 750);
    assert_eq!(holds(&chain, t, &b), 250);
    assert_eq!(
        chain.balance(&address(&relayer)),
        relayer_before - fee,
        "the gas was paid when it was queued, by the vault"
    );
}

#[test]
fn a_vault_cannot_send_native_tokens_to_a_contract_at_once() {
    let (owner, recovery) = (key(1), key(3));
    let a = address(&owner);
    let recovery_policy = AuthPolicy::single(recovery.public_key().clone());
    let mut chain = Chain::new(&[&owner]);
    let escrow = chain.deploy(ESCROW, vec![]);
    vault(&mut chain, &owner, &recovery_policy);
    let deadline = chain.now + 10 * DELAY;
    chain.done(
        &owner,
        escrow,
        "open",
        open_args(&a, &a, &NATIVE, 1_000, deadline),
        1_000,
    );
    assert_eq!(chain.balance(&escrow), 0);
}

#[test]
fn a_queued_call_cannot_spend_the_recovery_fee() {
    let (owner, recovery, relayer) = (key(1), key(3), key(4));
    let a = address(&owner);
    let recovery_policy = AuthPolicy::single(recovery.public_key().clone());
    let mut chain = Chain::new(&[&owner, &relayer]);
    let escrow = chain.deploy(ESCROW, vec![]);
    vault(&mut chain, &owner, &recovery_policy);
    let reserve = recovery_reserve(&params());
    let deadline = chain.now + 10 * DELAY;
    let open = |amount: u128| {
        let args = open_args(&a, &a, &NATIVE, amount, deadline);
        call_payload(escrow, "open", args, amount, GAS)
    };

    let fee = chain.from(&owner, open(0)).tx.fee;
    let too_much = chain.balance(&a) - fee - reserve + 1;
    assert_eq!(
        chain.submit(chain.from(&owner, open(too_much))),
        Err(TxError::RecoveryReserve { reserve })
    );

    chain.submit(chain.from(&owner, open(2_000))).unwrap();
    let most = chain.balance(&a) - fee - reserve - 1_000;
    chain.submit(chain.from(&owner, open(most))).unwrap();

    chain.now += DELAY;
    let exec = |id| Payload::ExecutePending { account: a, id };
    let receipt = chain.submit(chain.from(&relayer, exec(1))).unwrap();
    assert_eq!(receipt.outcome, Outcome::Done);
    assert_eq!(chain.balance(&a), reserve + 1_000);

    let receipt = chain.submit(chain.from(&relayer, exec(0))).unwrap();
    reverted(&receipt, "insufficient balance");
    assert_eq!(receipt.gas_used, 0);
    assert_eq!(chain.balance(&a), reserve + 1_000);
    assert!(chain.account(&a).pending.is_empty());
}

/// `bounce(next, rest...)`: notes that it ran, then calls `next.bounce(rest...)`. Records
/// `failed` if that call fails.
const BOUNCE: &str = r#"(module
  (import "qubits" "input_size" (func $size (result i32)))
  (import "qubits" "input" (func $input (param i32)))
  (import "qubits" "call" (func $call (param i32 i32 i32 i32 i32 i32) (result i32)))
  (import "qubits" "set" (func $set (param i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 60000) "bounce")
  (data (i32.const 60010) "ran")
  (data (i32.const 60020) "failed")
  (func (export "bounce")
    (local $n i32)
    (local.set $n (call $size))
    (call $input (i32.const 0))
    (call $set (i32.const 60010) (i32.const 3) (i32.const 60010) (i32.const 3))
    (if (i32.ge_u (local.get $n) (i32.const 32))
      (then
        (if (call $call
              (i32.const 0)
              (i32.const 60000) (i32.const 6)
              (i32.const 32) (i32.sub (local.get $n) (i32.const 32))
              (i32.const 61000))
          (then (call $set (i32.const 60020) (i32.const 6) (i32.const 60020) (i32.const 6))))))))"#;

#[test]
fn a_failed_callee_is_undone_and_the_caller_carries_on() {
    let alice = key(1);
    let mut chain = Chain::new(&[&alice]);
    let bouncer = chain.deploy(&wasm(BOUNCE), vec![]);
    let failing = chain.deploy(&wasm(WRITE_THEN_REVERT), vec![]);
    let receipt = chain.done(&alice, bouncer, "bounce", failing.as_bytes().to_vec(), 0);
    assert!(receipt.events.is_empty());
    assert_eq!(chain.stored(failing, b"key"), None, "undone");
    assert!(
        chain.stored(bouncer, b"failed").is_some(),
        "and the caller knew"
    );
    assert!(chain.stored(bouncer, b"ran").is_some(), "and kept going");
}

#[test]
fn a_contract_cannot_be_reentered() {
    let alice = key(1);
    let mut chain = Chain::new(&[&alice]);
    let first = chain.deploy(&wasm(BOUNCE), vec![]);
    let second = chain.deploy(&wasm(BOUNCE), vec![]);
    let path = pack(&[second.as_bytes(), first.as_bytes()]);
    chain.done(&alice, first, "bounce", path, 0);
    assert!(
        chain.stored(second, b"failed").is_some(),
        "second could not call first back"
    );
    assert_eq!(
        chain.stored(first, b"failed"),
        None,
        "first's call to second went fine"
    );
}

#[test]
fn calls_go_only_so_deep() {
    let alice = key(1);
    let mut chain = Chain::new(&[&alice]);
    let code = wasm(BOUNCE);
    let chain_of: Vec<Address> = (0..=MAX_CALL_DEPTH)
        .map(|_| chain.deploy(&code, vec![]))
        .collect();
    let path: Vec<&[u8]> = chain_of[1..]
        .iter()
        .map(|a| a.as_bytes().as_slice())
        .collect();
    chain.done(&alice, chain_of[0], "bounce", path.concat(), 0);
    let last_that_ran = MAX_CALL_DEPTH - 1;
    assert!(chain.stored(chain_of[last_that_ran], b"ran").is_some());
    assert!(chain.stored(chain_of[last_that_ran], b"failed").is_some());
    assert_eq!(chain.stored(chain_of[MAX_CALL_DEPTH], b"ran"), None);
}

#[test]
fn a_contract_reaches_only_its_own_storage() {
    let alice = key(1);
    let mut chain = Chain::new(&[&alice]);
    let code = wasm(BOUNCE);
    let (one, other) = (chain.deploy(&code, vec![]), chain.deploy(&code, vec![]));
    chain.done(&alice, one, "bounce", vec![], 0);
    assert!(chain.stored(one, b"ran").is_some());
    assert_eq!(chain.stored(other, b"ran"), None);
}

fn outcome_of(body: &str) -> Outcome {
    let alice = key(1);
    let mut chain = Chain::new(&[&alice]);
    let code = wasm(&format!(
        r#"(module
  (import "qubits" "set" (func $set (param i32 i32 i32 i32)))
  (import "qubits" "output" (func $output (param i32 i32)))
  (import "qubits" "input" (func $input (param i32)))
  (import "qubits" "emit" (func $emit (param i32 i32 i32 i32)))
  (import "qubits" "get" (func $get (param i32 i32 i32 i32) (result i32)))
  (import "qubits" "call" (func $call (param i32 i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  {body})"#
    ));
    let contract = chain.deploy(&code, vec![]);
    chain
        .call(&alice, contract, "go", vec![], 0)
        .unwrap()
        .outcome
}

#[test]
fn hostile_host_calls_stop_the_contract_and_not_the_node() {
    for body in [
        // lengths past everything: these must not overflow or allocate
        r#"(func (export "go") (call $set (i32.const 0) (i32.const -1) (i32.const 0) (i32.const -1)))"#,
        r#"(func (export "go") (call $emit (i32.const 0) (i32.const -1) (i32.const 0) (i32.const -1)))"#,
    ] {
        assert_eq!(outcome_of(body), Outcome::OutOfGas, "{body}");
    }
    for body in [
        // pointers outside memory
        r#"(func (export "go") (call $output (i32.const 70000) (i32.const 100)))"#,
        r#"(func (export "go") (call $set (i32.const 65530) (i32.const 100) (i32.const 0) (i32.const 1)))"#,
        r#"(func (export "go") (drop (call $get (i32.const 65530) (i32.const 100) (i32.const 0) (i32.const 1))))"#,
        // over the limits
        r#"(func (export "go") (call $set (i32.const 0) (i32.const 129) (i32.const 0) (i32.const 1)))"#,
        r#"(func (export "go") (call $set (i32.const 0) (i32.const 1) (i32.const 0) (i32.const 16385)))"#,
        r#"(func (export "go") (drop (call $call (i32.const 0) (i32.const 0) (i32.const -1) (i32.const 0) (i32.const 0) (i32.const 0))))"#,
        // the plain traps
        r#"(func (export "go") unreachable)"#,
        r#"(func (export "go") (drop (i32.div_u (i32.const 1) (i32.const 0))))"#,
        r#"(func (export "go") (drop (i32.load (i32.const 70000))))"#,
        r#"(func $down (call $down)) (func (export "go") (call $down))"#,
    ] {
        assert_eq!(outcome_of(body), Outcome::Trapped, "{body}");
    }
}

#[test]
fn memory_stops_at_the_limit() {
    let grow = r#"(func (export "go")
        (if (i32.ne (memory.grow (i32.const 65535)) (i32.const -1)) (then unreachable)))"#;
    assert_eq!(
        outcome_of(grow),
        Outcome::Done,
        "the grow fails, the contract can see that"
    );
}

#[test]
fn a_table_stops_at_the_limit() {
    let mut chain = Chain::new(&[]);
    let largest = r#"(module (memory (export "memory") 1) (table 4096 funcref))"#;
    let receipt = chain
        .submit(chain.deploy_tx(&wasm(largest), vec![], GAS))
        .unwrap();
    assert_eq!(receipt.outcome, Outcome::Done);
    let grow = r#"(module (memory (export "memory") 1) (table 4096 funcref)
        (func (export "init")
          (if (i32.ne (table.grow (ref.null func) (i32.const 1)) (i32.const -1)) (then unreachable))))"#;
    let receipt = chain
        .submit(chain.deploy_tx(&wasm(grow), vec![], GAS))
        .unwrap();
    assert_eq!(
        receipt.outcome,
        Outcome::Done,
        "the grow fails, the contract can see that"
    );
}

#[test]
fn code_that_could_differ_between_machines_is_refused() {
    let mut chain = Chain::new(&[]);
    for text in [
        r#"(module (memory (export "memory") 1)
             (func (export "init") (drop (f64.add (f64.const 1) (f64.const 2)))))"#,
        r#"(module (memory (export "memory") 1)
             (func $s) (start $s))"#,
        r#"(module (import "env" "anything" (func)) (memory (export "memory") 1))"#,
        r#"(module (func (export "init")))"#,
        r#"(module (memory (export "memory") 65))"#,
        r#"(module (memory (export "memory") 1) (table 4097 funcref))"#,
        r#"(module (memory (export "memory") 1) (table 1000000 funcref))"#,
    ] {
        let receipt = chain
            .submit(chain.deploy_tx(&wasm(text), vec![], GAS))
            .unwrap();
        assert_eq!(receipt.outcome, Outcome::Invalid, "{text}");
        assert_eq!(receipt.contract, None);
    }
}

#[test]
fn gas_limits_in_a_block_are_capped() {
    let (a, b, c) = (key(1), key(2), key(3));
    let mut chain = Chain::new(&[&a, &b, &c]);
    let t = token(&mut chain, &address(&a), 1);
    let call =
        |chain: &Chain, sk| chain.from(sk, call_payload(t, "total_supply", vec![], 0, MAX_TX_GAS));
    let txs = [call(&chain, &a), call(&chain, &b)];
    const { assert!(MAX_TX_GAS * 2 <= MAX_BLOCK_GAS) };
    chain.block(&txs).unwrap();
    let txs = [call(&chain, &a), call(&chain, &b), call(&chain, &c)];
    assert!(matches!(
        chain.block(&txs),
        Err(BlockError::Transaction {
            index: 2,
            error: TxError::BlockGasFull,
            ..
        })
    ));
}

#[test]
fn taking_a_transaction_in_runs_nothing() {
    let alice = key(1);
    let mut chain = Chain::new(&[&alice]);
    let spin = chain.deploy(
        &wasm(
            r#"(module
        (memory (export "memory") 1)
        (func (export "spin") (loop $l (br $l))))"#,
        ),
        vec![],
    );
    let stx = chain.from(&alice, call_payload(spin, "spin", vec![], 0, MAX_TX_GAS));
    let mut executor = Executor::new(&chain.state, chain.env()).without_contracts();
    executor.apply(&stx).unwrap();
    assert_eq!(executor.receipts(), [Receipt::default()]);
}

#[test]
fn a_block_comes_out_the_same_every_time() {
    let (alice, bob) = (key(1), key(2));
    let (a, b) = (address(&alice), address(&bob));
    let mut chain = Chain::new(&[&alice, &bob]);
    let t = token(&mut chain, &a, 1_000);
    let escrow = chain.deploy(ESCROW, vec![]);
    let txs = [
        chain.from(
            &alice,
            call_payload(t, "transfer", send_args(&b, 300), 0, GAS),
        ),
        chain.from(
            &bob,
            call_payload(
                escrow,
                "open",
                open_args(&a, &a, &NATIVE, 5, u64::MAX),
                5,
                GAS,
            ),
        ),
    ];
    let first = execute_block(&chain.state, chain.env(), &txs).unwrap();
    let second = execute_block(&chain.state, chain.env(), &txs).unwrap();
    assert_eq!(first.writes, second.writes);
    assert_eq!(first.receipts, second.receipts);
    assert_eq!(
        receipt_root(&first.receipts),
        receipt_root(&second.receipts)
    );
    assert_ne!(receipt_root(&first.receipts), Hash::ZERO);
}

#[test]
fn a_view_changes_nothing() {
    let alice = key(1);
    let a = address(&alice);
    let mut chain = Chain::new(&[&alice]);
    let t = token(&mut chain, &a, 100);
    let bouncer = chain.deploy(&wasm(BOUNCE), vec![]);

    let receipt = chain.view(t, "balance_of", a.as_bytes().to_vec());
    assert_eq!(receipt.output, 100u128.to_le_bytes());
    assert_eq!(chain.view(bouncer, "bounce", vec![]).outcome, Outcome::Done);
    assert_eq!(chain.stored(bouncer, b"ran"), None);

    let env = chain.env();
    assert_eq!(
        view(&chain.state, env.clone(), &Address([9; 32]), "x", &[]),
        Err(TxError::NotAContract)
    );
    assert_eq!(
        view(&chain.state, env, &t, "init", &[]),
        Err(TxError::NotCallable)
    );
}

#[test]
fn a_simulation_shows_what_a_call_would_do_for_its_caller() {
    let (alice, bob) = (key(1), key(2));
    let (a, b) = (address(&alice), address(&bob));
    let mut chain = Chain::new(&[&alice, &bob]);
    let t = token(&mut chain, &a, 100);
    let escrow = chain.deploy(ESCROW, vec![]);
    let run = |chain: &Chain, who: &Address, to: Address, function: &str, args: Vec<u8>, amount| {
        simulate(&chain.state, chain.env(), who, &to, function, &args, amount).unwrap()
    };

    let sent = run(&chain, &a, t, "transfer", send_args(&b, 30), 0);
    assert_eq!(sent.receipt.outcome, Outcome::Done);
    assert_eq!(sent.receipt.events[0].topic, b"transfer");
    assert_eq!(holds(&chain, t, &a), 100);
    let refused = run(&chain, &b, t, "transfer", send_args(&a, 30), 0);
    reverted(&refused.receipt, "balance too low");

    let before = chain.balance(&a);
    let deadline = chain.now + 10_000;
    let args = open_args(&b, &b, &NATIVE, 500, deadline);
    let opened = run(&chain, &a, escrow, "open", args, 500);
    assert_eq!(
        opened.receipt.outcome,
        Outcome::Done,
        "{:?}",
        opened.receipt
    );
    assert_eq!(opened.balance_after, before - 500);
    assert_eq!(chain.balance(&a), before);

    let too_much = run(
        &chain,
        &a,
        escrow,
        "open",
        open_args(&b, &b, &NATIVE, 5, deadline),
        before + 1,
    );
    reverted(&too_much.receipt, "insufficient balance");
    assert_eq!(too_much.balance_after, before);
}

fn escaped(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("\\{b:02x}")).collect()
}

#[test]
fn a_contract_checks_a_post_quantum_signature() {
    let (alice, signer) = (key(1), key(9));
    let mut chain = Chain::new(&[&alice]);
    let message = b"pay bob 5";
    let good = signer.sign(Domain::Message, message).unwrap();
    let wrong_domain = signer.sign(Domain::Transaction, message).unwrap();
    let raw_key = signer.public_key().as_raw().to_vec();
    let checker = |signature: &[u8]| {
        wasm(&format!(
            r#"(module
  (import "qubits" "verify" (func $verify (param i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{key}")
  (data (i32.const 4000) "{message}")
  (data (i32.const 8000) "{signature}")
  (func (export "check")
    (if (call $verify (i32.const 1)
          (i32.const 0) (i32.const {key_len})
          (i32.const 4000) (i32.const {message_len})
          (i32.const 8000) (i32.const {signature_len}))
      (then unreachable))))"#,
            key = escaped(&raw_key),
            key_len = raw_key.len(),
            message = escaped(message),
            message_len = message.len(),
            signature = escaped(signature),
            signature_len = signature.len(),
        ))
    };
    let accepts = chain.deploy(&checker(good.as_raw()), vec![]);
    chain.done(&alice, accepts, "check", vec![], 0);

    let refuses = chain.deploy(&checker(wrong_domain.as_raw()), vec![]);
    let receipt = chain.call(&alice, refuses, "check", vec![], 0).unwrap();
    assert_eq!(
        receipt.outcome,
        Outcome::Trapped,
        "a transaction signature is not a message"
    );
}
