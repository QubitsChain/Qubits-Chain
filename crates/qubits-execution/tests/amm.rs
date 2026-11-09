//! The market contract. Exact numbers come from unbounded integers outside this code, and the
//! random trading at the end holds it to what must be true whatever anyone does.

mod common;

use common::*;
use qubits_execution::{TxError, read_contracts};
use qubits_types::limits::MAX_TX_GAS;
use qubits_types::*;

const AMM: &[u8] = include_bytes!("../../../contracts/out/amm.wasm");
const NATIVE: Address = Address([0; 32]);
const LATER: u64 = u64::MAX;
const LOCKED: u128 = 1_000;
const GAS_FOR_THE_MARKET: u64 = 3_000_000;
const ONE: u128 = 1_000_000_000_000_000_000;
const SUPPLY: u128 = 1_000_000 * ONE;

struct Market {
    chain: Chain,
    amm: Address,
    protocol: Address,
    t: Address,
    u: Address,
    alice: qubits_crypto::SecretKey,
    bob: qubits_crypto::SecretKey,
    a: Address,
    b: Address,
}

fn market() -> Market {
    market_funded(1_000_000_000)
}

fn launchpad() -> Market {
    market_funded(1_000_000 * ONE)
}

fn market_funded(balance: Amount) -> Market {
    let (alice, bob) = (key(1), key(2));
    let (a, b) = (address(&alice), address(&bob));
    let mut chain = Chain::funded(&[&alice, &bob], balance);
    let supply = 1u128 << 120;
    let t = token(&mut chain, &a, supply);
    let u = token(&mut chain, &a, supply);
    let protocol = address(&key(5));
    let amm = chain.deploy(AMM, amm_args(&protocol, code_hash(TOKEN)));
    let mut m = Market {
        chain,
        amm,
        protocol,
        t,
        u,
        alice,
        bob,
        a,
        b,
    };
    for asset in [m.t, m.u] {
        m.give_bob(asset, 1 << 118);
        m.approve_all(asset);
    }
    m
}

fn u(value: u128) -> [u8; 16] {
    value.to_le_bytes()
}

fn amm_args(protocol: &Address, token_code: Hash) -> Vec<u8> {
    pack(&[protocol.as_bytes(), &token_code.0])
}

fn text(value: &str) -> Vec<u8> {
    pack(&[&(value.len() as u32).to_le_bytes(), value.as_bytes()])
}

fn created(receipt: &Receipt) -> (Address, u128) {
    assert_eq!(receipt.outcome, Outcome::Done, "{receipt:?}");
    let token = Address(receipt.output[..32].try_into().unwrap());
    (
        token,
        u128::from_le_bytes(receipt.output[32..].try_into().unwrap()),
    )
}

impl Market {
    fn give_bob(&mut self, asset: Address, amount: u128) {
        let args = send_args(&self.b, amount);
        let alice = self.alice.clone();
        self.chain.done(&alice, asset, "transfer", args, 0);
    }

    fn approve_all(&mut self, asset: Address) {
        let args = send_args(&self.amm, u128::MAX >> 1);
        for sk in [self.alice.clone(), self.bob.clone()] {
            self.chain.done(&sk, asset, "approve", args.clone(), 0);
        }
    }

    fn send(
        &mut self,
        sk: &qubits_crypto::SecretKey,
        function: &str,
        args: Vec<u8>,
        amount: Amount,
    ) -> Receipt {
        let payload = Payload::Call {
            contract: self.amm,
            function: function.into(),
            args,
            amount,
            gas_limit: GAS_FOR_THE_MARKET,
        };
        self.chain.submit(self.chain.from(sk, payload)).unwrap()
    }

    fn add_args(&self, a: &Address, b: &Address, want_a: u128, want_b: u128) -> Vec<u8> {
        pack(&[
            a.as_bytes(),
            b.as_bytes(),
            &u(want_a),
            &u(want_b),
            &u(0),
            &u(0),
            &LATER.to_le_bytes(),
        ])
    }

    fn add(
        &mut self,
        sk: &qubits_crypto::SecretKey,
        a: Address,
        b: Address,
        want_a: u128,
        want_b: u128,
    ) -> Receipt {
        let native = if a == NATIVE {
            want_a
        } else if b == NATIVE {
            want_b
        } else {
            0
        };
        let args = self.add_args(&a, &b, want_a, want_b);
        self.send(sk, "add_liquidity", args, native)
    }

    fn swap_args(
        &self,
        from: &Address,
        to: &Address,
        amount: u128,
        min_out: u128,
        deadline: u64,
    ) -> Vec<u8> {
        pack(&[
            from.as_bytes(),
            to.as_bytes(),
            &u(amount),
            &u(min_out),
            &deadline.to_le_bytes(),
        ])
    }

    fn swap(
        &mut self,
        sk: &qubits_crypto::SecretKey,
        from: Address,
        to: Address,
        amount: u128,
    ) -> Receipt {
        let args = self.swap_args(&from, &to, amount, 0, LATER);
        let native = if from == NATIVE { amount } else { 0 };
        self.send(sk, "swap", args, native)
    }

    fn remove(
        &mut self,
        sk: &qubits_crypto::SecretKey,
        a: Address,
        b: Address,
        shares: u128,
    ) -> Receipt {
        let args = pack(&[
            a.as_bytes(),
            b.as_bytes(),
            &u(shares),
            &u(0),
            &u(0),
            &LATER.to_le_bytes(),
        ]);
        self.send(sk, "remove_liquidity", args, 0)
    }

    fn pool(&self, a: Address, b: Address) -> (u128, u128, u128) {
        let args = pack(&[a.as_bytes(), b.as_bytes()]);
        let receipt = self.chain.view(self.amm, "pool", args);
        assert_eq!(receipt.outcome, Outcome::Done, "{receipt:?}");
        let word = |i: usize| u128::from_le_bytes(receipt.output[i..i + 16].try_into().unwrap());
        (word(0), word(16), word(32))
    }

    fn shares(&self, a: Address, b: Address, who: &Address) -> u128 {
        let args = pack(&[a.as_bytes(), b.as_bytes(), who.as_bytes()]);
        self.chain.view_u128(self.amm, "shares", args)
    }

    fn holds(&self, asset: Address, who: &Address) -> u128 {
        if asset == NATIVE {
            self.chain.balance(who)
        } else {
            holds(&self.chain, asset, who)
        }
    }

    fn quote(&self, from: Address, to: Address, amount: u128) -> u128 {
        let args = pack(&[from.as_bytes(), to.as_bytes(), &u(amount)]);
        self.chain.view_u128(self.amm, "quote", args)
    }

    fn allow(&mut self, sk: &qubits_crypto::SecretKey, coin: Address, amount: u128) {
        let args = send_args(&self.amm, amount);
        self.chain.done(sk, coin, "approve", args, 0);
    }

    fn create(
        &mut self,
        sk: &qubits_crypto::SecretKey,
        name: &str,
        symbol: &str,
        virtual_native: u128,
        buy: u128,
    ) -> Receipt {
        let args = pack(&[&text(name), &text(symbol), &u(virtual_native)]);
        self.send(sk, "create", args, buy)
    }

    fn launched_coin(&mut self, virtual_native: u128) -> Address {
        let (alice, bob) = (self.alice.clone(), self.bob.clone());
        let (coin, _) = created(&self.create(&alice, "Coin", "COIN", virtual_native, 0));
        for sk in [&alice, &bob] {
            self.allow(sk, coin, u128::MAX >> 1);
        }
        coin
    }

    fn launched(&self, coin: Address) -> (u128, Address) {
        let receipt = self
            .chain
            .view(self.amm, "launched", coin.as_bytes().to_vec());
        assert_eq!(receipt.outcome, Outcome::Done, "{receipt:?}");
        let virtual_native = u128::from_le_bytes(receipt.output[..16].try_into().unwrap());
        (
            virtual_native,
            Address(receipt.output[16..].try_into().unwrap()),
        )
    }
}

fn done(receipt: &Receipt) -> u128 {
    assert_eq!(receipt.outcome, Outcome::Done, "{receipt:?}");
    u128::from_le_bytes(receipt.output.clone().try_into().unwrap_or([0; 16]))
}

#[test]
fn the_first_liquidity_sets_the_price_and_locks_a_little_for_good() {
    let mut m = market();
    let (alice, a) = (m.alice.clone(), m.a);
    let before = m.holds(m.t, &a);
    let minted = done(&m.add(&alice, m.t, m.u, 1_000_000, 4_000_000));
    assert_eq!(
        minted,
        2_000_000 - LOCKED,
        "the root of the product, less what is locked"
    );
    assert_eq!(m.pool(m.t, m.u), (1_000_000, 4_000_000, 2_000_000));
    assert_eq!(
        m.pool(m.u, m.t),
        (4_000_000, 1_000_000, 2_000_000),
        "either way round"
    );
    assert_eq!(m.shares(m.t, m.u, &a), minted);
    assert_eq!(before - m.holds(m.t, &a), 1_000_000);
    assert_eq!(m.holds(m.t, &m.amm), 1_000_000);
    assert_eq!(m.holds(m.u, &m.amm), 4_000_000);
}

#[test]
fn later_liquidity_takes_the_pools_ratio_and_only_what_it_needs() {
    let mut m = market();
    let (alice, bob, b) = (m.alice.clone(), m.bob.clone(), m.b);
    m.add(&alice, m.t, m.u, 1_000_000, 4_000_000);
    let (t_before, u_before) = (m.holds(m.t, &b), m.holds(m.u, &b));
    let minted = done(&m.add(&bob, m.t, m.u, 500_000, 3_000_000));
    assert_eq!(minted, 1_000_000);
    assert_eq!(t_before - m.holds(m.t, &b), 500_000);
    assert_eq!(u_before - m.holds(m.u, &b), 2_000_000);
    assert_eq!(m.pool(m.t, m.u), (1_500_000, 6_000_000, 3_000_000));
    let minted = done(&m.add(&bob, m.t, m.u, 9_000_000, 6_000_000));
    assert_eq!(minted, 3_000_000);
    assert_eq!(m.pool(m.t, m.u), (3_000_000, 12_000_000, 6_000_000));
}

#[test]
fn a_provider_is_protected_from_a_moved_price() {
    let mut m = market();
    let (alice, bob) = (m.alice.clone(), m.bob.clone());
    m.add(&alice, m.t, m.u, 1_000_000, 4_000_000);
    let args = pack(&[
        m.t.as_bytes(),
        m.u.as_bytes(),
        &u(500_000),
        &u(3_000_000),
        &u(0),
        &u(2_500_000),
        &LATER.to_le_bytes(),
    ]);
    reverted(
        &m.send(&bob, "add_liquidity", args, 0),
        "price moved past the limit",
    );
    assert_eq!(m.pool(m.t, m.u).2, 2_000_000);
}

#[test]
fn liquidity_comes_back_with_its_share_of_the_fees() {
    let mut m = market();
    let (alice, bob, a) = (m.alice.clone(), m.bob.clone(), m.a);
    let minted = done(&m.add(&alice, m.t, m.u, 10_000_000, 10_000_000));
    let (t_before, u_before) = (m.holds(m.t, &a), m.holds(m.u, &a));
    for _ in 0..20 {
        done(&m.swap(&bob, m.t, m.u, 1_000_000));
        done(&m.swap(&bob, m.u, m.t, 1_000_000));
    }
    let (reserve_t, reserve_u, total) = m.pool(m.t, m.u);
    assert!(
        reserve_t * reserve_u > 10_000_000u128 * 10_000_000,
        "the fees stayed in"
    );
    m.remove(&alice, m.t, m.u, minted);
    let (got_t, got_u) = (m.holds(m.t, &a) - t_before, m.holds(m.u, &a) - u_before);
    assert_eq!(got_t, reserve_t * minted / total);
    assert_eq!(got_u, reserve_u * minted / total);
    assert!(
        got_t * got_u > 9_999_000u128 * 9_999_000,
        "worth more than went in"
    );
    assert_eq!(m.pool(m.t, m.u).2, LOCKED, "what is locked stays");
    assert_eq!(m.shares(m.t, m.u, &a), 0);
}

#[test]
fn only_a_holder_takes_liquidity_out() {
    let mut m = market();
    let (alice, bob, a) = (m.alice.clone(), m.bob.clone(), m.a);
    let minted = done(&m.add(&alice, m.t, m.u, 1_000_000, 1_000_000));
    reverted(&m.remove(&bob, m.t, m.u, 1), "not that many shares");
    reverted(
        &m.remove(&alice, m.t, m.u, minted + 1),
        "not that many shares",
    );
    reverted(&m.remove(&alice, m.t, m.u, 0), "not that many shares");
    assert_eq!(m.shares(m.t, m.u, &a), minted);
}

#[test]
fn a_swap_pays_the_formula() {
    let mut m = market();
    let (alice, bob, b) = (m.alice.clone(), m.bob.clone(), m.b);
    m.add(&alice, m.t, m.u, 1_000_000, 4_000_000);
    assert_eq!(
        m.quote(m.t, m.u, 10_000),
        39486,
        "worked out in unbounded integers"
    );
    let (t_before, u_before) = (m.holds(m.t, &b), m.holds(m.u, &b));
    let out = done(&m.swap(&bob, m.t, m.u, 10_000));
    assert_eq!(out, 39486);
    assert_eq!(t_before - m.holds(m.t, &b), 10_000);
    assert_eq!(m.holds(m.u, &b) - u_before, 39486);
    assert_eq!(m.pool(m.t, m.u), (1_010_000, 3960514, 2_000_000));
}

#[test]
fn a_trade_is_protected_by_its_limits() {
    let mut m = market();
    let (alice, bob, b) = (m.alice.clone(), m.bob.clone(), m.b);
    m.add(&alice, m.t, m.u, 1_000_000, 4_000_000);
    let before = m.holds(m.t, &b);

    let greedy = m.swap_args(&m.t, &m.u, 10_000, 39487, LATER);
    reverted(
        &m.send(&bob, "swap", greedy, 0),
        "price moved past the limit",
    );
    let late = m.swap_args(&m.t, &m.u, 10_000, 0, m.chain.now);
    reverted(&m.send(&bob, "swap", late, 0), "deadline has passed");
    let exact = m.swap_args(&m.t, &m.u, 10_000, 39486, LATER);
    assert_eq!(done(&m.send(&bob, "swap", exact, 0)), 39486);
    assert_eq!(
        before - m.holds(m.t, &b),
        10_000,
        "the refused ones took nothing"
    );
}

#[test]
fn what_makes_no_sense_is_refused() {
    let mut m = market();
    let (alice, bob) = (m.alice.clone(), m.bob.clone());
    reverted(&m.swap(&bob, m.t, m.u, 100), "no such pool");
    reverted(
        &m.add(&alice, m.t, m.t, 1_000_000, 1_000_000),
        "a pool needs two assets",
    );
    reverted(&m.add(&alice, m.t, m.u, 0, 1_000_000), "nothing to add");
    reverted(
        &m.add(&alice, m.t, m.u, 1_000, 1_000),
        "too small to open a pool",
    );
    m.add(&alice, m.t, m.u, 1_000_000, 1_000_000);
    reverted(&m.swap(&bob, m.t, m.t, 100), "a pool needs two assets");
    reverted(&m.swap(&bob, m.t, m.u, 0), "nothing to swap");
    reverted(&m.swap(&bob, m.t, m.u, 1), "too small for this pool");
    let args = m.swap_args(&m.t, &m.u, 100, 0, LATER);
    reverted(
        &m.send(&bob, "swap", args, 5),
        "send the native amount with the call",
    );
}

#[test]
fn taking_a_token_needs_its_approval() {
    let mut m = market();
    let alice = m.alice.clone();
    let carol = key(3);
    m.add(&alice, m.t, m.u, 1_000_000, 1_000_000);
    let fund = m.chain.from(
        &alice,
        Payload::Transfer {
            to: address(&carol),
            asset: AssetId::NATIVE,
            amount: 100_000_000,
        },
    );
    m.chain.submit(fund).unwrap();
    let args = send_args(&address(&carol), 1_000);
    m.chain.done(&alice, m.t, "transfer", args, 0);
    reverted(
        &m.swap(&carol, m.t, m.u, 100),
        "token transfer failed; approve this contract first",
    );
    assert_eq!(m.pool(m.t, m.u), (1_000_000, 1_000_000, 1_000_000));
}

#[test]
fn the_native_token_trades_like_any_other() {
    let mut m = market();
    let (alice, bob, a, b) = (m.alice.clone(), m.bob.clone(), m.a, m.b);
    let minted = done(&m.add(&alice, NATIVE, m.t, 20_000_000, 10_000_000));
    assert_eq!(m.holds(NATIVE, &m.amm), 20_000_000);
    assert_eq!(m.pool(NATIVE, m.t), (20_000_000, 10_000_000, 14_142_135));

    let t_before = m.holds(m.t, &b);
    let out = done(&m.swap(&bob, NATIVE, m.t, 1_000_000));
    assert_eq!(m.holds(m.t, &b) - t_before, out);
    assert_eq!(m.holds(NATIVE, &m.amm), 21_000_000);

    let native_before = m.holds(NATIVE, &b);
    let quoted = m.quote(m.t, NATIVE, 100_000);
    let receipt = m.swap(&bob, m.t, NATIVE, 100_000);
    assert_eq!(done(&receipt), quoted);
    assert!(
        m.holds(NATIVE, &b) > native_before + quoted - 100_000,
        "paid, less gas"
    );
    assert_eq!(m.holds(NATIVE, &m.amm), 21_000_000 - quoted);

    let reserves = m.pool(NATIVE, m.t);
    assert_eq!(reserves.0, m.holds(NATIVE, &m.amm));
    assert_eq!(reserves.1, m.holds(m.t, &m.amm));

    let native_before = m.holds(NATIVE, &a);
    done(&m.remove(&alice, NATIVE, m.t, minted));
    assert!(m.holds(NATIVE, &a) > native_before + 10_000_000);
}

#[test]
fn unused_native_tokens_come_back() {
    let mut m = market();
    let (alice, bob, b) = (m.alice.clone(), m.bob.clone(), m.b);
    m.add(&alice, NATIVE, m.t, 2_000_000, 1_000_000);
    let before = m.holds(NATIVE, &b);
    let args = m.add_args(&NATIVE, &m.t, 5_000_000, 1_000_000);
    let payload = Payload::Call {
        contract: m.amm,
        function: "add_liquidity".into(),
        args,
        amount: 5_000_000,
        gas_limit: GAS_FOR_THE_MARKET,
    };
    let stx = m.chain.from(&bob, payload);
    let fee = stx.tx.fee;
    let receipt = m.chain.submit(stx).unwrap();
    assert_eq!(receipt.outcome, Outcome::Done, "{receipt:?}");
    assert_eq!(m.holds(NATIVE, &m.amm), 4_000_000, "only the ratio went in");
    let refund = u128::from((GAS_FOR_THE_MARKET - receipt.gas_used) / 16);
    assert_eq!(m.holds(NATIVE, &b), before - fee + refund - 2_000_000);

    let args = m.add_args(&NATIVE, &m.t, 5_000_000, 1_000_000);
    let short = m.send(&bob, "add_liquidity", args, 4_999_999);
    reverted(&short, "send the native amount with the call");
}

#[test]
fn sending_to_the_contract_moves_no_price_and_buys_no_shares() {
    let mut m = market();
    let (alice, bob) = (m.alice.clone(), m.bob.clone());
    m.add(&alice, m.t, m.u, 1_000_000, 1_000_000);
    let quoted = m.quote(m.t, m.u, 1_000);
    let donation = send_args(&m.amm, 500_000_000);
    m.chain.done(&bob, m.t, "transfer", donation, 0);
    assert_eq!(m.pool(m.t, m.u), (1_000_000, 1_000_000, 1_000_000));
    assert_eq!(m.quote(m.t, m.u, 1_000), quoted);
    assert_eq!(
        done(&m.add(&bob, m.t, m.u, 1_000_000, 1_000_000)),
        1_000_000
    );
}

#[test]
fn a_round_trip_never_makes_money() {
    let mut m = market();
    let (alice, bob) = (m.alice.clone(), m.bob.clone());
    m.add(&alice, m.t, m.u, 7_777_777, 3_333_333);
    for amount in [1_000, 12_345, 1_000_000, 50_000_000] {
        let out = done(&m.swap(&bob, m.t, m.u, amount));
        let back = done(&m.swap(&bob, m.u, m.t, out));
        assert!(back < amount, "{amount} came back as {back}");
    }
}

/// A token that says yes to everything and moves nothing. Only governance could deploy one, but
/// the market shouldn't depend on that.
const FAKE: &str = r#"(module
  (memory (export "memory") 1)
  (func (export "transfer"))
  (func (export "transfer_from")))"#;

#[test]
fn a_fake_token_only_reaches_its_own_pool() {
    let mut m = market();
    let (alice, bob, b) = (m.alice.clone(), m.bob.clone(), m.b);
    let fake = m.chain.deploy(&wat::parse_str(FAKE).unwrap(), vec![]);
    m.add(&alice, NATIVE, m.t, 50_000_000, 50_000_000);
    let honest = m.pool(NATIVE, m.t);

    let shares = done(&m.add(&bob, NATIVE, fake, 2_000_000, 1_000_000_000_000));
    assert_eq!(m.holds(NATIVE, &m.amm), 52_000_000);
    let before = m.holds(NATIVE, &b);
    let out = done(&m.swap(&bob, fake, NATIVE, 1 << 100));
    assert!(out < 2_000_000 && m.holds(NATIVE, &b) < before + 2_000_000);
    assert_eq!(m.shares(NATIVE, fake, &b), shares);

    assert_eq!(m.pool(NATIVE, m.t), honest, "the honest pool is untouched");
    assert!(
        m.holds(NATIVE, &m.amm) >= 50_000_000,
        "and so is what backs it"
    );
    let alice_shares = m.shares(NATIVE, m.t, &m.a);
    done(&m.remove(&alice, NATIVE, m.t, alice_shares));
}

#[test]
fn a_vaults_trade_waits_like_everything_else() {
    let mut m = market();
    let (alice, bob, a) = (m.alice.clone(), m.bob.clone(), m.a);
    m.add(&alice, m.t, m.u, 1_000_000, 1_000_000);
    let recovery = AuthPolicy::single(key(9).public_key().clone());
    let vault = VaultPolicy {
        delay_ms: DELAY,
        recovery: Some(recovery),
    };
    let stx = m
        .chain
        .from(&alice, Payload::SetVault { vault: Some(vault) });
    m.chain.submit(stx).unwrap();
    let held = m.holds(m.t, &a);

    let queued = m.swap(&alice, m.t, m.u, 1_000);
    assert_eq!(queued, Receipt::default());
    assert_eq!(m.holds(m.t, &a), held);
    assert_eq!(m.pool(m.t, m.u).0, 1_000_000);

    m.chain.now += DELAY;
    let run = m
        .chain
        .from(&bob, Payload::ExecutePending { account: a, id: 0 });
    let receipt = m.chain.submit(run).unwrap();
    assert_eq!(receipt.outcome, Outcome::Done, "{receipt:?}");
    assert_eq!(m.holds(m.t, &a), held - 1_000);
    assert_eq!(m.pool(m.t, m.u).0, 1_001_000);
}

#[test]
fn huge_amounts_are_exact() {
    let mut m = market();
    let (alice, bob) = (m.alice.clone(), m.bob.clone());
    let (reserve_t, reserve_u) = ((1u128 << 111) + 12_345, (1u128 << 110) - 6_789);
    let shares = done(&m.add(&alice, m.t, m.u, reserve_t, reserve_u));
    assert_eq!(shares + LOCKED, 1835754159301792232857008151836913);
    let amount = 1u128 << 100;
    assert_eq!(m.quote(m.t, m.u, amount), 631616343015536765749889438610);
    assert_eq!(
        done(&m.swap(&bob, m.t, m.u, amount)),
        631616343015536765749889438610
    );
}

#[test]
fn a_pool_stops_at_its_limit() {
    let mut m = market();
    let (alice, bob) = (m.alice.clone(), m.bob.clone());
    let limit = 1u128 << 112;
    done(&m.add(&alice, m.t, m.u, limit, limit));
    reverted(&m.add(&bob, m.t, m.u, 1 << 100, 1 << 100), "pool is full");
    reverted(&m.swap(&bob, m.t, m.u, 1 << 100), "pool is full");
    reverted(&m.swap(&bob, m.t, m.u, limit + 1), "pool is full");
}

/// The same random numbers every run, so a failure can be run again.
struct Dice(u64);

impl Dice {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, limit: u128) -> u128 {
        u128::from(self.next()) % limit
    }
}

#[test]
fn random_trading_never_breaks_the_books() {
    for seed in [1, 2, 3] {
        let mut m = market();
        let (alice, bob, a, b) = (m.alice.clone(), m.bob.clone(), m.a, m.b);
        let mut dice = Dice(0x2545_F491_4F6C_DD1D ^ seed);
        done(&m.add(&alice, NATIVE, m.t, 30_000_000, 70_000_000));
        let mut last = m.pool(NATIVE, m.t);
        let mut tried = 0;
        let mut worked = 0;
        for _ in 0..250 {
            tried += 1;
            let sk = if dice.below(2) == 0 { &alice } else { &bob };
            let who = if dice.below(2) == 0 { a } else { b };
            let amount = 1 + dice.below(5_000_000);
            let receipt = match dice.below(5) {
                0 => m.swap(sk, NATIVE, m.t, amount),
                1 => m.swap(sk, m.t, NATIVE, amount),
                2 => m.add(sk, NATIVE, m.t, amount, amount),
                3 => {
                    let held = m.shares(NATIVE, m.t, &address(sk));
                    m.remove(sk, NATIVE, m.t, 1 + dice.below(held.max(1)))
                }
                _ => m.swap(sk, m.t, NATIVE, dice.below(2_000)),
            };
            if receipt.outcome == Outcome::Done {
                worked += 1;
            }

            let (native, token, total) = m.pool(NATIVE, m.t);
            assert_eq!(native, m.holds(NATIVE, &m.amm), "the books are the balance");
            assert_eq!(token, m.holds(m.t, &m.amm), "the books are the balance");
            assert_eq!(
                m.shares(NATIVE, m.t, &a) + m.shares(NATIVE, m.t, &b) + LOCKED,
                total,
                "every share has an owner"
            );
            // what a share is worth never falls: k / shares^2, compared without dividing
            let (old_native, old_token, old_total) = last;
            assert!(
                native * token * (old_total * old_total)
                    >= old_native * old_token * (total * total),
                "a share lost value: {last:?} to {:?}",
                (native, token, total)
            );
            last = (native, token, total);
            let _ = who;
        }
        assert!(worked * 2 > tried, "only {worked} of {tried} did anything");
    }
}

#[test]
fn everything_the_market_does_fits_in_a_transaction() {
    let mut m = market();
    let (alice, bob) = (m.alice.clone(), m.bob.clone());
    let opening = m.add(&alice, m.t, m.u, 1 << 100, 1 << 90);
    let adding = m.add(&bob, m.t, m.u, 1 << 90, 1 << 90);
    let trading = m.swap(&bob, m.t, m.u, 1 << 80);
    let leaving = m.remove(&bob, m.t, m.u, 1 << 60);
    for (name, receipt) in [
        ("open", &opening),
        ("add", &adding),
        ("swap", &trading),
        ("remove", &leaving),
    ] {
        println!("{name}: {} gas", receipt.gas_used);
        assert_eq!(receipt.outcome, Outcome::Done, "{name}: {receipt:?}");
        assert!(receipt.gas_used < GAS_FOR_THE_MARKET);
    }
    const { assert!(GAS_FOR_THE_MARKET <= MAX_TX_GAS) };
    let refused = m.chain.call(&alice, m.amm, "init", vec![], 0);
    assert_eq!(refused, Err(TxError::NotCallable));

    let mut m = launchpad();
    let (alice, bob) = (m.alice.clone(), m.bob.clone());
    let creating = m.create(&alice, "Coin", "COIN", 1_000, 0);
    let creating_and_buying = m.create(&alice, "Other", "OTHER", 1_000, 50 * ONE);
    let coin = created(&creating).0;
    m.allow(&bob, coin, u128::MAX >> 1);
    let buying = m.swap(&bob, NATIVE, coin, 400_000 * ONE);
    let selling = m.swap(&bob, coin, NATIVE, 1 << 70);
    for (name, receipt) in [
        ("create", &creating),
        ("create and buy", &creating_and_buying),
        ("buy", &buying),
        ("sell", &selling),
    ] {
        println!("{name}: {} gas", receipt.gas_used);
        assert_eq!(receipt.outcome, Outcome::Done, "{name}: {receipt:?}");
        assert!(receipt.gas_used < GAS_FOR_THE_MARKET);
    }
}

#[test]
fn deploying_needs_somewhere_for_the_protocols_fees() {
    let mut chain = Chain::new(&[]);
    let nobody = amm_args(&NATIVE, code_hash(TOKEN));
    let receipt = chain
        .submit(chain.deploy_tx(AMM, nobody, MAX_TX_GAS))
        .unwrap();
    reverted(&receipt, "the protocol's fees need an address");
    assert_eq!(receipt.contract, None);
    let short = address(&key(5)).as_bytes().to_vec();
    let receipt = chain
        .submit(chain.deploy_tx(AMM, short, MAX_TX_GAS))
        .unwrap();
    reverted(&receipt, "missing arguments");
}

#[test]
fn a_created_token_puts_its_whole_supply_against_virtual_liquidity() {
    let mut m = launchpad();
    let (alice, a) = (m.alice.clone(), m.a);
    let receipt = m.create(&alice, "Quantum Cat", "QCAT", 500, 0);
    let (coin, bought) = created(&receipt);
    assert_eq!(bought, 0);
    assert_eq!(read_contracts(&m.chain.state).unwrap().last(), Some(&coin));
    assert_eq!(m.chain.view(coin, "name", vec![]).output, b"Quantum Cat");
    assert_eq!(m.chain.view(coin, "symbol", vec![]).output, b"QCAT");
    assert_eq!(
        m.chain.view(coin, "decimals", vec![]).output,
        18u64.to_le_bytes()
    );
    assert_eq!(m.chain.view_u128(coin, "total_supply", vec![]), SUPPLY);
    assert_eq!(
        m.chain.view(coin, "owner", vec![]).output,
        NATIVE.as_bytes()
    );
    reverted(
        &m.chain
            .call(&alice, coin, "mint", send_args(&a, 1), 0)
            .unwrap(),
        "only the owner can do that",
    );

    assert_eq!(m.pool(NATIVE, coin), (0, SUPPLY, 0));
    assert_eq!(m.pool(coin, NATIVE), (SUPPLY, 0, 0));
    assert_eq!(m.launched(coin), (500 * ONE, a));
    assert_eq!(m.holds(coin, &m.amm), SUPPLY);
    assert_eq!(m.holds(NATIVE, &m.amm), 0);
    let launch = receipt.events.last().unwrap();
    assert_eq!(
        (launch.contract, launch.topic.as_slice()),
        (m.amm, &b"launch"[..])
    );
    assert_eq!(&launch.data[32..64], coin.as_bytes());
    assert_eq!(&launch.data[64..96], a.as_bytes());
    assert_eq!(
        m.quote(NATIVE, coin, 10 * ONE),
        19_540_556_704_871_902_973_733,
        "worked out in unbounded integers"
    );
    let protocol = m.chain.view(m.amm, "protocol", vec![]);
    assert_eq!(protocol.output, m.protocol.as_bytes());
}

#[test]
fn an_initial_buy_comes_in_the_same_call() {
    let mut m = launchpad();
    let (alice, a, protocol) = (m.alice.clone(), m.a, m.protocol);
    let receipt = m.create(&alice, "Coin", "COIN", 500, 10 * ONE);
    let (coin, bought) = created(&receipt);
    assert_eq!(bought, 19_540_556_704_871_902_973_733);
    assert_eq!(m.holds(coin, &a), bought);
    assert_eq!(
        m.pool(NATIVE, coin),
        (
            9_965_000_000_000_000_000,
            980_459_443_295_128_097_026_267,
            0
        )
    );
    assert_eq!(m.holds(NATIVE, &protocol), 10_000_000_000_000_000);
    assert_eq!(m.holds(NATIVE, &m.amm), 9_965_000_000_000_000_000);
    let market: Vec<&[u8]> = receipt
        .events
        .iter()
        .filter(|e| e.contract == m.amm)
        .map(|e| e.topic.as_slice())
        .collect();
    assert_eq!(market, [&b"launch"[..], b"swap"]);
}

#[test]
fn a_trade_pays_the_protocol_and_the_launcher() {
    let mut m = launchpad();
    let (bob, a, b, protocol) = (m.bob.clone(), m.a, m.b, m.protocol);
    let coin = m.launched_coin(500);
    let launcher_before = m.holds(NATIVE, &a);
    let paid = |m: &Market| {
        (
            m.holds(NATIVE, &protocol),
            m.holds(NATIVE, &a) - launcher_before,
        )
    };

    let bought = done(&m.swap(&bob, NATIVE, coin, 10 * ONE));
    assert_eq!(bought, 19_540_556_704_871_902_973_733);
    assert_eq!(m.holds(coin, &b), bought);
    assert_eq!(
        m.pool(NATIVE, coin),
        (
            9_965_000_000_000_000_000,
            980_459_443_295_128_097_026_267,
            0
        )
    );
    assert_eq!(paid(&m), (10_000_000_000_000_000, 25_000_000_000_000_000));

    let half = bought / 2;
    assert_eq!(m.quote(coin, NATIVE, half), 5_014_049_913_326_204_375);
    let sold = m.swap(&bob, coin, NATIVE, half);
    assert_eq!(done(&sold), 5_014_049_913_326_204_375);
    let event = sold.events.last().unwrap();
    assert_eq!(event.topic, b"swap");
    assert_eq!(&event.data[96..128], a.as_bytes());
    assert_eq!(&event.data[128..144], &u(5_031_660_725_866_737));
    assert_eq!(&event.data[144..], &u(12_579_151_814_666_844));
    assert_eq!(
        m.pool(NATIVE, coin),
        (
            4_933_339_274_133_262_044,
            990_229_721_647_564_048_513_133,
            0
        )
    );
    assert_eq!(paid(&m), (15_031_660_725_866_737, 37_579_151_814_666_844));
    assert_eq!(m.holds(NATIVE, &m.amm), 4_933_339_274_133_262_044);

    let rest = m.holds(coin, &b);
    assert_eq!(
        done(&m.swap(&bob, coin, NATIVE, rest)),
        4_916_072_586_673_795_626
    );
    assert_eq!(
        m.pool(NATIVE, coin),
        (1, SUPPLY, 0),
        "back where it began, but for rounding"
    );
    assert_eq!(paid(&m), (19_964_999_999_999_999, 49_912_499_999_999_999));
    assert_eq!(m.holds(NATIVE, &m.amm), 1);
}

#[test]
fn a_creation_needs_sensible_terms() {
    let mut m = launchpad();
    let (alice, a) = (m.alice.clone(), m.a);
    let before = read_contracts(&m.chain.state).unwrap();
    for (name, symbol, virtual_native, reason) in [
        (
            "Coin",
            "COIN",
            300,
            "the virtual amount is 100, 250, 500 or 1000",
        ),
        ("", "COIN", 100, "a name of 1 to 32 printable bytes"),
        (
            &"x".repeat(33),
            "COIN",
            100,
            "a name of 1 to 32 printable bytes",
        ),
        ("Co\nin", "COIN", 100, "a name of 1 to 32 printable bytes"),
        ("Coin", "", 100, "a symbol of 1 to 10 printable bytes"),
        (
            "Coin",
            "ELEVENBYTES",
            100,
            "a symbol of 1 to 10 printable bytes",
        ),
    ] {
        reverted(&m.create(&alice, name, symbol, virtual_native, ONE), reason);
    }
    assert_eq!(read_contracts(&m.chain.state).unwrap(), before);
    assert_eq!(m.holds(NATIVE, &m.amm), 0);

    let longest = "x".repeat(32);
    let (coin, _) = created(&m.create(&alice, &longest, "TENLETTERS", 100, 0));
    assert_eq!(
        read_contracts(&m.chain.state).unwrap(),
        [before, vec![coin]].concat()
    );
    assert_eq!(m.launched(coin), (100 * ONE, a));
    reverted(
        &m.add(&alice, NATIVE, coin, ONE, ONE),
        "a launched pool takes no liquidity",
    );
    reverted(&m.remove(&alice, NATIVE, coin, 1), "not that many shares");
    let receipt = m.chain.view(m.amm, "launched", m.t.as_bytes().to_vec());
    reverted(&receipt, "not launched");
}

#[test]
fn a_creation_needs_the_token_code_on_chain() {
    let mut m = launchpad();
    let alice = m.alice.clone();
    m.amm = m.chain.deploy(AMM, amm_args(&m.protocol, Hash([7; 32])));
    reverted(
        &m.create(&alice, "Coin", "COIN", 100, ONE),
        "could not create the token",
    );
    assert_eq!(m.holds(NATIVE, &m.amm), 0);
}

/// Moves nothing, whatever it is asked.
const LIAR: &str = r#"(module
  (memory (export "memory") 1)
  (func (export "set_owner"))
  (func (export "transfer"))
  (func (export "transfer_from")))"#;

#[test]
fn a_lying_token_takes_out_only_what_its_own_buyers_paid() {
    let mut m = launchpad();
    let (alice, bob) = (m.alice.clone(), m.bob.clone());
    let liar = wat::parse_str(LIAR).unwrap();
    m.chain.deploy(&liar, vec![]);
    m.amm = m.chain.deploy(AMM, amm_args(&m.protocol, code_hash(&liar)));
    let (first, _) = created(&m.create(&alice, "First", "ONE", 500, 10 * ONE));
    let untouched = m.pool(NATIVE, first);

    let (second, _) = created(&m.create(&bob, "Second", "TWO", 100, 0));
    let got = done(&m.swap(&bob, NATIVE, second, ONE));
    let paid_in = m.pool(NATIVE, second).0;
    reverted(
        &m.swap(&bob, second, NATIVE, 2 * got),
        "the pool holds less than that",
    );
    reverted(
        &m.swap(&bob, second, NATIVE, 1 << 100),
        "the pool holds less than that",
    );
    let back = done(&m.swap(&bob, second, NATIVE, got));
    assert!(back < paid_in);

    assert_eq!(m.pool(NATIVE, first), untouched);
    assert_eq!(
        m.holds(NATIVE, &m.amm),
        untouched.0 + m.pool(NATIVE, second).0,
        "the other pool's native tokens are all still here"
    );
}

/// `a * b` as its high and low halves, which compare in order.
fn wide(a: u128, b: u128) -> (u128, u128) {
    const LOW: u128 = u64::MAX as u128;
    let (a1, a0, b1, b0) = (a >> 64, a & LOW, b >> 64, b & LOW);
    let (low, cross1, cross2) = (a0 * b0, a1 * b0, a0 * b1);
    let middle = (low >> 64) + (cross1 & LOW) + (cross2 & LOW);
    let high = a1 * b1 + (cross1 >> 64) + (cross2 >> 64) + (middle >> 64);
    (high, (low & LOW) | (middle << 64))
}

#[test]
fn random_trading_on_a_launch_never_breaks_the_books() {
    for seed in [1u64, 2, 3, 4] {
        let mut m = launchpad();
        let (alice, bob, a, b, protocol) = (m.alice.clone(), m.bob.clone(), m.a, m.b, m.protocol);
        let virtual_native = [100, 250, 500, 1_000][seed as usize - 1];
        let coin = m.launched_coin(virtual_native);
        let virtual_native = virtual_native * ONE;
        let mut dice = Dice(0x2545_F491_4F6C_DD1D ^ seed);
        let mut last = wide(virtual_native, SUPPLY);
        let mut protocol_paid = 0;
        let (mut tried, mut worked) = (0, 0);
        for _ in 0..200 {
            tried += 1;
            let (sk, who) = if dice.below(2) == 0 {
                (&alice, a)
            } else {
                (&bob, b)
            };
            let receipt = if dice.below(2) == 0 {
                m.swap(sk, NATIVE, coin, 1 + dice.below(80 * ONE))
            } else {
                let held = m.holds(coin, &who);
                m.swap(sk, coin, NATIVE, 1 + dice.below(held.max(1)))
            };
            if receipt.outcome == Outcome::Done {
                worked += 1;
            }

            let (native, coins, shares) = m.pool(NATIVE, coin);
            assert_eq!(shares, 0);
            assert_eq!(coins, m.holds(coin, &m.amm), "the books are the balance");
            assert_eq!(m.holds(coin, &a) + m.holds(coin, &b) + coins, SUPPLY);
            assert_eq!(native, m.holds(NATIVE, &m.amm), "the fees left at once");
            assert!(m.holds(NATIVE, &protocol) >= protocol_paid);
            protocol_paid = m.holds(NATIVE, &protocol);
            let product = wide(native + virtual_native, coins);
            assert!(product >= last, "the product fell");
            last = product;
        }
        assert!(worked * 2 > tried, "only {worked} of {tried} did anything");
    }
}
