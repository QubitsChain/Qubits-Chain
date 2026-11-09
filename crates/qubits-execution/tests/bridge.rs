//! The Qubits side of the bridge: coins sent to Ethereum, releases attested by a threshold.

mod common;

use common::*;
use qubits_crypto::SecretKey;
use qubits_types::*;

const BRIDGE: &[u8] = include_bytes!("../../../contracts/out/bridge.wasm");
const ONE: u128 = 1_000_000_000_000_000_000;

struct Setup {
    chain: Chain,
    bridge: Address,
    admin: SecretKey,
    alice: SecretKey,
    attesters: [SecretKey; 3],
    fee_to: Address,
    bob: Address,
}

fn ethereum(byte: u8) -> [u8; 32] {
    let mut to = [0; 32];
    to[12..].fill(byte);
    to
}

fn ethereum_tx(lock_id: u64) -> [u8; 32] {
    let mut tx = [0xee; 32];
    tx[..8].copy_from_slice(&lock_id.to_le_bytes());
    tx
}

fn list(addresses: &[Address]) -> Vec<u8> {
    let bytes: Vec<u8> = addresses
        .iter()
        .flat_map(|a| a.as_bytes().to_vec())
        .collect();
    pack(&[&(bytes.len() as u32).to_le_bytes(), &bytes])
}

fn setup() -> Setup {
    let (admin, alice) = (key(1), key(2));
    let attesters = [key(11), key(12), key(13)];
    let mut funded: Vec<&SecretKey> = vec![&admin, &alice];
    funded.extend(attesters.iter());
    let mut chain = Chain::funded(&funded, 1_000_000 * ONE);
    let fee_to = address(&key(20));
    let bob = address(&key(21));
    let signers: Vec<Address> = attesters.iter().map(address).collect();
    let args = pack(&[
        address(&admin).as_bytes(),
        fee_to.as_bytes(),
        &10u128.to_le_bytes(),
        &ONE.to_le_bytes(),
        &2u128.to_le_bytes(),
        &list(&signers),
    ]);
    let bridge = chain.deploy(BRIDGE, args);
    Setup {
        chain,
        bridge,
        admin,
        alice,
        attesters,
        fee_to,
        bob,
    }
}

impl Setup {
    fn fund(&mut self, amount: u128) {
        let admin = self.admin.clone();
        self.chain.done(&admin, self.bridge, "fund", vec![], amount);
    }

    fn attest(&mut self, who: usize, lock_id: u64, to: Address, amount: u128) -> Receipt {
        let sk = self.attesters[who].clone();
        let args = pack(&[
            &lock_id.to_le_bytes(),
            &ethereum_tx(lock_id),
            to.as_bytes(),
            &amount.to_le_bytes(),
        ]);
        self.chain
            .call(&sk, self.bridge, "attest", args, 0)
            .unwrap()
    }

    fn admin(&mut self, function: &str, args: Vec<u8>) -> Receipt {
        let admin = self.admin.clone();
        self.chain
            .call(&admin, self.bridge, function, args, 0)
            .unwrap()
    }

    fn paid(&self, lock_id: u64) -> bool {
        self.chain
            .view_u128(self.bridge, "paid", lock_id.to_le_bytes().to_vec())
            == 1
    }
}

#[test]
fn bridging_keeps_coins_less_the_fee() {
    let mut s = setup();
    let alice = s.alice.clone();
    let receipt = s.chain.done(
        &alice,
        s.bridge,
        "bridge",
        ethereum(7).to_vec(),
        2_500 * ONE,
    );
    assert_eq!(receipt.output, 0u64.to_le_bytes());
    assert_eq!(s.chain.balance(&s.bridge), 2_497_500_000_000_000_000_000);
    assert_eq!(s.chain.balance(&s.fee_to), 2_500_000_000_000_000_000);
    let event = receipt
        .events
        .iter()
        .find(|e| e.topic == b"bridge")
        .unwrap();
    assert_eq!(
        event.data,
        pack(&[
            address(&alice).as_bytes(),
            &ethereum(7),
            &0u64.to_le_bytes(),
            &2_497_500_000_000_000_000_000u128.to_le_bytes(),
            &2_500_000_000_000_000_000u128.to_le_bytes(),
        ])
    );
    let next = s
        .chain
        .done(&alice, s.bridge, "bridge", ethereum(7).to_vec(), ONE);
    assert_eq!(next.output, 1u64.to_le_bytes());
}

#[test]
fn bridging_needs_the_minimum_and_an_ethereum_address() {
    let mut s = setup();
    let alice = s.alice.clone();
    let r = s
        .chain
        .call(&alice, s.bridge, "bridge", ethereum(7).to_vec(), ONE - 1)
        .unwrap();
    reverted(&r, "less than the bridge's minimum");
    let mut wide = ethereum(7);
    wide[0] = 1;
    let r = s
        .chain
        .call(&alice, s.bridge, "bridge", wide.to_vec(), ONE)
        .unwrap();
    reverted(&r, "an Ethereum address is 20 bytes");
    let r = s
        .chain
        .call(&alice, s.bridge, "bridge", [0; 32].to_vec(), ONE)
        .unwrap();
    reverted(&r, "an Ethereum address is 20 bytes");
}

#[test]
fn two_of_three_pay_once() {
    let mut s = setup();
    s.fund(1_000 * ONE);
    let bob = s.bob;
    assert_eq!(s.attest(0, 7, bob, 40 * ONE).outcome, Outcome::Done);
    assert_eq!(s.chain.balance(&bob), 0);
    assert!(!s.paid(7));
    let r = s.attest(2, 7, bob, 40 * ONE);
    assert_eq!(r.outcome, Outcome::Done);
    let release = r.events.iter().find(|e| e.topic == b"release").unwrap();
    assert_eq!(
        release.data,
        pack(&[
            bob.as_bytes(),
            &7u64.to_le_bytes(),
            &(40 * ONE).to_le_bytes(),
            &ethereum_tx(7)
        ])
    );
    assert_eq!(s.chain.balance(&bob), 40 * ONE);
    assert!(s.paid(7));
    assert_eq!(
        s.chain
            .view(s.bridge, "source", 7u64.to_le_bytes().to_vec())
            .output,
        ethereum_tx(7)
    );
    reverted(&s.attest(1, 7, bob, 40 * ONE), "already paid");
    assert_eq!(s.chain.balance(&bob), 40 * ONE);
}

#[test]
fn the_same_attester_counts_once() {
    let mut s = setup();
    s.fund(1_000 * ONE);
    let bob = s.bob;
    s.attest(1, 3, bob, ONE);
    s.attest(1, 3, bob, ONE);
    assert!(!s.paid(3));
    assert_eq!(s.chain.balance(&bob), 0);
}

#[test]
fn attesters_must_agree_on_what_to_pay() {
    let mut s = setup();
    s.fund(1_000 * ONE);
    let bob = s.bob;
    s.attest(0, 9, bob, 5 * ONE);
    s.attest(1, 9, bob, 6 * ONE);
    assert!(!s.paid(9));
    s.attest(2, 9, bob, 5 * ONE);
    assert!(s.paid(9));
    assert_eq!(s.chain.balance(&bob), 5 * ONE);
}

#[test]
fn strangers_cannot_attest() {
    let mut s = setup();
    s.fund(1_000 * ONE);
    let alice = s.alice.clone();
    let args = pack(&[
        &1u64.to_le_bytes(),
        &ethereum_tx(1),
        s.bob.as_bytes(),
        &ONE.to_le_bytes(),
    ]);
    let r = s.chain.call(&alice, s.bridge, "attest", args, 0).unwrap();
    reverted(&r, "only an attester can attest");
}

#[test]
fn a_release_waits_for_funds() {
    let mut s = setup();
    s.fund(10 * ONE);
    let bob = s.bob;
    s.attest(0, 4, bob, 11 * ONE);
    reverted(
        &s.attest(1, 4, bob, 11 * ONE),
        "the bridge holds less than that",
    );
    assert!(!s.paid(4));
    s.fund(ONE);
    assert_eq!(s.attest(1, 4, bob, 11 * ONE).outcome, Outcome::Done);
    assert_eq!(s.chain.balance(&bob), 11 * ONE);
}

#[test]
fn the_admin_sets_fee_minimum_and_recipient() {
    let mut s = setup();
    let alice = s.alice.clone();
    reverted(
        &s.admin("set_fee_bps", 101u128.to_le_bytes().to_vec()),
        "the fee is at most 1%",
    );
    assert_eq!(
        s.admin("set_fee_bps", 100u128.to_le_bytes().to_vec())
            .outcome,
        Outcome::Done
    );
    let other = address(&key(30));
    assert_eq!(
        s.admin("set_fee_to", other.as_bytes().to_vec()).outcome,
        Outcome::Done
    );
    assert_eq!(
        s.admin("set_min", (50 * ONE).to_le_bytes().to_vec())
            .outcome,
        Outcome::Done
    );
    let r = s
        .chain
        .call(&alice, s.bridge, "bridge", ethereum(1).to_vec(), 49 * ONE)
        .unwrap();
    reverted(&r, "less than the bridge's minimum");
    s.chain
        .done(&alice, s.bridge, "bridge", ethereum(1).to_vec(), 100 * ONE);
    assert_eq!(s.chain.balance(&other), ONE);
    assert_eq!(s.chain.balance(&s.bridge), 99 * ONE);
}

#[test]
fn only_the_admin_changes_things() {
    let mut s = setup();
    let alice = s.alice.clone();
    for (function, args) in [
        ("set_fee_bps", 5u128.to_le_bytes().to_vec()),
        ("set_fee_to", address(&alice).as_bytes().to_vec()),
        ("set_min", 0u128.to_le_bytes().to_vec()),
        ("set_admin", address(&alice).as_bytes().to_vec()),
        ("pause", vec![]),
        ("unpause", vec![]),
        (
            "set_attesters_to",
            pack(&[&1u128.to_le_bytes(), &list(&[address(&alice)])]),
        ),
    ] {
        let r = s.chain.call(&alice, s.bridge, function, args, 0).unwrap();
        reverted(&r, "only the admin can do that");
    }
}

#[test]
fn pausing_stops_both_ways() {
    let mut s = setup();
    s.fund(100 * ONE);
    let (alice, bob) = (s.alice.clone(), s.bob);
    s.attest(0, 1, bob, ONE);
    s.admin("pause", vec![]);
    let r = s
        .chain
        .call(&alice, s.bridge, "bridge", ethereum(1).to_vec(), ONE)
        .unwrap();
    reverted(&r, "the bridge is paused");
    reverted(&s.attest(1, 1, bob, ONE), "the bridge is paused");
    s.admin("unpause", vec![]);
    assert_eq!(s.attest(1, 1, bob, ONE).outcome, Outcome::Done);
    assert_eq!(s.chain.balance(&bob), ONE);
}

#[test]
fn new_attesters_start_from_nothing() {
    let mut s = setup();
    s.fund(100 * ONE);
    let bob = s.bob;
    s.attest(0, 5, bob, ONE);
    let signers: Vec<Address> = s.attesters.iter().map(address).collect();
    let args = pack(&[
        &2u128.to_le_bytes(),
        &list(&[signers[2], signers[1], signers[0]]),
    ]);
    assert_eq!(s.admin("set_attesters_to", args).outcome, Outcome::Done);
    s.attest(1, 5, bob, ONE);
    assert!(!s.paid(5), "a vote from before the change must not count");
    s.attest(2, 5, bob, ONE);
    assert!(s.paid(5));
    let twice = pack(&[&1u128.to_le_bytes(), &list(&[signers[0], signers[0]])]);
    reverted(
        &s.admin("set_attesters_to", twice),
        "an attester is listed twice",
    );
    let zero = pack(&[&0u128.to_le_bytes(), &list(&[signers[0]])]);
    reverted(
        &s.admin("set_attesters_to", zero),
        "the threshold is 1 to the number of attesters",
    );
}

#[test]
fn config_reads_back() {
    let s = setup();
    let receipt = s.chain.view(s.bridge, "config", vec![]);
    assert_eq!(receipt.outcome, Outcome::Done);
    let out = receipt.output;
    assert_eq!(&out[..32], address(&s.admin).as_bytes());
    assert_eq!(&out[32..64], s.fee_to.as_bytes());
    assert_eq!(u128::from_le_bytes(out[64..80].try_into().unwrap()), 10);
    assert_eq!(u128::from_le_bytes(out[80..96].try_into().unwrap()), ONE);
    assert_eq!(u128::from_le_bytes(out[96..112].try_into().unwrap()), 2);
    assert_eq!(u64::from_le_bytes(out[112..120].try_into().unwrap()), 0);
    assert_eq!(out[120], 0);
    assert_eq!(out.len(), 121 + 3 * 32);
}
