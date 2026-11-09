//! The Qubits side of the bridge to BITS on Ethereum, one for one less a fee.
//!
//! - `bridge(ethereum_to)` takes the native coins sent with it for the Ethereum address `ethereum_to`
//!   (20 bytes, left-padded to 32). The fee goes to the fee recipient; the attesters release the
//!   rest as BITS there.
//! - `attest(lock_id, ethereum_tx, to, amount)`: an attester saw lock `lock_id` in transaction
//!   `ethereum_tx` on Ethereum. Once a threshold of them agree on all of it, this pays it, once,
//!   and keeps `ethereum_tx` (`source(lock_id)`).
//! - `fund()` adds coins for releases. The admin sets the fee, its recipient, the minimum, the
//!   attesters and can pause.
#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use qubits_contract_sdk::{self as qb, Address, NOBODY, pack};

const ADMIN: &[u8] = b"admin";
const FEE_TO: &[u8] = b"fee_to";
const FEE_BPS: &[u8] = b"fee_bps";
const MIN: &[u8] = b"min";
const THRESHOLD: &[u8] = b"threshold";
const ATTESTERS: &[u8] = b"attesters";
const ERA: &[u8] = b"era";
const PAUSED: &[u8] = b"paused";
const NEXT: &[u8] = b"next";

const MAX_FEE_BPS: u128 = 100;
const MAX_ATTESTERS: usize = 16;

fn address_at(key: &[u8]) -> Address {
    qb::get(key)
        .expect("set at init")
        .try_into()
        .expect("stored as 32 bytes")
}

fn attesters() -> Vec<Address> {
    qb::get(ATTESTERS)
        .unwrap_or_default()
        .chunks(32)
        .map(|c| c.try_into().expect("32 bytes each"))
        .collect()
}

fn u64_at(key: &[u8]) -> u64 {
    qb::get(key).map_or(0, |b| {
        u64::from_le_bytes(b.try_into().expect("stored as 8 bytes"))
    })
}

fn only_admin() {
    qb::require(
        qb::caller() == address_at(ADMIN),
        "only the admin can do that",
    );
}

fn not_paused() {
    qb::require(qb::get(PAUSED).is_none(), "the bridge is paused");
}

fn set_fee(bps: u128) {
    qb::require(bps <= MAX_FEE_BPS, "the fee is at most 1%");
    qb::set_u128(FEE_BPS, bps);
    qb::emit("fee", &bps.to_le_bytes());
}

fn set_attesters(threshold: u128, list: &[u8]) {
    let count = list.len() / 32;
    qb::require(
        list.len().is_multiple_of(32),
        "attesters are 32-byte addresses",
    );
    qb::require(count <= MAX_ATTESTERS, "at most 16 attesters");
    qb::require(
        threshold > 0 && threshold <= count as u128,
        "the threshold is 1 to the number of attesters",
    );
    let addresses: Vec<&[u8]> = list.chunks(32).collect();
    for (i, a) in addresses.iter().enumerate() {
        qb::require(*a != NOBODY, "an attester has no address");
        qb::require(!addresses[..i].contains(a), "an attester is listed twice");
    }
    qb::set(ATTESTERS, list);
    qb::set_u128(THRESHOLD, threshold);
    qb::set(ERA, &(u64_at(ERA) + 1).to_le_bytes());
    qb::emit("attesters", &pack(&[&threshold.to_le_bytes(), list]));
}

#[unsafe(no_mangle)]
pub extern "C" fn init() {
    let mut args = qb::args();
    let admin = args.address();
    let fee_to = args.address();
    let fee_bps = args.u128();
    let min = args.u128();
    let threshold = args.u128();
    let list = args.bytes();
    qb::require(
        admin != NOBODY && fee_to != NOBODY,
        "the admin and the fee recipient need addresses",
    );
    qb::set(ADMIN, &admin);
    qb::set(FEE_TO, &fee_to);
    set_fee(fee_bps);
    qb::set_u128(MIN, min);
    set_attesters(threshold, &list);
}

#[unsafe(no_mangle)]
pub extern "C" fn bridge() {
    not_paused();
    let to = qb::args().address();
    qb::require(
        to[..12] == [0; 12] && to != NOBODY,
        "an Ethereum address is 20 bytes",
    );
    let amount = qb::value();
    qb::require(
        amount >= qb::get_u128(MIN),
        "less than the bridge's minimum",
    );
    let fee = amount * qb::get_u128(FEE_BPS) / 10_000;
    if fee > 0 {
        qb::require(
            qb::pay(&address_at(FEE_TO), fee),
            "the fee could not be paid",
        );
    }
    let id = u64_at(NEXT);
    qb::set(NEXT, &(id + 1).to_le_bytes());
    let net = amount - fee;
    qb::emit(
        "bridge",
        &pack(&[
            &qb::caller(),
            &to,
            &id.to_le_bytes(),
            &net.to_le_bytes(),
            &fee.to_le_bytes(),
        ]),
    );
    qb::finish(&id.to_le_bytes());
}

fn paid_key(lock_id: u64) -> [u8; 9] {
    let mut key = [b'p'; 9];
    key[1..].copy_from_slice(&lock_id.to_le_bytes());
    key
}

fn votes_key(lock_id: u64, ethereum_tx: &[u8; 32], to: &Address, amount: u128) -> Vec<u8> {
    let claim = qb::hash(&pack(&[
        &u64_at(ERA).to_le_bytes(),
        &lock_id.to_le_bytes(),
        ethereum_tx,
        to,
        &amount.to_le_bytes(),
    ]));
    pack(&[b"v", &claim])
}

#[unsafe(no_mangle)]
pub extern "C" fn attest() {
    not_paused();
    let mut args = qb::args();
    let lock_id = args.u64();
    let ethereum_tx = args.address();
    let to = args.address();
    let amount = args.u128();
    let by = qb::caller();
    let Some(index) = attesters().iter().position(|a| *a == by) else {
        qb::revert("only an attester can attest");
    };
    qb::require(qb::get(&paid_key(lock_id)).is_none(), "already paid");
    qb::require(to != NOBODY && amount > 0, "nothing to pay");
    qb::require(ethereum_tx != NOBODY, "the Ethereum transaction is missing");
    let key = votes_key(lock_id, &ethereum_tx, &to, amount);
    let votes = qb::get_u128(&key) | (1 << index);
    qb::emit("attest", &pack(&[&by, &lock_id.to_le_bytes()]));
    if u128::from(votes.count_ones()) < qb::get_u128(THRESHOLD) {
        qb::set_u128(&key, votes);
        return;
    }
    qb::del(&key);
    qb::set(&paid_key(lock_id), &ethereum_tx);
    qb::require(qb::pay(&to, amount), "the bridge holds less than that");
    qb::emit(
        "release",
        &pack(&[
            &to,
            &lock_id.to_le_bytes(),
            &amount.to_le_bytes(),
            &ethereum_tx,
        ]),
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn fund() {
    qb::require(qb::value() > 0, "send coins with the call");
    qb::emit("fund", &pack(&[&qb::caller(), &qb::value().to_le_bytes()]));
}

#[unsafe(no_mangle)]
pub extern "C" fn set_admin() {
    only_admin();
    let admin = qb::args().address();
    qb::require(admin != NOBODY, "the admin needs an address");
    qb::set(ADMIN, &admin);
    qb::emit("admin", &admin);
}

#[unsafe(no_mangle)]
pub extern "C" fn set_fee_bps() {
    only_admin();
    set_fee(qb::args().u128());
}

#[unsafe(no_mangle)]
pub extern "C" fn set_fee_to() {
    only_admin();
    let fee_to = qb::args().address();
    qb::require(fee_to != NOBODY, "the fee recipient needs an address");
    qb::set(FEE_TO, &fee_to);
    qb::emit("fee_to", &fee_to);
}

#[unsafe(no_mangle)]
pub extern "C" fn set_min() {
    only_admin();
    let min = qb::args().u128();
    qb::set_u128(MIN, min);
    qb::emit("min", &min.to_le_bytes());
}

#[unsafe(no_mangle)]
pub extern "C" fn set_attesters_to() {
    only_admin();
    let mut args = qb::args();
    let threshold = args.u128();
    let list = args.bytes();
    set_attesters(threshold, &list);
}

#[unsafe(no_mangle)]
pub extern "C" fn pause() {
    only_admin();
    qb::set(PAUSED, &[1]);
    qb::emit("paused", &[]);
}

#[unsafe(no_mangle)]
pub extern "C" fn unpause() {
    only_admin();
    qb::del(PAUSED);
    qb::emit("unpaused", &[]);
}

#[unsafe(no_mangle)]
pub extern "C" fn config() {
    let paused: u8 = qb::get(PAUSED).is_some().into();
    qb::finish(&pack(&[
        &address_at(ADMIN),
        &address_at(FEE_TO),
        &qb::get_u128(FEE_BPS).to_le_bytes(),
        &qb::get_u128(MIN).to_le_bytes(),
        &qb::get_u128(THRESHOLD).to_le_bytes(),
        &u64_at(NEXT).to_le_bytes(),
        &[paused],
        &qb::get(ATTESTERS).unwrap_or_default(),
    ]));
}

#[unsafe(no_mangle)]
pub extern "C" fn paid() {
    qb::finish_u128(qb::get(&paid_key(qb::args().u64())).is_some().into());
}

#[unsafe(no_mangle)]
pub extern "C" fn source() {
    let Some(ethereum_tx) = qb::get(&paid_key(qb::args().u64())) else {
        qb::revert("not paid");
    };
    qb::finish(&ethereum_tx);
}
