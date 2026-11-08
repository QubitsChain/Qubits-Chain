//! A fungible token: what a bridged or issued asset is on this chain. The owner mints, and can
//! hand that on or give it up for good; anyone can spend what they hold, or let someone else
//! spend it. Amounts are whole base units: `decimals` only says how to show them.
//!
//! `init(owner, supply, name, symbol, decimals)`, `transfer(to, amount)`,
//! `approve(spender, amount)`, `transfer_from(from, to, amount)`, `mint(to, amount)`,
//! `burn(amount)`, `set_owner(new_owner)`, `balance_of(who)`, `allowance(owner, spender)`,
//! `total_supply()`, `owner()`, `name()`, `symbol()`, `decimals()`.
#![no_std]

use qubits_contract_sdk::{self as qb, Address, NOBODY, pack};

const OWNER: &[u8] = b"owner";
const SUPPLY: &[u8] = b"supply";
const NAME: &[u8] = b"name";
const SYMBOL: &[u8] = b"symbol";
const DECIMALS: &[u8] = b"decimals";

fn balance_key(who: &Address) -> [u8; 33] {
    let mut key = [b'b'; 33];
    key[1..].copy_from_slice(who);
    key
}

fn allowance_key(owner: &Address, spender: &Address) -> [u8; 65] {
    let mut key = [b'a'; 65];
    key[1..33].copy_from_slice(owner);
    key[33..].copy_from_slice(spender);
    key
}

fn credit(to: &Address, amount: u128) {
    let key = balance_key(to);
    qb::set_u128(&key, qb::get_u128(&key) + amount);
}

fn debit(from: &Address, amount: u128) {
    let key = balance_key(from);
    let balance = qb::get_u128(&key);
    qb::require(balance >= amount, "balance too low");
    qb::set_u128(&key, balance - amount);
}

fn send(from: &Address, to: &Address, amount: u128) {
    debit(from, amount);
    credit(to, amount);
    qb::emit("transfer", &pack(&[from, to, &amount.to_le_bytes()]));
}

fn add_supply(amount: u128) {
    qb::set_u128(SUPPLY, qb::get_u128(SUPPLY) + amount);
}

#[unsafe(no_mangle)]
pub extern "C" fn init() {
    let mut args = qb::args();
    let owner = args.address();
    let supply = args.u128();
    let name = args.bytes();
    let symbol = args.bytes();
    let decimals = args.u64();
    qb::require(decimals <= 38, "more decimals than a u128 has digits");
    qb::set(OWNER, &owner);
    qb::set(NAME, &name);
    qb::set(SYMBOL, &symbol);
    qb::set(DECIMALS, &decimals.to_le_bytes());
    add_supply(supply);
    credit(&owner, supply);
}

#[unsafe(no_mangle)]
pub extern "C" fn transfer() {
    let mut args = qb::args();
    let to = args.address();
    let amount = args.u128();
    send(&qb::caller(), &to, amount);
}

#[unsafe(no_mangle)]
pub extern "C" fn approve() {
    let mut args = qb::args();
    let spender = args.address();
    let amount = args.u128();
    let owner = qb::caller();
    qb::set_u128(&allowance_key(&owner, &spender), amount);
    qb::emit("approve", &pack(&[&owner, &spender, &amount.to_le_bytes()]));
}

#[unsafe(no_mangle)]
pub extern "C" fn transfer_from() {
    let mut args = qb::args();
    let from = args.address();
    let to = args.address();
    let amount = args.u128();
    let key = allowance_key(&from, &qb::caller());
    let allowed = qb::get_u128(&key);
    qb::require(allowed >= amount, "allowance too low");
    qb::set_u128(&key, allowed - amount);
    send(&from, &to, amount);
}

#[unsafe(no_mangle)]
pub extern "C" fn mint() {
    let mut args = qb::args();
    let to = args.address();
    let amount = args.u128();
    only_owner();
    add_supply(amount);
    credit(&to, amount);
    qb::emit("mint", &pack(&[&to, &amount.to_le_bytes()]));
}

fn only_owner() {
    let owner = qb::get(OWNER).expect("set at init");
    qb::require(owner == qb::caller(), "only the owner can do that");
}

/// `NOBODY` as the new owner ends minting for good.
#[unsafe(no_mangle)]
pub extern "C" fn set_owner() {
    let new_owner = qb::args().address();
    only_owner();
    qb::set(OWNER, &new_owner);
    qb::emit("owner", &new_owner);
    if new_owner == NOBODY {
        qb::emit("supply_fixed", &qb::get_u128(SUPPLY).to_le_bytes());
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn burn() {
    let amount = qb::args().u128();
    let from = qb::caller();
    debit(&from, amount);
    qb::set_u128(SUPPLY, qb::get_u128(SUPPLY) - amount);
    qb::emit("burn", &pack(&[&from, &amount.to_le_bytes()]));
}

#[unsafe(no_mangle)]
pub extern "C" fn balance_of() {
    qb::finish_u128(qb::get_u128(&balance_key(&qb::args().address())));
}

#[unsafe(no_mangle)]
pub extern "C" fn allowance() {
    let mut args = qb::args();
    let owner = args.address();
    let spender = args.address();
    qb::finish_u128(qb::get_u128(&allowance_key(&owner, &spender)));
}

#[unsafe(no_mangle)]
pub extern "C" fn total_supply() {
    qb::finish_u128(qb::get_u128(SUPPLY));
}

#[unsafe(no_mangle)]
pub extern "C" fn owner() {
    qb::finish(&qb::get(OWNER).expect("set at init"));
}

#[unsafe(no_mangle)]
pub extern "C" fn name() {
    qb::finish(&qb::get(NAME).expect("set at init"));
}

#[unsafe(no_mangle)]
pub extern "C" fn symbol() {
    qb::finish(&qb::get(SYMBOL).expect("set at init"));
}

#[unsafe(no_mangle)]
pub extern "C" fn decimals() {
    qb::finish(&qb::get(DECIMALS).expect("set at init"));
}
