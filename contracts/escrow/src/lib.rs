//! Settlement between two parties who don't trust each other: the payer locks funds, and they
//! go to the payee or back, never anywhere else. An arbiter can decide either way. After the
//! deadline the payer can take them back alone, so a silent payee can't hold them forever.
//!
//! `asset` is a token contract, or all zeros for the native token, which comes with the call.
//! Before locking a token the payer approves this contract for the amount.
//!
//! `open(payee, arbiter, asset, amount, deadline_ms)` gives a deal id; `release(id)` pays the
//! payee, `refund(id)` pays the payer back, `deal(id)` shows the deal.
#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use qubits_contract_sdk::{self as qb, Address, NOBODY, pack};

const NEXT: &[u8] = b"next";

struct Deal {
    payer: Address,
    payee: Address,
    arbiter: Address,
    asset: Address,
    amount: u128,
    deadline_ms: u64,
}

impl Deal {
    fn encode(&self) -> Vec<u8> {
        pack(&[
            &self.payer,
            &self.payee,
            &self.arbiter,
            &self.asset,
            &self.amount.to_le_bytes(),
            &self.deadline_ms.to_le_bytes(),
        ])
    }

    fn decode(bytes: Vec<u8>) -> Deal {
        let mut args = qb::Args::over(bytes);
        Deal {
            payer: args.address(),
            payee: args.address(),
            arbiter: args.address(),
            asset: args.address(),
            amount: args.u128(),
            deadline_ms: args.u64(),
        }
    }
}

fn deal_key(id: u64) -> [u8; 9] {
    let mut key = [b'd'; 9];
    key[1..].copy_from_slice(&id.to_le_bytes());
    key
}

/// Takes the deal off the books first, so it can only ever be settled once.
fn close(id: u64) -> Deal {
    let key = deal_key(id);
    let Some(bytes) = qb::get(&key) else {
        qb::revert("no such deal");
    };
    qb::del(&key);
    Deal::decode(bytes)
}

fn pay_out(deal: &Deal, to: &Address) {
    let paid = if deal.asset == NOBODY {
        qb::pay(to, deal.amount)
    } else {
        let args = pack(&[to, &deal.amount.to_le_bytes()]);
        qb::call(&deal.asset, "transfer", &args, 0).is_ok()
    };
    qb::require(paid, "payment failed");
}

#[unsafe(no_mangle)]
pub extern "C" fn open() {
    let mut args = qb::args();
    let payee = args.address();
    let arbiter = args.address();
    let asset = args.address();
    let amount = args.u128();
    let deadline_ms = args.u64();
    let payer = qb::caller();
    qb::require(amount > 0, "nothing to lock");
    qb::require(deadline_ms > qb::now_ms(), "deadline has passed");
    if asset == NOBODY {
        qb::require(qb::value() == amount, "send the amount with the call");
    } else {
        qb::require(qb::value() == 0, "native tokens sent with a token deal");
        let args = pack(&[&payer, &qb::this(), &amount.to_le_bytes()]);
        qb::require(
            qb::call(&asset, "transfer_from", &args, 0).is_ok(),
            "token transfer failed",
        );
    }
    let id = qb::get(NEXT).map_or(0, |bytes| {
        u64::from_le_bytes(bytes.try_into().expect("stored as 8 bytes"))
    });
    qb::set(NEXT, &(id + 1).to_le_bytes());
    let deal = Deal {
        payer,
        payee,
        arbiter,
        asset,
        amount,
        deadline_ms,
    };
    qb::set(&deal_key(id), &deal.encode());
    qb::emit("open", &id.to_le_bytes());
    qb::finish(&id.to_le_bytes());
}

#[unsafe(no_mangle)]
pub extern "C" fn release() {
    let id = qb::args().u64();
    let deal = close(id);
    let by = qb::caller();
    qb::require(
        by == deal.payer || by == deal.arbiter,
        "only the payer or the arbiter can release",
    );
    pay_out(&deal, &deal.payee);
    qb::emit("release", &id.to_le_bytes());
}

#[unsafe(no_mangle)]
pub extern "C" fn refund() {
    let id = qb::args().u64();
    let deal = close(id);
    let by = qb::caller();
    let expired = by == deal.payer && qb::now_ms() >= deal.deadline_ms;
    qb::require(
        by == deal.payee || by == deal.arbiter || expired,
        "only the payee or the arbiter, or the payer after the deadline, can refund",
    );
    pay_out(&deal, &deal.payer);
    qb::emit("refund", &id.to_le_bytes());
}

#[unsafe(no_mangle)]
pub extern "C" fn deal() {
    let id = qb::args().u64();
    let Some(bytes) = qb::get(&deal_key(id)) else {
        qb::revert("no such deal");
    };
    qb::finish(&bytes);
}
