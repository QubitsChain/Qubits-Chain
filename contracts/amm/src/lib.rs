//! A constant product market: each pool holds two assets, and any swap leaves the product of its
//! reserves no lower than it was. Only governance deploys contracts, so this one contract holds
//! every pool, and anyone can open one by adding its first liquidity.
//!
//! An asset is a token contract, or `native` (all zeros), which comes with the call. For a token,
//! approve this contract for the amount first. A swap pays 0.30%, which stays in the pool for its
//! liquidity providers.
//!
//! - `add_liquidity(a, b, want_a, want_b, min_a, min_b, deadline_ms)` gives shares. The first one
//!   sets the price; later ones take the pool's own ratio, and unused native tokens come back.
//! - `remove_liquidity(a, b, shares, min_a, min_b, deadline_ms)`
//! - `swap(asset_in, asset_out, amount_in, min_out, deadline_ms)` gives the amount out.
//! - `quote(asset_in, asset_out, amount_in)`, `pool(a, b)` (reserve of a, reserve of b, shares),
//!   `shares(a, b, who)`.
//!
//! The limits are what protect a trade: anyone can see it coming and trade first, so `min_out`
//! says how bad a price is acceptable and the deadline how late. A pool's price is what the last
//! trade left it at, not a fair price: another contract must not trust it as one.
//!
//! Reserves are this contract's own books, never its balances. Sending tokens here directly
//! changes no price and buys no shares, which closes the usual way to steal from the first
//! depositors. Calls out can't come back in: the chain refuses re-entry.
#![no_std]

use qubits_contract_math::{mul_div, product_at_least, sqrt_product};
use qubits_contract_sdk::{self as qb, Address, NOBODY, pack};

const FEE_BPS: u128 = 30;
const BPS: u128 = 10_000;
/// Keeps every price calculation within `u128`, with room for the basis points.
const MAX_RESERVE: u128 = 1 << 112;
/// Burned from a pool's first shares, so a pool can never shrink to a few indivisible units.
const LOCKED_SHARES: u128 = 1_000;

/// Always in address order, so a pair of assets has one pool whichever way it is named.
struct Pool {
    id: [u8; 32],
    low: Address,
    high: Address,
    reserve_low: u128,
    reserve_high: u128,
    shares: u128,
}

fn pool_key(id: &[u8; 32]) -> [u8; 33] {
    let mut key = [b'p'; 33];
    key[1..].copy_from_slice(id);
    key
}

fn shares_key(id: &[u8; 32], who: &Address) -> [u8; 65] {
    let mut key = [b's'; 65];
    key[1..33].copy_from_slice(id);
    key[33..].copy_from_slice(who);
    key
}

impl Pool {
    fn load(a: &Address, b: &Address) -> Pool {
        qb::require(a != b, "a pool needs two assets");
        let (low, high) = if a < b { (*a, *b) } else { (*b, *a) };
        let id = qb::hash(&pack(&[&low, &high]));
        let mut pool = Pool {
            id,
            low,
            high,
            reserve_low: 0,
            reserve_high: 0,
            shares: 0,
        };
        if let Some(bytes) = qb::get(&pool_key(&id)) {
            let mut stored = qb::Args::over(bytes);
            pool.reserve_low = stored.u128();
            pool.reserve_high = stored.u128();
            pool.shares = stored.u128();
        }
        pool
    }

    fn save(&self) {
        let stored = pack(&[
            &self.reserve_low.to_le_bytes(),
            &self.reserve_high.to_le_bytes(),
            &self.shares.to_le_bytes(),
        ]);
        qb::set(&pool_key(&self.id), &stored);
    }

    /// `(this, other)` of any pair given in `a`'s terms.
    fn ordered<T>(&self, a: &Address, for_a: T, for_b: T) -> (T, T) {
        if *a == self.low {
            (for_a, for_b)
        } else {
            (for_b, for_a)
        }
    }

    fn held_by(&self, who: &Address) -> u128 {
        qb::get_u128(&shares_key(&self.id, who))
    }

    fn set_held_by(&self, who: &Address, shares: u128) {
        qb::set_u128(&shares_key(&self.id, who), shares);
    }
}

fn scaled(amount: u128, numerator: u128, denominator: u128) -> u128 {
    match mul_div(amount, numerator, denominator) {
        Some(result) => result,
        None => qb::revert("amount out of range"),
    }
}

fn check_deadline(deadline_ms: u64) {
    qb::require(qb::now_ms() <= deadline_ms, "deadline has passed");
}

/// Native tokens came with the call, so only tokens have to be fetched.
fn pull(asset: &Address, from: &Address, amount: u128) {
    if *asset != NOBODY {
        let args = pack(&[from, &qb::this(), &amount.to_le_bytes()]);
        qb::require(
            qb::call(asset, "transfer_from", &args, 0).is_ok(),
            "token transfer failed; approve this contract first",
        );
    }
}

fn push(asset: &Address, to: &Address, amount: u128) {
    let paid = if *asset == NOBODY {
        qb::pay(to, amount)
    } else {
        let args = pack(&[to, &amount.to_le_bytes()]);
        qb::call(asset, "transfer", &args, 0).is_ok()
    };
    qb::require(paid, "payment failed");
}

fn amount_out(amount_in: u128, reserve_in: u128, reserve_out: u128) -> u128 {
    qb::require(amount_in <= MAX_RESERVE, "pool is full");
    let after_fee = amount_in * (BPS - FEE_BPS);
    scaled(reserve_out, after_fee, reserve_in * BPS + after_fee)
}

#[unsafe(no_mangle)]
pub extern "C" fn add_liquidity() {
    let mut args = qb::args();
    let (a, b) = (args.address(), args.address());
    let (want_a, want_b) = (args.u128(), args.u128());
    let (min_a, min_b) = (args.u128(), args.u128());
    check_deadline(args.u64());
    let provider = qb::caller();
    let mut pool = Pool::load(&a, &b);
    let (want_low, want_high) = pool.ordered(&a, want_a, want_b);
    let (min_low, min_high) = pool.ordered(&a, min_a, min_b);
    qb::require(want_low > 0 && want_high > 0, "nothing to add");

    let native_wanted = if a == NOBODY {
        want_a
    } else if b == NOBODY {
        want_b
    } else {
        0
    };
    qb::require(
        qb::value() == native_wanted,
        "send the native amount with the call",
    );

    let (low, high) = if pool.shares == 0 {
        (want_low, want_high)
    } else {
        let high = scaled(want_low, pool.reserve_high, pool.reserve_low);
        if high <= want_high {
            (want_low, high)
        } else {
            (
                scaled(want_high, pool.reserve_low, pool.reserve_high),
                want_high,
            )
        }
    };
    qb::require(
        low >= min_low && high >= min_high,
        "price moved past the limit",
    );
    qb::require(low > 0 && high > 0, "too small for this pool");

    let minted = if pool.shares == 0 {
        let root = sqrt_product(low, high);
        qb::require(root > LOCKED_SHARES, "too small to open a pool");
        pool.shares = LOCKED_SHARES;
        root - LOCKED_SHARES
    } else {
        scaled(low, pool.shares, pool.reserve_low).min(scaled(high, pool.shares, pool.reserve_high))
    };
    qb::require(minted > 0, "too small for this pool");

    pool.reserve_low += low;
    pool.reserve_high += high;
    pool.shares += minted;
    qb::require(
        pool.reserve_low <= MAX_RESERVE && pool.reserve_high <= MAX_RESERVE,
        "pool is full",
    );
    pool.save();
    pool.set_held_by(&provider, pool.held_by(&provider) + minted);

    pull(&pool.low, &provider, low);
    pull(&pool.high, &provider, high);
    let native_used = if pool.low == NOBODY { low } else { 0 };
    if native_wanted > native_used {
        push(&NOBODY, &provider, native_wanted - native_used);
    }
    qb::emit(
        "add",
        &pack(&[&pool.id, &provider, &low.to_le_bytes(), &high.to_le_bytes()]),
    );
    qb::finish_u128(minted);
}

#[unsafe(no_mangle)]
pub extern "C" fn remove_liquidity() {
    let mut args = qb::args();
    let (a, b) = (args.address(), args.address());
    let shares = args.u128();
    let (min_a, min_b) = (args.u128(), args.u128());
    check_deadline(args.u64());
    let provider = qb::caller();
    let mut pool = Pool::load(&a, &b);
    let held = pool.held_by(&provider);
    qb::require(shares > 0 && shares <= held, "not that many shares");

    let low = scaled(shares, pool.reserve_low, pool.shares);
    let high = scaled(shares, pool.reserve_high, pool.shares);
    let (min_low, min_high) = pool.ordered(&a, min_a, min_b);
    qb::require(
        low >= min_low && high >= min_high,
        "price moved past the limit",
    );
    qb::require(low > 0 && high > 0, "too small for this pool");

    pool.reserve_low -= low;
    pool.reserve_high -= high;
    pool.shares -= shares;
    pool.save();
    pool.set_held_by(&provider, held - shares);

    push(&pool.low, &provider, low);
    push(&pool.high, &provider, high);
    qb::emit(
        "remove",
        &pack(&[&pool.id, &provider, &low.to_le_bytes(), &high.to_le_bytes()]),
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn swap() {
    let mut args = qb::args();
    let (asset_in, asset_out) = (args.address(), args.address());
    let amount_in = args.u128();
    let min_out = args.u128();
    check_deadline(args.u64());
    let trader = qb::caller();
    qb::require(amount_in > 0, "nothing to swap");
    let native_in = if asset_in == NOBODY { amount_in } else { 0 };
    qb::require(
        qb::value() == native_in,
        "send the native amount with the call",
    );

    let mut pool = Pool::load(&asset_in, &asset_out);
    qb::require(pool.shares > 0, "no such pool");
    let (reserve_in, reserve_out) = pool.ordered(&asset_in, pool.reserve_low, pool.reserve_high);
    let out = amount_out(amount_in, reserve_in, reserve_out);
    qb::require(out >= min_out, "price moved past the limit");
    qb::require(out > 0, "too small for this pool");

    let after_in = reserve_in + amount_in;
    let after_out = reserve_out - out;
    qb::require(after_in <= MAX_RESERVE, "pool is full");
    // the formula already keeps this; it costs little to refuse if the formula is ever wrong
    qb::require(
        product_at_least(after_in, after_out, reserve_in, reserve_out),
        "the product fell",
    );
    (pool.reserve_low, pool.reserve_high) = pool.ordered(&asset_in, after_in, after_out);
    pool.save();

    pull(&asset_in, &trader, amount_in);
    push(&asset_out, &trader, out);
    qb::emit(
        "swap",
        &pack(&[
            &pool.id,
            &trader,
            &amount_in.to_le_bytes(),
            &out.to_le_bytes(),
        ]),
    );
    qb::finish_u128(out);
}

#[unsafe(no_mangle)]
pub extern "C" fn quote() {
    let mut args = qb::args();
    let (asset_in, asset_out) = (args.address(), args.address());
    let amount_in = args.u128();
    let pool = Pool::load(&asset_in, &asset_out);
    qb::require(pool.shares > 0, "no such pool");
    let (reserve_in, reserve_out) = pool.ordered(&asset_in, pool.reserve_low, pool.reserve_high);
    qb::finish_u128(amount_out(amount_in, reserve_in, reserve_out));
}

#[unsafe(no_mangle)]
pub extern "C" fn pool() {
    let mut args = qb::args();
    let (a, b) = (args.address(), args.address());
    let pool = Pool::load(&a, &b);
    let (reserve_a, reserve_b) = pool.ordered(&a, pool.reserve_low, pool.reserve_high);
    qb::finish(&pack(&[
        &reserve_a.to_le_bytes(),
        &reserve_b.to_le_bytes(),
        &pool.shares.to_le_bytes(),
    ]));
}

#[unsafe(no_mangle)]
pub extern "C" fn shares() {
    let mut args = qb::args();
    let (a, b) = (args.address(), args.address());
    let who = args.address();
    qb::finish_u128(Pool::load(&a, &b).held_by(&who));
}
