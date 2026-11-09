//! A constant product market: each pool holds two assets, and any swap leaves the product of its
//! reserves no lower than it was. Only governance adds code, so this one contract holds every
//! pool.
//!
//! An open pool is opened by anyone adding its first liquidity; a swap there pays 0.30%, which
//! stays in the pool for its liquidity providers. A launched pool is made by `create`, which
//! starts a new token of 1,000,000 that no one can mint more of, puts all of it in, and trades it
//! as if 100, 250, 500 or 1,000 native tokens stood against it. Native tokens sent with `create`
//! buy some at once for whoever launched it. Its liquidity can't be taken out. A trade there,
//! buying or selling, pays 0.35% of its native side in the same call: 0.10% to the protocol and
//! 0.25% to the launcher.
//!
//! An asset is a token contract, or `native` (all zeros), which comes with the call. For a token,
//! approve this contract for the amount first.
//!
//! - `init(protocol, token_code)`: where the protocol's 0.10% goes, and the hash of the token
//!   code `create` starts, which must already be on chain.
//! - `add_liquidity(a, b, want_a, want_b, min_a, min_b, deadline_ms)` gives shares. The first one
//!   sets the price; later ones take the pool's own ratio, and unused native tokens come back.
//! - `remove_liquidity(a, b, shares, min_a, min_b, deadline_ms)`
//! - `create(name, symbol, virtual_native)`, the virtual amount in whole native tokens, gives the
//!   token's address and what the native tokens sent along bought.
//! - `swap(asset_in, asset_out, amount_in, min_out, deadline_ms)` gives the amount out.
//! - `quote(asset_in, asset_out, amount_in)`, `pool(a, b)` (reserve of a, reserve of b, shares),
//!   `shares(a, b, who)`, `launched(token)` (virtual amount in base units, launcher),
//!   `protocol()`.
//!
//! The limits are what protect a trade: anyone can see it coming and trade first, so `min_out`
//! says how bad a price is acceptable and the deadline how late. A pool's price is what the last
//! trade left it at, not a fair price: another contract must not trust it as one.
//!
//! Reserves are this contract's own books, never its balances. Sending tokens here directly
//! changes no price and buys no shares, which closes the usual way to steal from the first
//! depositors. Calls out can't come back in: the chain refuses re-entry. A launched pool pays out
//! only what its buyers paid in, never the virtual amount.
#![no_std]

use qubits_contract_math::{mul_div, product_at_least, sqrt_product};
use qubits_contract_sdk::{self as qb, Address, NOBODY, pack};

const FEE_BPS: u128 = 30;
const PROTOCOL_BPS: u128 = 10;
const LAUNCHER_BPS: u128 = 25;
const BPS: u128 = 10_000;
/// Keeps every price calculation within `u128`, with room for the basis points.
const MAX_RESERVE: u128 = 1 << 112;
/// Burned from a pool's first shares, so a pool can never shrink to a few indivisible units.
const LOCKED_SHARES: u128 = 1_000;

const ONE: u128 = 1_000_000_000_000_000_000;
const LAUNCH_DECIMALS: u64 = 18;
const LAUNCH_SUPPLY: u128 = 1_000_000 * ONE;
const VIRTUAL_CHOICES: [u128; 4] = [100, 250, 500, 1_000];
const MAX_NAME: usize = 32;
const MAX_SYMBOL: usize = 10;

const PROTOCOL: &[u8] = b"protocol";
const TOKEN_CODE: &[u8] = b"token_code";

#[derive(Clone, Copy)]
struct Launch {
    virtual_native: u128,
    launcher: Address,
}

/// Always in address order, so a pair of assets has one pool whichever way it is named.
struct Pool {
    id: [u8; 32],
    low: Address,
    high: Address,
    reserve_low: u128,
    reserve_high: u128,
    shares: u128,
    launch: Option<Launch>,
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
            launch: None,
        };
        if let Some(bytes) = qb::get(&pool_key(&id)) {
            let launched = bytes.len() > 48;
            let mut stored = qb::Args::over(bytes);
            pool.reserve_low = stored.u128();
            pool.reserve_high = stored.u128();
            pool.shares = stored.u128();
            if launched {
                pool.launch = Some(Launch {
                    virtual_native: stored.u128(),
                    launcher: stored.address(),
                });
            }
        }
        pool
    }

    fn save(&self) {
        let mut stored = pack(&[
            &self.reserve_low.to_le_bytes(),
            &self.reserve_high.to_le_bytes(),
            &self.shares.to_le_bytes(),
        ]);
        if let Some(launch) = &self.launch {
            stored.extend_from_slice(&launch.virtual_native.to_le_bytes());
            stored.extend_from_slice(&launch.launcher);
        }
        qb::set(&pool_key(&self.id), &stored);
    }

    fn exists(&self) -> bool {
        self.shares > 0 || self.launch.is_some()
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

fn protocol_address() -> Address {
    qb::Args::over(qb::get(PROTOCOL).expect("set at init")).address()
}

fn pay_fee(to: &Address, amount: u128) {
    if amount > 0 {
        push(&NOBODY, to, amount);
    }
}

fn launch_fees(native: u128) -> (u128, u128) {
    (native * PROTOCOL_BPS / BPS, native * LAUNCHER_BPS / BPS)
}

struct Trade {
    out: u128,
    reserve_in: u128,
    reserve_out: u128,
    protocol_fee: u128,
    launcher_fee: u128,
}

// the formula already keeps the product; it costs little to refuse if the formula is ever wrong
fn check_product(after_in: u128, after_out: u128, before_in: u128, before_out: u128) {
    qb::require(after_in <= MAX_RESERVE, "pool is full");
    qb::require(
        product_at_least(after_in, after_out, before_in, before_out),
        "the product fell",
    );
}

fn trade(pool: &Pool, asset_in: &Address, amount_in: u128) -> Trade {
    qb::require(amount_in <= MAX_RESERVE, "pool is full");
    let (reserve_in, reserve_out) = pool.ordered(asset_in, pool.reserve_low, pool.reserve_high);
    let Some(launch) = pool.launch else {
        let after_fee = amount_in * (BPS - FEE_BPS);
        let out = scaled(reserve_out, after_fee, reserve_in * BPS + after_fee);
        check_product(reserve_in + amount_in, reserve_out - out, reserve_in, reserve_out);
        return Trade {
            out,
            reserve_in: reserve_in + amount_in,
            reserve_out: reserve_out - out,
            protocol_fee: 0,
            launcher_fee: 0,
        };
    };
    if *asset_in == NOBODY {
        let (protocol_fee, launcher_fee) = launch_fees(amount_in);
        let paid = amount_in - protocol_fee - launcher_fee;
        let native = reserve_in + launch.virtual_native;
        let out = scaled(reserve_out, paid, native + paid);
        check_product(native + paid, reserve_out - out, native, reserve_out);
        Trade {
            out,
            reserve_in: reserve_in + paid,
            reserve_out: reserve_out - out,
            protocol_fee,
            launcher_fee,
        }
    } else {
        let native = reserve_out + launch.virtual_native;
        let gross = scaled(native, amount_in, reserve_in + amount_in);
        qb::require(gross <= reserve_out, "the pool holds less than that");
        check_product(reserve_in + amount_in, native - gross, reserve_in, native);
        let (protocol_fee, launcher_fee) = launch_fees(gross);
        Trade {
            out: gross - protocol_fee - launcher_fee,
            reserve_in: reserve_in + amount_in,
            reserve_out: reserve_out - gross,
            protocol_fee,
            launcher_fee,
        }
    }
}

fn readable(text: &[u8], longest: usize) -> bool {
    !text.is_empty() && text.len() <= longest && !text.iter().any(|&b| b < 0x20 || b == 0x7f)
}

fn exchange(
    pool: &mut Pool,
    trader: &Address,
    asset_in: &Address,
    asset_out: &Address,
    amount_in: u128,
    min_out: u128,
) -> u128 {
    let trade = trade(pool, asset_in, amount_in);
    qb::require(trade.out >= min_out, "price moved past the limit");
    qb::require(trade.out > 0, "too small for this pool");
    (pool.reserve_low, pool.reserve_high) =
        pool.ordered(asset_in, trade.reserve_in, trade.reserve_out);
    pool.save();

    pull(asset_in, trader, amount_in);
    push(asset_out, trader, trade.out);
    let mut event = pack(&[
        &pool.id,
        trader,
        &amount_in.to_le_bytes(),
        &trade.out.to_le_bytes(),
    ]);
    if let Some(launch) = &pool.launch {
        pay_fee(&protocol_address(), trade.protocol_fee);
        pay_fee(&launch.launcher, trade.launcher_fee);
        event.extend_from_slice(&launch.launcher);
        event.extend_from_slice(&trade.protocol_fee.to_le_bytes());
        event.extend_from_slice(&trade.launcher_fee.to_le_bytes());
    }
    qb::emit("swap", &event);
    trade.out
}

#[unsafe(no_mangle)]
pub extern "C" fn init() {
    let mut args = qb::args();
    let protocol = args.address();
    let token_code = args.address();
    qb::require(protocol != NOBODY, "the protocol's fees need an address");
    qb::set(PROTOCOL, &protocol);
    qb::set(TOKEN_CODE, &token_code);
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
    qb::require(pool.launch.is_none(), "a launched pool takes no liquidity");
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
pub extern "C" fn create() {
    let mut args = qb::args();
    let name = args.bytes();
    let symbol = args.bytes();
    let virtual_whole = args.u128();
    qb::require(
        VIRTUAL_CHOICES.contains(&virtual_whole),
        "the virtual amount is 100, 250, 500 or 1000",
    );
    qb::require(readable(&name, MAX_NAME), "a name of 1 to 32 printable bytes");
    qb::require(
        readable(&symbol, MAX_SYMBOL),
        "a symbol of 1 to 10 printable bytes",
    );
    let launcher = qb::caller();
    let this = qb::this();

    let code: [u8; 32] = qb::get(TOKEN_CODE)
        .expect("set at init")
        .try_into()
        .expect("stored as 32 bytes");
    let init = pack(&[
        &this,
        &LAUNCH_SUPPLY.to_le_bytes(),
        &(name.len() as u32).to_le_bytes(),
        &name,
        &(symbol.len() as u32).to_le_bytes(),
        &symbol,
        &LAUNCH_DECIMALS.to_le_bytes(),
    ]);
    let Ok(token) = qb::create(&code, &init, 0) else {
        qb::revert("could not create the token");
    };
    qb::require(
        qb::call(&token, "set_owner", &NOBODY, 0).is_ok(),
        "could not end the token's minting",
    );

    let virtual_native = virtual_whole * ONE;
    let mut pool = Pool::load(&NOBODY, &token);
    (pool.reserve_low, pool.reserve_high) = pool.ordered(&NOBODY, 0, LAUNCH_SUPPLY);
    pool.launch = Some(Launch {
        virtual_native,
        launcher,
    });
    pool.save();
    qb::emit(
        "launch",
        &pack(&[&pool.id, &token, &launcher, &virtual_native.to_le_bytes()]),
    );

    let spent = qb::value();
    let bought = if spent > 0 {
        exchange(&mut pool, &launcher, &NOBODY, &token, spent, 0)
    } else {
        0
    };
    qb::finish(&pack(&[&token, &bought.to_le_bytes()]));
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
    qb::require(pool.exists(), "no such pool");
    let out = exchange(&mut pool, &trader, &asset_in, &asset_out, amount_in, min_out);
    qb::finish_u128(out);
}

#[unsafe(no_mangle)]
pub extern "C" fn quote() {
    let mut args = qb::args();
    let (asset_in, asset_out) = (args.address(), args.address());
    let amount_in = args.u128();
    let pool = Pool::load(&asset_in, &asset_out);
    qb::require(pool.exists(), "no such pool");
    qb::finish_u128(trade(&pool, &asset_in, amount_in).out);
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

#[unsafe(no_mangle)]
pub extern "C" fn launched() {
    let token = qb::args().address();
    let Some(launch) = Pool::load(&NOBODY, &token).launch else {
        qb::revert("not launched");
    };
    qb::finish(&pack(&[
        &launch.virtual_native.to_le_bytes(),
        &launch.launcher,
    ]));
}

#[unsafe(no_mangle)]
pub extern "C" fn protocol() {
    qb::finish(&protocol_address());
}
