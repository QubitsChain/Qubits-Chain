# Contracts

The contracts the chain runs. For now only the governance account can deploy, so new code runs only once a quorum of validators has signed its deployment. A running contract can start others from code already on chain.

| | |
|---|---|
| `sdk/` | what contracts are written with: `qubits-contract-sdk`, `no_std`, no dependencies |
| `math/` | what prices need and `u128` can't hold: 256-bit products, exact division, roots |
| `token/` | a fungible token with a name, a symbol, decimals and an owner who mints |
| `amm/` | a constant product market: every pool in one contract, 0.30% to liquidity providers, and `create`, which makes a token and puts its whole supply against virtual liquidity |
| `escrow/` | settlement between two parties, in the native token or a token |
| `bridge/` | the Qubits side of the bridge to BITS on Ethereum: coins sent out less a fee, and releases a threshold of attesters agree on, each paid once with its Ethereum transaction kept |
| `out/` | the built contracts, which tests and deployments use |

```sh
./build.sh      # from this directory; needs the wasm32-unknown-unknown target, which the toolchain file installs
```

## Writing one

A contract is a `no_std` `cdylib`. Each function is an exported `extern "C" fn()` that reads its arguments from the host. `init` runs once, at deployment, and no one can call it again.

```rust
#![no_std]
use qubits_contract_sdk::{self as qb};

#[unsafe(no_mangle)]
pub extern "C" fn set_note() {
    let note = qb::args().bytes();
    qb::require(!note.is_empty(), "an empty note");
    qb::set(&qb::caller(), &note);
    qb::emit("note", &qb::caller());
}
```

What the chain guarantees, so a contract doesn't have to:

- **No re-entrancy.** A running contract can't be called again, in any depth of calls.
- **Failure undoes everything.** A revert, a trap or running out of gas removes all the call changed, events included.
- **A failed callee is undone alone.** `qb::call` returns `Err` and the caller decides.
- **Nobody reaches in.** A contract sees only its own storage and sends only its own balance.
- **A panic reverts.** With overflow checks on, so does overflowing arithmetic.

What it does not get: floats, a clock finer than the block time, randomness, or a way to pull tokens from an account. A vault's calls wait for its delay, so don't expect a call in the same block as the one before it.

The block time is agreed on to within seconds. Don't build on seconds.

## Deploying and calling

```sh
qubits contract deploy contracts/out/token.wasm --arg qb1owner… --arg 1000000000000 \
    --arg '"Example Token"' --arg '"EXT"' --arg u64:6 --out token.json
qubits tx sign --file token.json --key validator.json --password-file pw   # each validator, up to a quorum
qubits tx submit --file token.json --wait                                  # prints the contract's address

qubits contract call 'qb1token….transfer(qb1bob…, 5)' --key alice.json --password-file pw --wait
qubits contract view 'qb1token….balance_of(qb1bob…)' --as u128
```

In a call, `qb1…` is an address, `native` the native token's zero address, `5` a `u128`, `u64:5` a `u64`, `deadline:600` the time 600 seconds from now, `"text"` bytes with a length in front, and `0xabcd` raw bytes. These are the shapes `Args` reads, in the same order. The governance account pays for deployments, so it needs funds.

## Trading

```sh
# open a pool, or add to one: a token approves first, the native token comes with the call
qubits contract call 'qb1token….approve(qb1amm…, 100000)' --key alice.json --password-file pw --wait
qubits contract call 'qb1amm….add_liquidity(qb1token…, native, 100000, 400000, 0, 0, deadline:600)' \
    --amount 400000 --key alice.json --password-file pw --wait

qubits contract view 'qb1amm….quote(native, qb1token…, 40000)' --as u128
qubits contract call 'qb1amm….swap(native, qb1token…, 40000, 8900, deadline:600)' \
    --amount 40000 --key alice.json --password-file pw --wait

qubits contract view 'qb1amm….pool(qb1token…, native)' --as u128s    # reserves and shares
```

`8900` there is the least you accept. Set it from `quote`, a little lower: without it anyone can trade just before you and take the difference. Removing liquidity is `remove_liquidity(a, b, shares, min_a, min_b, deadline)`.

The AMM is deployed after `token.wasm` is on chain, with the address that gets the protocol's share and the token code's hash (the `code` of `qubits contract show qb1token…`): `--arg qb1protocol… --arg 0x<hash>`. Anyone can then make a token of 1,000,000 (18 decimals, minting ended) whose whole supply trades against 100, 250, 500 or 1000 virtual native tokens. Native tokens sent along buy some in the same call. Its liquidity stays in for good, and every trade pays 0.10% to the protocol and 0.25% to the launcher, in native tokens, in the same call.

```sh
qubits contract call 'qb1amm….create("Quantum Cat", "QCAT", 500)' --amount 10000000000000000000 \
    --key you.json --password-file pw --wait          # gives the token's address and what 10 bought
qubits contract view 'qb1amm….launched(qb1coin…)'     # the virtual amount and the launcher
```

Amounts are base units: the native token has 18 decimals, a token as many as it says. Gas is paid in the fee, as `min_fee_per_byte × (size + gas_limit / 16)`, and what isn't used comes back. A vault's call pays when it is queued and gets nothing back.

## The contract interface

These are the imports of the `qubits` module, which the SDK wraps. Addresses are 32 bytes and amounts 16 bytes, little-endian, passed by pointer. Each is part of the on-chain format.

| call | does |
|---|---|
| `input_size() -> i32`, `input(ptr)` | the call's arguments |
| `output(ptr, len)` | what the call gives back, at most 16 KiB |
| `revert(ptr, len)` | stops and undoes, handing unused gas back, with a reason of at most 256 bytes |
| `caller(ptr)`, `self(ptr)`, `value(ptr)` | who called, this contract, the native tokens that came along |
| `height() -> i64`, `timestamp_ms() -> i64` | the block |
| `balance(who, out)` | an account's native balance |
| `get(key, len, out, cap) -> i32` | -1 if absent, else the value's length; keys up to 128 bytes |
| `set(key, len, value, len)`, `del(key, len)` | this contract's storage; values up to 16 KiB |
| `transfer(to, amount) -> i32` | from this contract's balance; 0 if it went |
| `emit(topic, len, data, len)` | an event, in the receipt; topics up to 64 bytes, data up to 4 KiB |
| `call(to, name, len, args, len, value) -> i32` | another contract with all the gas left; 0 if it finished |
| `create(code, args, len, value, out) -> i32` | a new contract running code already on chain, its `init` given `args`, `value` and all the gas left; 0 and the address at `out` if `init` finished |
| `result_size() -> i32`, `result(ptr)` | what that call gave back |
| `hash(ptr, len, out)` | BLAKE3, 32 bytes |
| `verify(scheme, key, len, msg, len, sig, len) -> i32` | a signature from `qubits sign`; scheme 1 is ML-DSA-65, 2 SLH-DSA-SHA2-192s; 0 if good |

Memory is limited to 4 MiB, calls to 8 deep, and code to 160 KiB. The gas table is in `crates/qubits-vm/src/lib.rs`.
