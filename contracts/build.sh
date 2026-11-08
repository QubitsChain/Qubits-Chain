#!/bin/sh
# Builds the contracts into out/, which is what tests and deployments use.
set -e
cd "$(dirname "$0")"
cargo test --locked -p qubits-contract-math --target "$(rustc -vV | sed -n 's/^host: //p')"
cargo build --release --locked
for name in token escrow amm; do
    cp "target/wasm32-unknown-unknown/release/qubits_contract_$name.wasm" "out/$name.wasm"
done
ls -l out
