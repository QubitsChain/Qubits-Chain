![qubits: quantum-safe vault and settlement layer 1](assets/banner.png)

The Rust workspace behind [qubits.sh](https://qubits.sh): a quantum-safe vault and settlement layer 1.

| crate | role |
|---|---|
| `qubits-crypto` | ML-DSA-65 (FIPS 204) and SLH-DSA-SHA2-192s (FIPS 205) behind one `SignatureScheme` trait; password-encrypted key files |
| `qubits-types` | addresses, accounts, auth and vault policies, transactions, blocks, genesis, the HTTP API's JSON shapes |
| `qubits-state` | a Jellyfish Merkle Tree on RocksDB, versioned by block height |
| `qubits-execution` | the transaction rules, applied all-or-nothing, and running contracts inside them |
| `qubits-vm` | the sandbox contracts run in: WebAssembly, metered gas, post-quantum signature checks |
| `qubits-consensus` | Pipelined Moonshot as a sans-I/O state machine, with simulation, chaos and restart tests and an SMT model of the voting rules |
| `qubits-node` | the validator and API node: p2p over TLS 1.3 with hybrid X25519MLKEM768, HTTP API, sync, snapshots, pruning, era files |
| `qubits-cli` | the `qubits` binary: keys, transfers, vaults, multisig, governance, contracts |
| `qubits-wasm` | the wallet core for browsers |
| `qubits-e2e` | end-to-end tests with real processes (not published) |

```sh
cargo build --workspace
cargo test --workspace --all-features
cargo clippy --workspace --all-features --all-targets -- -D warnings
```

Contracts are in [`contracts/`](contracts/), with their own guide.

The first build compiles RocksDB. Dependencies are optimised even in debug builds, because SLH-DSA is unusably slow otherwise.

The documentation, including how to run a local chain, is at [qubits.sh/docs](https://qubits.sh/docs).

## License

Apache-2.0, see [`LICENSE`](LICENSE).
