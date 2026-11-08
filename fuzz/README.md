# Fuzzing

Coverage-guided fuzzing with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer). This directory is a cargo workspace of its own, built with nightly Rust (`rust-toolchain.toml` here); the chain itself stays on its pinned compiler.

| Target | What it feeds | What must hold |
| --- | --- | --- |
| `network` | Four validators in simulated time, from `crates/qubits-consensus/tests/sim`, the harness `tests/chaos.rs` uses. The first bytes pick a hostile validator, whether it also sends signed nonsense, and how many faults; every later choice of the run (delays, loss, partitions, crashes, restarts, what the hostile validator signs and to whom) is read from the rest, so the fuzzer steers the network | No two honest validators commit different blocks at a height, commits are consecutive and carry a proof that verifies, and once everything heals the chain moves again. No panic |
| `message` | Raw bytes read as a stream of consensus messages from validators 1 to 3, handed to validator 0 with time moving between them | No panic, memory stays bounded |

```sh
cargo install cargo-fuzz
cd chain/fuzz
cargo fuzz run -O -s none network corpus/network -- -max_len=2048 -len_control=0 -max_total_time=600 -rss_limit_mb=4096 -timeout=120
cargo fuzz run -O -s none message corpus/message -- -max_total_time=600 -rss_limit_mb=4096
```

`-s none` leaves out AddressSanitizer: the code under test is safe Rust, and the sanitizer made every run twice as slow. `-max_len=2048 -len_control=0` lets inputs be long from the start, so the fuzzer and not the seed made from its bytes chooses most of a run.

`network` is slow by nature: every message carries a real ML-DSA signature, signed and checked, and coverage instrumentation slows the signing code too. Its validators make a block every 200 ms rather than the tests' 10, which keeps the rounds and cuts the signatures, and runs take tens of milliseconds instead of tens of seconds. Long runs belong on a machine of their own, with `-fork=N` for N cores. A failing input lands in `artifacts/<target>/`; replay it with `cargo fuzz run -O <target> artifacts/<target>/<file>`. `corpus/`, `artifacts/` and `target/` are not kept in the repository.
