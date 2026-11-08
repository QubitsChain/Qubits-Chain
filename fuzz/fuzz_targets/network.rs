//! Four validators in simulated time, steered by the fuzzer. The first bytes say who misbehaves
//! and for how long; every later choice of the run, delays, losses, partitions, crashes and what
//! the hostile validator signs, is read from the rest. No two honest validators may commit
//! different blocks at a height, every commit must carry a proof, and once the network heals the
//! chain must move again.

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../crates/qubits-consensus/tests/sim/mod.rs"]
mod sim;

use sim::{Chaos, Rng, run};

fuzz_target!(|data: &[u8]| {
    let [who, how, length, rest @ ..] = data else {
        return;
    };
    let equivocator = (who % 5 < 4).then_some(u16::from(who % 5));
    let nonsense = how & 1 == 1;
    let strikes = 1 + u64::from(length % 8);
    // a block every 200 ms and faults close together: every signature is real, so fewer blocks
    // leave more runs a second for the orderings
    let chaos = Chaos::paced(4, 0, Rng::from_bytes(rest), equivocator, 200);
    run(chaos, 0, strikes, (10, 300), nonsense);
});
