mod sim;

use sim::{Chaos, Rng, run};

fn scenario(n: usize, seed: u64, equivocator: Option<u16>, strikes: u64) {
    run_scenario(n, seed, equivocator, strikes, false);
}

fn run_scenario(n: usize, seed: u64, equivocator: Option<u16>, strikes: u64, nonsense: bool) {
    let chaos = Chaos::new(n, seed, Rng::seeded(seed), equivocator);
    run(chaos, seed, strikes, (50, 1_500), nonsense);
}

fn seeds() -> u64 {
    std::env::var("QUBITS_CHAOS_SEEDS").map_or(16, |s| s.parse().unwrap())
}

#[test]
fn four_validators_survive_random_faults() {
    for seed in 0..seeds() {
        scenario(4, seed, None, 40);
    }
}

#[test]
fn seven_validators_survive_random_faults() {
    for seed in 0..seeds() / 2 {
        scenario(7, seed + 1_000, None, 40);
    }
}

#[test]
fn an_equivocating_leader_changes_nothing_under_random_faults() {
    for seed in 0..seeds() {
        scenario(4, seed + 2_000, Some((seed % 4) as u16), 40);
    }
}

#[test]
fn a_validator_sending_signed_nonsense_changes_nothing() {
    for seed in 0..seeds() {
        run_scenario(4, seed + 3_000, Some((seed % 4) as u16), 40, true);
    }
}
