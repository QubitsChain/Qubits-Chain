//! Whatever bytes a peer could send, read as consensus messages and handed to one validator of
//! four: nothing may panic, and nothing may grow without bound.

#![no_main]

use std::sync::OnceLock;

use borsh::BorshDeserialize;
use libfuzzer_sys::fuzz_target;
use qubits_consensus::{
    App, Block, Config, Engine, Final, FinalityProof, Message, Round, Start, ValidatorSet,
};
use qubits_crypto::{SchemeId, SecretKey};
use qubits_types::Hash;

struct Accept;

impl App<u64> for Accept {
    fn propose(&mut self, _: &Hash, height: u64, round: Round, _: u64) -> u64 {
        round * 1_000 + height
    }

    fn verify(&mut self, _: &Hash, _: &Block<u64>, _: u64) -> bool {
        true
    }

    fn commit(&mut self, _: &[Final<'_, u64>], _: &FinalityProof) {}
}

fn keys() -> &'static [SecretKey] {
    static KEYS: OnceLock<Vec<SecretKey>> = OnceLock::new();
    KEYS.get_or_init(|| {
        (0..4u8)
            .map(|i| SecretKey::from_seed(SchemeId::MlDsa65, &[i + 1; 32]).unwrap())
            .collect()
    })
}

fuzz_target!(|data: &[u8]| {
    let keys = keys();
    let validators =
        ValidatorSet::new(keys.iter().map(|k| k.public_key().clone()).collect()).unwrap();
    let chain = Hash::digest("fuzz", b"message");
    let cfg = Config {
        me: 0,
        key: keys[0].clone(),
        validators,
        chain,
        round_timeout_ms: 400,
        min_block_interval_ms: 10,
    };
    let (mut engine, _) = Engine::new(cfg, Accept, Start::genesis(chain), 1_000);
    let mut now = 1_000;
    let mut rest = data;
    // each message: who sent it, how much later it came, then the message itself
    while let [from, later, tail @ ..] = rest {
        rest = tail;
        let Ok(message) = Message::<u64>::deserialize(&mut rest) else {
            return;
        };
        now += u64::from(*later);
        engine.handle(1 + u16::from(from % 3), message, now);
        engine.tick(now);
    }
});
