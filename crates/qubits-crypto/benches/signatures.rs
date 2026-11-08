use criterion::{Criterion, criterion_group, criterion_main};
use qubits_crypto::{Domain, SchemeId, SecretKey};
use std::hint::black_box;

fn bench(c: &mut Criterion) {
    let msg = [0x42u8; 256];
    for scheme in SchemeId::ALL {
        let mut group = c.benchmark_group(scheme.name());
        group.sample_size(10);

        let seed = vec![1u8; scheme.seed_len()];
        group.bench_function("keygen", |b| {
            b.iter(|| SecretKey::from_seed(scheme, black_box(&seed)).unwrap())
        });

        let sk = SecretKey::from_seed(scheme, &seed).unwrap();
        group.bench_function("sign", |b| {
            b.iter(|| sk.sign(Domain::Transaction, black_box(&msg)).unwrap())
        });

        let sig = sk.sign(Domain::Transaction, &msg).unwrap();
        group.bench_function("verify", |b| {
            b.iter(|| {
                sk.public_key()
                    .verify(Domain::Transaction, black_box(&msg), black_box(&sig))
                    .unwrap()
            })
        });
        group.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
