use qubits_consensus::*;
use qubits_crypto::{Domain, SchemeId, SecretKey};
use qubits_types::Hash;

fn keys(n: usize) -> Vec<SecretKey> {
    (0..n)
        .map(|i| SecretKey::from_seed(SchemeId::MlDsa65, &[i as u8 + 1; 32]).unwrap())
        .collect()
}

fn set(keys: &[SecretKey]) -> ValidatorSet {
    ValidatorSet::new(keys.iter().map(|k| k.public_key().clone()).collect()).unwrap()
}

const CHAIN: Hash = Hash([7; 32]);

fn real_qc(keys: &[SecretKey]) -> QuorumCert {
    struct Null;
    impl App<u8> for Null {
        fn propose(&mut self, _: &Hash, _: u64, _: Round, _: u64) -> u8 {
            0
        }
        fn verify(&mut self, _: &Hash, _: &Block<u8>, _: u64) -> bool {
            true
        }
        fn commit(&mut self, _: &[Final<'_, u8>], _: &FinalityProof) {}
    }
    let validators = set(keys);
    let mut engines: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let cfg = Config {
                me: i as ValidatorIndex,
                key: k.clone(),
                validators: validators.clone(),
                chain: CHAIN,
                round_timeout_ms: 1_000,
                min_block_interval_ms: 0,
            };
            Engine::new(cfg, Null, Start::genesis(CHAIN), 0)
        })
        .collect();
    let mut queue: Vec<(usize, usize, Message<u8>)> = Vec::new();
    let push = |from: usize, out: Vec<Output<u8>>, queue: &mut Vec<_>| {
        for o in out {
            match o {
                Output::Send(to, m) => queue.push((from, usize::from(to), m)),
                Output::Broadcast(m) => (0..keys.len())
                    .filter(|&t| t != from)
                    .for_each(|t| queue.push((from, t, m.clone()))),
                _ => {}
            }
        }
    };
    let initial: Vec<_> = engines
        .iter_mut()
        .enumerate()
        .map(|(i, (_, out))| (i, std::mem::take(out)))
        .collect();
    for (i, out) in initial {
        push(i, out, &mut queue);
    }
    for _ in 0..200 {
        let Some((from, to, msg)) = queue.pop() else {
            break;
        };
        let out = engines[to].0.handle(from as ValidatorIndex, msg, 10);
        push(to, out, &mut queue);
        if let Some((e, _)) = engines.iter().find(|(e, _)| e.high_qc().round >= 1) {
            return e.high_qc().clone();
        }
    }
    panic!("no QC formed");
}

#[test]
fn validator_set_rules() {
    let k = keys(4);
    let s = set(&k);
    assert_eq!((s.len(), s.max_faulty(), s.quorum()), (4, 1, 3));
    assert_eq!(set(&keys(10)).quorum(), 7);
    assert_eq!(set(&keys(1)).quorum(), 1);
    assert_eq!(s.leader(5), 1);
    assert_eq!(s.index_of(k[2].public_key()), Some(2));
    assert!(ValidatorSet::new(vec![]).is_err());
    assert!(ValidatorSet::new(vec![k[0].public_key().clone(), k[0].public_key().clone()]).is_err());
}

#[test]
fn genesis_qc_is_valid_only_for_genesis() {
    let s = set(&keys(4));
    assert!(QuorumCert::genesis(CHAIN).verify(&s, &CHAIN));
    assert!(!QuorumCert::genesis(Hash([1; 32])).verify(&s, &CHAIN));
}

#[test]
fn quorum_certificates_resist_tampering() {
    let k = keys(4);
    let s = set(&k);
    let qc = real_qc(&k);
    assert!(qc.verify(&s, &CHAIN), "a real QC verifies");
    assert_eq!(qc.votes.len(), s.quorum());

    let mut short = qc.clone();
    short.votes.pop();
    assert!(!short.verify(&s, &CHAIN));

    let mut dup = qc.clone();
    dup.votes[1] = dup.votes[0].clone();
    assert!(!dup.verify(&s, &CHAIN));

    let mut unordered = qc.clone();
    unordered.votes.swap(0, 1);
    assert!(!unordered.verify(&s, &CHAIN));

    assert!(
        !QuorumCert {
            kind: VoteKind::Fallback,
            ..qc.clone()
        }
        .verify(&s, &CHAIN),
        "votes of one kind can't count as another"
    );

    let mut misattributed = qc.clone();
    let missing = (0..4u16)
        .find(|i| !qc.votes.iter().any(|(v, _)| v == i))
        .unwrap();
    misattributed.votes[0].0 = missing;
    misattributed.votes.sort_by_key(|(i, _)| *i);
    assert!(!misattributed.verify(&s, &CHAIN));

    let mut outsider = qc.clone();
    outsider.votes.last_mut().unwrap().0 = 99;
    assert!(!outsider.verify(&s, &CHAIN));

    assert!(
        !QuorumCert {
            block: Hash([9; 32]),
            ..qc.clone()
        }
        .verify(&s, &CHAIN)
    );
    assert!(
        !QuorumCert {
            round: qc.round + 1,
            ..qc.clone()
        }
        .verify(&s, &CHAIN)
    );
    assert!(!qc.verify(&s, &Hash([8; 32])));

    let mut foreign = qc.clone();
    let stranger = SecretKey::from_seed(SchemeId::MlDsa65, &[99; 32]).unwrap();
    foreign.votes[0].1 = stranger.sign(Domain::Consensus, b"anything").unwrap();
    assert!(!foreign.verify(&s, &CHAIN));
}

#[test]
fn timeout_certificates_need_a_quorum_of_distinct_validators() {
    let k = keys(4);
    let s = set(&k);
    let no_qc = QuorumCert::genesis(CHAIN);
    let tc = TimeoutCert {
        round: 3,
        entries: vec![],
        high_qc: no_qc.clone(),
    };
    assert!(!tc.verify(&s, &CHAIN));
    let bogus: Vec<_> = (0..3u16)
        .map(|i| {
            (
                i,
                0,
                k[usize::from(i)]
                    .sign(Domain::Consensus, b"not a timeout")
                    .unwrap(),
            )
        })
        .collect();
    assert!(
        !TimeoutCert {
            round: 3,
            entries: bogus,
            high_qc: no_qc.clone(),
        }
        .verify(&s, &CHAIN)
    );
    assert_eq!(
        TimeoutCert {
            round: 3,
            entries: vec![
                (0, 2, k[0].sign(Domain::Consensus, b"x").unwrap()),
                (1, 5, k[1].sign(Domain::Consensus, b"y").unwrap())
            ],
            high_qc: no_qc,
        }
        .max_high_qc_round(),
        5
    );
}

#[test]
fn signatures_from_other_domains_are_not_consensus_signatures() {
    let k = keys(4);
    let s = set(&k);
    let qc = real_qc(&k);
    let mut cross = qc.clone();
    for (i, sig) in cross.votes.iter_mut() {
        *sig = k[usize::from(*i)]
            .sign(Domain::Transaction, b"vote")
            .unwrap();
    }
    assert!(!cross.verify(&s, &CHAIN));
}

#[test]
fn a_timeout_certificate_must_prove_its_highest_qc() {
    let k = keys(4);
    let s = set(&k);
    let qc = real_qc(&k);
    let genesis = QuorumCert::genesis(CHAIN);
    let timeout = |voter: ValidatorIndex, high_qc: &QuorumCert| {
        Timeout::signed(3, high_qc.clone(), voter, &k[usize::from(voter)], &CHAIN)
    };
    let tc_of = |timeouts: Vec<Timeout>, high_qc: QuorumCert| TimeoutCert {
        round: 3,
        entries: timeouts
            .into_iter()
            .map(|t| (t.voter, t.high_qc.round, t.signature))
            .collect(),
        high_qc,
    };

    let honest = vec![timeout(0, &qc), timeout(1, &genesis), timeout(2, &genesis)];
    assert!(tc_of(honest.clone(), qc.clone()).verify(&s, &CHAIN));
    assert!(!tc_of(honest, genesis.clone()).verify(&s, &CHAIN));
    let inflated = QuorumCert {
        round: 2_000_000,
        ..genesis.clone()
    };
    let lying = vec![
        timeout(0, &inflated),
        timeout(1, &genesis),
        timeout(2, &genesis),
    ];
    assert!(!tc_of(lying.clone(), genesis.clone()).verify(&s, &CHAIN));
    assert!(!tc_of(lying, inflated).verify(&s, &CHAIN));
}
