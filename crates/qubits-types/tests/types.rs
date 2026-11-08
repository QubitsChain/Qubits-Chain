use qubits_crypto::{SchemeId, SecretKey};
use qubits_types::limits::{MAX_AUTH_KEYS, MAX_TX_BYTES, MAX_VAULT_DELAY_MS};
use qubits_types::*;

fn key(scheme: SchemeId, seed_byte: u8) -> SecretKey {
    SecretKey::from_seed(scheme, &vec![seed_byte; scheme.seed_len()]).unwrap()
}

fn ml(seed_byte: u8) -> SecretKey {
    key(SchemeId::MlDsa65, seed_byte)
}

fn transfer(sender: Address, nonce: u64) -> Transaction {
    Transaction {
        genesis_hash: Hash([1; 32]),
        sender,
        nonce,
        fee: 1_000,
        valid_until_ms: 5_000,
        role: Role::Owner,
        payload: Payload::Transfer {
            to: AuthPolicy::single(ml(9).public_key().clone()).address(),
            asset: AssetId::NATIVE,
            amount: 5,
        },
    }
}

#[test]
fn address_format_is_pinned() {
    let policy = AuthPolicy::single(ml(1).public_key().clone());
    assert_eq!(
        policy.address().to_string(),
        "qb1dx6lxtksedtyjjqn547vzsue6pald63x4nk0g77jzs5y3rz8f7aq2d9vg6"
    );
}

#[test]
fn address_round_trips_and_detects_typos() {
    let addr = AuthPolicy::single(ml(1).public_key().clone()).address();
    let text = addr.to_string();
    assert!(text.starts_with("qb1"));
    assert_eq!(text.parse::<Address>().unwrap(), addr);
    assert_eq!(text.to_uppercase().parse::<Address>().unwrap(), addr);

    let mut chars: Vec<char> = text.chars().collect();
    chars[10] = if chars[10] == 'q' { 'p' } else { 'q' };
    let typo: String = chars.into_iter().collect();
    assert!(typo.parse::<Address>().is_err());

    let other_hrp = bech32::encode::<bech32::Bech32m>(bech32::Hrp::parse("bc").unwrap(), &addr.0);
    assert!(other_hrp.unwrap().parse::<Address>().is_err());
    let bech32_classic =
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("qb").unwrap(), &addr.0).unwrap();
    assert!(bech32_classic.parse::<Address>().is_err());
    assert!("qb1".parse::<Address>().is_err());
}

#[test]
fn address_depends_on_the_whole_policy() {
    let (a, b) = (ml(1).public_key().clone(), ml(2).public_key().clone());
    let single = AuthPolicy::single(a.clone());
    let multi_1 = AuthPolicy {
        threshold: 1,
        keys: vec![a.clone(), b.clone()],
    };
    let multi_2 = AuthPolicy {
        threshold: 2,
        keys: vec![a.clone(), b.clone()],
    };
    let swapped = AuthPolicy {
        threshold: 2,
        keys: vec![b, a],
    };
    let addrs = [
        single.address(),
        multi_1.address(),
        multi_2.address(),
        swapped.address(),
    ];
    for i in 0..addrs.len() {
        for j in i + 1..addrs.len() {
            assert_ne!(addrs[i], addrs[j]);
        }
    }
}

#[test]
fn auth_policy_structure_is_validated() {
    let keys: Vec<_> = (0..=MAX_AUTH_KEYS as u8)
        .map(|i| ml(i).public_key().clone())
        .collect();
    let policy = |threshold, n: usize| AuthPolicy {
        threshold,
        keys: keys[..n].to_vec(),
    };

    assert!(policy(1, 1).validate().is_ok());
    assert!(policy(3, 3).validate().is_ok());
    assert!(policy(1, MAX_AUTH_KEYS).validate().is_ok());
    assert!(policy(1, 0).validate().is_err(), "no keys");
    assert!(policy(0, 2).validate().is_err(), "zero threshold");
    assert!(
        policy(3, 2).validate().is_err(),
        "threshold above key count"
    );
    assert!(
        policy(1, MAX_AUTH_KEYS + 1).validate().is_err(),
        "too many keys"
    );
    let dup = AuthPolicy {
        threshold: 1,
        keys: vec![keys[0].clone(), keys[0].clone()],
    };
    assert!(dup.validate().is_err(), "duplicate keys");
}

#[test]
fn multisig_with_mixed_schemes() {
    let (hot, cold, other) = (ml(1), key(SchemeId::SlhDsaSha2_192s, 2), ml(3));
    let policy = AuthPolicy {
        threshold: 2,
        keys: vec![
            hot.public_key().clone(),
            cold.public_key().clone(),
            other.public_key().clone(),
        ],
    };
    policy.validate().unwrap();
    let msg = b"tx bytes";

    let sigs = policy.sign(msg, &[&other, &hot]).unwrap();
    assert_eq!(sigs.iter().map(|s| s.index).collect::<Vec<_>>(), [0, 2]);
    policy.check(msg, &sigs).unwrap();
    policy
        .check(msg, &policy.sign(msg, &[&hot, &cold]).unwrap())
        .unwrap();

    assert!(
        policy
            .check(msg, &policy.sign(msg, &[&hot]).unwrap())
            .is_err()
    );
    let one = policy.sign(msg, &[&hot]).unwrap();
    assert!(
        policy
            .check(msg, &[one[0].clone(), one[0].clone()])
            .is_err()
    );
    assert!(
        policy
            .check(msg, &[sigs[1].clone(), sigs[0].clone()])
            .is_err()
    );
    let mut bad = sigs.clone();
    bad[1].index = 7;
    assert!(policy.check(msg, &bad).is_err());
    let mut wrong = sigs.clone();
    wrong[1].index = 1;
    assert!(policy.check(msg, &wrong).is_err());
    assert!(policy.check(b"other", &sigs).is_err());
    assert!(policy.sign(msg, &[&ml(42)]).is_err());
}

#[test]
fn vault_policy_bounds() {
    let ok = VaultPolicy {
        delay_ms: 60_000,
        recovery: None,
    };
    assert!(ok.validate().is_ok());
    assert!(
        VaultPolicy {
            delay_ms: 0,
            ..ok.clone()
        }
        .validate()
        .is_err()
    );
    assert!(
        VaultPolicy {
            delay_ms: MAX_VAULT_DELAY_MS,
            ..ok.clone()
        }
        .validate()
        .is_ok()
    );
    assert!(
        VaultPolicy {
            delay_ms: MAX_VAULT_DELAY_MS + 1,
            ..ok.clone()
        }
        .validate()
        .is_err()
    );
    let bad_recovery = AuthPolicy {
        threshold: 2,
        keys: vec![ml(1).public_key().clone()],
    };
    assert!(
        VaultPolicy {
            delay_ms: 1,
            recovery: Some(bad_recovery)
        }
        .validate()
        .is_err()
    );
}

#[test]
fn signed_transaction_round_trips() {
    let sk = ml(1);
    let policy = AuthPolicy::single(sk.public_key().clone());
    let tx = transfer(policy.address(), 0);
    let signed = SignedTransaction::sign(tx, &policy, Some(policy.clone()), &[&sk]).unwrap();
    policy
        .check(&signed.tx.signing_bytes(), &signed.signatures)
        .unwrap();

    let bytes = signed.encode();
    assert_eq!(SignedTransaction::decode(&bytes).unwrap(), signed);

    let json = serde_json::to_string(&signed).unwrap();
    assert_eq!(
        serde_json::from_str::<SignedTransaction>(&json).unwrap(),
        signed
    );
    assert!(
        json.contains(r#""amount":"5""#),
        "amounts are JSON strings: {json}"
    );
}

#[test]
fn decoding_rejects_trailing_and_oversized_input() {
    let sk = ml(1);
    let policy = AuthPolicy::single(sk.public_key().clone());
    let signed =
        SignedTransaction::sign(transfer(policy.address(), 0), &policy, None, &[&sk]).unwrap();
    let mut bytes = signed.encode();
    bytes.push(0);
    assert!(SignedTransaction::decode(&bytes).is_err());
    assert!(matches!(
        SignedTransaction::decode(&vec![0; MAX_TX_BYTES + 1]),
        Err(Error::TooLarge { .. })
    ));
    assert!(SignedTransaction::decode(&[1, 2, 3]).is_err());
}

#[test]
fn transaction_id_ignores_signatures_but_covers_every_field() {
    let sk = ml(1);
    let policy = AuthPolicy::single(sk.public_key().clone());
    let tx = transfer(policy.address(), 0);
    let a = SignedTransaction::sign(tx.clone(), &policy, None, &[&sk]).unwrap();
    let b = SignedTransaction::sign(tx.clone(), &policy, None, &[&sk]).unwrap();
    assert_ne!(a.signatures, b.signatures);
    assert_eq!(a.id(), b.id());

    let variants = [
        Transaction {
            nonce: 1,
            ..tx.clone()
        },
        Transaction {
            fee: 1_001,
            ..tx.clone()
        },
        Transaction {
            role: Role::Recovery,
            ..tx.clone()
        },
        Transaction {
            genesis_hash: Hash([2; 32]),
            ..tx.clone()
        },
        Transaction {
            valid_until_ms: 5_001,
            ..tx.clone()
        },
    ];
    for v in variants {
        assert_ne!(v.id(), tx.id());
    }
}

fn sample_txs(n: u64) -> Vec<SignedTransaction> {
    let sk = ml(1);
    let policy = AuthPolicy::single(sk.public_key().clone());
    (0..n)
        .map(|n| {
            SignedTransaction::sign(transfer(policy.address(), n), &policy, None, &[&sk]).unwrap()
        })
        .collect()
}

#[test]
fn payload_tx_root_must_match_transactions() {
    let txs = sample_txs(3);
    let payload = BlockPayload {
        timestamp_ms: 1_000,
        tx_root: tx_root(&txs),
        transactions: txs,
        state_root: Hash([7; 32]),
        receipt_root: Hash::ZERO,
    };
    payload.check_tx_root().unwrap();

    let mut dropped = payload.clone();
    dropped.transactions.pop();
    assert!(dropped.check_tx_root().is_err(), "transaction removed");

    let mut reordered = payload;
    reordered.transactions.swap(0, 1);
    assert!(reordered.check_tx_root().is_err(), "transactions reordered");
}

#[test]
fn tx_root_has_no_duplicate_last_leaf_ambiguity() {
    let txs = sample_txs(3);
    assert_eq!(tx_root(&[]), Hash::ZERO);
    assert_ne!(tx_root(&txs[..1]), Hash::ZERO);
    let mut with_dup = txs.clone();
    with_dup.push(txs[2].clone());
    assert_ne!(tx_root(&txs), tx_root(&with_dup));
}

fn genesis() -> Genesis {
    Genesis {
        chain_id: "qubits-test".into(),
        timestamp_ms: 1_000,
        params: ChainParams {
            min_fee_per_byte: 1,
            max_block_transactions: 100,
        },
        validators: [ml(5), ml(6)]
            .iter()
            .map(|k| Validator::self_paid(k.public_key().clone()))
            .collect(),
        accounts: vec![
            GenesisAccount {
                address: AuthPolicy::single(ml(1).public_key().clone()).address(),
                balance: 1_000_000,
            },
            GenesisAccount {
                address: AuthPolicy::single(ml(2).public_key().clone()).address(),
                balance: 5,
            },
        ],
    }
}

#[test]
fn genesis_validation_and_json() {
    let g = genesis();
    g.validate().unwrap();
    let json = serde_json::to_string_pretty(&g).unwrap();
    assert_eq!(serde_json::from_str::<Genesis>(&json).unwrap(), g);
    assert_eq!(g.hash(), genesis().hash());

    for bad_id in ["", "has space", "ünicode", &"x".repeat(65)] {
        assert!(
            Genesis {
                chain_id: bad_id.into(),
                ..genesis()
            }
            .validate()
            .is_err(),
            "{bad_id:?}"
        );
    }

    let mut dup = genesis();
    dup.accounts.push(dup.accounts[0].clone());
    assert!(dup.validate().is_err());

    assert!(
        Genesis {
            validators: vec![],
            ..genesis()
        }
        .validate()
        .is_err(),
        "no validators"
    );
    let mut dup_validator = genesis();
    dup_validator
        .validators
        .push(dup_validator.validators[0].clone());
    assert!(dup_validator.validate().is_err(), "duplicate validator");

    let mut overflow = genesis();
    overflow.accounts[0].balance = Amount::MAX;
    assert!(overflow.validate().is_err());

    let mut extra: serde_json::Value = serde_json::from_str(&json).unwrap();
    extra["surprise"] = 1.into();
    assert!(
        serde_json::from_value::<Genesis>(extra).is_err(),
        "unknown fields rejected"
    );
}

#[test]
fn hash_parses_from_hex() {
    let h = Hash([0xab; 32]);
    assert_eq!(h.to_string().parse::<Hash>().unwrap(), h);
    assert!("abc".parse::<Hash>().is_err());
}

fn zero_signature(scheme: SchemeId, index: u8) -> KeySignature {
    KeySignature {
        index,
        signature: qubits_crypto::Signature::from_raw(scheme, &vec![0; scheme.signature_len()])
            .unwrap(),
    }
}

fn zero_key(scheme: SchemeId, seed: u8) -> qubits_crypto::PublicKey {
    qubits_crypto::PublicKey::from_raw(scheme, &vec![seed; scheme.public_key_len()]).unwrap()
}

#[test]
fn largest_multisig_transaction_fits_the_limit() {
    let scheme = SchemeId::SlhDsaSha2_192s;
    let policy = AuthPolicy {
        threshold: MAX_AUTH_KEYS as u8,
        keys: (0..MAX_AUTH_KEYS as u8)
            .map(|i| zero_key(scheme, i))
            .collect(),
    };
    let stx = SignedTransaction {
        tx: transfer(policy.address(), 0),
        reveal: Some(policy),
        signatures: (0..MAX_AUTH_KEYS as u8)
            .map(|i| zero_signature(scheme, i))
            .collect(),
    };
    let size = stx.encode().len();
    assert!(size <= MAX_TX_BYTES, "{size} bytes");
    assert_eq!(SignedTransaction::decode(&stx.encode()).unwrap(), stx);
}

#[test]
fn largest_validator_change_fits_the_limit() {
    let scheme = SchemeId::MlDsa65;
    let validators: Vec<_> = (0..limits::MAX_VALIDATORS as u8)
        .map(|i| Validator::self_paid(zero_key(scheme, i)))
        .collect();
    let quorum = ValidatorSet {
        epoch: 0,
        validators: validators.clone(),
    }
    .quorum();
    assert_eq!(quorum, 34);
    let mut tx = transfer(governance_address(), 0);
    tx.payload = Payload::SetValidators { validators };
    let stx = SignedTransaction {
        tx,
        reveal: None,
        signatures: (0..quorum as u8)
            .map(|i| zero_signature(scheme, i))
            .collect(),
    };
    let size = stx.encode().len();
    assert!(
        size > 192 * 1024,
        "this is what the previous limit could not hold: {size} bytes"
    );
    assert!(size <= MAX_TX_BYTES, "{size} bytes");
}
