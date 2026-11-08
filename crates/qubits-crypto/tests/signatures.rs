use qubits_crypto::{
    Domain, Error, MlDsa65, PublicKey, SchemeId, SecretKey, Signature, SignatureScheme,
    SlhDsaSha2_192s,
};

const DOMAINS: [Domain; 5] = [
    Domain::Transaction,
    Domain::Consensus,
    Domain::BridgeAttestation,
    Domain::Message,
    Domain::Handshake,
];

fn vectors(name: &str) -> Vec<Vec<Vec<u8>>> {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| {
            l.split_whitespace()
                .map(|f| hex::decode(f).unwrap())
                .collect()
        })
        .collect()
}

#[test]
fn ml_dsa_65_keygen_matches_nist_vectors() {
    let cases = vectors("ml-dsa-65-keygen.txt");
    assert_eq!(cases.len(), 3);
    for case in cases {
        let (seed, pk) = (&case[0], &case[1]);
        let sk = SecretKey::from_seed(SchemeId::MlDsa65, seed).unwrap();
        assert_eq!(sk.public_key().as_raw(), &pk[..]);
    }
}

#[test]
fn slh_dsa_sha2_192s_keygen_matches_nist_vectors() {
    let cases = vectors("slh-dsa-sha2-192s-keygen.txt");
    assert_eq!(cases.len(), 3);
    for case in cases {
        let seed = [&case[0][..], &case[1][..], &case[2][..]].concat();
        let sk = SecretKey::from_seed(SchemeId::SlhDsaSha2_192s, &seed).unwrap();
        assert_eq!(sk.public_key().as_raw(), &case[3][..]);
    }
}

#[test]
fn scheme_sizes_match_implementations() {
    assert_eq!(SchemeId::MlDsa65.public_key_len(), 1952);
    assert_eq!(SchemeId::MlDsa65.signature_len(), 3309);
    assert_eq!(SchemeId::MlDsa65.seed_len(), MlDsa65::SEED_LEN);
    assert_eq!(SchemeId::SlhDsaSha2_192s.public_key_len(), 48);
    assert_eq!(SchemeId::SlhDsaSha2_192s.signature_len(), 16224);
    assert_eq!(
        SchemeId::SlhDsaSha2_192s.seed_len(),
        SlhDsaSha2_192s::SEED_LEN
    );

    for scheme in SchemeId::ALL {
        let sk = SecretKey::generate(scheme).unwrap();
        let sig = sk.sign(Domain::Message, b"size").unwrap();
        assert_eq!(sk.expose_seed().len(), scheme.seed_len());
        assert_eq!(sk.public_key().as_raw().len(), scheme.public_key_len());
        assert_eq!(sig.as_raw().len(), scheme.signature_len());
    }
}

#[test]
fn sign_and_verify_in_every_domain() {
    for scheme in SchemeId::ALL {
        let sk = SecretKey::generate(scheme).unwrap();
        for domain in DOMAINS {
            let sig = sk.sign(domain, b"transfer 10 QBT").unwrap();
            sk.public_key()
                .verify(domain, b"transfer 10 QBT", &sig)
                .unwrap();
        }
    }
}

#[test]
fn signature_is_not_valid_in_another_domain() {
    for scheme in SchemeId::ALL {
        let sk = SecretKey::generate(scheme).unwrap();
        for signed_in in DOMAINS {
            let sig = sk.sign(signed_in, b"msg").unwrap();
            for checked_in in DOMAINS.into_iter().filter(|d| *d != signed_in) {
                assert_eq!(
                    sk.public_key().verify(checked_in, b"msg", &sig),
                    Err(Error::InvalidSignature),
                    "{scheme}: {signed_in:?} signature accepted as {checked_in:?}",
                );
            }
        }
    }
}

#[test]
fn rejects_wrong_message_wrong_key_and_tampering() {
    for scheme in SchemeId::ALL {
        let sk = SecretKey::generate(scheme).unwrap();
        let other = SecretKey::generate(scheme).unwrap();
        let pk = sk.public_key();
        let sig = sk.sign(Domain::Transaction, b"pay alice").unwrap();

        assert_eq!(
            pk.verify(Domain::Transaction, b"pay mallory", &sig),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            other
                .public_key()
                .verify(Domain::Transaction, b"pay alice", &sig),
            Err(Error::InvalidSignature)
        );

        let len = sig.as_raw().len();
        for pos in [0, 1, len / 2, len - 2, len - 1] {
            let mut raw = sig.as_raw().to_vec();
            raw[pos] ^= 0x01;
            let tampered = Signature::from_raw(scheme, &raw).unwrap();
            assert_eq!(
                pk.verify(Domain::Transaction, b"pay alice", &tampered),
                Err(Error::InvalidSignature),
                "{scheme}: flipped bit at byte {pos} still verifies",
            );
        }

        let mut raw_pk = pk.as_raw().to_vec();
        raw_pk[0] ^= 0x01;
        let tampered_pk = PublicKey::from_raw(scheme, &raw_pk).unwrap();
        assert_eq!(
            tampered_pk.verify(Domain::Transaction, b"pay alice", &sig),
            Err(Error::InvalidSignature)
        );
    }
}

#[test]
fn garbage_signature_is_rejected_without_panicking() {
    for scheme in SchemeId::ALL {
        let sk = SecretKey::generate(scheme).unwrap();
        for fill in [0x00, 0xff, 0x5a] {
            let sig = Signature::from_raw(scheme, &vec![fill; scheme.signature_len()]).unwrap();
            assert_eq!(
                sk.public_key().verify(Domain::Message, b"x", &sig),
                Err(Error::InvalidSignature)
            );
        }
    }
    assert!(!MlDsa65::verify(&[0; 10], b"x", &[0; 10], b""));
    assert!(!SlhDsaSha2_192s::verify(&[0; 10], b"x", &[0; 10], b""));
}

#[test]
fn scheme_mismatch_is_reported() {
    let ml = SecretKey::generate(SchemeId::MlDsa65).unwrap();
    let slh = SecretKey::generate(SchemeId::SlhDsaSha2_192s).unwrap();
    let sig = slh.sign(Domain::Message, b"x").unwrap();
    assert_eq!(
        ml.public_key().verify(Domain::Message, b"x", &sig),
        Err(Error::SchemeMismatch {
            key: SchemeId::MlDsa65,
            signature: SchemeId::SlhDsaSha2_192s
        })
    );
}

#[test]
fn signing_is_hedged() {
    for scheme in SchemeId::ALL {
        let sk = SecretKey::generate(scheme).unwrap();
        let a = sk.sign(Domain::Message, b"same").unwrap();
        let b = sk.sign(Domain::Message, b"same").unwrap();
        assert_ne!(a, b);
        sk.public_key()
            .verify(Domain::Message, b"same", &a)
            .unwrap();
        sk.public_key()
            .verify(Domain::Message, b"same", &b)
            .unwrap();
    }
}

#[test]
fn keys_derive_deterministically_from_seed() {
    for scheme in SchemeId::ALL {
        let seed = vec![7u8; scheme.seed_len()];
        let a = SecretKey::from_seed(scheme, &seed).unwrap();
        let b = SecretKey::from_seed(scheme, &seed).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(a.expose_seed(), &seed[..]);

        let short = vec![7u8; scheme.seed_len() - 1];
        assert!(matches!(
            SecretKey::from_seed(scheme, &short),
            Err(Error::InvalidLength { .. })
        ));
    }
}

#[test]
fn tagged_encoding_round_trips() {
    for scheme in SchemeId::ALL {
        let sk = SecretKey::generate(scheme).unwrap();
        let sig = sk.sign(Domain::Message, b"x").unwrap();

        let pk_bytes = sk.public_key().to_tagged_bytes();
        assert_eq!(pk_bytes[0], scheme.as_u8());
        assert_eq!(
            &PublicKey::from_tagged_bytes(&pk_bytes).unwrap(),
            sk.public_key()
        );

        let sig_bytes = sig.to_tagged_bytes();
        assert_eq!(sig_bytes[0], scheme.as_u8());
        assert_eq!(Signature::from_tagged_bytes(&sig_bytes).unwrap(), sig);

        assert!(PublicKey::from_tagged_bytes(&pk_bytes[..pk_bytes.len() - 1]).is_err());
        assert!(Signature::from_tagged_bytes(&[&sig_bytes[..], &[0]].concat()).is_err());
    }
}

#[test]
fn malformed_encodings_are_rejected() {
    assert_eq!(PublicKey::from_tagged_bytes(&[]), Err(Error::Empty));
    assert_eq!(Signature::from_tagged_bytes(&[]), Err(Error::Empty));
    assert_eq!(
        PublicKey::from_tagged_bytes(&[0x00; 33]),
        Err(Error::UnknownScheme(0x00))
    );
    assert_eq!(
        PublicKey::from_tagged_bytes(&[0xff; 33]),
        Err(Error::UnknownScheme(0xff))
    );
    assert_eq!(
        PublicKey::from_raw(SchemeId::MlDsa65, &[0; 32]),
        Err(Error::InvalidLength {
            what: "public key",
            expected: 1952,
            actual: 32
        })
    );
}

#[test]
fn scheme_ids_and_names_are_stable() {
    assert_eq!(SchemeId::MlDsa65.as_u8(), 0x01);
    assert_eq!(SchemeId::SlhDsaSha2_192s.as_u8(), 0x02);
    assert_eq!(Domain::Transaction.context(), b"qubits/tx/v1");
    assert_eq!(Domain::Consensus.context(), b"qubits/consensus/v1");
    assert_eq!(Domain::BridgeAttestation.context(), b"qubits/bridge/v1");
    assert_eq!(Domain::Message.context(), b"qubits/message/v1");
    assert_eq!(Domain::Handshake.context(), b"qubits/handshake/v1");

    for scheme in SchemeId::ALL {
        assert_eq!(SchemeId::from_u8(scheme.as_u8()), Ok(scheme));
        assert_eq!(scheme.name().parse::<SchemeId>(), Ok(scheme));
    }
    assert!("ed25519".parse::<SchemeId>().is_err());
}

#[test]
fn debug_output_does_not_leak_the_seed() {
    let seed = [0xab; 32];
    let sk = SecretKey::from_seed(SchemeId::MlDsa65, &seed).unwrap();
    let debug = format!("{sk:?}");
    assert!(debug.contains("redacted"));
    assert!(!debug.contains("abababab"));
}

#[cfg(feature = "borsh")]
#[test]
fn borsh_encoding_round_trips_and_validates() {
    for scheme in SchemeId::ALL {
        let sk = SecretKey::generate(scheme).unwrap();
        let sig = sk.sign(Domain::Message, b"x").unwrap();

        let pk_bytes = borsh::to_vec(sk.public_key()).unwrap();
        assert_eq!(
            borsh::from_slice::<PublicKey>(&pk_bytes).unwrap(),
            *sk.public_key()
        );
        let sig_bytes = borsh::to_vec(&sig).unwrap();
        assert_eq!(borsh::from_slice::<Signature>(&sig_bytes).unwrap(), sig);
        assert_eq!(
            borsh::from_slice::<SchemeId>(&[scheme.as_u8()]).unwrap(),
            scheme
        );
    }
    assert!(borsh::from_slice::<PublicKey>(&[3, 0, 0, 0, 0x01, 0xaa, 0xbb]).is_err());
    assert!(borsh::from_slice::<SchemeId>(&[0x7f]).is_err());
}

#[cfg(feature = "serde")]
#[test]
fn serde_encoding_is_tagged_hex() {
    let sk = SecretKey::generate(SchemeId::SlhDsaSha2_192s).unwrap();
    let json = serde_json::to_string(sk.public_key()).unwrap();
    assert_eq!(
        json,
        format!("\"{}\"", hex::encode(sk.public_key().to_tagged_bytes()))
    );
    assert_eq!(
        serde_json::from_str::<PublicKey>(&json).unwrap(),
        *sk.public_key()
    );
    assert_eq!(
        serde_json::to_string(&SchemeId::MlDsa65).unwrap(),
        "\"ml-dsa-65\""
    );
    assert!(serde_json::from_str::<PublicKey>("\"02abcd\"").is_err());
    assert!(serde_json::from_str::<PublicKey>("\"not hex\"").is_err());
}
