#![cfg(feature = "keystore")]

use qubits_crypto::keystore::{EncryptedKey, KdfParams};
use qubits_crypto::{Error, SchemeId, SecretKey};
use serde_json::Value;

const PASSWORD: &[u8] = b"correct horse battery staple";

type JsonEdit = fn(&mut Value);

fn fast() -> KdfParams {
    KdfParams::new(256, 1, 1).unwrap()
}

fn encrypted(scheme: SchemeId) -> (SecretKey, EncryptedKey) {
    let sk = SecretKey::generate(scheme).unwrap();
    let file = EncryptedKey::encrypt(&sk, PASSWORD, fast()).unwrap();
    (sk, file)
}

fn edit(file: &EncryptedKey, f: impl FnOnce(&mut Value)) -> Result<EncryptedKey, Error> {
    let mut json: Value = serde_json::from_str(&file.to_json()).unwrap();
    f(&mut json);
    EncryptedKey::from_json(&json.to_string())
}

#[test]
fn round_trip_through_json() {
    for scheme in SchemeId::ALL {
        let (sk, file) = encrypted(scheme);
        let parsed = EncryptedKey::from_json(&file.to_json()).unwrap();
        assert_eq!(parsed.public_key().unwrap(), *sk.public_key());
        let restored = parsed.decrypt(PASSWORD).unwrap();
        assert_eq!(restored.expose_seed(), sk.expose_seed());
        assert_eq!(restored.public_key(), sk.public_key());
    }
}

#[test]
fn default_parameters_round_trip() {
    let sk = SecretKey::generate(SchemeId::MlDsa65).unwrap();
    let file = EncryptedKey::encrypt(&sk, PASSWORD, KdfParams::DEFAULT).unwrap();
    assert_eq!(file.kdf_params(), KdfParams::DEFAULT);
    assert_eq!(
        file.decrypt(PASSWORD).unwrap().public_key(),
        sk.public_key()
    );
}

#[test]
fn wrong_password_fails() {
    let (_, file) = encrypted(SchemeId::MlDsa65);
    assert_eq!(
        file.decrypt(b"wrong").unwrap_err(),
        Error::WrongPasswordOrCorrupted
    );
}

#[test]
fn empty_password_is_refused() {
    let sk = SecretKey::generate(SchemeId::MlDsa65).unwrap();
    assert!(matches!(
        EncryptedKey::encrypt(&sk, b"", fast()),
        Err(Error::Keystore(_))
    ));
}

#[test]
fn file_does_not_contain_the_seed() {
    let (sk, file) = encrypted(SchemeId::MlDsa65);
    assert!(!file.to_json().contains(&hex::encode(sk.expose_seed())));
}

#[test]
fn two_encryptions_use_fresh_salt_and_nonce() {
    let sk = SecretKey::generate(SchemeId::MlDsa65).unwrap();
    let a = EncryptedKey::encrypt(&sk, PASSWORD, fast()).unwrap();
    let b = EncryptedKey::encrypt(&sk, PASSWORD, fast()).unwrap();
    let (a, b): (Value, Value) = (
        serde_json::from_str(&a.to_json()).unwrap(),
        serde_json::from_str(&b.to_json()).unwrap(),
    );
    assert_ne!(a["kdf"]["salt"], b["kdf"]["salt"]);
    assert_ne!(a["cipher"]["nonce"], b["cipher"]["nonce"]);
    assert_ne!(a["ciphertext"], b["ciphertext"]);
}

#[test]
fn swapping_the_public_key_is_detected() {
    let (_, file) = encrypted(SchemeId::MlDsa65);
    let other = SecretKey::generate(SchemeId::MlDsa65).unwrap();
    let swapped = edit(&file, |j| {
        j["public_key"] = hex::encode(other.public_key().as_raw()).into();
    })
    .unwrap();
    assert_eq!(
        swapped.decrypt(PASSWORD).unwrap_err(),
        Error::WrongPasswordOrCorrupted
    );
}

#[test]
fn editing_authenticated_fields_is_detected() {
    let (_, file) = encrypted(SchemeId::MlDsa65);
    let edits: [(&str, JsonEdit); 4] = [
        ("t_cost", |j| j["kdf"]["t_cost"] = 2.into()),
        ("m_cost", |j| j["kdf"]["m_cost"] = 512.into()),
        ("salt", |j| j["kdf"]["salt"] = "00".repeat(16).into()),
        ("ciphertext", |j| {
            let mut ct = hex::decode(j["ciphertext"].as_str().unwrap()).unwrap();
            ct[0] ^= 1;
            j["ciphertext"] = hex::encode(ct).into();
        }),
    ];
    for (field, f) in edits {
        let edited = edit(&file, f).unwrap();
        assert_eq!(
            edited.decrypt(PASSWORD).unwrap_err(),
            Error::WrongPasswordOrCorrupted,
            "editing {field} was not detected",
        );
    }
}

#[test]
fn unsupported_or_malformed_files_are_rejected() {
    let (_, file) = encrypted(SchemeId::MlDsa65);
    let bad: [JsonEdit; 6] = [
        |j| j["version"] = 2.into(),
        |j| j["kdf"]["name"] = "scrypt".into(),
        |j| j["cipher"]["name"] = "aes-256-gcm".into(),
        |j| j["cipher"]["nonce"] = "00".into(),
        |j| j["scheme"] = "ed25519".into(),
        |j| j["public_key"] = "zz".into(),
    ];
    for f in bad {
        let edited = edit(&file, f).unwrap();
        assert!(matches!(
            edited.decrypt(PASSWORD).unwrap_err(),
            Error::Keystore(_) | Error::UnknownSchemeName(_)
        ));
    }
    assert!(
        edit(&file, |j| j["extra"] = 1.into()).is_err(),
        "unknown fields must be rejected"
    );
    assert!(EncryptedKey::from_json("not json").is_err());
}

#[test]
fn hostile_kdf_parameters_are_refused_before_hashing() {
    let (_, file) = encrypted(SchemeId::MlDsa65);
    let hostile = edit(&file, |j| j["kdf"]["m_cost"] = (4u64 * 1024 * 1024).into()).unwrap();
    assert!(matches!(
        hostile.decrypt(PASSWORD).unwrap_err(),
        Error::Keystore(_)
    ));
    assert!(KdfParams::new(4 * 1024 * 1024, 1, 1).is_err());
    assert!(KdfParams::new(256, 1000, 1).is_err());
}
