#![forbid(unsafe_code)]

use qubits_crypto::keystore::{EncryptedKey, KdfParams, MIN_PASSWORD_LEN};
use qubits_crypto::{PublicKey, SchemeId, SecretKey};
use qubits_types::client::build_transaction;
use qubits_types::rpc::{AccountResponse, StatusResponse};
use qubits_types::{Address, AuthPolicy, Payload, Role, SignedTransaction};
use serde::{Deserialize, Serialize};

pub type Error = String;

fn json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("serializing plain data cannot fail")
}

fn parse<'a, T: Deserialize<'a>>(what: &str, text: &'a str) -> Result<T, Error> {
    serde_json::from_str(text).map_err(|e| format!("invalid {what}: {e}"))
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyInfo {
    pub address: Address,
    pub public_key: String,
    pub scheme: SchemeId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreatedKey {
    pub keystore: String,
    #[serde(flatten)]
    pub info: KeyInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Signed {
    pub transaction: String,
    pub id: String,
    pub fee: String,
}

fn info(public: PublicKey) -> KeyInfo {
    KeyInfo {
        address: AuthPolicy::single(public.clone()).address(),
        public_key: hex::encode(public.to_tagged_bytes()),
        scheme: public.scheme(),
    }
}

pub fn create_key_with(
    scheme: &str,
    password: &str,
    params: KdfParams,
) -> Result<CreatedKey, Error> {
    let scheme: SchemeId = scheme
        .parse()
        .map_err(|e: qubits_crypto::Error| e.to_string())?;
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "the password must be at least {MIN_PASSWORD_LEN} characters"
        ));
    }
    let key = SecretKey::generate(scheme).map_err(|e| e.to_string())?;
    let file =
        EncryptedKey::encrypt(&key, password.as_bytes(), params).map_err(|e| e.to_string())?;
    Ok(CreatedKey {
        keystore: file.to_json(),
        info: info(key.public_key().clone()),
    })
}

pub fn create_key(scheme: &str, password: &str) -> Result<String, Error> {
    create_key_with(scheme, password, KdfParams::DEFAULT).map(|k| json(&k))
}

pub fn key_info(keystore: &str) -> Result<String, Error> {
    let file = EncryptedKey::from_json(keystore).map_err(|e| e.to_string())?;
    Ok(json(&info(file.public_key().map_err(|e| e.to_string())?)))
}

pub fn unlock(keystore: &str, password: &str) -> Result<SecretKey, Error> {
    let file = EncryptedKey::from_json(keystore).map_err(|e| e.to_string())?;
    file.decrypt(password.as_bytes()).map_err(|e| match e {
        qubits_crypto::Error::WrongPasswordOrCorrupted => "wrong password".to_owned(),
        other => other.to_string(),
    })
}

pub fn sign(
    status: &str,
    account: &str,
    keystore: &str,
    password: &str,
    role: &str,
    payload: &str,
    valid_until_ms: u64,
) -> Result<String, Error> {
    let status: StatusResponse = parse("status", status)?;
    let account: AccountResponse = parse("account", account)?;
    let role: Role = parse("role", &json(&role))?;
    let payload: Payload = parse("payload", payload)?;
    let key = unlock(keystore, password)?;
    let stx = build_transaction(&status, &account, &key, role, payload, valid_until_ms)
        .map_err(|e| e.to_string())?;
    Ok(json(&Signed {
        transaction: hex::encode(stx.encode()),
        id: stx.id().to_string(),
        fee: stx.tx.fee.to_string(),
    }))
}

pub fn decode_transaction(hex_tx: &str) -> Result<String, Error> {
    let bytes = hex::decode(hex_tx.trim()).map_err(|_| "transaction is not hex".to_owned())?;
    let stx = SignedTransaction::decode(&bytes).map_err(|e| e.to_string())?;
    #[derive(Serialize)]
    struct Decoded {
        id: String,
        #[serde(flatten)]
        transaction: SignedTransaction,
    }
    Ok(json(&Decoded {
        id: stx.id().to_string(),
        transaction: stx,
    }))
}

pub fn check_address(address: &str) -> Result<String, Error> {
    address
        .trim()
        .parse::<Address>()
        .map(|a| a.to_string())
        .map_err(|e| e.to_string())
}

pub fn public_key_info(tagged_hex: &str) -> Result<String, Error> {
    let bytes = hex::decode(tagged_hex.trim()).map_err(|_| "public key is not hex".to_owned())?;
    let public = PublicKey::from_tagged_bytes(&bytes).map_err(|e| e.to_string())?;
    Ok(json(&info(public)))
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use wasm_bindgen::prelude::*;

    fn js<T>(result: Result<T, super::Error>) -> Result<T, JsError> {
        result.map_err(|e| JsError::new(&e))
    }

    #[wasm_bindgen(js_name = createKey)]
    pub fn create_key(scheme: &str, password: &str) -> Result<String, JsError> {
        js(super::create_key(scheme, password))
    }

    #[wasm_bindgen(js_name = keyInfo)]
    pub fn key_info(keystore: &str) -> Result<String, JsError> {
        js(super::key_info(keystore))
    }

    #[wasm_bindgen(js_name = checkPassword)]
    pub fn check_password(keystore: &str, password: &str) -> Result<(), JsError> {
        js(super::unlock(keystore, password).map(|_| ()))
    }

    #[wasm_bindgen]
    pub fn sign(
        status: &str,
        account: &str,
        keystore: &str,
        password: &str,
        role: &str,
        payload: &str,
        valid_until_ms: f64,
    ) -> Result<String, JsError> {
        js(super::sign(
            status,
            account,
            keystore,
            password,
            role,
            payload,
            valid_until_ms as u64,
        ))
    }

    #[wasm_bindgen(js_name = decodeTransaction)]
    pub fn decode_transaction(hex_tx: &str) -> Result<String, JsError> {
        js(super::decode_transaction(hex_tx))
    }

    #[wasm_bindgen(js_name = checkAddress)]
    pub fn check_address(address: &str) -> Result<String, JsError> {
        js(super::check_address(address))
    }

    #[wasm_bindgen(js_name = publicKeyInfo)]
    pub fn public_key_info(tagged_hex: &str) -> Result<String, JsError> {
        js(super::public_key_info(tagged_hex))
    }

    #[wasm_bindgen(js_name = minPasswordLength)]
    pub fn min_password_length() -> usize {
        qubits_crypto::keystore::MIN_PASSWORD_LEN
    }
}
