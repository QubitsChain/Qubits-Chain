use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Error, PublicKey, SchemeId, SecretKey};

pub const MIN_PASSWORD_LEN: usize = 12;

const VERSION: u32 = 1;
const AAD_TAG: &[u8] = b"qubits-keystore/v1";
const KDF_NAME: &str = "argon2id";
const CIPHER_NAME: &str = "xchacha20poly1305";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

const MAX_M_COST_KIB: u32 = 1024 * 1024; // 1 GiB
const MAX_T_COST: u32 = 64;
const MAX_P_COST: u32 = 16;

fn malformed(msg: impl Into<String>) -> Error {
    Error::Keystore(msg.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    pub const DEFAULT: KdfParams = KdfParams {
        m_cost: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
    };

    pub fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Self, Error> {
        let params = KdfParams {
            m_cost,
            t_cost,
            p_cost,
        };
        params.argon2()?;
        Ok(params)
    }

    fn argon2(self) -> Result<Argon2<'static>, Error> {
        if self.m_cost > MAX_M_COST_KIB || self.t_cost > MAX_T_COST || self.p_cost > MAX_P_COST {
            return Err(malformed("KDF parameters exceed the allowed maximum"));
        }
        let params = Params::new(self.m_cost, self.t_cost, self.p_cost, Some(32))
            .map_err(|e| malformed(format!("KDF parameters: {e}")))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KdfSection {
    name: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: String,
}

impl KdfSection {
    fn params(&self) -> KdfParams {
        KdfParams {
            m_cost: self.m_cost,
            t_cost: self.t_cost,
            p_cost: self.p_cost,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CipherSection {
    name: String,
    nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedKey {
    version: u32,
    scheme: String,
    public_key: String,
    kdf: KdfSection,
    cipher: CipherSection,
    ciphertext: String,
}

fn decode_hex<const N: usize>(field: &str, s: &str) -> Result<[u8; N], Error> {
    let bytes = hex::decode(s).map_err(|_| malformed(format!("{field} is not hex")))?;
    bytes
        .try_into()
        .map_err(|_| malformed(format!("{field} must be {N} bytes")))
}

fn associated_data(
    scheme: SchemeId,
    public_key: &[u8],
    params: KdfParams,
    salt: &[u8; SALT_LEN],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_TAG.len() + 1 + public_key.len() + 12 + SALT_LEN);
    aad.extend_from_slice(AAD_TAG);
    aad.push(scheme.as_u8());
    aad.extend_from_slice(public_key);
    aad.extend_from_slice(&params.m_cost.to_le_bytes());
    aad.extend_from_slice(&params.t_cost.to_le_bytes());
    aad.extend_from_slice(&params.p_cost.to_le_bytes());
    aad.extend_from_slice(salt);
    aad
}

fn derive_key(
    password: &[u8],
    params: KdfParams,
    salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut key = Zeroizing::new([0u8; 32]);
    params
        .argon2()?
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| malformed(format!("key derivation failed: {e}")))?;
    Ok(key)
}

impl EncryptedKey {
    pub fn encrypt(key: &SecretKey, password: &[u8], params: KdfParams) -> Result<Self, Error> {
        if password.is_empty() {
            return Err(malformed("password must not be empty"));
        }
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.try_fill_bytes(&mut salt).map_err(|_| Error::Rng)?;
        OsRng.try_fill_bytes(&mut nonce).map_err(|_| Error::Rng)?;

        let public = key.public_key();
        let aad = associated_data(key.scheme(), public.as_raw(), params, &salt);
        let wrapping_key = derive_key(password, params, &salt)?;
        let ciphertext = XChaCha20Poly1305::new(wrapping_key.as_ref().into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: key.expose_seed(),
                    aad: &aad,
                },
            )
            .map_err(|_| malformed("encryption failed"))?;

        Ok(EncryptedKey {
            version: VERSION,
            scheme: key.scheme().name().to_owned(),
            public_key: hex::encode(public.as_raw()),
            kdf: KdfSection {
                name: KDF_NAME.to_owned(),
                m_cost: params.m_cost,
                t_cost: params.t_cost,
                p_cost: params.p_cost,
                salt: hex::encode(salt),
            },
            cipher: CipherSection {
                name: CIPHER_NAME.to_owned(),
                nonce: hex::encode(nonce),
            },
            ciphertext: hex::encode(ciphertext),
        })
    }

    pub fn public_key(&self) -> Result<PublicKey, Error> {
        let scheme: SchemeId = self.scheme.parse()?;
        let raw = hex::decode(&self.public_key).map_err(|_| malformed("public_key is not hex"))?;
        PublicKey::from_raw(scheme, &raw)
    }

    pub fn kdf_params(&self) -> KdfParams {
        self.kdf.params()
    }

    pub fn decrypt(&self, password: &[u8]) -> Result<SecretKey, Error> {
        if self.version != VERSION {
            return Err(malformed(format!(
                "unsupported key file version {}",
                self.version
            )));
        }
        if self.kdf.name != KDF_NAME {
            return Err(malformed(format!("unsupported KDF `{}`", self.kdf.name)));
        }
        if self.cipher.name != CIPHER_NAME {
            return Err(malformed(format!(
                "unsupported cipher `{}`",
                self.cipher.name
            )));
        }
        let public = self.public_key()?;
        let salt: [u8; SALT_LEN] = decode_hex("kdf.salt", &self.kdf.salt)?;
        let nonce: [u8; NONCE_LEN] = decode_hex("cipher.nonce", &self.cipher.nonce)?;
        let ciphertext =
            hex::decode(&self.ciphertext).map_err(|_| malformed("ciphertext is not hex"))?;

        let aad = associated_data(public.scheme(), public.as_raw(), self.kdf.params(), &salt);
        let wrapping_key = derive_key(password, self.kdf.params(), &salt)?;
        let seed = Zeroizing::new(
            XChaCha20Poly1305::new(wrapping_key.as_ref().into())
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::WrongPasswordOrCorrupted)?,
        );

        let key = SecretKey::from_seed(public.scheme(), &seed)?;
        if key.public_key() != &public {
            return Err(malformed("public key does not match the secret key"));
        }
        Ok(key)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("key file serialization cannot fail")
    }

    pub fn from_json(json: &str) -> Result<Self, Error> {
        serde_json::from_str(json).map_err(|e| malformed(e.to_string()))
    }
}
