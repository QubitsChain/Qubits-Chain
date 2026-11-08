use core::fmt;

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::scheme::{MlDsa65, SignatureScheme, SlhDsaSha2_192s};
use crate::{Domain, Error, SchemeId};

fn short_hex(bytes: &[u8]) -> String {
    let mut s: String = bytes.iter().take(8).map(|b| format!("{b:02x}")).collect();
    if bytes.len() > 8 {
        s.push('…');
    }
    s
}

fn split_tagged(bytes: &[u8]) -> Result<(SchemeId, &[u8]), Error> {
    let (&id, raw) = bytes.split_first().ok_or(Error::Empty)?;
    Ok((SchemeId::from_u8(id)?, raw))
}

fn check_len(what: &'static str, bytes: &[u8], expected: usize) -> Result<(), Error> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(Error::InvalidLength {
            what,
            expected,
            actual: bytes.len(),
        })
    }
}

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey {
    scheme: SchemeId,
    bytes: Box<[u8]>,
}

impl PublicKey {
    pub fn from_raw(scheme: SchemeId, bytes: &[u8]) -> Result<Self, Error> {
        check_len("public key", bytes, scheme.public_key_len())?;
        Ok(PublicKey {
            scheme,
            bytes: bytes.into(),
        })
    }

    pub fn from_tagged_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (scheme, raw) = split_tagged(bytes)?;
        Self::from_raw(scheme, raw)
    }

    pub fn to_tagged_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.bytes.len());
        out.push(self.scheme.as_u8());
        out.extend_from_slice(&self.bytes);
        out
    }

    pub fn scheme(&self) -> SchemeId {
        self.scheme
    }

    pub fn as_raw(&self) -> &[u8] {
        &self.bytes
    }

    pub fn verify(&self, domain: Domain, msg: &[u8], sig: &Signature) -> Result<(), Error> {
        if sig.scheme != self.scheme {
            return Err(Error::SchemeMismatch {
                key: self.scheme,
                signature: sig.scheme,
            });
        }
        let ctx = domain.context();
        let ok = match self.scheme {
            SchemeId::MlDsa65 => MlDsa65::verify(&self.bytes, msg, &sig.bytes, ctx),
            SchemeId::SlhDsaSha2_192s => SlhDsaSha2_192s::verify(&self.bytes, msg, &sig.bytes, ctx),
        };
        if ok {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({}, {})", self.scheme, short_hex(&self.bytes))
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Signature {
    scheme: SchemeId,
    bytes: Box<[u8]>,
}

impl Signature {
    pub fn from_raw(scheme: SchemeId, bytes: &[u8]) -> Result<Self, Error> {
        check_len("signature", bytes, scheme.signature_len())?;
        Ok(Signature {
            scheme,
            bytes: bytes.into(),
        })
    }

    pub fn from_tagged_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (scheme, raw) = split_tagged(bytes)?;
        Self::from_raw(scheme, raw)
    }

    pub fn to_tagged_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.bytes.len());
        out.push(self.scheme.as_u8());
        out.extend_from_slice(&self.bytes);
        out
    }

    pub fn scheme(&self) -> SchemeId {
        self.scheme
    }

    pub fn as_raw(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({}, {})", self.scheme, short_hex(&self.bytes))
    }
}

#[derive(Clone)]
enum PrivateKey {
    MlDsa65(<MlDsa65 as SignatureScheme>::PrivateKey),
    SlhDsaSha2_192s(<SlhDsaSha2_192s as SignatureScheme>::PrivateKey),
}

#[derive(Clone)]
pub struct SecretKey {
    seed: Zeroizing<Vec<u8>>,
    private: PrivateKey,
    public: PublicKey,
}

impl SecretKey {
    pub fn generate(scheme: SchemeId) -> Result<Self, Error> {
        let mut seed = Zeroizing::new(vec![0u8; scheme.seed_len()]);
        OsRng.try_fill_bytes(&mut seed).map_err(|_| Error::Rng)?;
        Self::from_seed(scheme, &seed)
    }

    pub fn from_seed(scheme: SchemeId, seed: &[u8]) -> Result<Self, Error> {
        let (public, private) = match scheme {
            SchemeId::MlDsa65 => {
                let (pk, sk) = MlDsa65::keypair_from_seed(seed)?;
                (pk, PrivateKey::MlDsa65(sk))
            }
            SchemeId::SlhDsaSha2_192s => {
                let (pk, sk) = SlhDsaSha2_192s::keypair_from_seed(seed)?;
                (pk, PrivateKey::SlhDsaSha2_192s(sk))
            }
        };
        Ok(SecretKey {
            seed: Zeroizing::new(seed.to_vec()),
            private,
            public: PublicKey::from_raw(scheme, &public)?,
        })
    }

    pub fn scheme(&self) -> SchemeId {
        self.public.scheme
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub fn expose_seed(&self) -> &[u8] {
        &self.seed
    }

    pub fn sign(&self, domain: Domain, msg: &[u8]) -> Result<Signature, Error> {
        let ctx = domain.context();
        let bytes = match &self.private {
            PrivateKey::MlDsa65(sk) => MlDsa65::sign(sk, msg, ctx)?,
            PrivateKey::SlhDsaSha2_192s(sk) => SlhDsaSha2_192s::sign(sk, msg, ctx)?,
        };
        Signature::from_raw(self.scheme(), &bytes)
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SecretKey({}, public: {:?}, <redacted>)",
            self.scheme(),
            self.public
        )
    }
}
