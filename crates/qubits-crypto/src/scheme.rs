use core::fmt;
use core::str::FromStr;

use fips204::ml_dsa_65;
use fips205::slh_dsa_sha2_192s;
use zeroize::Zeroizing;

use crate::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
#[non_exhaustive]
pub enum SchemeId {
    MlDsa65 = 0x01,
    SlhDsaSha2_192s = 0x02,
}

impl SchemeId {
    pub const ALL: [SchemeId; 2] = [SchemeId::MlDsa65, SchemeId::SlhDsaSha2_192s];

    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(id: u8) -> Result<Self, Error> {
        match id {
            0x01 => Ok(SchemeId::MlDsa65),
            0x02 => Ok(SchemeId::SlhDsaSha2_192s),
            other => Err(Error::UnknownScheme(other)),
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            SchemeId::MlDsa65 => "ml-dsa-65",
            SchemeId::SlhDsaSha2_192s => "slh-dsa-sha2-192s",
        }
    }

    pub const fn seed_len(self) -> usize {
        match self {
            SchemeId::MlDsa65 => MlDsa65::SEED_LEN,
            SchemeId::SlhDsaSha2_192s => SlhDsaSha2_192s::SEED_LEN,
        }
    }

    pub const fn public_key_len(self) -> usize {
        match self {
            SchemeId::MlDsa65 => MlDsa65::PUBLIC_KEY_LEN,
            SchemeId::SlhDsaSha2_192s => SlhDsaSha2_192s::PUBLIC_KEY_LEN,
        }
    }

    pub const fn signature_len(self) -> usize {
        match self {
            SchemeId::MlDsa65 => MlDsa65::SIGNATURE_LEN,
            SchemeId::SlhDsaSha2_192s => SlhDsaSha2_192s::SIGNATURE_LEN,
        }
    }
}

impl fmt::Display for SchemeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for SchemeId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        SchemeId::ALL
            .into_iter()
            .find(|id| id.name() == s)
            .ok_or_else(|| Error::UnknownSchemeName(s.to_owned()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Domain {
    Transaction,
    Consensus,
    BridgeAttestation,
    Message,
    Handshake,
}

impl Domain {
    pub const fn context(self) -> &'static [u8] {
        match self {
            Domain::Transaction => b"qubits/tx/v1",
            Domain::Consensus => b"qubits/consensus/v1",
            Domain::BridgeAttestation => b"qubits/bridge/v1",
            Domain::Message => b"qubits/message/v1",
            Domain::Handshake => b"qubits/handshake/v1",
        }
    }
}

pub trait SignatureScheme {
    const ID: SchemeId;
    const SEED_LEN: usize;
    const PUBLIC_KEY_LEN: usize;
    const SIGNATURE_LEN: usize;

    type PrivateKey: Clone;

    fn keypair_from_seed(seed: &[u8]) -> Result<(Vec<u8>, Self::PrivateKey), Error>;

    fn sign(sk: &Self::PrivateKey, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>, Error>;

    fn verify(pk: &[u8], msg: &[u8], sig: &[u8], ctx: &[u8]) -> bool;
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

#[derive(Debug, Clone, Copy)]
pub struct MlDsa65;

impl SignatureScheme for MlDsa65 {
    const ID: SchemeId = SchemeId::MlDsa65;
    const SEED_LEN: usize = 32;
    const PUBLIC_KEY_LEN: usize = ml_dsa_65::PK_LEN;
    const SIGNATURE_LEN: usize = ml_dsa_65::SIG_LEN;

    type PrivateKey = Box<ml_dsa_65::PrivateKey>;

    fn keypair_from_seed(seed: &[u8]) -> Result<(Vec<u8>, Self::PrivateKey), Error> {
        use fips204::traits::{KeyGen, SerDes};

        check_len("ML-DSA-65 seed", seed, Self::SEED_LEN)?;
        let mut xi = Zeroizing::new([0u8; 32]);
        xi.copy_from_slice(seed);
        let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(&xi);
        Ok((pk.into_bytes().to_vec(), Box::new(sk)))
    }

    fn sign(sk: &Self::PrivateKey, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>, Error> {
        use fips204::traits::Signer;

        sk.try_sign(msg, ctx)
            .map(|sig| sig.to_vec())
            .map_err(Error::Signing)
    }

    fn verify(pk: &[u8], msg: &[u8], sig: &[u8], ctx: &[u8]) -> bool {
        use fips204::traits::{SerDes, Verifier};

        let (Ok(pk), Ok(sig)) = (
            <[u8; ml_dsa_65::PK_LEN]>::try_from(pk),
            <&[u8; ml_dsa_65::SIG_LEN]>::try_from(sig),
        ) else {
            return false;
        };
        match ml_dsa_65::PublicKey::try_from_bytes(pk) {
            Ok(pk) => pk.verify(msg, sig, ctx),
            Err(_) => false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SlhDsaSha2_192s;

impl SignatureScheme for SlhDsaSha2_192s {
    const ID: SchemeId = SchemeId::SlhDsaSha2_192s;
    const SEED_LEN: usize = 3 * slh_dsa_sha2_192s::N;
    const PUBLIC_KEY_LEN: usize = slh_dsa_sha2_192s::PK_LEN;
    const SIGNATURE_LEN: usize = slh_dsa_sha2_192s::SIG_LEN;

    type PrivateKey = Box<slh_dsa_sha2_192s::PrivateKey>;

    fn keypair_from_seed(seed: &[u8]) -> Result<(Vec<u8>, Self::PrivateKey), Error> {
        use fips205::traits::{KeyGen, SerDes};
        const N: usize = slh_dsa_sha2_192s::N;

        check_len("SLH-DSA-SHA2-192s seed", seed, Self::SEED_LEN)?;
        let mut parts = Zeroizing::new([[0u8; N]; 3]);
        for (part, chunk) in parts.iter_mut().zip(seed.chunks_exact(N)) {
            part.copy_from_slice(chunk);
        }
        let (pk, sk) = slh_dsa_sha2_192s::KG::keygen_from_seed(&parts[0], &parts[1], &parts[2]);
        Ok((pk.into_bytes().to_vec(), Box::new(sk)))
    }

    fn sign(sk: &Self::PrivateKey, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>, Error> {
        use fips205::traits::Signer;

        sk.try_sign(msg, ctx, true)
            .map(|sig| sig.to_vec())
            .map_err(Error::Signing)
    }

    fn verify(pk: &[u8], msg: &[u8], sig: &[u8], ctx: &[u8]) -> bool {
        use fips205::traits::{SerDes, Verifier};

        let (Ok(pk), Ok(sig)) = (
            <[u8; slh_dsa_sha2_192s::PK_LEN]>::try_from(pk),
            <&[u8; slh_dsa_sha2_192s::SIG_LEN]>::try_from(sig),
        ) else {
            return false;
        };
        match slh_dsa_sha2_192s::PublicKey::try_from_bytes(pk) {
            Ok(pk) => pk.verify(msg, sig, ctx),
            Err(_) => false,
        }
    }
}
