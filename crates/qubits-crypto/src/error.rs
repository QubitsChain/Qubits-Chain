use core::fmt;

use crate::SchemeId;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    UnknownScheme(u8),
    UnknownSchemeName(String),
    InvalidLength {
        what: &'static str,
        expected: usize,
        actual: usize,
    },
    Empty,
    SchemeMismatch {
        key: SchemeId,
        signature: SchemeId,
    },
    InvalidSignature,
    Rng,
    Signing(&'static str),
    #[cfg(feature = "keystore")]
    WrongPasswordOrCorrupted,
    #[cfg(feature = "keystore")]
    Keystore(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnknownScheme(id) => write!(f, "unknown signature scheme id {id}"),
            Error::UnknownSchemeName(name) => write!(f, "unknown signature scheme `{name}`"),
            Error::InvalidLength {
                what,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "invalid {what} length: expected {expected} bytes, got {actual}"
                )
            }
            Error::Empty => write!(f, "empty input"),
            Error::SchemeMismatch { key, signature } => {
                write!(
                    f,
                    "signature scheme {signature} does not match key scheme {key}"
                )
            }
            Error::InvalidSignature => write!(f, "invalid signature"),
            Error::Rng => write!(f, "random number generator failure"),
            Error::Signing(e) => write!(f, "signing failed: {e}"),
            #[cfg(feature = "keystore")]
            Error::WrongPasswordOrCorrupted => {
                write!(
                    f,
                    "cannot decrypt key file: wrong password or corrupted file"
                )
            }
            #[cfg(feature = "keystore")]
            Error::Keystore(e) => write!(f, "invalid key file: {e}"),
        }
    }
}

impl std::error::Error for Error {}
