use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    InvalidAddress(String),
    InvalidHash,
    InvalidAuthPolicy(&'static str),
    InvalidVaultPolicy(&'static str),
    TooLarge {
        what: &'static str,
        max: usize,
        actual: usize,
    },
    Decode(String),
    Crypto(qubits_crypto::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidAddress(e) => write!(f, "invalid address: {e}"),
            Error::InvalidHash => write!(f, "invalid hash: expected 64 hex characters"),
            Error::InvalidAuthPolicy(e) => write!(f, "invalid auth policy: {e}"),
            Error::InvalidVaultPolicy(e) => write!(f, "invalid vault policy: {e}"),
            Error::TooLarge { what, max, actual } => {
                write!(
                    f,
                    "{what} is {actual} bytes, larger than the {max} byte limit"
                )
            }
            Error::Decode(e) => write!(f, "decoding failed: {e}"),
            Error::Crypto(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<qubits_crypto::Error> for Error {
    fn from(e: qubits_crypto::Error) -> Self {
        Error::Crypto(e)
    }
}
