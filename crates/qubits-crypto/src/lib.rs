#![forbid(unsafe_code)]

#[cfg(any(feature = "borsh", feature = "serde"))]
mod codec;
mod error;
mod keys;
mod scheme;

#[cfg(feature = "keystore")]
pub mod keystore;

pub use error::Error;
pub use keys::{PublicKey, SecretKey, Signature};
pub use scheme::{Domain, MlDsa65, SchemeId, SignatureScheme, SlhDsaSha2_192s};
