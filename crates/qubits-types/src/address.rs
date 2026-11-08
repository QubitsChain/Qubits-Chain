use core::fmt;
use core::str::FromStr;

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::hash::{Hash, context};
use crate::{AuthPolicy, Error};

const HRP: Hrp = Hrp::parse_unchecked("qb");

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub struct Address(pub [u8; 32]);

impl Address {
    pub fn from_auth(policy: &AuthPolicy) -> Address {
        let encoded = borsh::to_vec(policy).expect("in-memory encoding cannot fail");
        Address(Hash::digest(context::ADDRESS, &encoded).0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        bech32::encode_lower_to_fmt::<Bech32m, _>(f, HRP, &self.0).map_err(|_| fmt::Error)
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({self})")
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let parsed = CheckedHrpstring::new::<Bech32m>(s)
            .map_err(|e| Error::InvalidAddress(e.to_string()))?;
        if parsed.hrp() != HRP {
            return Err(Error::InvalidAddress(format!("prefix must be `{HRP}`")));
        }
        let bytes: Vec<u8> = parsed.byte_iter().collect();
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidAddress("must encode 32 bytes".into()))?;
        Ok(Address(bytes))
    }
}

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        <String as Deserialize>::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
