#[cfg(feature = "borsh")]
mod borsh_impls {
    use std::io::{Error as IoError, ErrorKind, Read, Write};

    use borsh::{BorshDeserialize, BorshSerialize};

    use crate::{PublicKey, SchemeId, Signature};

    fn invalid(e: crate::Error) -> IoError {
        IoError::new(ErrorKind::InvalidData, e.to_string())
    }

    impl BorshSerialize for SchemeId {
        fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
            self.as_u8().serialize(writer)
        }
    }

    impl BorshDeserialize for SchemeId {
        fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
            SchemeId::from_u8(u8::deserialize_reader(reader)?).map_err(invalid)
        }
    }

    macro_rules! tagged {
        ($ty:ty) => {
            impl BorshSerialize for $ty {
                fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
                    self.to_tagged_bytes().serialize(writer)
                }
            }

            impl BorshDeserialize for $ty {
                fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
                    let bytes = Vec::<u8>::deserialize_reader(reader)?;
                    <$ty>::from_tagged_bytes(&bytes).map_err(invalid)
                }
            }
        };
    }

    tagged!(PublicKey);
    tagged!(Signature);
}

#[cfg(feature = "serde")]
mod serde_impls {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::{PublicKey, SchemeId, Signature};

    impl Serialize for SchemeId {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(self.name())
        }
    }

    impl<'de> Deserialize<'de> for SchemeId {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            String::deserialize(d)?.parse().map_err(D::Error::custom)
        }
    }

    macro_rules! tagged {
        ($ty:ty) => {
            impl Serialize for $ty {
                fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                    s.serialize_str(&hex::encode(self.to_tagged_bytes()))
                }
            }

            impl<'de> Deserialize<'de> for $ty {
                fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                    let text = String::deserialize(d)?;
                    let bytes = hex::decode(&text).map_err(D::Error::custom)?;
                    <$ty>::from_tagged_bytes(&bytes).map_err(D::Error::custom)
                }
            }
        };
    }

    tagged!(PublicKey);
    tagged!(Signature);
}
