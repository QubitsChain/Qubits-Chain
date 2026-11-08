use borsh::{BorshDeserialize, BorshSerialize};
use qubits_crypto::{SecretKey, Signature};
use serde::{Deserialize, Serialize};

use crate::account::amount_serde;
use crate::hash::{Hash, context};
use crate::limits::MAX_TX_BYTES;
use crate::{Address, Amount, AssetId, AuthPolicy, Error, Validator, VaultPolicy, hex_serde};

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Owner,
    Recovery,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Payload {
    Transfer {
        to: Address,
        asset: AssetId,
        #[serde(with = "amount_serde")]
        amount: Amount,
    },
    SetAuth {
        auth: AuthPolicy,
    },
    SetVault {
        vault: Option<VaultPolicy>,
    },
    CancelPending {
        id: u64,
    },
    ExecutePending {
        account: Address,
        id: u64,
    },
    SetValidators {
        validators: Vec<Validator>,
    },
    /// Puts a contract on the chain. Only the governance account can, for now.
    Deploy {
        #[serde(with = "hex_serde")]
        code: Vec<u8>,
        #[serde(with = "hex_serde")]
        args: Vec<u8>,
        gas_limit: u64,
    },
    /// `contract.function(args)`, with `amount` of the native token going along.
    Call {
        contract: Address,
        function: String,
        #[serde(with = "hex_serde")]
        args: Vec<u8>,
        #[serde(with = "amount_serde")]
        amount: Amount,
        gas_limit: u64,
    },
    /// Pays out what `payout` has earned as a validator. Anyone can send it, so a new payout
    /// address needs no coins for the fee, and the money can only go to `payout`.
    ClaimRewards {
        payout: Address,
    },
}

impl Payload {
    /// The gas this transaction pays for in its fee.
    pub fn gas_limit(&self) -> u64 {
        match self {
            Payload::Deploy { gas_limit, .. } | Payload::Call { gas_limit, .. } => *gas_limit,
            _ => 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Transaction {
    pub genesis_hash: Hash,
    pub sender: Address,
    pub nonce: u64,
    #[serde(with = "amount_serde")]
    pub fee: Amount,
    pub valid_until_ms: u64,
    pub role: Role,
    pub payload: Payload,
}

impl Transaction {
    pub fn signing_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("in-memory encoding cannot fail")
    }

    pub fn id(&self) -> Hash {
        Hash::digest(context::TX_ID, &self.signing_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct KeySignature {
    pub index: u8,
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct SignedTransaction {
    pub tx: Transaction,
    pub reveal: Option<AuthPolicy>,
    pub signatures: Vec<KeySignature>,
}

impl SignedTransaction {
    pub fn sign(
        tx: Transaction,
        policy: &AuthPolicy,
        reveal: Option<AuthPolicy>,
        signers: &[&SecretKey],
    ) -> Result<Self, Error> {
        let signatures = policy.sign(&tx.signing_bytes(), signers)?;
        Ok(SignedTransaction {
            tx,
            reveal,
            signatures,
        })
    }

    pub fn id(&self) -> Hash {
        self.tx.id()
    }

    pub fn encode(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("in-memory encoding cannot fail")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_TX_BYTES {
            return Err(Error::TooLarge {
                what: "transaction",
                max: MAX_TX_BYTES,
                actual: bytes.len(),
            });
        }
        borsh::from_slice(bytes).map_err(|e| Error::Decode(e.to_string()))
    }
}
