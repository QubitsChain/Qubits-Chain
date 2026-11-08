use std::collections::{BTreeMap, BTreeSet};

use borsh::{BorshDeserialize, BorshSerialize};
use qubits_crypto::{Domain, PublicKey, SecretKey, Signature};
use serde::{Deserialize, Serialize};

use crate::limits::{MAX_AUTH_KEYS, MAX_VAULT_DELAY_MS};
use crate::{Address, Error, KeySignature};

pub type Amount = u128;

pub mod amount_serde {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    use super::Amount;

    pub fn serialize<S: Serializer>(amount: &Amount, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(amount)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Amount, D::Error> {
        String::deserialize(d)?.parse().map_err(D::Error::custom)
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(transparent)]
pub struct AssetId(pub u32);

impl AssetId {
    pub const NATIVE: AssetId = AssetId(0);
}

// display only, the chain deals in base units
pub const NATIVE_DECIMALS: u32 = 18;

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AuthPolicy {
    pub threshold: u8,
    pub keys: Vec<PublicKey>,
}

impl AuthPolicy {
    pub fn single(key: PublicKey) -> Self {
        AuthPolicy {
            threshold: 1,
            keys: vec![key],
        }
    }

    pub fn address(&self) -> Address {
        Address::from_auth(self)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.keys.is_empty() {
            return Err(Error::InvalidAuthPolicy("no keys"));
        }
        if self.keys.len() > MAX_AUTH_KEYS {
            return Err(Error::InvalidAuthPolicy("too many keys"));
        }
        if self.threshold == 0 || usize::from(self.threshold) > self.keys.len() {
            return Err(Error::InvalidAuthPolicy(
                "threshold must be between 1 and the number of keys",
            ));
        }
        let distinct: BTreeSet<_> = self.keys.iter().collect();
        if distinct.len() != self.keys.len() {
            return Err(Error::InvalidAuthPolicy("duplicate key"));
        }
        Ok(())
    }

    pub fn check(&self, msg: &[u8], signatures: &[KeySignature]) -> Result<(), Error> {
        self.check_with(signatures, |key, sig| {
            key.verify(Domain::Transaction, msg, sig)?;
            Ok(())
        })
    }

    pub fn check_cached(
        &self,
        msg: &[u8],
        signatures: &[KeySignature],
        cache: &crate::SignatureCache,
    ) -> Result<(), Error> {
        self.check_with(signatures, |key, sig| cache.verify(key, msg, sig))
    }

    fn check_with(
        &self,
        signatures: &[KeySignature],
        verify: impl Fn(&PublicKey, &Signature) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if signatures.len() < usize::from(self.threshold) {
            return Err(Error::InvalidAuthPolicy("not enough signatures"));
        }
        let mut previous: Option<u8> = None;
        for sig in signatures {
            if previous.is_some_and(|p| sig.index <= p) {
                return Err(Error::InvalidAuthPolicy(
                    "signature indices must be strictly increasing",
                ));
            }
            previous = Some(sig.index);
            let key = self
                .keys
                .get(usize::from(sig.index))
                .ok_or(Error::InvalidAuthPolicy("signature index out of range"))?;
            verify(key, &sig.signature)?;
        }
        Ok(())
    }

    pub fn sign(&self, msg: &[u8], signers: &[&SecretKey]) -> Result<Vec<KeySignature>, Error> {
        let mut signatures = Vec::with_capacity(signers.len());
        for signer in signers {
            let index = self
                .keys
                .iter()
                .position(|k| k == signer.public_key())
                .ok_or(Error::InvalidAuthPolicy("signer is not part of the policy"))?;
            let signature = signer.sign(Domain::Transaction, msg)?;
            signatures.push(KeySignature {
                index: index as u8,
                signature,
            });
        }
        signatures.sort_by_key(|s| s.index);
        Ok(signatures)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct VaultPolicy {
    pub delay_ms: u64,
    pub recovery: Option<AuthPolicy>,
}

impl VaultPolicy {
    pub fn validate(&self) -> Result<(), Error> {
        if self.delay_ms == 0 {
            return Err(Error::InvalidVaultPolicy("delay must be positive"));
        }
        if self.delay_ms > MAX_VAULT_DELAY_MS {
            return Err(Error::InvalidVaultPolicy("delay is longer than 365 days"));
        }
        if let Some(recovery) = &self.recovery {
            recovery.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct PendingAction {
    pub id: u64,
    pub unlock_at_ms: u64,
    pub action: DelayedAction,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelayedAction {
    Transfer {
        to: Address,
        asset: AssetId,
        #[serde(with = "amount_serde")]
        amount: Amount,
    },
    SetAuth(AuthPolicy),
    SetVault(Option<VaultPolicy>),
    /// A vault's contract call: it can move anything the vault holds in a contract, so it waits.
    Call {
        contract: Address,
        function: String,
        #[serde(with = "crate::hex_serde")]
        args: Vec<u8>,
        #[serde(with = "amount_serde")]
        amount: Amount,
        gas_limit: u64,
    },
}

pub fn governance_address() -> Address {
    Address(crate::hash::Hash::digest(crate::hash::context::GOVERNANCE, &[]).0)
}

/// Where fees wait for validators to claim them. No key leads to this address.
pub fn rewards_address() -> Address {
    Address(crate::hash::Hash::digest(crate::hash::context::REWARDS, &[]).0)
}

/// A validator's key sits on a server and signs blocks. Its share of the fees can only go to
/// `payout`, set by governance, so a stolen key can't take the money.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Validator {
    pub key: PublicKey,
    pub payout: Address,
}

impl Validator {
    /// Paid to the address of its own key: simple, and fine for a test chain.
    pub fn self_paid(key: PublicKey) -> Validator {
        let payout = AuthPolicy::single(key.clone()).address();
        Validator { key, payout }
    }
}

pub fn validator_keys(validators: &[Validator]) -> Vec<PublicKey> {
    validators.iter().map(|v| v.key.clone()).collect()
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub epoch: u64,
    pub validators: Vec<Validator>,
}

/// What every seat in the validator set has earned since genesis. Fees are split when they are
/// paid; what doesn't divide evenly waits in `carry` for the next fee.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RewardTotals {
    pub per_validator: Amount,
    pub carry: Amount,
}

/// One payout address. `baseline` is `per_validator` when it last started earning, so fees from
/// before that aren't its own. `owed` is what it earned and hasn't claimed yet from earlier seats.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RewardAccount {
    pub baseline: Amount,
    pub owed: Amount,
}

impl ValidatorSet {
    pub fn keys(&self) -> Vec<PublicKey> {
        validator_keys(&self.validators)
    }

    pub fn has_key(&self, key: &PublicKey) -> bool {
        self.validators.iter().any(|v| v.key == *key)
    }

    pub fn pays(&self, payout: &Address) -> bool {
        self.validators.iter().any(|v| v.payout == *payout)
    }

    pub fn max_faulty(&self) -> usize {
        self.validators.len().saturating_sub(1) / 3
    }

    pub fn quorum(&self) -> usize {
        self.validators.len() - self.max_faulty()
    }

    pub fn council(&self) -> AuthPolicy {
        AuthPolicy {
            threshold: self.quorum() as u8,
            keys: self.keys(),
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.validators.is_empty() || self.validators.len() > crate::limits::MAX_VALIDATORS {
            return Err(Error::InvalidAuthPolicy(
                "a validator set needs 1 to 50 validators",
            ));
        }
        let seats = self.validators.len();
        let keys: BTreeSet<_> = self.validators.iter().map(|v| &v.key).collect();
        if keys.len() != seats {
            return Err(Error::InvalidAuthPolicy("duplicate validator key"));
        }
        // rewards are kept per address, so each seat needs its own
        let payouts: BTreeSet<_> = self.validators.iter().map(|v| v.payout).collect();
        if payouts.len() != seats {
            return Err(Error::InvalidAuthPolicy("duplicate payout address"));
        }
        if self
            .validators
            .iter()
            .any(|v| v.key.scheme() != qubits_crypto::SchemeId::MlDsa65)
        {
            return Err(Error::InvalidAuthPolicy(
                "validators must use ML-DSA-65 keys",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Account {
    pub nonce: u64,
    pub balances: BTreeMap<AssetId, Amount>,
    pub auth: Option<AuthPolicy>,
    pub vault: Option<VaultPolicy>,
    pub pending: Vec<PendingAction>,
    pub next_pending_id: u64,
}

impl Account {
    pub fn balance(&self, asset: AssetId) -> Amount {
        self.balances.get(&asset).copied().unwrap_or(0)
    }

    pub fn set_balance(&mut self, asset: AssetId, amount: Amount) {
        if amount == 0 {
            self.balances.remove(&asset);
        } else {
            self.balances.insert(asset, amount);
        }
    }
}
