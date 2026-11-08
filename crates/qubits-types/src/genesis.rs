use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::account::{Validator, amount_serde};
use crate::hash::{Hash, context};
use crate::limits::{MAX_CHAIN_ID_LEN, MAX_VALIDATORS};
use crate::{Address, Amount, Error};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainParams {
    pub min_fee_per_byte: u64,
    pub max_block_transactions: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisAccount {
    pub address: Address,
    #[serde(with = "amount_serde")]
    pub balance: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    pub chain_id: String,
    pub timestamp_ms: u64,
    pub params: ChainParams,
    pub validators: Vec<Validator>,
    pub accounts: Vec<GenesisAccount>,
}

impl Genesis {
    pub fn hash(&self) -> Hash {
        Hash::digest(
            context::GENESIS,
            &borsh::to_vec(self).expect("in-memory encoding cannot fail"),
        )
    }

    pub fn validate(&self) -> Result<(), Error> {
        let id_ok = !self.chain_id.is_empty()
            && self.chain_id.len() <= MAX_CHAIN_ID_LEN
            && self
                .chain_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !id_ok {
            return Err(Error::Decode(format!(
                "chain_id must be 1-{MAX_CHAIN_ID_LEN} characters of a-z, A-Z, 0-9 and -"
            )));
        }
        if self.validators.is_empty() || self.validators.len() > MAX_VALIDATORS {
            return Err(Error::Decode(format!(
                "genesis needs 1 to {MAX_VALIDATORS} validators"
            )));
        }
        crate::ValidatorSet {
            epoch: 0,
            validators: self.validators.clone(),
        }
        .validate()
        .map_err(|e| Error::Decode(format!("genesis validators: {e}")))?;
        if self.params.max_block_transactions == 0 {
            return Err(Error::Decode(
                "max_block_transactions must be positive".into(),
            ));
        }
        let mut seen = BTreeSet::new();
        let mut supply: Amount = 0;
        for account in &self.accounts {
            if !seen.insert(account.address) {
                return Err(Error::Decode(format!(
                    "duplicate genesis account {}",
                    account.address
                )));
            }
            supply = supply
                .checked_add(account.balance)
                .ok_or_else(|| Error::Decode("total supply overflows".into()))?;
        }
        Ok(())
    }
}
