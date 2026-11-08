//! Fees paid to validators.
//!
//! A fee goes to `rewards_address()`, and `RewardTotals::per_validator` grows by a seat's share of
//! it. Only that one number moves, so a fee costs the same however many validators there are. A
//! validator's `baseline` is the number when it joined and it is owed the difference, so fees
//! from before it joined were never its own. One that leaves has the difference moved to `owed`,
//! where it stays until claimed. No coin is made here: the pool holds `carry` and what every
//! address can claim, as `tests/rewards.rs` checks after every block. Coins someone sends to the
//! pool's address on purpose add to neither, and stay there for good.

use qubits_state::StateReader;
use qubits_types::{
    Address, Amount, AssetId, RewardAccount, RewardTotals, ValidatorSet, rewards_address,
};

use crate::{Staged, TxError, keys, read_validators};

fn decode<T: borsh::BorshDeserialize + Default>(
    bytes: Option<Vec<u8>>,
    what: &str,
) -> Result<T, TxError> {
    match bytes {
        Some(bytes) => {
            borsh::from_slice(&bytes).map_err(|e| TxError::Storage(format!("corrupt {what}: {e}")))
        }
        None => Ok(T::default()),
    }
}

pub fn read_reward_totals(state: &impl StateReader) -> Result<RewardTotals, TxError> {
    decode(state.get(&keys::rewards())?, "reward totals")
}

/// What `payout` could claim now.
pub fn claimable(state: &impl StateReader, payout: &Address) -> Result<Amount, TxError> {
    let totals = read_reward_totals(state)?;
    let account = decode(state.get(&keys::reward(payout))?, "reward account")?;
    let seated = read_validators(state)?.pays(payout);
    owed(&totals, &account, seated)
}

fn owed(totals: &RewardTotals, account: &RewardAccount, seated: bool) -> Result<Amount, TxError> {
    let earning = if seated {
        totals.per_validator - account.baseline
    } else {
        0
    };
    account.owed.checked_add(earning).ok_or(TxError::Overflow)
}

impl<S: StateReader> Staged<'_, '_, S> {
    fn totals(&self) -> Result<RewardTotals, TxError> {
        decode(self.read(&keys::rewards())?, "reward totals")
    }

    fn reward_account(&self, payout: &Address) -> Result<RewardAccount, TxError> {
        decode(self.read(&keys::reward(payout))?, "reward account")
    }

    fn put_reward_account(&mut self, payout: &Address, account: &RewardAccount) {
        let bytes = borsh::to_vec(account).expect("encoding cannot fail");
        self.writes.insert(keys::reward(payout), Some(bytes));
    }

    /// Splits a fee among the seats in force before this transaction, so a change of validators
    /// pays the set it replaces. The first fee on a chain finds every `baseline` at 0, which is
    /// right for the validators of genesis.
    pub(crate) fn pay_validators(&mut self, fee: Amount) -> Result<(), TxError> {
        if fee == 0 {
            return Ok(());
        }
        self.credit(&rewards_address(), AssetId::NATIVE, fee)?;
        let seats = self.executor.seats()? as Amount;
        let mut totals = self.totals()?;
        let due = totals.carry.checked_add(fee).ok_or(TxError::Overflow)?;
        totals.per_validator = totals
            .per_validator
            .checked_add(due / seats)
            .ok_or(TxError::Overflow)?;
        totals.carry = due % seats;
        let bytes = borsh::to_vec(&totals).expect("encoding cannot fail");
        self.writes.insert(keys::rewards(), Some(bytes));
        Ok(())
    }

    /// Runs after the fee is split: a validator leaving has earned that share, and one joining
    /// hasn't.
    pub(crate) fn seat_validators(&mut self) -> Result<(), TxError> {
        let Some(next) = self.validators.clone() else {
            return Ok(());
        };
        let current: ValidatorSet = self.executor.validator_set()?;
        let totals = self.totals()?;
        for leaving in current.validators.iter().filter(|v| !next.pays(&v.payout)) {
            let mut account = self.reward_account(&leaving.payout)?;
            account.owed = owed(&totals, &account, true)?;
            account.baseline = totals.per_validator;
            self.put_reward_account(&leaving.payout, &account);
        }
        for joining in next.validators.iter().filter(|v| !current.pays(&v.payout)) {
            let mut account = self.reward_account(&joining.payout)?;
            account.baseline = totals.per_validator;
            self.put_reward_account(&joining.payout, &account);
        }
        Ok(())
    }

    pub(crate) fn claim_rewards(&mut self, payout: &Address) -> Result<(), TxError> {
        let totals = self.totals()?;
        let mut account = self.reward_account(payout)?;
        let seated = self.executor.validator_set()?.pays(payout);
        let amount = owed(&totals, &account, seated)?;
        if amount == 0 {
            return Err(TxError::NothingToClaim);
        }
        account.owed = 0;
        account.baseline = totals.per_validator;
        self.put_reward_account(payout, &account);
        self.debit(&rewards_address(), AssetId::NATIVE, amount)?;
        self.credit(payout, AssetId::NATIVE, amount)
    }
}
