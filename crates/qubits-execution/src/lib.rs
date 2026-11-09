#![forbid(unsafe_code)]

mod contracts;

use std::collections::BTreeMap;
use std::fmt;

use qubits_state::{StateReader, WriteSet};
use qubits_types::client::required_fee;
use qubits_types::limits::{
    GAS_PER_BYTE, MAX_ARGS_BYTES, MAX_BLOCK_GAS, MAX_CODE_BYTES, MAX_FEE_MULTIPLE,
    MAX_FUNCTION_NAME, MAX_PENDING_ACTIONS, MAX_TX_BYTES, MAX_TX_GAS,
};
use qubits_types::{
    Account, Address, Amount, AssetId, ChainParams, Contract, DelayedAction, Genesis, Hash,
    Payload, PendingAction, Receipt, Role, SignatureCache, SignedTransaction, ValidatorSet,
    VaultPolicy, contract_address, governance_address,
};

mod rewards;

pub use rewards::{claimable, read_reward_totals};

pub mod keys {
    use qubits_types::{Address, Hash};

    pub fn validators() -> Vec<u8> {
        b"validators".to_vec()
    }

    pub fn rewards() -> Vec<u8> {
        b"rewards".to_vec()
    }

    pub fn reward(payout: &Address) -> Vec<u8> {
        let mut key = b"reward/".to_vec();
        key.extend_from_slice(payout.as_bytes());
        key
    }

    pub fn account(address: &Address) -> Vec<u8> {
        let mut key = b"account/".to_vec();
        key.extend_from_slice(address.as_bytes());
        key
    }

    /// How many contracts there are, a `u64`. Each is under `contract_at`, in the order made.
    pub fn contracts() -> Vec<u8> {
        b"contracts".to_vec()
    }

    pub fn contract_at(index: u64) -> Vec<u8> {
        let mut key = b"contracts/".to_vec();
        key.extend_from_slice(&index.to_be_bytes());
        key
    }

    /// How many contracts a contract has started, a `u64`: the next one's address comes from it.
    pub fn created(creator: &Address) -> Vec<u8> {
        let mut key = b"created/".to_vec();
        key.extend_from_slice(creator.as_bytes());
        key
    }

    pub fn contract(address: &Address) -> Vec<u8> {
        let mut key = b"contract/".to_vec();
        key.extend_from_slice(address.as_bytes());
        key
    }

    pub fn code(hash: &Hash) -> Vec<u8> {
        let mut key = b"code/".to_vec();
        key.extend_from_slice(&hash.0);
        key
    }

    /// What a contract keeps. The address comes first and has a fixed length, so one contract
    /// can't reach another's keys.
    pub fn storage(contract: &Address, name: &[u8]) -> Vec<u8> {
        let mut key = b"storage/".to_vec();
        key.extend_from_slice(contract.as_bytes());
        key.extend_from_slice(name);
        key
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEnv {
    pub genesis_hash: Hash,
    pub height: u64,
    pub timestamp_ms: u64,
    pub params: ChainParams,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TxError {
    WrongChain {
        expected: Hash,
    },
    Expired {
        valid_until_ms: u64,
    },
    TooLarge,
    FeeTooLow {
        required: Amount,
    },
    FeeTooHigh {
        maximum: Amount,
    },
    UnknownSender,
    BadNonce {
        expected: u64,
    },
    RevealRequired,
    RevealMismatch,
    RevealNotAllowed,
    NoRecoveryPolicy,
    NotAllowedForRecovery,
    NotGovernance,
    NotAllowedForGovernance,
    Unauthorized(String),
    InvalidPolicy(String),
    InsufficientBalance {
        asset: AssetId,
        needed: Amount,
        available: Amount,
    },
    ZeroAmount,
    NothingToClaim,
    Overflow,
    PendingNotFound,
    PendingLocked {
        unlock_at_ms: u64,
    },
    TooManyPending,
    /// A vault with a recovery policy keeps this much native token for recovery to pay with.
    RecoveryReserve {
        reserve: Amount,
    },
    /// Too much gas for this block; the transaction may fit in the next one.
    BlockGasFull,
    /// The validator set already changes in this block; the transaction may fit in a later one.
    ValidatorsChanging,
    GasTooHigh,
    NotAContract,
    NotCallable,
    Storage(String),
}

impl fmt::Display for TxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxError::WrongChain { expected } => {
                write!(f, "wrong chain, expected genesis hash {expected}")
            }
            TxError::Expired { valid_until_ms } => {
                write!(f, "transaction expired at {valid_until_ms} ms")
            }
            TxError::TooLarge => write!(f, "transaction is larger than {MAX_TX_BYTES} bytes"),
            TxError::FeeTooLow { required } => {
                write!(f, "fee too low, at least {required} required")
            }
            TxError::FeeTooHigh { maximum } => write!(f, "fee too high, at most {maximum} allowed"),
            TxError::UnknownSender => write!(f, "sender account does not exist"),
            TxError::BadNonce { expected } => write!(f, "bad nonce, expected {expected}"),
            TxError::RevealRequired => {
                write!(
                    f,
                    "first transaction from this address must reveal its auth policy"
                )
            }
            TxError::RevealMismatch => write!(f, "revealed auth policy does not match the address"),
            TxError::RevealNotAllowed => write!(f, "auth policy already revealed"),
            TxError::NoRecoveryPolicy => write!(f, "account has no recovery policy"),
            TxError::NotAllowedForRecovery => {
                write!(
                    f,
                    "recovery may only cancel pending actions or replace the owner policy"
                )
            }
            TxError::Unauthorized(e) => write!(f, "unauthorized: {e}"),
            TxError::InvalidPolicy(e) => write!(f, "{e}"),
            TxError::InsufficientBalance {
                asset,
                needed,
                available,
            } => write!(
                f,
                "insufficient balance of asset {}: need {needed}, have {available}",
                asset.0
            ),
            TxError::ZeroAmount => write!(f, "amount must be positive"),
            TxError::NothingToClaim => write!(f, "nothing to claim for that address"),
            TxError::Overflow => write!(f, "balance overflow"),
            TxError::PendingNotFound => write!(f, "no pending action with that id"),
            TxError::PendingLocked { unlock_at_ms } => {
                write!(f, "pending action is locked until {unlock_at_ms} ms")
            }
            TxError::TooManyPending => {
                write!(f, "vault already has {MAX_PENDING_ACTIONS} pending actions")
            }
            TxError::RecoveryReserve { reserve } => write!(
                f,
                "a vault with a recovery policy keeps {reserve} for its recovery fee"
            ),
            TxError::BlockGasFull => write!(f, "no gas left in this block"),
            TxError::ValidatorsChanging => {
                write!(f, "the validator set already changes in this block")
            }
            TxError::GasTooHigh => write!(f, "gas limit is above {MAX_TX_GAS}"),
            TxError::NotAContract => write!(f, "no contract at that address"),
            TxError::NotCallable => write!(f, "init runs once, at deployment"),
            TxError::Storage(e) => write!(f, "storage error: {e}"),
            TxError::NotGovernance => {
                write!(
                    f,
                    "only the governance account can change validators or deploy contracts"
                )
            }
            TxError::NotAllowedForGovernance => {
                write!(
                    f,
                    "the governance account can only change the validator set and deploy contracts"
                )
            }
        }
    }
}

impl std::error::Error for TxError {}

impl From<qubits_state::Error> for TxError {
    fn from(e: qubits_state::Error) -> Self {
        TxError::Storage(e.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockError {
    TooManyTransactions,
    Transaction {
        index: usize,
        id: Hash,
        error: TxError,
    },
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockError::TooManyTransactions => write!(f, "too many transactions in block"),
            BlockError::Transaction { index, id, error } => {
                write!(f, "transaction {index} ({id}) failed: {error}")
            }
        }
    }
}

impl std::error::Error for BlockError {}

pub fn read_account(
    state: &impl StateReader,
    address: &Address,
) -> Result<Option<Account>, TxError> {
    match state.get(&keys::account(address))? {
        Some(bytes) => borsh::from_slice(&bytes)
            .map(Some)
            .map_err(|e| TxError::Storage(format!("corrupt account {address}: {e}"))),
        None => Ok(None),
    }
}

pub fn genesis_writes(genesis: &Genesis) -> WriteSet {
    let encode = |v: &dyn Fn() -> Vec<u8>| Some(v());
    let mut writes: WriteSet = genesis
        .accounts
        .iter()
        .map(|a| {
            let mut account = Account::default();
            account.set_balance(AssetId::NATIVE, a.balance);
            (
                keys::account(&a.address),
                encode(&|| borsh::to_vec(&account).expect("encoding cannot fail")),
            )
        })
        .collect();
    let set = ValidatorSet {
        epoch: 0,
        validators: genesis.validators.clone(),
    };
    let governance = keys::account(&governance_address());
    let mut account: Account = match writes.get(&governance) {
        Some(Some(bytes)) => borsh::from_slice(bytes).expect("just encoded"),
        _ => Account::default(),
    };
    account.auth = Some(set.council());
    writes.insert(
        governance,
        Some(borsh::to_vec(&account).expect("encoding cannot fail")),
    );
    writes.insert(
        keys::validators(),
        Some(borsh::to_vec(&set).expect("encoding cannot fail")),
    );
    writes
}

/// Every contract, in the order made. It is in state, and not an index beside it, so a node that
/// joined from a snapshot knows them too.
pub fn read_contracts(state: &impl StateReader) -> Result<Vec<Address>, TxError> {
    Ok(read_contracts_page(state, 0, None)?.0)
}

/// The contracts from index `from` on, at most `limit` of them, and how many there are in all.
pub fn read_contracts_page(
    state: &impl StateReader,
    from: u64,
    limit: Option<u64>,
) -> Result<(Vec<Address>, u64), TxError> {
    let total = counter(state.get(&keys::contracts())?)?;
    let end = limit.map_or(total, |limit| from.saturating_add(limit).min(total));
    let contracts = (from.min(total)..end)
        .map(|index| {
            let bytes = state
                .get(&keys::contract_at(index))?
                .ok_or_else(|| TxError::Storage(format!("contract {index} missing")))?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| TxError::Storage(format!("corrupt contract {index}")))?;
            Ok(Address(bytes))
        })
        .collect::<Result<_, TxError>>()?;
    Ok((contracts, total))
}

pub(crate) fn counter(stored: Option<Vec<u8>>) -> Result<u64, TxError> {
    match stored {
        None => Ok(0),
        Some(bytes) => {
            let bytes: [u8; 8] = bytes
                .try_into()
                .map_err(|_| TxError::Storage("corrupt counter".into()))?;
            Ok(u64::from_le_bytes(bytes))
        }
    }
}

pub fn read_validators(state: &impl StateReader) -> Result<ValidatorSet, TxError> {
    let bytes = state
        .get(&keys::validators())?
        .ok_or_else(|| TxError::Storage("no validator set".into()))?;
    borsh::from_slice(&bytes).map_err(|e| TxError::Storage(format!("corrupt validator set: {e}")))
}

pub fn min_fee(params: &ChainParams, size: usize) -> Amount {
    required_fee(params.min_fee_per_byte, size, 0)
}

/// The fee of the largest transaction there can be. A vault with a recovery policy can't spend
/// below it on the owner's word, so recovery can always pay, even after a stolen key has burned
/// the rest in fees.
pub fn recovery_reserve(params: &ChainParams) -> Amount {
    min_fee(params, MAX_TX_BYTES)
}

fn reserve_of(params: &ChainParams, vault: Option<&VaultPolicy>) -> Amount {
    match vault {
        Some(v) if v.recovery.is_some() => recovery_reserve(params),
        _ => 0,
    }
}

/// What is left of a transaction's gas, back in the native token. Rounds down, so never more
/// than was paid for it.
fn gas_refund(params: &ChainParams, gas_left: u64) -> Amount {
    Amount::from(params.min_fee_per_byte) * Amount::from(gas_left / GAS_PER_BYTE)
}

pub struct Executor<'a, S: StateReader> {
    state: &'a S,
    env: BlockEnv,
    changed: BTreeMap<Address, Account>,
    validators: Option<ValidatorSet>,
    /// A set takes kilobytes to read and every fee needs its size.
    stored_seats: std::cell::Cell<Option<usize>>,
    signatures: Option<&'a SignatureCache>,
    contract_writes: WriteSet,
    receipts: Vec<Receipt>,
    gas_reserved: u64,
    run_contracts: bool,
}

impl<'a, S: StateReader> Executor<'a, S> {
    pub fn new(state: &'a S, env: BlockEnv) -> Self {
        Executor {
            state,
            env,
            changed: BTreeMap::new(),
            validators: None,
            stored_seats: std::cell::Cell::new(None),
            signatures: None,
            contract_writes: WriteSet::new(),
            receipts: Vec::new(),
            gas_reserved: 0,
            run_contracts: true,
        }
    }

    /// Checks transactions without running any contract: a node deciding whether to take a
    /// transaction in has no fee to run it for. The result says nothing about what it would do.
    pub fn without_contracts(mut self) -> Self {
        self.run_contracts = false;
        self
    }

    pub fn with_signatures(mut self, cache: &'a SignatureCache) -> Self {
        self.signatures = Some(cache);
        self
    }

    /// Checks the block's signatures on all cores before it runs one transaction at a time.
    /// Only a head start: a transaction changing a key makes a later one miss and verify in turn.
    pub fn prewarm(&self, transactions: &[SignedTransaction]) -> Result<(), TxError> {
        let Some(cache) = self.signatures else {
            return Ok(());
        };
        let mut owned = Vec::with_capacity(transactions.len());
        for stx in transactions {
            let policy = match (stx.tx.role, self.account(&stx.tx.sender)?) {
                (Role::Owner, Some(account)) => account.auth.or_else(|| stx.reveal.clone()),
                (Role::Owner, None) => stx.reveal.clone(),
                (Role::Recovery, account) => account.and_then(|a| a.vault).and_then(|v| v.recovery),
            };
            if let Some(policy) = policy {
                owned.push((policy, stx.tx.signing_bytes(), &stx.signatures));
            }
        }
        let mut jobs = Vec::with_capacity(owned.len());
        for (policy, message, signatures) in &owned {
            for signature in signatures.iter() {
                if let Some(key) = policy.keys.get(usize::from(signature.index)) {
                    jobs.push((key, message.as_slice(), &signature.signature));
                }
            }
        }
        cache.prewarm(&jobs);
        Ok(())
    }

    pub fn env(&self) -> &BlockEnv {
        &self.env
    }

    pub fn account(&self, address: &Address) -> Result<Option<Account>, TxError> {
        match self.changed.get(address) {
            Some(account) => Ok(Some(account.clone())),
            None => read_account(self.state, address),
        }
    }

    pub fn apply(&mut self, stx: &SignedTransaction) -> Result<(), TxError> {
        self.run(stx, true)
    }

    pub fn apply_verified(&mut self, stx: &SignedTransaction) -> Result<(), TxError> {
        self.run(stx, false)
    }

    fn staged(&self) -> Staged<'_, 'a, S> {
        Staged {
            executor: self,
            accounts: BTreeMap::new(),
            validators: None,
            writes: WriteSet::new(),
            receipt: Receipt::default(),
            gas_reserved: 0,
            refunded: 0,
        }
    }

    fn run(&mut self, stx: &SignedTransaction, check_signatures: bool) -> Result<(), TxError> {
        let mut staged = self.staged();
        staged.apply(stx, check_signatures)?;
        let Staged {
            accounts,
            validators,
            writes,
            receipt,
            gas_reserved,
            ..
        } = staged;
        self.changed.extend(accounts);
        if validators.is_some() {
            self.validators = validators;
        }
        self.contract_writes.extend(writes);
        self.receipts.push(receipt);
        self.gas_reserved += gas_reserved;
        Ok(())
    }

    /// What each applied transaction did, in order.
    pub fn receipts(&self) -> &[Receipt] {
        &self.receipts
    }

    pub fn validator_set(&self) -> Result<ValidatorSet, TxError> {
        match &self.validators {
            Some(set) => Ok(set.clone()),
            None => read_validators(self.state),
        }
    }

    fn seats(&self) -> Result<usize, TxError> {
        if let Some(set) = &self.validators {
            return Ok(set.validators.len());
        }
        if let Some(seats) = self.stored_seats.get() {
            return Ok(seats);
        }
        let seats = read_validators(self.state)?.validators.len();
        self.stored_seats.set(Some(seats));
        Ok(seats)
    }

    pub fn into_executed(mut self) -> Executed {
        let receipts = std::mem::take(&mut self.receipts);
        Executed {
            writes: self.into_writes(),
            receipts,
        }
    }

    pub fn into_writes(self) -> WriteSet {
        let mut writes: WriteSet = self
            .changed
            .into_iter()
            .map(|(address, account)| {
                (
                    keys::account(&address),
                    Some(borsh::to_vec(&account).expect("encoding cannot fail")),
                )
            })
            .collect();
        if let Some(set) = self.validators {
            writes.insert(
                keys::validators(),
                Some(borsh::to_vec(&set).expect("encoding cannot fail")),
            );
        }
        writes.extend(self.contract_writes);
        writes
    }
}

#[derive(Debug)]
pub struct Executed {
    pub writes: WriteSet,
    pub receipts: Vec<Receipt>,
}

/// What a call would do, and what its caller's native balance would be, before any fee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Simulated {
    pub receipt: Receipt,
    pub balance_after: Amount,
}

/// `contract.function(args)` against this state as `caller`, with `amount` going along, for free.
/// Whatever it changes goes away with it. This is how a wallet shows what a call will do without
/// taking a website's word for it; state is public, so acting as anyone reveals nothing.
pub fn simulate(
    state: &impl StateReader,
    env: BlockEnv,
    caller: &Address,
    contract: &Address,
    function: &str,
    args: &[u8],
    amount: Amount,
) -> Result<Simulated, TxError> {
    if function == "init" {
        return Err(TxError::NotCallable);
    }
    let executor = Executor::new(state, env);
    let mut staged = executor.staged();
    if staged.read(&keys::contract(contract))?.is_none() {
        return Err(TxError::NotAContract);
    }
    let (receipt, _) = contracts::call(
        &mut staged,
        caller,
        contract,
        function,
        args,
        amount,
        MAX_TX_GAS,
    )?;
    let balance_after = staged
        .get(caller)?
        .map_or(0, |account| account.balance(AssetId::NATIVE));
    Ok(Simulated {
        receipt,
        balance_after,
    })
}

/// `contract.function(args)` against this state, with no caller. `output` is the answer.
pub fn view(
    state: &impl StateReader,
    env: BlockEnv,
    contract: &Address,
    function: &str,
    args: &[u8],
) -> Result<Receipt, TxError> {
    let nobody = Address([0; 32]);
    simulate(state, env, &nobody, contract, function, args, 0).map(|s| s.receipt)
}

pub fn execute_block(
    state: &impl StateReader,
    env: BlockEnv,
    transactions: &[SignedTransaction],
) -> Result<Executed, BlockError> {
    let cache = SignatureCache::default();
    execute_block_cached(state, env, transactions, &cache)
}

pub fn execute_block_cached(
    state: &impl StateReader,
    env: BlockEnv,
    transactions: &[SignedTransaction],
    cache: &SignatureCache,
) -> Result<Executed, BlockError> {
    if transactions.len() > env.params.max_block_transactions as usize {
        return Err(BlockError::TooManyTransactions);
    }
    let mut executor = Executor::new(state, env).with_signatures(cache);
    executor
        .prewarm(transactions)
        .map_err(|error| BlockError::Transaction {
            index: 0,
            id: transactions
                .first()
                .map_or(Hash::ZERO, SignedTransaction::id),
            error,
        })?;
    for (index, tx) in transactions.iter().enumerate() {
        executor
            .apply(tx)
            .map_err(|error| BlockError::Transaction {
                index,
                id: tx.id(),
                error,
            })?;
    }
    Ok(executor.into_executed())
}

struct Staged<'e, 'a, S: StateReader> {
    executor: &'e Executor<'a, S>,
    accounts: BTreeMap<Address, Account>,
    validators: Option<ValidatorSet>,
    writes: WriteSet,
    receipt: Receipt,
    gas_reserved: u64,
    refunded: Amount,
}

impl<S: StateReader> Staged<'_, '_, S> {
    fn read(&self, key: &[u8]) -> Result<Option<Vec<u8>>, TxError> {
        if let Some(value) = self.writes.get(key) {
            return Ok(value.clone());
        }
        if let Some(value) = self.executor.contract_writes.get(key) {
            return Ok(value.clone());
        }
        Ok(self.executor.state.get(key)?)
    }

    fn code_of(&self, address: &Address) -> Result<Option<Vec<u8>>, TxError> {
        let Some(record) = self.read(&keys::contract(address))? else {
            return Ok(None);
        };
        let contract: Contract = borsh::from_slice(&record)
            .map_err(|e| TxError::Storage(format!("corrupt contract {address}: {e}")))?;
        self.read(&keys::code(&contract.code))
    }

    /// The whole gas limit counts against the block, used or not: a proposer can then fill a
    /// block without knowing what its calls will do.
    fn reserve_gas(&mut self, gas_limit: u64) -> Result<(), TxError> {
        let reserved = self.executor.gas_reserved + self.gas_reserved + gas_limit;
        if reserved > MAX_BLOCK_GAS {
            return Err(TxError::BlockGasFull);
        }
        self.gas_reserved += gas_limit;
        Ok(())
    }

    fn get(&mut self, address: &Address) -> Result<Option<&mut Account>, TxError> {
        if !self.accounts.contains_key(address) {
            match self.executor.account(address)? {
                Some(account) => {
                    self.accounts.insert(*address, account);
                }
                None => return Ok(None),
            }
        }
        Ok(self.accounts.get_mut(address))
    }

    fn get_or_create(&mut self, address: &Address) -> Result<&mut Account, TxError> {
        if self.get(address)?.is_none() {
            self.accounts.insert(*address, Account::default());
        }
        Ok(self.accounts.get_mut(address).expect("just inserted"))
    }

    fn debit(&mut self, from: &Address, asset: AssetId, amount: Amount) -> Result<(), TxError> {
        let account = self.get(from)?.ok_or(TxError::UnknownSender)?;
        let available = account.balance(asset);
        if available < amount {
            return Err(TxError::InsufficientBalance {
                asset,
                needed: amount,
                available,
            });
        }
        account.set_balance(asset, available - amount);
        Ok(())
    }

    fn credit(&mut self, to: &Address, asset: AssetId, amount: Amount) -> Result<(), TxError> {
        let account = self.get_or_create(to)?;
        let balance = account
            .balance(asset)
            .checked_add(amount)
            .ok_or(TxError::Overflow)?;
        account.set_balance(asset, balance);
        Ok(())
    }

    fn apply(&mut self, stx: &SignedTransaction, check_signatures: bool) -> Result<(), TxError> {
        let executor = self.executor;
        let env = &executor.env;
        let tx = &stx.tx;

        let size = stx.encode().len();
        if size > MAX_TX_BYTES {
            return Err(TxError::TooLarge);
        }
        if tx.genesis_hash != env.genesis_hash {
            return Err(TxError::WrongChain {
                expected: env.genesis_hash,
            });
        }
        let now = env.timestamp_ms;
        if now > tx.valid_until_ms {
            return Err(TxError::Expired {
                valid_until_ms: tx.valid_until_ms,
            });
        }
        match &tx.payload {
            Payload::Deploy { code, args, .. }
                if code.len() > MAX_CODE_BYTES || args.len() > MAX_ARGS_BYTES =>
            {
                return Err(TxError::TooLarge);
            }
            Payload::Call { function, args, .. }
                if function.len() > MAX_FUNCTION_NAME || args.len() > MAX_ARGS_BYTES =>
            {
                return Err(TxError::TooLarge);
            }
            _ => {}
        }
        if tx.payload.gas_limit() > MAX_TX_GAS {
            return Err(TxError::GasTooHigh);
        }
        let required = required_fee(env.params.min_fee_per_byte, size, tx.payload.gas_limit());
        if tx.fee < required {
            return Err(TxError::FeeTooLow { required });
        }
        let maximum = required.saturating_mul(MAX_FEE_MULTIPLE);
        if tx.fee > maximum {
            return Err(TxError::FeeTooHigh { maximum });
        }

        let sender = tx.sender;
        let account = self.get(&sender)?.ok_or(TxError::UnknownSender)?;
        // signatures go last: they're expensive and a failed tx pays nothing
        if tx.nonce != account.nonce {
            return Err(TxError::BadNonce {
                expected: account.nonce,
            });
        }
        let available = account.balance(AssetId::NATIVE);
        if available < tx.fee {
            return Err(TxError::InsufficientBalance {
                asset: AssetId::NATIVE,
                needed: tx.fee,
                available,
            });
        }
        let reserve = match tx.role {
            Role::Owner => reserve_of(&env.params, account.vault.as_ref()),
            Role::Recovery => 0,
        };
        if available - tx.fee < reserve {
            return Err(TxError::RecoveryReserve { reserve });
        }
        let owner_policy = match (&account.auth, &stx.reveal) {
            (Some(auth), None) => auth.clone(),
            (Some(_), Some(_)) => return Err(TxError::RevealNotAllowed),
            (None, None) => return Err(TxError::RevealRequired),
            (None, Some(reveal)) => {
                if reveal.address() != sender {
                    return Err(TxError::RevealMismatch);
                }
                reveal
                    .validate()
                    .map_err(|e| TxError::InvalidPolicy(e.to_string()))?;
                reveal.clone()
            }
        };
        let policy = match tx.role {
            Role::Owner => owner_policy.clone(),
            Role::Recovery => account
                .vault
                .as_ref()
                .and_then(|v| v.recovery.clone())
                .ok_or(TxError::NoRecoveryPolicy)?,
        };
        if check_signatures {
            let message = tx.signing_bytes();
            match executor.signatures {
                Some(cache) => policy.check_cached(&message, &stx.signatures, cache),
                None => policy.check(&message, &stx.signatures),
            }
            .map_err(|e| TxError::Unauthorized(e.to_string()))?;
        }

        account.auth = Some(owner_policy);
        account.nonce += 1;
        let vault = account.vault.clone();
        self.debit(&sender, AssetId::NATIVE, tx.fee)?;

        let is_governance = sender == governance_address();
        match (&tx.payload, is_governance) {
            (Payload::SetValidators { .. } | Payload::Deploy { .. }, false) => {
                return Err(TxError::NotGovernance);
            }
            (Payload::SetValidators { .. } | Payload::Deploy { .. }, true) => {}
            (_, true) => return Err(TxError::NotAllowedForGovernance),
            _ => {}
        }

        if tx.role == Role::Recovery
            && !matches!(
                tx.payload,
                Payload::CancelPending { .. } | Payload::SetAuth { .. }
            )
        {
            return Err(TxError::NotAllowedForRecovery);
        }

        let delay = match (tx.role, &vault) {
            (Role::Owner, Some(v)) => Some(v.delay_ms),
            _ => None,
        };

        match &tx.payload {
            Payload::SetValidators { validators } => {
                if self.executor.validators.is_some() {
                    return Err(TxError::ValidatorsChanging);
                }
                let current = self.executor.validator_set()?;
                let next = ValidatorSet {
                    epoch: current.epoch + 1,
                    validators: validators.clone(),
                };
                next.validate()
                    .map_err(|e| TxError::InvalidPolicy(e.to_string()))?;
                self.get(&sender)?.expect("sender loaded").auth = Some(next.council());
                self.validators = Some(next);
            }
            Payload::Deploy {
                code,
                args,
                gas_limit,
            } => {
                if self.executor.run_contracts {
                    self.reserve_gas(*gas_limit)?;
                    let address = contract_address(&sender, tx.nonce);
                    let (receipt, gas_left) =
                        contracts::deploy(self, &sender, &address, code, args, *gas_limit)?;
                    self.receipt = receipt;
                    self.refund_gas(&sender, gas_left)?;
                }
            }
            Payload::Call {
                contract,
                function,
                args,
                amount,
                gas_limit,
            } => {
                if function == "init" {
                    return Err(TxError::NotCallable);
                }
                if self.read(&keys::contract(contract))?.is_none() {
                    return Err(TxError::NotAContract);
                }
                let available = self
                    .get(&sender)?
                    .expect("sender loaded")
                    .balance(AssetId::NATIVE);
                if available < *amount {
                    return Err(TxError::InsufficientBalance {
                        asset: AssetId::NATIVE,
                        needed: *amount,
                        available,
                    });
                }
                if available - *amount < reserve {
                    return Err(TxError::RecoveryReserve { reserve });
                }
                match delay {
                    Some(delay_ms) => {
                        let action = DelayedAction::Call {
                            contract: *contract,
                            function: function.clone(),
                            args: args.clone(),
                            amount: *amount,
                            gas_limit: *gas_limit,
                        };
                        self.queue(&sender, now, delay_ms, action)?;
                    }
                    None if self.executor.run_contracts => {
                        self.reserve_gas(*gas_limit)?;
                        let (receipt, gas_left) = contracts::call(
                            self, &sender, contract, function, args, *amount, *gas_limit,
                        )?;
                        self.receipt = receipt;
                        self.refund_gas(&sender, gas_left)?;
                    }
                    None => {}
                }
            }
            Payload::Transfer { to, asset, amount } => {
                if *amount == 0 {
                    return Err(TxError::ZeroAmount);
                }
                match delay {
                    Some(delay_ms) => {
                        let available = self.get(&sender)?.expect("sender loaded").balance(*asset);
                        if available < *amount {
                            return Err(TxError::InsufficientBalance {
                                asset: *asset,
                                needed: *amount,
                                available,
                            });
                        }
                        if *asset == AssetId::NATIVE && available - *amount < reserve {
                            return Err(TxError::RecoveryReserve { reserve });
                        }
                        let action = DelayedAction::Transfer {
                            to: *to,
                            asset: *asset,
                            amount: *amount,
                        };
                        self.queue(&sender, now, delay_ms, action)?;
                    }
                    None => {
                        self.debit(&sender, *asset, *amount)?;
                        self.credit(to, *asset, *amount)?;
                    }
                }
            }
            Payload::SetAuth { auth } => {
                auth.validate()
                    .map_err(|e| TxError::InvalidPolicy(e.to_string()))?;
                match delay {
                    Some(delay_ms) => {
                        self.queue(&sender, now, delay_ms, DelayedAction::SetAuth(auth.clone()))?
                    }
                    None => {
                        let account = self.get(&sender)?.expect("sender loaded");
                        account.auth = Some(auth.clone());
                        // every action in the queue was signed by an owner key recovery replaces
                        if tx.role == Role::Recovery {
                            account.pending.clear();
                        }
                    }
                }
            }
            Payload::SetVault { vault: new_vault } => {
                if let Some(v) = new_vault {
                    v.validate()
                        .map_err(|e| TxError::InvalidPolicy(e.to_string()))?;
                }
                match delay {
                    Some(delay_ms) => self.queue(
                        &sender,
                        now,
                        delay_ms,
                        DelayedAction::SetVault(new_vault.clone()),
                    )?,
                    None => {
                        let account = self.get(&sender)?.expect("sender loaded");
                        let reserve = reserve_of(&env.params, new_vault.as_ref());
                        if account.balance(AssetId::NATIVE) < reserve {
                            return Err(TxError::RecoveryReserve { reserve });
                        }
                        account.vault = new_vault.clone();
                    }
                }
            }
            Payload::CancelPending { id } => {
                let account = self.get(&sender)?.expect("sender loaded");
                let position = account
                    .pending
                    .iter()
                    .position(|p| p.id == *id)
                    .ok_or(TxError::PendingNotFound)?;
                account.pending.remove(position);
            }
            Payload::ExecutePending {
                account: target,
                id,
            } => {
                let target_account = self.get(target)?.ok_or(TxError::PendingNotFound)?;
                let position = target_account
                    .pending
                    .iter()
                    .position(|p| p.id == *id)
                    .ok_or(TxError::PendingNotFound)?;
                let pending = &target_account.pending[position];
                if now < pending.unlock_at_ms {
                    return Err(TxError::PendingLocked {
                        unlock_at_ms: pending.unlock_at_ms,
                    });
                }
                let PendingAction { action, .. } = target_account.pending.remove(position);
                let reserve = reserve_of(&env.params, target_account.vault.as_ref());
                let spendable = target_account
                    .balance(AssetId::NATIVE)
                    .saturating_sub(reserve);
                match action {
                    DelayedAction::Transfer { to, asset, amount } => {
                        if asset == AssetId::NATIVE
                            && amount <= target_account.balance(AssetId::NATIVE)
                            && amount > spendable
                        {
                            return Err(TxError::RecoveryReserve { reserve });
                        }
                        self.debit(target, asset, amount)?;
                        self.credit(&to, asset, amount)?;
                    }
                    DelayedAction::SetAuth(auth) => {
                        self.get(target)?.expect("target loaded").auth = Some(auth);
                    }
                    DelayedAction::SetVault(vault) => {
                        self.get(target)?.expect("target loaded").vault = vault;
                    }
                    // paid for when it was queued, gas included, so nothing comes back
                    DelayedAction::Call {
                        contract,
                        function,
                        args,
                        amount,
                        gas_limit,
                    } if self.executor.run_contracts => {
                        self.reserve_gas(gas_limit)?;
                        self.receipt = if amount > spendable {
                            contracts::refused("insufficient balance", gas_limit)
                        } else {
                            contracts::call(
                                self, target, &contract, &function, &args, amount, gas_limit,
                            )?
                            .0
                        };
                    }
                    DelayedAction::Call { .. } => {}
                }
            }
            Payload::ClaimRewards { payout } => self.claim_rewards(payout)?,
        }
        self.pay_validators(tx.fee - self.refunded)?;
        self.seat_validators()
    }

    fn refund_gas(&mut self, sender: &Address, gas_left: u64) -> Result<(), TxError> {
        let refund = gas_refund(&self.executor.env.params, gas_left);
        self.refunded += refund;
        self.credit(sender, AssetId::NATIVE, refund)
    }

    fn queue(
        &mut self,
        address: &Address,
        now: u64,
        delay_ms: u64,
        action: DelayedAction,
    ) -> Result<(), TxError> {
        let account = self.get(address)?.expect("sender loaded");
        if account.pending.len() >= MAX_PENDING_ACTIONS {
            return Err(TxError::TooManyPending);
        }
        let unlock_at_ms = now.checked_add(delay_ms).ok_or(TxError::Overflow)?;
        let id = account.next_pending_id;
        account.next_pending_id += 1;
        account.pending.push(PendingAction {
            id,
            unlock_at_ms,
            action,
        });
        Ok(())
    }
}
