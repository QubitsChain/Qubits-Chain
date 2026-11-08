//! Running contracts inside a transaction. All a contract changes goes through an undo log, so a
//! callee that fails is rolled back alone; the fee and nonce sit outside it and always stand.

use qubits_state::StateReader;
use qubits_types::limits::MAX_CALL_DEPTH;
use qubits_types::{Address, Amount, AssetId, Contract, Event, Hash, Outcome, Receipt, code_hash};
use qubits_vm::{Called, Fatal, Finish, Host, Invocation, gas};

use crate::{Staged, TxError, keys};

enum Undo {
    Write {
        key: Vec<u8>,
        /// None if this transaction hadn't touched the key.
        previous: Option<Option<Vec<u8>>>,
    },
    Balance {
        address: Address,
        previous: Amount,
    },
    Created(Address),
}

struct Run<'r, 'e, 'a, S: StateReader> {
    staged: &'r mut Staged<'e, 'a, S>,
    undo: Vec<Undo>,
    events: Vec<Event>,
    stack: Vec<Address>,
}

fn fatal(error: TxError) -> Fatal {
    Fatal(error.to_string())
}

fn reverted(reason: &str, gas_left: u64) -> Finish {
    let reason = reason.as_bytes().to_vec();
    Finish::early(Outcome::Reverted { reason }, gas_left)
}

impl<S: StateReader> Run<'_, '_, '_, S> {
    fn put(&mut self, key: Vec<u8>, value: Option<Vec<u8>>) {
        let previous = self.staged.writes.insert(key.clone(), value);
        self.undo.push(Undo::Write { key, previous });
    }

    fn rollback(&mut self, mark: usize, events: usize) {
        self.events.truncate(events);
        while self.undo.len() > mark {
            match self.undo.pop().expect("longer than the mark") {
                Undo::Write {
                    key,
                    previous: Some(value),
                } => {
                    self.staged.writes.insert(key, value);
                }
                Undo::Write {
                    key,
                    previous: None,
                } => {
                    self.staged.writes.remove(&key);
                }
                Undo::Balance { address, previous } => {
                    if let Some(account) = self.staged.accounts.get_mut(&address) {
                        account.set_balance(AssetId::NATIVE, previous);
                    }
                }
                Undo::Created(address) => {
                    self.staged.accounts.remove(&address);
                }
            }
        }
    }

    fn set_balance(&mut self, address: &Address, amount: Amount) -> Result<(), Fatal> {
        if self.staged.get(address).map_err(fatal)?.is_none() {
            self.undo.push(Undo::Created(*address));
        }
        let account = self.staged.get_or_create(address).map_err(fatal)?;
        let previous = account.balance(AssetId::NATIVE);
        account.set_balance(AssetId::NATIVE, amount);
        self.undo.push(Undo::Balance {
            address: *address,
            previous,
        });
        Ok(())
    }

    fn enter(
        &mut self,
        from: &Address,
        to: &Address,
        function: &str,
        input: &[u8],
        value: Amount,
        gas: u64,
    ) -> Result<Finish, Fatal> {
        // a running contract can't be re-entered
        if self.stack.len() >= MAX_CALL_DEPTH || self.stack.contains(to) {
            return Ok(reverted("call not allowed here", gas));
        }
        let Some(code) = self.staged.code_of(to).map_err(fatal)? else {
            return Ok(Finish::early(Outcome::Invalid, gas));
        };
        let (mark, events) = (self.undo.len(), self.events.len());
        if value > 0 && !self.transfer(from, to, value)? {
            return Ok(reverted("insufficient balance", gas));
        }
        self.stack.push(*to);
        let finish = qubits_vm::run(
            Invocation {
                code: &code,
                function,
                input,
                contract: *to,
                caller: *from,
                value,
                gas,
            },
            self,
        );
        self.stack.pop();
        let finish = finish?;
        if finish.outcome != Outcome::Done {
            self.rollback(mark, events);
        }
        Ok(finish)
    }

    fn receipt(self, finish: Finish, gas: u64, contract: Option<Address>) -> (Receipt, u64) {
        let receipt = Receipt {
            gas_used: gas - finish.gas_left,
            contract: contract.filter(|_| finish.outcome == Outcome::Done),
            outcome: finish.outcome,
            output: finish.output,
            events: self.events,
        };
        (receipt, finish.gas_left)
    }
}

impl<S: StateReader> Host for Run<'_, '_, '_, S> {
    fn height(&self) -> u64 {
        self.staged.executor.env.height
    }

    fn timestamp_ms(&self) -> u64 {
        self.staged.executor.env.timestamp_ms
    }

    fn balance(&mut self, who: &Address) -> Result<Amount, Fatal> {
        if let Some(account) = self.staged.accounts.get(who) {
            return Ok(account.balance(AssetId::NATIVE));
        }
        let account = self.staged.executor.account(who).map_err(fatal)?;
        Ok(account.map_or(0, |a| a.balance(AssetId::NATIVE)))
    }

    fn read(&mut self, contract: &Address, key: &[u8]) -> Result<Option<Vec<u8>>, Fatal> {
        self.staged
            .read(&keys::storage(contract, key))
            .map_err(fatal)
    }

    fn write(&mut self, contract: &Address, key: &[u8], value: Option<&[u8]>) -> Result<(), Fatal> {
        self.put(keys::storage(contract, key), value.map(<[u8]>::to_vec));
        Ok(())
    }

    fn transfer(&mut self, from: &Address, to: &Address, amount: Amount) -> Result<bool, Fatal> {
        let balance = self.balance(from)?;
        if balance < amount {
            return Ok(false);
        }
        if amount == 0 || from == to {
            return Ok(true);
        }
        let Some(credited) = self.balance(to)?.checked_add(amount) else {
            return Ok(false);
        };
        self.set_balance(from, balance - amount)?;
        self.set_balance(to, credited)?;
        Ok(true)
    }

    fn emit(&mut self, contract: &Address, topic: Vec<u8>, data: Vec<u8>) {
        self.events.push(Event {
            contract: *contract,
            topic,
            data,
        });
    }

    fn call(
        &mut self,
        from: &Address,
        to: &Address,
        function: &str,
        args: &[u8],
        value: Amount,
        gas: u64,
    ) -> Result<Called, Fatal> {
        if function == "init" {
            return Ok(Called {
                ok: false,
                output: Vec::new(),
                gas_left: gas,
            });
        }
        let finish = self.enter(from, to, function, args, value, gas)?;
        Ok(Called {
            ok: finish.outcome == Outcome::Done,
            output: finish.output,
            gas_left: finish.gas_left,
        })
    }
}

fn run_for<'r, 'e, 'a, S: StateReader>(staged: &'r mut Staged<'e, 'a, S>) -> Run<'r, 'e, 'a, S> {
    Run {
        staged,
        undo: Vec::new(),
        events: Vec::new(),
        stack: Vec::new(),
    }
}

/// The receipt of a call that never started: nothing ran and no gas was used.
pub(crate) fn refused(reason: &str, gas: u64) -> Receipt {
    let finish = reverted(reason, gas);
    Receipt {
        gas_used: 0,
        contract: None,
        outcome: finish.outcome,
        output: finish.output,
        events: Vec::new(),
    }
}

/// The receipt, and the gas left.
pub(crate) fn call<S: StateReader>(
    staged: &mut Staged<'_, '_, S>,
    caller: &Address,
    contract: &Address,
    function: &str,
    args: &[u8],
    amount: Amount,
    gas: u64,
) -> Result<(Receipt, u64), TxError> {
    let mut run = run_for(staged);
    let finish = run
        .enter(caller, contract, function, args, amount, gas)
        .map_err(|e| TxError::Storage(e.0))?;
    Ok(run.receipt(finish, gas, None))
}

pub(crate) fn deploy<S: StateReader>(
    staged: &mut Staged<'_, '_, S>,
    deployer: &Address,
    address: &Address,
    code: &[u8],
    args: &[u8],
    gas_limit: u64,
) -> Result<(Receipt, u64), TxError> {
    let mut run = run_for(staged);
    let stored = code.len() as u64 + 32;
    let Some(gas) = gas_limit.checked_sub(stored * gas::STATE_BYTE) else {
        let finish = Finish::early(Outcome::OutOfGas, 0);
        return Ok(run.receipt(finish, gas_limit, None));
    };
    let hash: Hash = code_hash(code);
    let record = borsh::to_vec(&Contract { code: hash }).expect("encoding cannot fail");
    run.put(keys::code(&hash), Some(code.to_vec()));
    run.put(keys::contract(address), Some(record));
    let mut all: Vec<Address> = match run.staged.read(&keys::contracts())? {
        Some(bytes) => borsh::from_slice(&bytes)
            .map_err(|e| TxError::Storage(format!("corrupt contract list: {e}")))?,
        None => Vec::new(),
    };
    all.push(*address);
    let list = borsh::to_vec(&all).expect("encoding cannot fail");
    run.put(keys::contracts(), Some(list));
    let finish = run
        .enter(deployer, address, "init", args, 0, gas)
        .map_err(|e| TxError::Storage(e.0))?;
    if finish.outcome != Outcome::Done {
        run.rollback(0, 0);
    }
    let (mut receipt, gas_left) = run.receipt(finish, gas, Some(*address));
    receipt.gas_used = gas_limit - gas_left;
    Ok((receipt, gas_left))
}
