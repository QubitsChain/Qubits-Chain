//! The small chain the contract tests run on.
#![allow(dead_code)]

use qubits_crypto::{SchemeId, SecretKey};
use qubits_execution::{
    BlockEnv, BlockError, Executed, TxError, execute_block, genesis_writes, keys, read_account,
    view,
};
use qubits_state::{MemoryState, StateReader};
use qubits_types::client::required_fee;
use qubits_types::*;

pub const TOKEN: &[u8] = include_bytes!("../../../../contracts/out/token.wasm");
pub const ESCROW: &[u8] = include_bytes!("../../../../contracts/out/escrow.wasm");
pub const GAS: u64 = 2_000_000;
pub const DELAY: u64 = 60_000;

pub fn key(seed: u8) -> SecretKey {
    SecretKey::from_seed(SchemeId::MlDsa65, &[seed; 32]).unwrap()
}

pub fn address(sk: &SecretKey) -> Address {
    AuthPolicy::single(sk.public_key().clone()).address()
}

pub struct Chain {
    pub state: MemoryState,
    pub genesis_hash: Hash,
    pub height: u64,
    pub now: u64,
    pub validator: SecretKey,
    pub receipts: Vec<Receipt>,
}

pub fn params() -> ChainParams {
    ChainParams {
        min_fee_per_byte: 1,
        max_block_transactions: 50,
    }
}

impl Chain {
    pub fn new(funded: &[&SecretKey]) -> Chain {
        let validator = key(200);
        let mut accounts: Vec<GenesisAccount> = funded
            .iter()
            .map(|sk| GenesisAccount {
                address: address(sk),
                balance: 1_000_000_000,
            })
            .collect();
        accounts.push(GenesisAccount {
            address: governance_address(),
            balance: 1_000_000_000,
        });
        let genesis = Genesis {
            chain_id: "qubits-test".into(),
            timestamp_ms: 1_000,
            params: params(),
            validators: vec![qubits_types::Validator::self_paid(
                validator.public_key().clone(),
            )],
            accounts,
        };
        genesis.validate().unwrap();
        let mut state = MemoryState::new();
        state.apply(&genesis_writes(&genesis));
        Chain {
            state,
            genesis_hash: genesis.hash(),
            height: 0,
            now: 1_000,
            validator,
            receipts: Vec::new(),
        }
    }

    pub fn env(&self) -> BlockEnv {
        BlockEnv {
            genesis_hash: self.genesis_hash,
            height: self.height + 1,
            timestamp_ms: self.now + 1,
            params: params(),
        }
    }

    pub fn account(&self, who: &Address) -> Account {
        read_account(&self.state, who).unwrap().unwrap_or_default()
    }

    pub fn balance(&self, who: &Address) -> Amount {
        self.account(who).balance(AssetId::NATIVE)
    }

    pub fn block(&mut self, txs: &[SignedTransaction]) -> Result<(), BlockError> {
        let env = self.env();
        let Executed { writes, receipts } = execute_block(&self.state, env.clone(), txs)?;
        self.state.apply(&writes);
        self.height = env.height;
        self.now = env.timestamp_ms;
        self.receipts = receipts;
        Ok(())
    }

    pub fn submit(&mut self, stx: SignedTransaction) -> Result<Receipt, TxError> {
        self.block(&[stx]).map_err(|e| match e {
            BlockError::Transaction { error, .. } => error,
            other => panic!("unexpected block error {other}"),
        })?;
        Ok(self.receipts[0].clone())
    }

    pub fn signed(
        &self,
        sk: &SecretKey,
        sender: Address,
        policy: &AuthPolicy,
        payload: Payload,
    ) -> SignedTransaction {
        self.signed_with_fee(sk, sender, policy, payload, None)
    }

    pub fn signed_with_fee(
        &self,
        sk: &SecretKey,
        sender: Address,
        policy: &AuthPolicy,
        payload: Payload,
        fee: Option<Amount>,
    ) -> SignedTransaction {
        let account = self.account(&sender);
        let reveal = account.auth.is_none().then(|| policy.clone());
        let mut tx = Transaction {
            genesis_hash: self.genesis_hash,
            sender,
            nonce: account.nonce,
            fee: 0,
            valid_until_ms: u64::MAX,
            role: Role::Owner,
            payload,
        };
        let size = SignedTransaction::sign(tx.clone(), policy, reveal.clone(), &[sk])
            .unwrap()
            .encode()
            .len();
        tx.fee = fee.unwrap_or(required_fee(1, size, tx.payload.gas_limit()));
        SignedTransaction::sign(tx, policy, reveal, &[sk]).unwrap()
    }

    pub fn from(&self, sk: &SecretKey, payload: Payload) -> SignedTransaction {
        self.signed(
            sk,
            address(sk),
            &AuthPolicy::single(sk.public_key().clone()),
            payload,
        )
    }

    pub fn deploy_tx(&self, code: &[u8], args: Vec<u8>, gas_limit: u64) -> SignedTransaction {
        let council = AuthPolicy::single(self.validator.public_key().clone());
        let payload = Payload::Deploy {
            code: code.to_vec(),
            args,
            gas_limit,
        };
        self.signed(&self.validator, governance_address(), &council, payload)
    }

    pub fn deploy(&mut self, code: &[u8], args: Vec<u8>) -> Address {
        let receipt = self.submit(self.deploy_tx(code, args, GAS)).unwrap();
        assert_eq!(receipt.outcome, Outcome::Done, "{receipt:?}");
        receipt.contract.expect("deployed")
    }

    pub fn call(
        &mut self,
        sk: &SecretKey,
        contract: Address,
        function: &str,
        args: Vec<u8>,
        amount: Amount,
    ) -> Result<Receipt, TxError> {
        let payload = call_payload(contract, function, args, amount, GAS);
        self.submit(self.from(sk, payload))
    }

    pub fn done(
        &mut self,
        sk: &SecretKey,
        contract: Address,
        function: &str,
        args: Vec<u8>,
        amount: Amount,
    ) -> Receipt {
        let receipt = self.call(sk, contract, function, args, amount).unwrap();
        assert_eq!(receipt.outcome, Outcome::Done, "{receipt:?}");
        receipt
    }

    pub fn view(&self, contract: Address, function: &str, args: Vec<u8>) -> Receipt {
        view(&self.state, self.env(), &contract, function, &args).unwrap()
    }

    pub fn view_u128(&self, contract: Address, function: &str, args: Vec<u8>) -> u128 {
        let receipt = self.view(contract, function, args);
        assert_eq!(receipt.outcome, Outcome::Done, "{receipt:?}");
        u128::from_le_bytes(receipt.output.try_into().unwrap())
    }

    pub fn stored(&self, contract: Address, name: &[u8]) -> Option<Vec<u8>> {
        self.state.get(&keys::storage(&contract, name)).unwrap()
    }
}

pub fn call_payload(
    contract: Address,
    function: &str,
    args: Vec<u8>,
    amount: Amount,
    gas_limit: u64,
) -> Payload {
    Payload::Call {
        contract,
        function: function.into(),
        args,
        amount,
        gas_limit,
    }
}

pub fn pack(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

pub fn reverted(receipt: &Receipt, reason: &str) {
    assert_eq!(
        receipt.outcome,
        Outcome::Reverted {
            reason: reason.as_bytes().to_vec()
        }
    );
}

pub fn wasm(text: &str) -> Vec<u8> {
    wat::parse_str(text).unwrap()
}

pub fn token_args(owner: &Address, supply: u128, name: &str, symbol: &str) -> Vec<u8> {
    pack(&[
        owner.as_bytes(),
        &supply.to_le_bytes(),
        &(name.len() as u32).to_le_bytes(),
        name.as_bytes(),
        &(symbol.len() as u32).to_le_bytes(),
        symbol.as_bytes(),
        &6u64.to_le_bytes(),
    ])
}

pub fn token(chain: &mut Chain, owner: &Address, supply: u128) -> Address {
    chain.deploy(TOKEN, token_args(owner, supply, "Test", "TST"))
}

pub fn holds(chain: &Chain, token: Address, who: &Address) -> u128 {
    chain.view_u128(token, "balance_of", who.as_bytes().to_vec())
}

pub fn send_args(to: &Address, amount: u128) -> Vec<u8> {
    pack(&[to.as_bytes(), &amount.to_le_bytes()])
}
