use qubits_crypto::{SchemeId, SecretKey};
use qubits_execution::{
    BlockEnv, BlockError, Executor, TxError, execute_block, genesis_writes, min_fee, read_account,
    recovery_reserve,
};
use qubits_state::MemoryState;
use qubits_types::limits::MAX_PENDING_ACTIONS;
use qubits_types::*;

const CHAIN: &str = "qubits-test";
const DELAY: u64 = 60_000;

fn params() -> ChainParams {
    ChainParams {
        min_fee_per_byte: 1,
        max_block_transactions: 50,
    }
}

fn key(seed: u8) -> SecretKey {
    SecretKey::from_seed(SchemeId::MlDsa65, &[seed; 32]).unwrap()
}

fn slh_key(seed: u8) -> SecretKey {
    SecretKey::from_seed(SchemeId::SlhDsaSha2_192s, &[seed; 72]).unwrap()
}

fn single(sk: &SecretKey) -> AuthPolicy {
    AuthPolicy::single(sk.public_key().clone())
}

#[derive(Clone)]
struct Wallet {
    address: Address,
    policy: AuthPolicy,
    keys: Vec<SecretKey>,
    revealed: bool,
}

impl Wallet {
    fn new(sk: SecretKey) -> Wallet {
        let policy = single(&sk);
        Wallet {
            address: policy.address(),
            policy,
            keys: vec![sk],
            revealed: false,
        }
    }

    fn multisig(threshold: u8, keys: Vec<SecretKey>) -> Wallet {
        let policy = AuthPolicy {
            threshold,
            keys: keys.iter().map(|k| k.public_key().clone()).collect(),
        };
        Wallet {
            address: policy.address(),
            policy,
            keys,
            revealed: false,
        }
    }
}

struct Chain {
    state: MemoryState,
    genesis_hash: Hash,
    height: u64,
    now: u64,
}

impl Chain {
    fn new(funded: &[(&Wallet, Amount)]) -> Chain {
        Chain::with_validators(funded, vec![key(200)], 0)
    }

    fn with_validators(
        funded: &[(&Wallet, Amount)],
        validators: Vec<SecretKey>,
        governance_funds: Amount,
    ) -> Chain {
        let mut accounts: Vec<GenesisAccount> = funded
            .iter()
            .map(|(w, balance)| GenesisAccount {
                address: w.address,
                balance: *balance,
            })
            .collect();
        if governance_funds > 0 {
            accounts.push(GenesisAccount {
                address: governance_address(),
                balance: governance_funds,
            });
        }
        let genesis = Genesis {
            chain_id: CHAIN.into(),
            timestamp_ms: 1_000,
            params: params(),
            validators: validators.iter().map(seat).collect(),
            accounts,
        };
        Chain::from_genesis(&genesis)
    }

    fn from_genesis(genesis: &Genesis) -> Chain {
        genesis.validate().unwrap();
        let mut state = MemoryState::new();
        state.apply(&genesis_writes(genesis));
        Chain {
            state,
            genesis_hash: genesis.hash(),
            height: 0,
            now: 1_000,
        }
    }

    fn env(&self) -> BlockEnv {
        BlockEnv {
            genesis_hash: self.genesis_hash,
            height: self.height + 1,
            timestamp_ms: self.now + 1,
            params: params(),
        }
    }

    fn account(&self, address: &Address) -> Account {
        read_account(&self.state, address)
            .unwrap()
            .unwrap_or_default()
    }

    fn balance(&self, w: &Wallet) -> Amount {
        self.account(&w.address).balance(AssetId::NATIVE)
    }

    fn nonce(&self, w: &Wallet) -> u64 {
        self.account(&w.address).nonce
    }

    fn advance(&mut self, ms: u64) {
        self.now += ms;
    }

    fn block(&mut self, txs: &[SignedTransaction]) -> Result<(), BlockError> {
        let env = self.env();
        let writes = execute_block(&self.state, env.clone(), txs)?.writes;
        self.state.apply(&writes);
        self.height = env.height;
        self.now = env.timestamp_ms;
        Ok(())
    }

    fn submit(&mut self, stx: SignedTransaction) -> Result<(), TxError> {
        self.block(&[stx]).map_err(|e| match e {
            BlockError::Transaction { error, .. } => error,
            other => panic!("unexpected block error {other}"),
        })
    }

    fn tx_with(
        &self,
        w: &Wallet,
        role: Role,
        policy: &AuthPolicy,
        signers: &[&SecretKey],
        payload: Payload,
    ) -> SignedTransaction {
        let reveal = (!w.revealed && role == Role::Owner).then(|| w.policy.clone());
        let mut tx = Transaction {
            genesis_hash: self.genesis_hash,
            sender: w.address,
            nonce: self.nonce(w),
            fee: 0,
            valid_until_ms: u64::MAX,
            role,
            payload,
        };
        let draft = SignedTransaction::sign(tx.clone(), policy, reveal.clone(), signers).unwrap();
        tx.fee = min_fee(&params(), draft.encode().len());
        SignedTransaction::sign(tx, policy, reveal, signers).unwrap()
    }

    fn tx(&self, w: &Wallet, payload: Payload) -> SignedTransaction {
        let signers: Vec<&SecretKey> = w.keys.iter().take(w.policy.threshold.into()).collect();
        self.tx_with(w, Role::Owner, &w.policy, &signers, payload)
    }

    fn send(&mut self, w: &mut Wallet, payload: Payload) -> Result<(), TxError> {
        let stx = self.tx(w, payload);
        self.submit(stx)?;
        w.revealed = true;
        Ok(())
    }
}

fn pay(to: &Wallet, amount: Amount) -> Payload {
    Payload::Transfer {
        to: to.address,
        asset: AssetId::NATIVE,
        amount,
    }
}

fn fee_of(stx: &SignedTransaction) -> Amount {
    stx.tx.fee
}

#[test]
fn genesis_funds_accounts() {
    let alice = Wallet::new(key(1));
    let chain = Chain::new(&[(&alice, 1_000_000)]);
    assert_eq!(chain.balance(&alice), 1_000_000);
    assert_eq!(chain.nonce(&alice), 0);
    assert_eq!(chain.account(&alice.address).auth, None);
}

#[test]
fn transfer_moves_funds_burns_fee_and_bumps_nonce() {
    let mut alice = Wallet::new(key(1));
    let bob = Wallet::new(key(2));
    let mut chain = Chain::new(&[(&alice, 1_000_000)]);

    let stx = chain.tx(&alice, pay(&bob, 400));
    let fee = fee_of(&stx);
    chain.submit(stx).unwrap();
    alice.revealed = true;

    assert_eq!(chain.balance(&alice), 1_000_000 - 400 - fee);
    assert_eq!(chain.balance(&bob), 400);
    assert_eq!(chain.nonce(&alice), 1);
    assert_eq!(
        chain.account(&alice.address).auth,
        Some(alice.policy.clone())
    );
    assert_eq!(
        chain.account(&bob.address).auth,
        None,
        "bob has not sent anything yet"
    );
}

#[test]
fn first_transaction_must_reveal_the_matching_policy() {
    let alice = Wallet::new(key(1));
    let bob = Wallet::new(key(2));
    let mut chain = Chain::new(&[(&alice, 1_000_000)]);

    let mut stx = chain.tx(&alice, pay(&bob, 1));
    stx.reveal = None;
    assert_eq!(chain.submit(stx), Err(TxError::RevealRequired));

    let thief = Wallet {
        address: alice.address,
        ..Wallet::new(key(2))
    };
    let stx = chain.tx(&thief, pay(&bob, 1));
    assert_eq!(chain.submit(stx), Err(TxError::RevealMismatch));

    let stx = chain.tx(&alice, pay(&bob, 1));
    chain.submit(stx).unwrap();
    let stx = chain.tx(&alice, pay(&bob, 1));
    assert_eq!(chain.submit(stx), Err(TxError::RevealNotAllowed));
}

#[test]
fn replay_and_wrong_nonce_are_rejected() {
    let mut alice = Wallet::new(key(1));
    let bob = Wallet::new(key(2));
    let mut chain = Chain::new(&[(&alice, 1_000_000)]);
    let stx = chain.tx(&alice, pay(&bob, 1));
    chain.submit(stx.clone()).unwrap();
    alice.revealed = true;

    let mut replay = stx;
    replay.reveal = None;
    assert_eq!(chain.submit(replay), Err(TxError::BadNonce { expected: 1 }));

    let mut future = chain.tx(&alice, pay(&bob, 1));
    future.tx.nonce = 5;
    let future =
        SignedTransaction::sign(future.tx, &alice.policy, None, &[&alice.keys[0]]).unwrap();
    assert_eq!(chain.submit(future), Err(TxError::BadNonce { expected: 1 }));
}

#[test]
fn wrong_chain_low_fee_and_bad_signatures_are_rejected() {
    let alice = Wallet::new(key(1));
    let bob = Wallet::new(key(2));
    let mut chain = Chain::new(&[(&alice, 1_000_000)]);
    let good = chain.tx(&alice, pay(&bob, 1));

    let mut other_chain = good.tx.clone();
    other_chain.genesis_hash = Hash([9; 32]);
    let stx = SignedTransaction::sign(
        other_chain,
        &alice.policy,
        good.reveal.clone(),
        &[&alice.keys[0]],
    )
    .unwrap();
    assert!(matches!(chain.submit(stx), Err(TxError::WrongChain { .. })));

    let mut cheap = good.tx.clone();
    cheap.fee -= 1;
    let stx = SignedTransaction::sign(cheap, &alice.policy, good.reveal.clone(), &[&alice.keys[0]])
        .unwrap();
    assert!(matches!(chain.submit(stx), Err(TxError::FeeTooLow { .. })));

    let mut forged = good.clone();
    forged.signatures = bob_sign(&good.tx);
    assert!(matches!(
        chain.submit(forged),
        Err(TxError::Unauthorized(_))
    ));

    let mut swapped = good.clone();
    let mut other = good.tx.clone();
    other.payload = pay(&bob, 2);
    swapped.signatures = alice
        .policy
        .sign(&other.signing_bytes(), &[&alice.keys[0]])
        .unwrap();
    assert!(matches!(
        chain.submit(swapped),
        Err(TxError::Unauthorized(_))
    ));

    chain.submit(good).unwrap();
    assert_eq!(chain.balance(&bob), 1);
}

fn bob_sign(tx: &Transaction) -> Vec<KeySignature> {
    let bob = key(2);
    single(&bob).sign(&tx.signing_bytes(), &[&bob]).unwrap()
}

#[test]
fn failed_transaction_changes_nothing() {
    let alice = Wallet::new(key(1));
    let bob = Wallet::new(key(2));
    let mut chain = Chain::new(&[(&alice, 1_000_000)]);
    let stx = chain.tx(&alice, pay(&bob, 2_000_000));
    assert!(matches!(
        chain.submit(stx),
        Err(TxError::InsufficientBalance { .. })
    ));
    assert_eq!(chain.balance(&alice), 1_000_000, "fee not charged");
    assert_eq!(chain.nonce(&alice), 0, "nonce not used");
    assert_eq!(
        chain.account(&alice.address).auth,
        None,
        "policy not recorded"
    );
}

#[test]
fn unfunded_sender_and_zero_amount_are_rejected() {
    let alice = Wallet::new(key(1));
    let bob = Wallet::new(key(2));
    let mut chain = Chain::new(&[(&alice, 1_000_000)]);
    let stx = chain.tx(&bob, pay(&alice, 1));
    assert_eq!(chain.submit(stx), Err(TxError::UnknownSender));
    let stx = chain.tx(&alice, pay(&bob, 0));
    assert_eq!(chain.submit(stx), Err(TxError::ZeroAmount));
}

#[test]
fn rotating_keys_and_changing_scheme_keeps_the_address() {
    let mut alice = Wallet::new(key(1));
    let bob = Wallet::new(key(2));
    let mut chain = Chain::new(&[(&alice, 10_000_000)]);

    let cold = slh_key(3);
    let new_policy = single(&cold);
    chain
        .send(
            &mut alice,
            Payload::SetAuth {
                auth: new_policy.clone(),
            },
        )
        .unwrap();
    assert_eq!(chain.account(&alice.address).auth, Some(new_policy.clone()));

    let stx = chain.tx(&alice, pay(&bob, 1));
    assert!(matches!(chain.submit(stx), Err(TxError::Unauthorized(_))));

    alice.policy = new_policy;
    alice.keys = vec![cold];
    chain.send(&mut alice, pay(&bob, 7)).unwrap();
    assert_eq!(chain.balance(&bob), 7);
}

#[test]
fn multisig_account_needs_threshold_signatures() {
    let (k1, k2, k3) = (key(1), key(2), key(3));
    let mut vault = Wallet::multisig(2, vec![k1.clone(), k2.clone(), k3.clone()]);
    let bob = Wallet::new(key(9));
    let mut chain = Chain::new(&[(&vault, 1_000_000)]);

    let one = chain.tx_with(&vault, Role::Owner, &vault.policy, &[&k1], pay(&bob, 5));
    assert!(matches!(chain.submit(one), Err(TxError::Unauthorized(_))));

    let two = chain.tx_with(
        &vault,
        Role::Owner,
        &vault.policy,
        &[&k3, &k1],
        pay(&bob, 5),
    );
    chain.submit(two).unwrap();
    vault.revealed = true;
    assert_eq!(chain.balance(&bob), 5);
}

#[test]
fn invalid_new_policies_are_rejected() {
    let mut alice = Wallet::new(key(1));
    let mut chain = Chain::new(&[(&alice, 1_000_000)]);
    let bad_auth = AuthPolicy {
        threshold: 0,
        keys: vec![key(2).public_key().clone()],
    };
    assert!(matches!(
        chain.send(&mut alice, Payload::SetAuth { auth: bad_auth }),
        Err(TxError::InvalidPolicy(_))
    ));
    let bad_vault = VaultPolicy {
        delay_ms: 0,
        recovery: None,
    };
    assert!(matches!(
        chain.send(
            &mut alice,
            Payload::SetVault {
                vault: Some(bad_vault)
            }
        ),
        Err(TxError::InvalidPolicy(_))
    ));
}

struct VaultSetup {
    chain: Chain,
    vault: Wallet,
    recovery_key: SecretKey,
    recovery: AuthPolicy,
    bob: Wallet,
    relayer: Wallet,
}

fn vault_setup() -> VaultSetup {
    let mut vault = Wallet::new(key(1));
    let recovery_key = slh_key(50);
    let recovery = single(&recovery_key);
    let bob = Wallet::new(key(2));
    let relayer = Wallet::new(key(3));
    let mut chain = Chain::new(&[(&vault, 10_000_000), (&relayer, 10_000_000)]);
    let policy = VaultPolicy {
        delay_ms: DELAY,
        recovery: Some(recovery.clone()),
    };
    chain
        .send(
            &mut vault,
            Payload::SetVault {
                vault: Some(policy.clone()),
            },
        )
        .unwrap();
    assert_eq!(
        chain.account(&vault.address).vault,
        Some(policy),
        "creating a vault is immediate"
    );
    VaultSetup {
        chain,
        vault,
        recovery_key,
        recovery,
        bob,
        relayer,
    }
}

impl VaultSetup {
    fn recovery_tx(&self, payload: Payload) -> SignedTransaction {
        self.chain.tx_with(
            &self.vault,
            Role::Recovery,
            &self.recovery,
            &[&self.recovery_key],
            payload,
        )
    }

    fn pending(&self) -> Vec<PendingAction> {
        self.chain.account(&self.vault.address).pending
    }
}

#[test]
fn vault_transfer_waits_for_the_delay() {
    let mut s = vault_setup();
    let before = s.chain.balance(&s.vault);
    let stx = s.chain.tx(&s.vault, pay(&s.bob, 1_000));
    let fee = fee_of(&stx);
    s.chain.submit(stx).unwrap();

    assert_eq!(s.chain.balance(&s.bob), 0, "nothing moved yet");
    assert_eq!(
        s.chain.balance(&s.vault),
        before - fee,
        "only the fee is charged"
    );
    let pending = s.pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].unlock_at_ms, s.chain.now + DELAY);

    s.chain.advance(DELAY - 2);
    let exec = s.chain.tx(
        &s.relayer,
        Payload::ExecutePending {
            account: s.vault.address,
            id: 0,
        },
    );
    assert!(matches!(
        s.chain.submit(exec),
        Err(TxError::PendingLocked { .. })
    ));

    s.chain.advance(1);
    let mut relayer = s.relayer.clone();
    s.chain
        .send(
            &mut relayer,
            Payload::ExecutePending {
                account: s.vault.address,
                id: 0,
            },
        )
        .unwrap();
    assert_eq!(s.chain.balance(&s.bob), 1_000);
    assert_eq!(s.chain.balance(&s.vault), before - fee - 1_000);
    assert!(s.pending().is_empty());

    let again = s.chain.tx(
        &relayer,
        Payload::ExecutePending {
            account: s.vault.address,
            id: 0,
        },
    );
    assert_eq!(s.chain.submit(again), Err(TxError::PendingNotFound));
}

#[test]
fn owner_can_cancel_a_pending_action() {
    let mut s = vault_setup();
    s.chain.send(&mut s.vault, pay(&s.bob, 1_000)).unwrap();
    s.chain
        .send(&mut s.vault, Payload::CancelPending { id: 0 })
        .unwrap();
    assert!(s.pending().is_empty());
    s.chain.advance(DELAY);
    let exec = s.chain.tx(
        &s.relayer,
        Payload::ExecutePending {
            account: s.vault.address,
            id: 0,
        },
    );
    assert_eq!(s.chain.submit(exec), Err(TxError::PendingNotFound));
    assert_eq!(s.chain.balance(&s.bob), 0);
}

#[test]
fn stolen_owner_key_is_stopped_by_recovery() {
    let mut s = vault_setup();
    let before = s.chain.balance(&s.vault);

    let mut thief = s.vault.clone();
    let thief_dest = Wallet::new(key(66));
    s.chain
        .send(&mut thief, pay(&thief_dest, before / 2))
        .unwrap();
    assert_eq!(s.pending().len(), 1);

    let cancel = s.recovery_tx(Payload::CancelPending { id: 0 });
    s.chain.submit(cancel).unwrap();
    let fresh = key(77);
    let rotate = s.recovery_tx(Payload::SetAuth {
        auth: single(&fresh),
    });
    s.chain.submit(rotate).unwrap();
    assert_eq!(
        s.chain.account(&s.vault.address).auth,
        Some(single(&fresh)),
        "immediate"
    );

    let stx = s.chain.tx(&thief, pay(&thief_dest, 1));
    assert!(matches!(s.chain.submit(stx), Err(TxError::Unauthorized(_))));
    s.chain.advance(DELAY);
    let exec = s.chain.tx(
        &s.relayer,
        Payload::ExecutePending {
            account: s.vault.address,
            id: 0,
        },
    );
    assert_eq!(s.chain.submit(exec), Err(TxError::PendingNotFound));
    assert_eq!(s.chain.balance(&thief_dest), 0);

    let mut owner = Wallet {
        policy: single(&fresh),
        keys: vec![fresh],
        ..s.vault.clone()
    };
    s.chain.send(&mut owner, pay(&s.bob, 10)).unwrap();
    assert_eq!(
        s.pending().len(),
        1,
        "still a vault: the transfer is delayed"
    );
}

#[test]
fn owner_policy_changes_on_a_vault_are_delayed() {
    let mut s = vault_setup();
    let new_key = key(10);
    s.chain
        .send(
            &mut s.vault,
            Payload::SetAuth {
                auth: single(&new_key),
            },
        )
        .unwrap();
    s.chain
        .send(&mut s.vault, Payload::SetVault { vault: None })
        .unwrap();
    assert_eq!(s.pending().len(), 2);
    let account = s.chain.account(&s.vault.address);
    assert_eq!(
        account.auth,
        Some(s.vault.policy.clone()),
        "auth unchanged for now"
    );
    assert!(account.vault.is_some(), "still a vault for now");

    s.chain.advance(DELAY);
    let mut relayer = s.relayer.clone();
    s.chain
        .send(
            &mut relayer,
            Payload::ExecutePending {
                account: s.vault.address,
                id: 1,
            },
        )
        .unwrap();
    s.chain
        .send(
            &mut relayer,
            Payload::ExecutePending {
                account: s.vault.address,
                id: 0,
            },
        )
        .unwrap();
    let account = s.chain.account(&s.vault.address);
    assert_eq!(account.auth, Some(single(&new_key)));
    assert_eq!(account.vault, None);
}

#[test]
fn recovery_powers_are_limited() {
    let s = vault_setup();
    let mut chain = s.chain;
    for payload in [
        pay(&s.bob, 1),
        Payload::SetVault { vault: None },
        Payload::ExecutePending {
            account: s.vault.address,
            id: 0,
        },
    ] {
        let stx = chain.tx_with(
            &s.vault,
            Role::Recovery,
            &s.recovery,
            &[&s.recovery_key],
            payload,
        );
        assert_eq!(chain.submit(stx), Err(TxError::NotAllowedForRecovery));
    }

    let stx = chain.tx_with(
        &s.vault,
        Role::Recovery,
        &s.vault.policy,
        &[&s.vault.keys[0]],
        Payload::CancelPending { id: 0 },
    );
    assert!(matches!(chain.submit(stx), Err(TxError::Unauthorized(_))));
}

#[test]
fn recovery_role_needs_a_vault_with_recovery() {
    let mut alice = Wallet::new(key(1));
    let mut chain = Chain::new(&[(&alice, 1_000_000)]);
    chain
        .send(
            &mut alice,
            Payload::SetVault {
                vault: Some(VaultPolicy {
                    delay_ms: DELAY,
                    recovery: None,
                }),
            },
        )
        .unwrap();
    let r = key(5);
    let stx = chain.tx_with(
        &alice,
        Role::Recovery,
        &single(&r),
        &[&r],
        Payload::CancelPending { id: 0 },
    );
    assert_eq!(chain.submit(stx), Err(TxError::NoRecoveryPolicy));
}

#[test]
fn pending_queue_is_bounded() {
    let mut s = vault_setup();
    for _ in 0..MAX_PENDING_ACTIONS {
        s.chain.send(&mut s.vault, pay(&s.bob, 1)).unwrap();
    }
    assert_eq!(
        s.chain.send(&mut s.vault, pay(&s.bob, 1)),
        Err(TxError::TooManyPending)
    );
    s.chain
        .send(&mut s.vault, Payload::CancelPending { id: 3 })
        .unwrap();
    s.chain.send(&mut s.vault, pay(&s.bob, 1)).unwrap();
    assert_eq!(s.pending().last().unwrap().id, MAX_PENDING_ACTIONS as u64);
}

#[test]
fn delayed_transfer_rechecks_balance_on_execution() {
    let mut s = vault_setup();
    let balance = s.chain.balance(&s.vault);
    s.chain
        .send(&mut s.vault, pay(&s.bob, balance / 2))
        .unwrap();
    s.chain
        .send(&mut s.vault, pay(&s.bob, balance / 2))
        .unwrap();
    s.chain.advance(DELAY);
    let mut relayer = s.relayer.clone();
    s.chain
        .send(
            &mut relayer,
            Payload::ExecutePending {
                account: s.vault.address,
                id: 0,
            },
        )
        .unwrap();
    let exec = s.chain.tx(
        &relayer,
        Payload::ExecutePending {
            account: s.vault.address,
            id: 1,
        },
    );
    assert!(matches!(
        s.chain.submit(exec),
        Err(TxError::InsufficientBalance { .. })
    ));
    s.chain
        .send(&mut s.vault, Payload::CancelPending { id: 1 })
        .unwrap();
}

#[test]
fn queuing_more_than_the_balance_is_refused() {
    let mut s = vault_setup();
    let balance = s.chain.balance(&s.vault);
    assert!(matches!(
        s.chain.send(&mut s.vault, pay(&s.bob, balance)),
        Err(TxError::InsufficientBalance { .. })
    ));
}

#[test]
fn block_with_a_failing_transaction_is_invalid() {
    let alice = Wallet::new(key(1));
    let bob = Wallet::new(key(2));
    let mut chain = Chain::new(&[(&alice, 1_000_000)]);
    let carol = Wallet::new(key(3));
    let ok = chain.tx(&alice, pay(&bob, 1));
    let bad = chain.tx(&carol, pay(&alice, 1));

    match chain.block(&[ok.clone(), bad]) {
        Err(BlockError::Transaction {
            index: 1,
            error: TxError::UnknownSender,
            ..
        }) => {}
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(chain.balance(&bob), 0, "the whole block was rejected");

    let mut alice2 = alice.clone();
    alice2.revealed = true;
    let mut second = chain.tx(&alice2, pay(&bob, 2));
    second.tx.nonce = 1;
    let second =
        SignedTransaction::sign(second.tx, &alice.policy, None, &[&alice.keys[0]]).unwrap();
    chain.block(&[ok, second]).unwrap();
    assert_eq!(chain.balance(&bob), 3);
    assert_eq!(chain.nonce(&alice), 2);
}

#[test]
fn block_size_is_bounded() {
    let alice = Wallet::new(key(1));
    let bob = Wallet::new(key(2));
    let mut chain = Chain::new(&[(&alice, 1_000_000)]);
    let tx = chain.tx(&alice, pay(&bob, 1));
    let txs = vec![tx; params().max_block_transactions as usize + 1];
    assert_eq!(chain.block(&txs), Err(BlockError::TooManyTransactions));
}

fn validator(i: u8) -> SecretKey {
    key(200 + i)
}

fn council(keys: Vec<SecretKey>, chain: &Chain) -> Wallet {
    let policy = chain
        .account(&governance_address())
        .auth
        .expect("set at genesis");
    Wallet {
        address: governance_address(),
        policy,
        keys,
        revealed: true,
    }
}

fn seat(key: &SecretKey) -> Validator {
    Validator::self_paid(key.public_key().clone())
}

fn set_validators(keys: &[SecretKey]) -> Payload {
    Payload::SetValidators {
        validators: keys.iter().map(seat).collect(),
    }
}

#[test]
fn two_thirds_of_validators_change_the_set() {
    let validators: Vec<_> = (0..4).map(validator).collect();
    let mut chain = Chain::with_validators(&[], validators.clone(), 10_000_000);
    let before = qubits_execution::read_validators(&chain.state).unwrap();
    assert_eq!((before.epoch, before.validators.len()), (0, 4));

    let gov = council(validators.clone(), &chain);
    let two = chain.tx_with(
        &gov,
        Role::Owner,
        &gov.policy,
        &[&validators[0], &validators[1]],
        set_validators(&validators[..3]),
    );
    assert!(matches!(chain.submit(two), Err(TxError::Unauthorized(_))));

    let next = vec![
        validators[0].clone(),
        validators[1].clone(),
        validators[2].clone(),
        validator(9),
    ];
    let three = chain.tx_with(
        &gov,
        Role::Owner,
        &gov.policy,
        &[&validators[3], &validators[1], &validators[2]],
        set_validators(&next),
    );
    chain.submit(three).unwrap();
    let after = qubits_execution::read_validators(&chain.state).unwrap();
    assert_eq!(after.epoch, 1);
    assert_eq!(
        after.keys(),
        next.iter()
            .map(|k| k.public_key().clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        chain.account(&governance_address()).auth,
        Some(after.council())
    );

    let gov = council(next.clone(), &chain);
    let mut with_removed = chain.tx_with(
        &gov,
        Role::Owner,
        &gov.policy,
        &[&validator(9), &validators[0], &validators[2]],
        set_validators(&next),
    );
    let forged = validators[3]
        .sign(
            qubits_crypto::Domain::Transaction,
            &with_removed.tx.signing_bytes(),
        )
        .unwrap();
    with_removed.signatures[2] = KeySignature {
        index: 3,
        signature: forged,
    };
    with_removed.signatures.sort_by_key(|s| s.index);
    assert!(matches!(
        chain.submit(with_removed),
        Err(TxError::Unauthorized(_))
    ));
    let again = chain.tx_with(
        &gov,
        Role::Owner,
        &gov.policy,
        &[&validator(9), &validators[0], &validators[2]],
        set_validators(&next[..3]),
    );
    chain.submit(again).unwrap();
    assert_eq!(
        qubits_execution::read_validators(&chain.state)
            .unwrap()
            .epoch,
        2
    );
}

#[test]
fn only_governance_changes_validators_and_it_does_nothing_else() {
    let validators: Vec<_> = (0..4).map(validator).collect();
    let mut alice = Wallet::new(key(1));
    let mut chain = Chain::with_validators(&[(&alice, 1_000_000)], validators.clone(), 10_000_000);
    assert_eq!(
        chain.send(&mut alice, set_validators(&validators[..1])),
        Err(TxError::NotGovernance)
    );

    let gov = council(validators.clone(), &chain);
    let signers: Vec<&SecretKey> = validators.iter().take(3).collect();
    let transfer = chain.tx_with(&gov, Role::Owner, &gov.policy, &signers, pay(&alice, 1));
    assert_eq!(
        chain.submit(transfer),
        Err(TxError::NotAllowedForGovernance)
    );
}

#[test]
fn invalid_validator_sets_are_refused() {
    let validators: Vec<_> = (0..4).map(validator).collect();
    let mut chain = Chain::with_validators(&[], validators.clone(), 100_000_000);
    let gov = council(validators.clone(), &chain);
    let signers: Vec<&SecretKey> = validators.iter().take(3).collect();
    let too_many: Vec<Validator> = (0..51u8).map(|i| seat(&key(i))).collect();
    let same_payout = Validator {
        payout: seat(&validators[0]).payout,
        ..seat(&validators[1])
    };
    let bad_sets = [
        vec![],
        vec![seat(&validators[0]), seat(&validators[0])],
        vec![seat(&validators[0]), seat(&slh_key(5))],
        vec![seat(&validators[0]), same_payout],
        too_many,
    ];
    for set in bad_sets {
        let stx = chain.tx_with(
            &gov,
            Role::Owner,
            &gov.policy,
            &signers,
            Payload::SetValidators { validators: set },
        );
        assert!(matches!(
            chain.submit(stx),
            Err(TxError::InvalidPolicy(_) | TxError::TooLarge)
        ));
    }
}

#[test]
fn governance_pays_fees_like_any_account() {
    let validators: Vec<_> = (0..4).map(validator).collect();
    let mut chain = Chain::with_validators(&[], validators.clone(), 0);
    let gov = council(validators.clone(), &chain);
    let signers: Vec<&SecretKey> = validators.iter().take(3).collect();
    let stx = chain.tx_with(
        &gov,
        Role::Owner,
        &gov.policy,
        &signers,
        set_validators(&validators[..3]),
    );
    assert!(matches!(
        chain.submit(stx),
        Err(TxError::InsufficientBalance { .. })
    ));
}

#[test]
fn genesis_requires_ml_dsa_validators() {
    let mut genesis = Genesis {
        chain_id: CHAIN.into(),
        timestamp_ms: 1,
        params: params(),
        validators: vec![seat(&slh_key(1))],
        accounts: vec![],
    };
    assert!(genesis.validate().is_err());
    genesis.validators = vec![seat(&validator(0))];
    assert!(genesis.validate().is_ok());
}

#[test]
fn a_signed_transaction_expires() {
    let alice = Wallet::new(key(1));
    let bob = Wallet::new(key(2));
    let mut chain = Chain::new(&[(&alice, 1_000_000)]);
    let mut stale = chain.tx(&alice, pay(&bob, 1));
    stale.tx.valid_until_ms = chain.env().timestamp_ms - 1;
    let stale =
        SignedTransaction::sign(stale.tx, &alice.policy, stale.reveal, &[&alice.keys[0]]).unwrap();
    assert!(matches!(
        chain.block(std::slice::from_ref(&stale)),
        Err(BlockError::Transaction {
            error: TxError::Expired { .. },
            ..
        })
    ));

    let mut last_moment = stale;
    last_moment.tx.valid_until_ms = chain.env().timestamp_ms;
    let last_moment = SignedTransaction::sign(
        last_moment.tx,
        &alice.policy,
        last_moment.reveal,
        &[&alice.keys[0]],
    )
    .unwrap();
    chain.block(&[last_moment]).unwrap();
}

#[test]
fn a_stolen_owner_key_cannot_burn_a_vault_through_fees() {
    let mut vault = Wallet::new(key(1));
    let bob = Wallet::new(key(2));
    let balance = 1_000_000_000;
    let mut chain = Chain::new(&[(&vault, balance)]);
    let setup = chain.tx(
        &vault,
        Payload::SetVault {
            vault: Some(VaultPolicy {
                delay_ms: 60_000,
                recovery: Some(vault.policy.clone()),
            }),
        },
    );
    chain.block(&[setup]).unwrap();
    vault.revealed = true;

    let honest = chain.tx(&vault, pay(&bob, 1));
    let required = honest.tx.fee;
    let mut burning = honest.tx.clone();
    burning.fee = chain.account(&vault.address).balance(AssetId::NATIVE);
    let burning = SignedTransaction::sign(burning, &vault.policy, None, &[&vault.keys[0]]).unwrap();
    assert!(matches!(
        chain.block(&[burning]),
        Err(BlockError::Transaction {
            error: TxError::FeeTooHigh { .. },
            ..
        })
    ));

    let mut highest = honest.tx.clone();
    highest.fee = required * qubits_types::limits::MAX_FEE_MULTIPLE;
    let highest = SignedTransaction::sign(highest, &vault.policy, None, &[&vault.keys[0]]).unwrap();
    chain.block(&[highest]).unwrap();
    let left = chain.account(&vault.address).balance(AssetId::NATIVE);
    assert!(left > balance - 100 * required, "burned too much: {left}");
}

#[test]
fn cheap_checks_come_before_signatures() {
    let alice = Wallet::new(key(1));
    let bob = Wallet::new(key(2));
    let chain = Chain::new(&[(&alice, 1_000_000)]);
    let unsigned = |nonce_delta: u64, fee: Option<Amount>| {
        let good = chain.tx(&alice, pay(&bob, 1));
        let mut bad = good.clone();
        bad.tx.nonce += nonce_delta;
        bad.tx.fee = fee.unwrap_or(bad.tx.fee);
        bad
    };

    let wrong_nonce = unsigned(5, None);
    let mut executor = qubits_execution::Executor::new(&chain.state, chain.env());
    assert!(matches!(
        executor.apply(&wrong_nonce),
        Err(TxError::BadNonce { expected: 0 })
    ));

    let poor = Wallet::new(key(3));
    let chain = Chain::new(&[(&poor, 1)]);
    let tx = chain.tx(&poor, pay(&bob, 1));
    let mut executor = qubits_execution::Executor::new(&chain.state, chain.env());
    assert!(matches!(
        executor.apply(&tx),
        Err(TxError::InsufficientBalance { .. })
    ));
}

#[test]
fn signatures_are_skipped_only_when_asked() {
    let alice = Wallet::new(key(1));
    let bob = Wallet::new(key(2));
    let chain = Chain::new(&[(&alice, 1_000_000)]);
    let mut tampered = chain.tx(&alice, pay(&bob, 1));
    tampered.tx.valid_until_ms -= 1;
    let mut strict = qubits_execution::Executor::new(&chain.state, chain.env());
    assert!(matches!(
        strict.apply(&tampered),
        Err(TxError::Unauthorized(_))
    ));
    let mut trusting = qubits_execution::Executor::new(&chain.state, chain.env());
    trusting.apply_verified(&tampered).unwrap();
}

#[test]
fn recovery_replacing_the_owner_clears_the_queue() {
    let mut s = vault_setup();
    let mut thief = s.vault.clone();
    let thief_dest = Wallet::new(key(66));
    s.chain.send(&mut thief, pay(&thief_dest, 1_000)).unwrap();
    s.chain
        .send(
            &mut thief,
            Payload::SetAuth {
                auth: single(&key(67)),
            },
        )
        .unwrap();
    s.chain
        .send(&mut thief, Payload::SetVault { vault: None })
        .unwrap();
    assert_eq!(s.pending().len(), 3);

    let fresh = key(77);
    let rotate = s.recovery_tx(Payload::SetAuth {
        auth: single(&fresh),
    });
    s.chain.submit(rotate).unwrap();
    assert!(s.pending().is_empty());

    s.chain.advance(DELAY);
    for id in 0..3 {
        let exec = s.chain.tx(
            &s.relayer,
            Payload::ExecutePending {
                account: s.vault.address,
                id,
            },
        );
        assert_eq!(s.chain.submit(exec), Err(TxError::PendingNotFound));
    }
    let account = s.chain.account(&s.vault.address);
    assert_eq!(account.auth, Some(single(&fresh)));
    assert!(account.vault.is_some());
    assert_eq!(s.chain.balance(&thief_dest), 0);
}

#[test]
fn a_vault_with_recovery_keeps_its_recovery_fee() {
    let reserve = recovery_reserve(&params());
    let recovery_key = slh_key(50);
    let policy = VaultPolicy {
        delay_ms: DELAY,
        recovery: Some(single(&recovery_key)),
    };
    let set_vault = Payload::SetVault {
        vault: Some(policy.clone()),
    };

    let poor = Wallet::new(key(4));
    let mut chain = Chain::new(&[(&poor, reserve)]);
    let stx = chain.tx(&poor, set_vault.clone());
    assert_eq!(chain.submit(stx), Err(TxError::RecoveryReserve { reserve }));

    let mut no_recovery = Wallet::new(key(5));
    let mut chain = Chain::new(&[(&no_recovery, 100_000)]);
    let only_delay = VaultPolicy {
        delay_ms: DELAY,
        recovery: None,
    };
    chain
        .send(
            &mut no_recovery,
            Payload::SetVault {
                vault: Some(only_delay),
            },
        )
        .unwrap();

    let mut vault = Wallet::new(key(1));
    let bob = Wallet::new(key(2));
    let mut relayer = Wallet::new(key(3));
    let mut chain = Chain::new(&[(&vault, reserve + 1_000_000), (&relayer, 10_000_000)]);
    chain.send(&mut vault, set_vault).unwrap();

    let probe = chain.tx(&vault, pay(&bob, 0));
    let most = chain.balance(&vault) - fee_of(&probe) - reserve;
    let stx = chain.tx(&vault, pay(&bob, most + 1));
    assert_eq!(chain.submit(stx), Err(TxError::RecoveryReserve { reserve }));
    chain.send(&mut vault, pay(&bob, most)).unwrap();

    chain.advance(DELAY);
    chain
        .send(
            &mut relayer,
            Payload::ExecutePending {
                account: vault.address,
                id: 0,
            },
        )
        .unwrap();
    assert_eq!(chain.balance(&bob), most);
    assert_eq!(chain.balance(&vault), reserve);

    let stx = chain.tx(&vault, pay(&bob, 1));
    assert_eq!(chain.submit(stx), Err(TxError::RecoveryReserve { reserve }));

    let fresh = key(77);
    let rotate = chain.tx_with(
        &vault,
        Role::Recovery,
        &single(&recovery_key),
        &[&recovery_key],
        Payload::SetAuth {
            auth: single(&fresh),
        },
    );
    chain.submit(rotate).unwrap();
    assert_eq!(chain.account(&vault.address).auth, Some(single(&fresh)));
    assert!(chain.balance(&vault) < reserve);
}

#[test]
fn the_validator_set_changes_once_a_block() {
    let validators: Vec<_> = (0..4).map(validator).collect();
    let mut chain = Chain::with_validators(&[], validators.clone(), 10_000_000);
    let next: Vec<_> = (5..9).map(validator).collect();
    let gov = council(validators.clone(), &chain);
    let first = chain.tx_with(
        &gov,
        Role::Owner,
        &gov.policy,
        &[&validators[0], &validators[1], &validators[2]],
        set_validators(&next),
    );
    let installed = ValidatorSet {
        epoch: 1,
        validators: next.iter().map(seat).collect(),
    }
    .council();
    let mut tx = first.tx.clone();
    tx.nonce += 1;
    tx.payload = set_validators(&validators);
    let second =
        SignedTransaction::sign(tx, &installed, None, &[&next[0], &next[1], &next[2]]).unwrap();

    let mut executor = Executor::new(&chain.state, chain.env());
    executor.apply(&first).unwrap();
    assert_eq!(executor.apply(&second), Err(TxError::ValidatorsChanging));
    assert!(matches!(
        chain.block(&[first.clone(), second.clone()]),
        Err(BlockError::Transaction {
            index: 1,
            error: TxError::ValidatorsChanging,
            ..
        })
    ));

    chain.block(&[first]).unwrap();
    chain.submit(second).unwrap();
    let after = qubits_execution::read_validators(&chain.state).unwrap();
    assert_eq!(after.epoch, 2);
}
