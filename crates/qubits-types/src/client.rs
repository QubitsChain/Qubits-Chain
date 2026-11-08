use core::fmt;

use qubits_crypto::SecretKey;

use crate::rpc::{AccountResponse, StatusResponse};
use crate::{Amount, AuthPolicy, Payload, Role, SignedTransaction, Transaction};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    NoAccount,
    NotController,
    NoRecoveryPolicy,
    KeyNotInPolicy(Role),
    NeedsMoreSigners,
    Signing(String),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::NoAccount => {
                write!(
                    f,
                    "this account does not exist yet; it needs funds to pay fees"
                )
            }
            BuildError::NotController => write!(f, "this key does not control the account"),
            BuildError::NoRecoveryPolicy => write!(f, "the account has no recovery policy"),
            BuildError::KeyNotInPolicy(role) => {
                let name = match role {
                    Role::Owner => "owner",
                    Role::Recovery => "recovery",
                };
                write!(f, "this key is not part of the account's {name} policy")
            }
            BuildError::NeedsMoreSigners => {
                write!(
                    f,
                    "the policy needs several signatures; multisig signing is not supported here yet"
                )
            }
            BuildError::Signing(e) => write!(f, "signing failed: {e}"),
        }
    }
}

impl std::error::Error for BuildError {}

/// The lowest fee a transaction of this size and gas limit may pay.
pub fn required_fee(min_fee_per_byte: u64, size: usize, gas_limit: u64) -> Amount {
    let weight = size as u128 + u128::from(gas_limit.div_ceil(crate::limits::GAS_PER_BYTE));
    u128::from(min_fee_per_byte) * weight
}

pub fn build_transaction(
    status: &StatusResponse,
    account: &AccountResponse,
    key: &SecretKey,
    role: Role,
    payload: Payload,
    valid_until_ms: u64,
) -> Result<SignedTransaction, BuildError> {
    if !account.exists {
        return Err(BuildError::NoAccount);
    }
    let (policy, reveal) = match role {
        Role::Owner => match &account.auth {
            Some(policy) => (policy.clone(), None),
            None => {
                let policy = AuthPolicy::single(key.public_key().clone());
                if policy.address() != account.address {
                    return Err(BuildError::NotController);
                }
                (policy.clone(), Some(policy))
            }
        },
        Role::Recovery => {
            let recovery = account.vault.as_ref().and_then(|v| v.recovery.clone());
            (recovery.ok_or(BuildError::NoRecoveryPolicy)?, None)
        }
    };
    if !policy.keys.contains(key.public_key()) {
        return Err(BuildError::KeyNotInPolicy(role));
    }
    if policy.threshold > 1 {
        return Err(BuildError::NeedsMoreSigners);
    }

    let mut tx = Transaction {
        genesis_hash: status.genesis_hash,
        sender: account.address,
        nonce: account.nonce,
        fee: 0,
        valid_until_ms,
        role,
        payload,
    };
    // fixed-width fee and signature: a placeholder gives the final size
    let scheme = key.public_key().scheme();
    let placeholder = crate::KeySignature {
        index: 0,
        signature: qubits_crypto::Signature::from_raw(scheme, &vec![0; scheme.signature_len()])
            .expect("length matches the scheme"),
    };
    let draft = SignedTransaction {
        tx: tx.clone(),
        reveal: reveal.clone(),
        signatures: vec![placeholder],
    };
    tx.fee = required_fee(
        status.min_fee_per_byte,
        draft.encode().len(),
        tx.payload.gas_limit(),
    );
    SignedTransaction::sign(tx, &policy, reveal, &[key])
        .map_err(|e| BuildError::Signing(e.to_string()))
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PartialTransaction {
    pub tx: Transaction,
    pub policy: AuthPolicy,
    pub reveal: Option<AuthPolicy>,
    pub signatures: Vec<crate::KeySignature>,
}

impl PartialTransaction {
    pub fn new(
        status: &StatusResponse,
        account: &AccountResponse,
        role: Role,
        payload: Payload,
        initial_policy: Option<AuthPolicy>,
        valid_until_ms: u64,
    ) -> Result<Self, BuildError> {
        if !account.exists {
            return Err(BuildError::NoAccount);
        }
        let (policy, reveal) = match role {
            Role::Owner => match (&account.auth, initial_policy) {
                (Some(policy), _) => (policy.clone(), None),
                (None, Some(policy)) if policy.address() == account.address => {
                    (policy.clone(), Some(policy))
                }
                (None, _) => return Err(BuildError::NotController),
            },
            Role::Recovery => {
                let recovery = account.vault.as_ref().and_then(|v| v.recovery.clone());
                (recovery.ok_or(BuildError::NoRecoveryPolicy)?, None)
            }
        };
        let mut tx = Transaction {
            genesis_hash: status.genesis_hash,
            sender: account.address,
            nonce: account.nonce,
            fee: 0,
            valid_until_ms,
            role,
            payload,
        };
        let mut sizes: Vec<(usize, &qubits_crypto::PublicKey)> = policy
            .keys
            .iter()
            .map(|k| (k.scheme().signature_len(), k))
            .collect();
        sizes.sort_by_key(|(len, _)| std::cmp::Reverse(*len));
        let dummies = sizes
            .iter()
            .take(usize::from(policy.threshold))
            .enumerate()
            .map(|(i, (len, key))| crate::KeySignature {
                index: i as u8,
                signature: qubits_crypto::Signature::from_raw(key.scheme(), &vec![0; *len])
                    .expect("length matches the scheme"),
            })
            .collect();
        let draft = SignedTransaction {
            tx: tx.clone(),
            reveal: reveal.clone(),
            signatures: dummies,
        };
        tx.fee = required_fee(
            status.min_fee_per_byte,
            draft.encode().len(),
            tx.payload.gas_limit(),
        );
        Ok(PartialTransaction {
            tx,
            policy,
            reveal,
            signatures: Vec::new(),
        })
    }

    pub fn sign(&mut self, key: &SecretKey) -> Result<(), BuildError> {
        let index = self
            .policy
            .keys
            .iter()
            .position(|k| k == key.public_key())
            .ok_or(BuildError::KeyNotInPolicy(self.tx.role))? as u8;
        if self.signatures.iter().any(|s| s.index == index) {
            return Err(BuildError::Signing("this key already signed".into()));
        }
        let signature = key
            .sign(qubits_crypto::Domain::Transaction, &self.tx.signing_bytes())
            .map_err(|e| BuildError::Signing(e.to_string()))?;
        self.signatures
            .push(crate::KeySignature { index, signature });
        self.signatures.sort_by_key(|s| s.index);
        Ok(())
    }

    pub fn missing(&self) -> usize {
        usize::from(self.policy.threshold).saturating_sub(self.signatures.len())
    }

    pub fn finish(&self) -> Result<SignedTransaction, BuildError> {
        if self.missing() > 0 {
            return Err(BuildError::Signing(format!(
                "needs {} signatures, has {}",
                self.policy.threshold,
                self.signatures.len()
            )));
        }
        self.policy
            .check(&self.tx.signing_bytes(), &self.signatures)
            .map_err(|e| BuildError::Signing(e.to_string()))?;
        Ok(SignedTransaction {
            tx: self.tx.clone(),
            reveal: self.reveal.clone(),
            signatures: self.signatures.clone(),
        })
    }
}
