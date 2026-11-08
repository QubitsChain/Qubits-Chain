use qubits_state::Store;
use qubits_types::{Address, Payload, Receipt, SignedTransaction};

use crate::ChainBlock;

/// The version of the rule in `addresses`. A node whose index was built with another one
/// rebuilds it when it opens, so change this whenever the rule changes.
pub const VERSION: u32 = 1;

/// What a transaction is listed under at `/v1/accounts/{address}/transactions`: its sender, the
/// addresses its payload names, and from its receipt the contract a deployment made, every
/// contract that emitted an event, and each whole 32-byte word of an event's data, which is
/// where the standard contracts put the addresses an event is about. A word that isn't an
/// address costs one entry nobody looks up.
pub fn addresses(tx: &SignedTransaction, receipt: Option<&Receipt>) -> Vec<Address> {
    let mut named = vec![tx.tx.sender];
    match &tx.tx.payload {
        Payload::Transfer { to, .. } => named.push(*to),
        Payload::ExecutePending { account, .. } => named.push(*account),
        Payload::SetValidators { validators } => named.extend(validators.iter().map(|v| v.payout)),
        Payload::Call { contract, .. } => named.push(*contract),
        Payload::ClaimRewards { payout } => named.push(*payout),
        Payload::SetAuth { .. }
        | Payload::SetVault { .. }
        | Payload::CancelPending { .. }
        | Payload::Deploy { .. } => {}
    }
    if let Some(receipt) = receipt {
        named.extend(receipt.contract);
        for event in &receipt.events {
            named.push(event.contract);
            named.extend(
                event
                    .data
                    .chunks_exact(32)
                    .map(|word| Address(word.try_into().expect("chunks of 32"))),
            );
        }
    }
    named.sort();
    named.dedup();
    named
}

/// The addresses of every transaction of a block, from what it says and the receipts the store
/// kept for it.
pub fn of_block(store: &Store, block: &ChainBlock) -> Result<Vec<Vec<Address>>, String> {
    block
        .payload
        .transactions
        .iter()
        .map(|tx| {
            let receipt = match store.receipt(&tx.id()).map_err(|e| e.to_string())? {
                Some(bytes) => {
                    Some(borsh::from_slice::<Receipt>(&bytes).map_err(|e| e.to_string())?)
                }
                None => None,
            };
            Ok(addresses(tx, receipt.as_ref()))
        })
        .collect()
}

/// The addresses of a block's transactions from what they say alone: blocks put back from era
/// files or a snapshot come without receipts.
pub fn of_payload(block: &ChainBlock) -> Vec<Vec<Address>> {
    block
        .payload
        .transactions
        .iter()
        .map(|tx| addresses(tx, None))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use qubits_crypto::{SchemeId, SecretKey};
    use qubits_types::{AssetId, AuthPolicy, Event, Hash, Role, Transaction};

    fn sent(payload: Payload) -> SignedTransaction {
        let sk = SecretKey::from_seed(SchemeId::MlDsa65, &[1; 32]).unwrap();
        let policy = AuthPolicy::single(sk.public_key().clone());
        let tx = Transaction {
            genesis_hash: Hash::ZERO,
            sender: policy.address(),
            nonce: 0,
            fee: 0,
            valid_until_ms: 0,
            role: Role::Owner,
            payload,
        };
        SignedTransaction::sign(tx, &policy, None, &[&sk]).unwrap()
    }

    #[test]
    fn a_transaction_is_listed_under_what_it_names() {
        let (bob, token, carol) = (Address([2; 32]), Address([3; 32]), Address([4; 32]));
        let transfer = sent(Payload::Transfer {
            to: bob,
            asset: AssetId::NATIVE,
            amount: 1,
        });
        let sender = transfer.tx.sender;
        let mut expected = vec![sender, bob];
        expected.sort();
        assert_eq!(addresses(&transfer, None), expected);

        let to_self = sent(Payload::Transfer {
            to: sender,
            asset: AssetId::NATIVE,
            amount: 1,
        });
        assert_eq!(addresses(&to_self, None), [sender], "once");

        // a token transfer: the contract is called, and its event names both sides
        let call = sent(Payload::Call {
            contract: token,
            function: "transfer".into(),
            args: Vec::new(),
            amount: 0,
            gas_limit: 1,
        });
        let mut data = [sender.0, carol.0].concat();
        data.extend_from_slice(&5u128.to_le_bytes());
        let receipt = Receipt {
            events: vec![Event {
                contract: token,
                topic: b"transfer".to_vec(),
                data,
            }],
            ..Receipt::default()
        };
        let mut expected = vec![sender, token, carol];
        expected.sort();
        assert_eq!(addresses(&call, Some(&receipt)), expected);

        let deploy = sent(Payload::Deploy {
            code: Vec::new(),
            args: Vec::new(),
            gas_limit: 1,
        });
        let made = Receipt {
            contract: Some(token),
            ..Receipt::default()
        };
        let mut expected = vec![sender, token];
        expected.sort();
        assert_eq!(addresses(&deploy, Some(&made)), expected);
    }
}
