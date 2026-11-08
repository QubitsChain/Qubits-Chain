use std::str::FromStr;

use qubits_consensus::{Block, Message, Proposal, QuorumCert, VoteKind};
use qubits_crypto::keystore::EncryptedKey;
use qubits_crypto::{Domain, PublicKey, SchemeId, SecretKey, Signature};
use qubits_node::ChainBlock;
use qubits_node::network::NetMessage;
use qubits_types::*;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        let len = (self.next() as usize) % (max_len + 1);
        (0..len).map(|_| self.next() as u8).collect()
    }

    fn mutate(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = input.to_vec();
        for _ in 0..1 + self.next() % 4 {
            if out.is_empty() {
                out.push(self.next() as u8);
                continue;
            }
            let pos = (self.next() as usize) % out.len();
            match self.next() % 4 {
                0 => out[pos] ^= 1 << (self.next() % 8),
                1 => out[pos] = self.next() as u8,
                2 => out.truncate(pos),
                _ => out.insert(pos, self.next() as u8),
            }
        }
        out
    }
}

fn key(seed: u8) -> SecretKey {
    SecretKey::from_seed(SchemeId::MlDsa65, &[seed; 32]).unwrap()
}

fn sample_tx() -> (SignedTransaction, AuthPolicy) {
    let sk = key(1);
    let policy = AuthPolicy::single(sk.public_key().clone());
    let tx = Transaction {
        genesis_hash: Hash([5; 32]),
        sender: policy.address(),
        nonce: 3,
        fee: 9_000,
        valid_until_ms: u64::MAX,
        role: Role::Owner,
        payload: Payload::SetVault {
            vault: Some(VaultPolicy {
                delay_ms: 60_000,
                recovery: Some(policy.clone()),
            }),
        },
    };
    (
        SignedTransaction::sign(tx, &policy, Some(policy.clone()), &[&sk]).unwrap(),
        policy,
    )
}

fn sample_block() -> ChainBlock {
    let (tx, _) = sample_tx();
    Block {
        round: 7,
        height: 5,
        parent: Hash([1; 32]),
        proposer: 1,
        voters: vec![0, 1],
        payload: BlockPayload {
            timestamp_ms: 1,
            tx_root: tx_root(std::slice::from_ref(&tx)),
            transactions: vec![tx],
            state_root: Hash([2; 32]),
            receipt_root: Hash([3; 32]),
        },
    }
}

fn sample_qc() -> QuorumCert {
    QuorumCert {
        block: Hash([1; 32]),
        round: 6,
        kind: VoteKind::Optimistic,
        votes: vec![(0, key(2).sign(Domain::Consensus, b"x").unwrap())],
    }
}

#[test]
fn random_bytes_never_panic_any_decoder() {
    let mut rng = Rng(0x5eed);
    for _ in 0..3_000 {
        let bytes = rng.bytes(600);
        let _ = SignedTransaction::decode(&bytes);
        let _ = NetMessage::decode(&bytes);
        let _ = borsh::from_slice::<ChainBlock>(&bytes);
        let _ = borsh::from_slice::<Account>(&bytes);
        let _ = PublicKey::from_tagged_bytes(&bytes);
        let _ = Signature::from_tagged_bytes(&bytes);
        let text = String::from_utf8_lossy(&bytes);
        let _ = Address::from_str(&text);
        let _ = Hash::from_str(&text);
        let _ = EncryptedKey::from_json(&text);
        let _ = serde_json::from_str::<Genesis>(&text);
    }
}

#[test]
fn mutated_transactions_decode_safely_and_never_verify() {
    let (tx, policy) = sample_tx();
    let encoded = tx.encode();
    let mut rng = Rng(0xbad);
    let mut decoded_changed = 0;
    for _ in 0..3_000 {
        let mutated = rng.mutate(&encoded);
        if let Ok(other) = SignedTransaction::decode(&mutated)
            && other != tx
        {
            decoded_changed += 1;
            if other.tx != tx.tx {
                assert!(
                    policy
                        .check(&other.tx.signing_bytes(), &other.signatures)
                        .is_err(),
                    "a modified transaction still verifies"
                );
            }
        }
    }
    assert!(
        decoded_changed > 0,
        "the mutations should sometimes still decode"
    );
}

#[test]
fn mutated_network_messages_and_blocks_decode_safely() {
    let stored = sample_block();
    let proposal = Proposal {
        block: stored.clone(),
        justify: Some(sample_qc()),
        tc: None,
        signature: key(3).sign(Domain::Consensus, b"p").unwrap(),
    };
    let messages = [
        NetMessage::Consensus {
            epoch: 0,
            message: Message::Proposal(proposal),
        },
        NetMessage::Consensus {
            epoch: 3,
            message: Message::BlockRequest(Hash([4; 32])),
        },
        NetMessage::Transaction(sample_tx().0),
    ];
    let mut rng = Rng(0xfeed);
    for msg in &messages {
        let encoded = msg.encode();
        assert_eq!(NetMessage::decode(&encoded).as_ref(), Some(msg));
        for _ in 0..1_000 {
            let _ = NetMessage::decode(&rng.mutate(&encoded));
        }
    }
    let encoded = borsh::to_vec(&stored).unwrap();
    for _ in 0..1_000 {
        let _ = borsh::from_slice::<ChainBlock>(&rng.mutate(&encoded));
    }
}

#[test]
fn oversized_inputs_are_refused_before_decoding() {
    let huge = vec![0u8; qubits_node::network::MAX_MESSAGE_BYTES + 1];
    assert!(NetMessage::decode(&huge).is_none());
    let too_big_tx = vec![0u8; limits::MAX_TX_BYTES + 1];
    assert!(matches!(
        SignedTransaction::decode(&too_big_tx),
        Err(Error::TooLarge { .. })
    ));
    let mut lying = vec![0xff, 0xff, 0xff, 0x7f];
    lying.extend_from_slice(&[0; 16]);
    let _ = SignedTransaction::decode(&lying);
    let _ = NetMessage::decode(&lying);
}
