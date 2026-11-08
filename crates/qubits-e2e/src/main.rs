//! Helpers for `e2e.py`: signs load and hostile transactions, and runs a validator gone bad.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use qubits_consensus::shards::Shard;
use qubits_consensus::{Block, Message, Proposal, QuorumCert, Round, Timeout, Vote, VoteKind};
use qubits_crypto::keystore::EncryptedKey;
use qubits_crypto::{PublicKey, SchemeId, SecretKey};
use qubits_node::Node;
use qubits_node::network::{NetMessage, Transport};
use qubits_node::p2p::{self, P2pConfig};
use qubits_types::limits::MAX_FEE_MULTIPLE;
use qubits_types::*;
use rand_core::{OsRng, RngCore};

fn key(i: usize) -> SecretKey {
    let mut seed = [7u8; 32];
    seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
    SecretKey::from_seed(SchemeId::MlDsa65, &seed).unwrap()
}

fn policy(sk: &SecretKey) -> AuthPolicy {
    AuthPolicy::single(sk.public_key().clone())
}

fn hash(s: &str) -> Hash {
    Hash(hex::decode(s).unwrap().try_into().unwrap())
}

struct Draft {
    genesis: Hash,
    rate: u128,
    to: Address,
    until: u64,
}

impl Draft {
    fn new(args: &[String]) -> Draft {
        Draft {
            genesis: hash(&args[0]),
            rate: args[1].parse().unwrap(),
            to: args[2].parse().unwrap(),
            until: args[3].parse().unwrap(),
        }
    }

    fn transfer(&self, sender: usize, nonce: u64) -> (SignedTransaction, SecretKey) {
        let sk = key(sender);
        let p = policy(&sk);
        let reveal = (nonce == 0).then(|| p.clone());
        let mut tx = Transaction {
            genesis_hash: self.genesis,
            sender: p.address(),
            nonce,
            fee: 0,
            valid_until_ms: self.until,
            role: Role::Owner,
            payload: Payload::Transfer {
                to: self.to,
                asset: AssetId::NATIVE,
                amount: 1,
            },
        };
        let draft = SignedTransaction::sign(tx.clone(), &p, reveal.clone(), &[&sk]).unwrap();
        tx.fee = self.rate * draft.encode().len() as u128;
        (SignedTransaction::sign(tx, &p, reveal, &[&sk]).unwrap(), sk)
    }
}

fn generate(args: &[String]) {
    let draft = Draft::new(args);
    let (first, count, each): (usize, usize, u64) = (
        args[4].parse().unwrap(),
        args[5].parse().unwrap(),
        args[6].parse().unwrap(),
    );
    let senders: Vec<usize> = (first..first + count).collect();
    let workers = thread::available_parallelism().map_or(4, |n| n.get());
    let lines: Vec<String> = thread::scope(|scope| {
        let draft = &draft;
        let handles: Vec<_> = senders
            .chunks(senders.len().div_ceil(workers))
            .map(|chunk| {
                scope.spawn(move || {
                    let mut out = Vec::new();
                    for &sender in chunk {
                        for nonce in 0..each {
                            let (stx, _) = draft.transfer(sender, nonce);
                            out.push(format!("{sender} {}", hex::encode(stx.encode())));
                        }
                    }
                    out
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect()
    });
    println!("{}", lines.join("\n"));
}

fn hostile(args: &[String]) {
    let draft = Draft::new(args);
    let sender: usize = args[4].parse().unwrap();
    let (good, sk) = draft.transfer(sender, 0);
    let p = policy(&sk);
    let reveal = good.reveal.clone();
    let resign = |tx: Transaction| SignedTransaction::sign(tx, &p, reveal.clone(), &[&sk]).unwrap();
    let emit =
        |name: &str, stx: &SignedTransaction| println!("{name} {}", hex::encode(stx.encode()));

    let mut t = good.tx.clone();
    t.fee = t.fee * MAX_FEE_MULTIPLE + 1;
    emit("fee-too-high", &resign(t));
    let mut t = good.tx.clone();
    t.fee -= 1;
    emit("fee-too-low", &resign(t));
    let mut t = good.tx.clone();
    t.genesis_hash = Hash([9; 32]);
    emit("wrong-chain", &resign(t));
    let mut t = good.tx.clone();
    t.valid_until_ms = 1;
    emit("expired", &resign(t));
    let mut t = good.tx.clone();
    t.nonce += 5;
    emit("future-nonce", &resign(t));
    let mut tampered = good.clone();
    if let Payload::Transfer { amount, .. } = &mut tampered.tx.payload {
        *amount = 1_000_000;
    }
    emit("tampered-amount", &tampered);
    let other = key(sender + 1);
    let mut foreign =
        SignedTransaction::sign(good.tx.clone(), &policy(&other), None, &[&other]).unwrap();
    foreign.reveal = good.reveal.clone();
    emit("foreign-signature", &foreign);
    let mut unsigned = good.clone();
    unsigned.signatures.clear();
    emit("no-signatures", &unsigned);
    emit("good", &good);
}

fn random_u64() -> u64 {
    OsRng.next_u64()
}

fn random_round() -> Round {
    match random_u64() % 3 {
        0 => random_u64() % 5_000,
        1 => Round::MAX - random_u64() % 4,
        _ => random_u64(),
    }
}

fn nonsense(chain: &Hash, me: u16, sk: &SecretKey, i: u64) -> Vec<u8> {
    let qc = QuorumCert::genesis(*chain);
    let round = random_round();
    let block_id = Hash::digest("byzantine", &i.to_le_bytes());
    if i % 7 == 6 {
        let mut proof = vec![Hash::ZERO; 3];
        proof[0] = block_id;
        let shard = Shard {
            round: round % 5_000,
            proposer: (random_u64() % 4) as u16,
            root: block_id,
            size: (random_u64() % (1 << 24)) as u32,
            index: me,
            proof,
            data: vec![0; (random_u64() % (1 << 20)) as usize],
        };
        return NetMessage::Shard { epoch: 0, shard }.encode();
    }
    let message = match i % 6 {
        0 => {
            let size = 32 + (random_u64() % (4 * 1024 * 1024)) as usize;
            let mut junk = vec![0; size];
            OsRng.fill_bytes(&mut junk);
            return junk;
        }
        1 => Message::Vote(Vote::sign(block_id, round, VoteKind::Normal, me, sk, chain)),
        2 => Message::Timeout(Timeout::signed(round, qc, me, sk, chain)),
        3 => {
            let block = Block {
                round: round % 5_000 + 1,
                height: 1 + random_u64() % 5_000,
                parent: *chain,
                proposer: me,
                voters: Vec::new(),
                payload: BlockPayload {
                    timestamp_ms: random_u64(),
                    tx_root: Hash::ZERO,
                    transactions: Vec::new(),
                    state_root: Hash::ZERO,
                    receipt_root: Hash::ZERO,
                },
            };
            Message::Proposal(Proposal::sign(block, Some(qc), None, sk, chain))
        }
        4 => Message::BlockRequest(block_id),
        _ => Message::Sync {
            high_qc: QuorumCert { round, ..qc },
            last_tc: None,
        },
    };
    NetMessage::Consensus { epoch: 0, message }.encode()
}

/// `byzantine DATA_DIR KEY PASSWORD_FILE LISTEN SECONDS PEER...` with `PEER` = `HEXKEY=ADDR`:
/// a validator that passes the handshake with its real key and then sends only rubbish.
fn byzantine(args: &[String]) {
    let node = Node::open(Path::new(&args[0])).unwrap();
    let file = std::fs::read_to_string(&args[1]).unwrap();
    let password = std::fs::read_to_string(&args[2]).unwrap();
    let password = password.lines().next().unwrap();
    let sk = EncryptedKey::from_json(&file)
        .unwrap()
        .decrypt(password.as_bytes())
        .unwrap();
    let listen: SocketAddr = args[3].parse().unwrap();
    let seconds: u64 = args[4].parse().unwrap();
    let mut peers = BTreeMap::new();
    for peer in &args[5..] {
        let (key, addr) = peer.split_once('=').unwrap();
        let key = PublicKey::from_tagged_bytes(&hex::decode(key).unwrap()).unwrap();
        peers.insert(key, addr.parse().unwrap());
    }
    let me = node
        .validators()
        .unwrap()
        .keys()
        .iter()
        .position(|k| k == sk.public_key())
        .unwrap() as u16;
    let chain = node.genesis_hash();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let config = P2pConfig { listen, peers };
    let (transport, _inbox, _) = runtime
        .block_on(p2p::connect(&node, sk.clone(), config))
        .unwrap();

    let start = Instant::now();
    let (mut sent, mut bytes) = (0u64, 0u64);
    let mut last = Instant::now();
    while start.elapsed() < Duration::from_secs(seconds) {
        let message = nonsense(&chain, me, &sk, sent);
        bytes += message.len() as u64;
        sent += 1;
        transport.broadcast(message);
        if last.elapsed() > Duration::from_secs(5) {
            last = Instant::now();
            println!("sent {sent} messages, {} MiB", bytes / (1024 * 1024));
        }
        thread::sleep(Duration::from_millis(3));
    }
    println!("sent {sent} messages, {} MiB", bytes / (1024 * 1024));
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args[0].as_str() {
        "governance" => println!("{}", qubits_types::governance_address()),
        "addrs" => {
            for i in 0..args[1].parse().unwrap() {
                println!("{}", policy(&key(i)).address());
            }
        }
        "gen" => generate(&args[1..]),
        "bad" => hostile(&args[1..]),
        "byzantine" => byzantine(&args[1..]),
        other => panic!("unknown command {other}"),
    }
}
