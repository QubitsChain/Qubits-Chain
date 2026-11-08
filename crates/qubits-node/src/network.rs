use std::collections::BTreeSet;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

use borsh::{BorshDeserialize, BorshSerialize};
use qubits_consensus::Message;
use qubits_consensus::shards::Shard;
use qubits_crypto::PublicKey;
use qubits_types::{BlockPayload, SignedTransaction};

pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum NetMessage {
    Consensus {
        epoch: u64,
        message: Message<BlockPayload>,
    },
    Transaction(SignedTransaction),
    Shard {
        epoch: u64,
        shard: Shard,
    },
}

impl NetMessage {
    pub fn encode(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("in-memory encoding cannot fail")
    }

    pub fn decode(bytes: &[u8]) -> Option<NetMessage> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return None;
        }
        borsh::from_slice(bytes).ok()
    }
}

pub struct Frame {
    bytes: Vec<u8>,
    unhandled: Option<Arc<AtomicUsize>>,
}

impl Frame {
    pub fn new(bytes: Vec<u8>) -> Frame {
        Frame {
            bytes,
            unhandled: None,
        }
    }

    pub(crate) fn counted(bytes: Vec<u8>, unhandled: Arc<AtomicUsize>) -> Frame {
        Frame {
            bytes,
            unhandled: Some(unhandled),
        }
    }
}

impl Deref for Frame {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for Frame {
    fn drop(&mut self) {
        if let Some(unhandled) = &self.unhandled {
            unhandled.fetch_sub(self.bytes.len(), Ordering::Relaxed);
        }
    }
}

pub type Envelope = (PublicKey, Frame);

pub type Inbox = Receiver<Envelope>;

pub trait Transport: Send + Sync + 'static {
    fn send(&self, to: &PublicKey, bytes: Vec<u8>);
    fn broadcast(&self, bytes: Vec<u8>);
    fn connected(&self) -> usize {
        0
    }
}

pub struct NoPeers;

impl Transport for NoPeers {
    fn send(&self, _: &PublicKey, _: Vec<u8>) {}
    fn broadcast(&self, _: Vec<u8>) {}
}

#[derive(Clone)]
pub struct LocalHub {
    members: Arc<Vec<(PublicKey, Sender<Envelope>)>>,
    down: Arc<Mutex<BTreeSet<PublicKey>>>,
}

pub struct LocalTransport {
    hub: LocalHub,
    me: PublicKey,
}

impl LocalHub {
    pub fn new(members: &[PublicKey]) -> (LocalHub, Vec<Inbox>) {
        let mut senders = Vec::new();
        let mut inboxes = Vec::new();
        for key in members {
            let (tx, rx) = channel();
            senders.push((key.clone(), tx));
            inboxes.push(rx);
        }
        let hub = LocalHub {
            members: Arc::new(senders),
            down: Arc::new(Mutex::new(BTreeSet::new())),
        };
        (hub, inboxes)
    }

    pub fn transport(&self, me: &PublicKey) -> LocalTransport {
        LocalTransport {
            hub: self.clone(),
            me: me.clone(),
        }
    }

    pub fn set_down(&self, member: &PublicKey, down: bool) {
        let mut set = crate::lock(&self.down);
        if down {
            set.insert(member.clone());
        } else {
            set.remove(member);
        }
    }

    fn deliver(&self, from: &PublicKey, to: &PublicKey, bytes: Vec<u8>) {
        let down = crate::lock(&self.down);
        if down.contains(from) || down.contains(to) {
            return;
        }
        drop(down);
        if let Some((_, sender)) = self.members.iter().find(|(k, _)| k == to) {
            let _ = sender.send((from.clone(), Frame::new(bytes)));
        }
    }
}

impl Transport for LocalTransport {
    fn send(&self, to: &PublicKey, bytes: Vec<u8>) {
        self.hub.deliver(&self.me, to, bytes);
    }

    fn broadcast(&self, bytes: Vec<u8>) {
        for (to, _) in self.hub.members.iter() {
            if *to != self.me {
                self.hub.deliver(&self.me, to, bytes.clone());
            }
        }
    }

    fn connected(&self) -> usize {
        let down = crate::lock(&self.hub.down);
        self.hub
            .members
            .iter()
            .filter(|(key, _)| *key != self.me && !down.contains(key))
            .count()
    }
}
