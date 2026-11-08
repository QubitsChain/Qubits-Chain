use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Metrics {
    messages_in: AtomicU64,
    bytes_in: AtomicU64,
    messages_out: AtomicU64,
    bytes_out: AtomicU64,
    round: AtomicU64,
    epoch: AtomicU64,
    peers: AtomicU64,
    syncs: AtomicU64,
    shards_rebuilt: AtomicU64,
    snapshots: AtomicU64,
    history_pruned: AtomicU64,
}

#[derive(Clone, Copy, Default)]
pub struct Traffic {
    pub messages_in: u64,
    pub bytes_in: u64,
    pub messages_out: u64,
    pub bytes_out: u64,
}

impl Traffic {
    pub fn since(self, earlier: Traffic) -> Traffic {
        Traffic {
            messages_in: self.messages_in - earlier.messages_in,
            bytes_in: self.bytes_in - earlier.bytes_in,
            messages_out: self.messages_out - earlier.messages_out,
            bytes_out: self.bytes_out - earlier.bytes_out,
        }
    }
}

impl Metrics {
    pub fn received(&self, bytes: usize) {
        self.messages_in.fetch_add(1, Ordering::Relaxed);
        self.bytes_in.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn sent(&self, messages: u64, bytes: u64) {
        self.messages_out.fetch_add(messages, Ordering::Relaxed);
        self.bytes_out.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn consensus(&self, round: u64, epoch: u64, peers: u64) {
        self.round.store(round, Ordering::Relaxed);
        self.epoch.store(epoch, Ordering::Relaxed);
        self.peers.store(peers, Ordering::Relaxed);
    }

    pub fn shards_rebuilt(&self) {
        self.shards_rebuilt.fetch_add(1, Ordering::Relaxed);
    }

    pub fn history_pruned(&self, blocks: u64) {
        self.history_pruned.fetch_add(blocks, Ordering::Relaxed);
    }

    pub fn snapshot_synced(&self) {
        self.snapshots.fetch_add(1, Ordering::Relaxed);
    }

    pub fn synced(&self) {
        self.syncs.fetch_add(1, Ordering::Relaxed);
    }

    pub fn traffic(&self) -> Traffic {
        Traffic {
            messages_in: self.messages_in.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            messages_out: self.messages_out.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
        }
    }

    /// Prometheus text format.
    pub fn render(&self, height: u64, mempool: usize, connections: usize) -> String {
        let traffic = self.traffic();
        let get = |v: &AtomicU64| v.load(Ordering::Relaxed);
        let lines: [(&str, &str, u64); 14] = [
            ("qubits_height", "gauge", height),
            ("qubits_mempool_size", "gauge", mempool as u64),
            ("qubits_round", "gauge", get(&self.round)),
            ("qubits_epoch", "gauge", get(&self.epoch)),
            ("qubits_peers", "gauge", get(&self.peers)),
            ("qubits_ws_connections", "gauge", connections as u64),
            ("qubits_messages_in_total", "counter", traffic.messages_in),
            ("qubits_bytes_in_total", "counter", traffic.bytes_in),
            ("qubits_messages_out_total", "counter", traffic.messages_out),
            ("qubits_bytes_out_total", "counter", traffic.bytes_out),
            ("qubits_syncs_total", "counter", get(&self.syncs)),
            (
                "qubits_shards_rebuilt_total",
                "counter",
                get(&self.shards_rebuilt),
            ),
            (
                "qubits_snapshot_syncs_total",
                "counter",
                get(&self.snapshots),
            ),
            (
                "qubits_history_pruned_total",
                "counter",
                get(&self.history_pruned),
            ),
        ];
        let mut out = String::new();
        for (name, kind, value) in lines {
            writeln!(out, "# TYPE {name} {kind}\n{name} {value}").expect("writing to a string");
        }
        out
    }
}
