use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use qubits_state::Verdict;
use qubits_types::SignedTransaction;

use crate::app::{PROOF_EVERY, finality_key, reconfigures};
use crate::{ChainBlock, Node, NodeError, now_ms};

/// Proofs at these heights are never dropped, so a range of blocks can always be proven final
/// from the next checkpoint. 112 KB per 8192 blocks with 50 validators.
pub const CHECKPOINT_EVERY: u64 = 8_192;
/// Blocks this close to the head stay whatever their age: snapshots start from them.
pub const HISTORY_MARGIN: u64 = 2 * PROOF_EVERY;
const PRUNE_EVERY: Duration = Duration::from_secs(10);
const PRUNE_BATCH: usize = 1_024;

/// Epoch ends hand the next validator set to joining nodes; era ends anchor era files.
pub fn keeps_forever(block: &ChainBlock, era_length: u64) -> bool {
    block.height.is_multiple_of(era_length) || reconfigures(block)
}

/// `all`, or a count with a unit: `7d`, `12h`, `30m`, `45s`. Milliseconds, `None` for all.
pub fn parse_keep(text: &str) -> Result<Option<u64>, String> {
    if text == "all" {
        return Ok(None);
    }
    let (digits, unit) = text.split_at(
        text.trim_end_matches(|c: char| c.is_ascii_alphabetic())
            .len(),
    );
    let count: u64 = digits
        .parse()
        .map_err(|_| format!("`{text}`: expected a number and a unit, like 7d, or all"))?;
    let unit_ms = match unit {
        "d" => 24 * 60 * 60 * 1_000,
        "h" => 60 * 60 * 1_000,
        "m" => 60 * 1_000,
        "s" => 1_000,
        _ => return Err(format!("`{text}`: the unit must be d, h, m or s")),
    };
    count
        .checked_mul(unit_ms)
        .filter(|ms| *ms > 0)
        .map(Some)
        .ok_or_else(|| format!("`{text}` is out of range"))
}

/// Drops blocks older than `keep_ms` and further than `margin` below the head, up to `limit`
/// of them. Returns how many went.
pub fn prune_once(node: &Node, keep_ms: u64, margin: u64, limit: usize) -> Result<u64, NodeError> {
    let head = node.head()?.height;
    let cutoff = now_ms().saturating_sub(keep_ms);
    let era_length = node.era_length();
    let deleted =
        node.store()
            .prune_history(head.saturating_sub(margin), limit, |height, bytes| {
                let block: ChainBlock = borsh::from_slice(bytes).map_err(|e| e.to_string())?;
                if block.payload.timestamp_ms >= cutoff {
                    return Ok(Verdict::Stop);
                }
                if keeps_forever(&block, era_length) {
                    return Ok(Verdict::Keep);
                }
                let tx_ids = block
                    .payload
                    .transactions
                    .iter()
                    .map(SignedTransaction::id)
                    .collect();
                Ok(Verdict::Delete {
                    tx_ids,
                    meta: vec![finality_key(height)],
                })
            })?;
    if deleted > 0 {
        node.metrics().history_pruned(deleted);
        tracing::info!(
            deleted,
            from = node.store().blocks_from()?,
            "dropped old blocks"
        );
    }
    Ok(deleted)
}

pub struct PrunerHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for PrunerHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub fn spawn_history_pruner(node: Arc<Node>, keep_ms: u64) -> PrunerHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let thread = std::thread::Builder::new()
        .name("history".into())
        .spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                match prune_once(&node, keep_ms, HISTORY_MARGIN, PRUNE_BATCH) {
                    Ok(deleted) if deleted as usize == PRUNE_BATCH => continue,
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "could not drop old blocks"),
                }
                for _ in 0..PRUNE_EVERY.as_millis() / 100 {
                    if stopped.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        })
        .expect("spawning a thread cannot fail");
    PrunerHandle {
        stop,
        thread: Some(thread),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keep_durations_parse() {
        assert_eq!(parse_keep("all"), Ok(None));
        assert_eq!(parse_keep("7d"), Ok(Some(7 * 86_400_000)));
        assert_eq!(parse_keep("12h"), Ok(Some(12 * 3_600_000)));
        assert_eq!(parse_keep("30m"), Ok(Some(1_800_000)));
        assert_eq!(parse_keep("45s"), Ok(Some(45_000)));
        for bad in [
            "",
            "7",
            "d",
            "7w",
            "0d",
            "-1d",
            "7 d",
            "99999999999999999999d",
        ] {
            assert!(parse_keep(bad).is_err(), "{bad}");
        }
    }
}
