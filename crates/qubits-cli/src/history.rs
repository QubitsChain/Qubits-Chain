use qubits_types::rpc::{AccountTransactionsResponse, TransactionResponse};
use qubits_types::{Address, Outcome, Payload, Role};

/// What `--before` takes: `height-index`, as a page's `next` reads.
pub fn is_cursor(text: &str) -> bool {
    text.split_once('-').is_some_and(|(height, index)| {
        height.parse::<u64>().is_ok() && index.parse::<u32>().is_ok()
    })
}

pub fn print(address: &Address, page: &AccountTransactionsResponse) {
    if page.transactions.is_empty() {
        println!("no transactions");
    }
    for t in &page.transactions {
        println!(
            "block {}  {}  {}  {}",
            t.block_height.unwrap_or_default(),
            t.block_timestamp_ms.map(utc).unwrap_or_default(),
            t.id,
            describe(address, t)
        );
    }
    if page.blocks_from > 1 {
        println!(
            "this node keeps blocks from {} on, so older ones are not listed",
            page.blocks_from
        );
    }
    if let Some(next) = &page.next {
        println!("older: qubits account history {address} --before {next}");
    }
}

/// One transaction as the address sees it. Amounts are in base units, as everywhere in the CLI.
fn describe(address: &Address, t: &TransactionResponse) -> String {
    let tx = &t.transaction.tx;
    let own = tx.sender == *address;
    let who = |done: String| {
        if own {
            done
        } else {
            format!("{} {done}", tx.sender)
        }
    };
    let mut line = match &tx.payload {
        Payload::Transfer { to, asset, amount } => {
            let what = if asset.0 == 0 {
                amount.to_string()
            } else {
                format!("{amount} of asset {}", asset.0)
            };
            match (own, to == address) {
                (true, true) => format!("sent {what} to itself"),
                (true, false) => format!("sent {what} to {to}"),
                (false, true) => format!("received {what} from {}", tx.sender),
                (false, false) => format!("{} sent {what} to {to}", tx.sender),
            }
        }
        Payload::Call {
            contract,
            function,
            amount,
            ..
        } => {
            let with = if *amount > 0 {
                format!(" with {amount}")
            } else {
                String::new()
            };
            who(format!("called {contract}.{function}{with}"))
        }
        Payload::Deploy { .. } => match t.receipt.as_ref().and_then(|r| r.contract) {
            Some(made) => who(format!("deployed {made}")),
            None => who("deployed a contract".into()),
        },
        Payload::SetAuth { .. } => match tx.role {
            Role::Owner => who("changed its keys".into()),
            Role::Recovery => who("was recovered: new keys".into()),
        },
        Payload::SetVault { vault: Some(_) } => who("set its vault rules".into()),
        Payload::SetVault { vault: None } => who("stopped being a vault".into()),
        Payload::CancelPending { id } => who(format!("cancelled waiting action {id}")),
        Payload::ExecutePending { account, id } => {
            who(format!("carried out waiting action {id} of {account}"))
        }
        Payload::SetValidators { validators } => {
            who(format!("set {} validators", validators.len()))
        }
        Payload::ClaimRewards { payout } => who(format!("claimed rewards for {payout}")),
    };
    if let Some(receipt) = &t.receipt {
        let failed = match &receipt.outcome {
            Outcome::Done => None,
            Outcome::Reverted { reason } => {
                Some(format!("reverted: {}", String::from_utf8_lossy(reason)))
            }
            Outcome::OutOfGas => Some("out of gas".into()),
            Outcome::Trapped => Some("the contract crashed".into()),
            Outcome::Invalid => Some("no such function".into()),
        };
        if let Some(failed) = failed {
            line.push_str(&format!(" (failed, {failed})"));
        }
    }
    line
}

/// `2026-11-08 07:00:42 UTC`.
fn utc(ms: u64) -> String {
    let secs = ms / 1000;
    let (days, rest) = (secs / 86_400, secs % 86_400);
    // days since 1970-01-01 to a civil date (Howard Hinnant's algorithm)
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_read_as_utc() {
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(1_794_121_242_742), "2026-11-08 07:00:42 UTC");
        assert_eq!(utc(951_782_400_000), "2000-02-29 00:00:00 UTC");
    }

    #[test]
    fn cursors_are_height_and_index() {
        assert!(is_cursor("1234-0"));
        assert!(!is_cursor("1234"));
        assert!(!is_cursor("x-1"));
        assert!(!is_cursor("1-2&limit=9"));
    }
}
