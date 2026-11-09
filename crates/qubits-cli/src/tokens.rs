use qubits_types::rpc::{AccountTokensResponse, ViewRequest};
use qubits_types::{Address, Outcome};

use crate::chain::Client;

/// One line per token: its address, then what `address` holds of it in base units and its
/// symbol, when the contract answers like a token.
pub fn print(client: &Client, address: &Address, page: &AccountTokensResponse) {
    if page.tokens.is_empty() {
        println!("no tokens");
    }
    for token in &page.tokens {
        let ask = |function: &str, args: Vec<u8>| {
            let request = ViewRequest {
                function: function.into(),
                args,
                caller: None,
                amount: 0,
            };
            client
                .view(token, &request)
                .ok()
                .filter(|r| r.outcome == Outcome::Done)
                .map(|r| r.output)
        };
        let held = ask("balance_of", address.0.to_vec())
            .and_then(|out| <[u8; 16]>::try_from(out.as_slice()).ok())
            .map(u128::from_le_bytes);
        let symbol =
            ask("symbol", Vec::new()).map(|out| String::from_utf8_lossy(&out).into_owned());
        match (held, symbol) {
            (Some(held), Some(symbol)) => println!("{token}  {held} {symbol}"),
            (Some(held), None) => println!("{token}  {held}"),
            _ => println!("{token}"),
        }
    }
    if let Some(next) = page.next {
        println!("more: qubits account tokens {address} --after {next}");
    }
}
