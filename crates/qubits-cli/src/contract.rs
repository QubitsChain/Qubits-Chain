//! `contract.function(args)` on the command line. Arguments are typed by how they look:
//!
//! - `qb1…` is an address, 32 bytes.
//! - `5` is a `u128`, 16 bytes, little-endian. `u64:5` is 8 bytes.
//! - `"text"` is bytes with a `u32` length in front, like `Args::bytes` reads them.
//! - `0xabcd` is those bytes, as they are.
//! - `native` is the address the contracts use for the native token: 32 zero bytes.
//! - `deadline:600` is 600 seconds from now, as the `u64` of milliseconds a deadline is.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use clap::ValueEnum;
use qubits_types::{Address, Outcome, Receipt};

fn encode(argument: &str) -> Result<Vec<u8>> {
    let argument = argument.trim();
    if argument.starts_with("qb1") {
        let address: Address = argument.parse().map_err(|e| anyhow!("{argument}: {e}"))?;
        return Ok(address.as_bytes().to_vec());
    }
    if argument == "native" {
        return Ok(vec![0; 32]);
    }
    if let Some(seconds) = argument.strip_prefix("deadline:") {
        let seconds: u64 = seconds.parse().with_context(|| argument.to_owned())?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        return Ok((now + seconds * 1_000).to_le_bytes().to_vec());
    }
    if let Some(hex) = argument.strip_prefix("0x") {
        return hex::decode(hex).with_context(|| format!("{argument}: not hex"));
    }
    if let Some(number) = argument.strip_prefix("u64:") {
        let number: u64 = number.parse().with_context(|| argument.to_owned())?;
        return Ok(number.to_le_bytes().to_vec());
    }
    if let Some(text) = argument
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    {
        let mut bytes = (text.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(text.as_bytes());
        return Ok(bytes);
    }
    let number: u128 = argument
        .parse()
        .with_context(|| format!("{argument}: not an address, number, \"text\" or 0x bytes"))?;
    Ok(number.to_le_bytes().to_vec())
}

/// Splits on the commas that aren't inside quotes.
fn split(arguments: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut quoted, mut start) = (false, 0);
    for (at, c) in arguments.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                parts.push(&arguments[start..at]);
                start = at + 1;
            }
            _ => {}
        }
    }
    parts.push(&arguments[start..]);
    parts
}

pub fn encode_all<'a>(arguments: impl IntoIterator<Item = &'a str>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for argument in arguments {
        bytes.extend(encode(argument)?);
    }
    Ok(bytes)
}

pub struct Call {
    pub contract: Address,
    pub function: String,
    pub args: Vec<u8>,
}

/// Reads `qb1….function(a, b)`.
pub fn parse(text: &str) -> Result<Call> {
    let usage = || anyhow!("expected contract.function(args), got `{text}`");
    let (contract, rest) = text.trim().split_once('.').ok_or_else(usage)?;
    let (function, arguments) = rest.split_once('(').ok_or_else(usage)?;
    let arguments = arguments.strip_suffix(')').ok_or_else(usage)?;
    let function = function.trim();
    if function.is_empty() {
        return Err(usage());
    }
    let args = if arguments.trim().is_empty() {
        Vec::new()
    } else {
        encode_all(split(arguments))?
    };
    Ok(Call {
        contract: contract
            .trim()
            .parse()
            .map_err(|e| anyhow!("{contract}: {e}"))?,
        function: function.to_owned(),
        args,
    })
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Shape {
    Hex,
    U128,
    /// Several `u128`s in a row, as a pool's reserves come back.
    U128s,
    U64,
    Address,
    Text,
}

pub fn show(output: &[u8], shape: Shape) -> Result<String> {
    let wrong = || anyhow!("the output is {} bytes, not that shape", output.len());
    Ok(match shape {
        Shape::Hex => hex::encode(output),
        Shape::U128 => u128::from_le_bytes(output.try_into().map_err(|_| wrong())?).to_string(),
        Shape::U128s => {
            if output.is_empty() || !output.len().is_multiple_of(16) {
                return Err(wrong());
            }
            let words: Vec<String> = output
                .chunks_exact(16)
                .map(|word| u128::from_le_bytes(word.try_into().expect("16 bytes")).to_string())
                .collect();
            words.join(" ")
        }
        Shape::U64 => u64::from_le_bytes(output.try_into().map_err(|_| wrong())?).to_string(),
        Shape::Address => Address(output.try_into().map_err(|_| wrong())?).to_string(),
        Shape::Text => String::from_utf8_lossy(output).into_owned(),
    })
}

/// Says what a contract transaction did, and fails if it failed.
pub fn report(receipt: &Receipt) -> Result<()> {
    if let Some(address) = receipt.contract {
        println!("contract {address}");
    }
    if !receipt.output.is_empty() {
        println!("output {}", hex::encode(&receipt.output));
    }
    for event in &receipt.events {
        println!(
            "event {} from {}: {}",
            String::from_utf8_lossy(&event.topic),
            event.contract,
            hex::encode(&event.data)
        );
    }
    println!("gas used {}", receipt.gas_used);
    match &receipt.outcome {
        Outcome::Done => Ok(()),
        Outcome::Reverted { reason } => {
            bail!("reverted: {}", String::from_utf8_lossy(reason))
        }
        Outcome::OutOfGas => bail!("out of gas; the fee was paid, try a higher --gas"),
        Outcome::Trapped => bail!("the contract crashed; the fee was paid"),
        Outcome::Invalid => bail!("no such function, or the code is not a contract"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_call() {
        let address = "qb1vealhtjgvexg3cwye4vfj79ks33gj2f03kau8dne6uqwy5hur6esqyse9d";
        let call = parse(&format!("{address}.transfer({address}, 5)")).unwrap();
        assert_eq!(call.function, "transfer");
        assert_eq!(call.contract.to_string(), address);
        assert_eq!(call.args.len(), 48);
        assert_eq!(call.args[32..], 5u128.to_le_bytes());
        assert_eq!(
            parse(&format!("{address}.total_supply()")).unwrap().args,
            b""
        );
    }

    #[test]
    fn reads_each_kind_of_argument() {
        assert_eq!(encode("u64:7").unwrap(), 7u64.to_le_bytes());
        assert_eq!(encode("0xabcd").unwrap(), [0xab, 0xcd]);
        assert_eq!(encode("\"hi\"").unwrap(), [2, 0, 0, 0, b'h', b'i']);
        assert_eq!(split(r#"1, "a,b", 2"#).len(), 3);
        assert_eq!(encode("native").unwrap(), [0; 32]);
        assert_eq!(encode("deadline:600").unwrap().len(), 8);
        let words = [5u128.to_le_bytes(), 7u128.to_le_bytes()].concat();
        assert_eq!(show(&words, Shape::U128s).unwrap(), "5 7");
    }

    #[test]
    fn refuses_what_it_cannot_read() {
        for text in [
            "transfer(1)",
            "qb1x.transfer",
            "qb1x.(1)",
            "qb1x.f(1",
            "nonsense",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
        assert!(encode("twelve").is_err());
    }
}
