#![forbid(unsafe_code)]

mod chain;
mod contract;
mod history;
mod watch;

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use qubits_crypto::keystore::{EncryptedKey, KdfParams, MIN_PASSWORD_LEN};
use qubits_crypto::{Domain, PublicKey, SchemeId, SecretKey, Signature};
use qubits_types::client::PartialTransaction;
use qubits_types::rpc::ViewRequest;
use qubits_types::{
    Address, AssetId, AuthPolicy, Hash, Outcome, Payload, Role, Validator, VaultPolicy,
};
use zeroize::Zeroizing;

use chain::Client;

#[derive(Parser)]
#[command(name = "qubits", version, about = "Qubits command-line wallet")]
struct Cli {
    /// Node HTTP API.
    #[arg(
        long,
        global = true,
        env = "QUBITS_RPC",
        default_value = "http://127.0.0.1:8545"
    )]
    rpc: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage key files.
    #[command(subcommand)]
    Key(KeyCommand),
    /// Sign a message (off-chain only: message signatures are never valid as transactions).
    Sign {
        /// Encrypted key file.
        #[arg(long)]
        key: PathBuf,
        /// File to sign; reads standard input if omitted or `-`.
        #[arg(long)]
        message: Option<PathBuf>,
        #[command(flatten)]
        password: PasswordArgs,
    },
    /// Verify a message signature. Exits with status 1 if it is invalid.
    Verify {
        /// Scheme-tagged public key as hex, or `@path` to read it from a file.
        #[arg(long)]
        public_key: String,
        /// Scheme-tagged signature as hex, or `@path` to read it from a file.
        #[arg(long)]
        signature: String,
        /// Signed file; reads standard input if omitted or `-`.
        #[arg(long)]
        message: Option<PathBuf>,
    },
    /// Print the address a key controls when used as a single-key account.
    Address {
        /// Key file.
        #[arg(long)]
        key: PathBuf,
    },
    /// Show an account's balances, policies and pending vault actions; `account history` lists
    /// its transactions.
    #[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
    Account {
        /// Address (`qb1…`).
        #[arg(required = true)]
        address: Option<Address>,
        #[command(subcommand)]
        command: Option<AccountCommand>,
    },
    /// Send tokens. From a vault, the transfer waits for the vault delay.
    Transfer {
        /// Recipient address.
        #[arg(long)]
        to: Address,
        /// Amount in base units.
        #[arg(long)]
        amount: u128,
        /// Token id; 0 is the native token.
        #[arg(long, default_value_t = 0)]
        asset: u32,
        #[command(flatten)]
        tx: TxArgs,
    },
    /// Vault accounts: delayed transfers, cancellation and recovery.
    #[command(subcommand)]
    Vault(VaultCommand),
    /// Transactions: status, and multisig signing (sign, show, submit a transaction file).
    #[command(subcommand)]
    Tx(TxCommand),
    /// Multisig policies.
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// The validator set, and changing it through governance.
    #[command(subcommand)]
    Validators(ValidatorsCommand),
    /// Contracts: `qubits contract call 'qb1….transfer(qb1…, 5)'`.
    #[command(subcommand)]
    Contract(ContractCommand),
}

#[derive(Subcommand)]
enum AccountCommand {
    /// Transactions that name an address, newest first, one a line.
    History {
        /// Address (`qb1…`).
        address: Address,
        /// How many to show, at most 100.
        #[arg(long, default_value_t = 25)]
        limit: usize,
        /// Go on from the cursor an earlier page ended with.
        #[arg(long)]
        before: Option<String>,
        /// Print the node's answer as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print each new transaction that names an address as it lands, until stopped.
    Watch {
        /// Address (`qb1…`).
        address: Address,
        /// One JSON object a line instead.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ContractCommand {
    /// Prepare a contract's deployment. Only the governance account can deploy: current
    /// validators sign the file with `qubits tx sign` and anyone submits it, as with a change
    /// of validators. `qubits tx submit --wait` prints the contract's address.
    Deploy {
        /// The compiled contract (.wasm).
        code: PathBuf,
        /// An argument of its `init`: `qb1…`, `native`, a number, `u64:5`, `deadline:600`,
        /// `"text"` or `0xbytes`.
        #[arg(long = "arg")]
        args: Vec<String>,
        /// Gas limit. What isn't used goes back.
        #[arg(long, default_value_t = qubits_types::limits::MAX_TX_GAS)]
        gas: u64,
        /// Where to write the transaction file.
        #[arg(long)]
        out: PathBuf,
    },
    /// Call a contract in a transaction: `'qb1….transfer(qb1…, 5)'`. Quote it for the shell.
    /// From a vault, the call waits for the vault delay.
    Call {
        /// `contract.function(args)`.
        call: String,
        /// Native tokens to send along, in base units.
        #[arg(long, default_value_t = 0)]
        amount: u128,
        /// Gas limit. What isn't used goes back.
        #[arg(long, default_value_t = 2_000_000)]
        gas: u64,
        #[command(flatten)]
        tx: TxArgs,
    },
    /// Read from a contract, for free: `'qb1….balance_of(qb1…)'`. Nothing is kept.
    View {
        /// `contract.function(args)`.
        call: String,
        /// How to print what comes back.
        #[arg(long = "as", value_enum, default_value = "hex")]
        shape: contract::Shape,
    },
    /// Show a deployed contract.
    Show {
        /// Its address.
        address: Address,
    },
}

#[derive(Subcommand)]
enum ValidatorsCommand {
    /// Show the current validators, epoch and governance account.
    Show,
    /// Show the fee pool, or what one payout address can claim.
    Rewards {
        /// A payout address. Without it, the pool and every current validator.
        payout: Option<Address>,
    },
    /// Pay a validator's rewards out to its payout address. Any account can send this and pays
    /// the fee; the coins can only go to `payout`.
    Claim {
        /// The payout address.
        #[arg(long)]
        payout: Address,
        #[command(flatten)]
        tx: TxArgs,
    },
    /// Prepare a change of the validator set. Current validators then sign the file with
    /// `qubits tx sign --key <validator key>` until a quorum has signed, and anyone submits it
    /// with `qubits tx submit`. The governance account pays the fee, so it needs funds.
    Propose {
        /// Public keys of the new set (hex from `qubits key show`, or `@path`), in leader order.
        #[arg(long = "public-key")]
        public_keys: Vec<String>,
        /// Key files of members of the new set (only their public keys are read).
        #[arg(long = "key")]
        keys: Vec<PathBuf>,
        /// Payout addresses, one for each validator, in the same order: `--key` ones first.
        #[arg(long = "payout")]
        payouts: Vec<Address>,
        /// Where to write the transaction file.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum TxCommand {
    /// Show a submitted transaction.
    Status {
        /// Transaction id.
        id: Hash,
    },
    /// Show a transaction file and how many signatures it still needs.
    Show {
        /// Transaction file written with `--unsigned-out`.
        #[arg(long)]
        file: PathBuf,
    },
    /// Add your signature to a transaction file.
    Sign {
        /// Transaction file written with `--unsigned-out`.
        #[arg(long)]
        file: PathBuf,
        /// Key file to sign with.
        #[arg(long)]
        key: PathBuf,
        #[command(flatten)]
        password: PasswordArgs,
    },
    /// Submit a transaction file once it has enough signatures.
    Submit {
        /// Transaction file.
        #[arg(long)]
        file: PathBuf,
        /// Wait until the transaction is in a block.
        #[arg(long)]
        wait: bool,
    },
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Create a multisig policy: `threshold` of the given keys must sign. Prints its address.
    New {
        /// Signatures required.
        #[arg(long)]
        threshold: u8,
        /// Key files of the members (only their public keys are read).
        #[arg(long = "key")]
        keys: Vec<PathBuf>,
        /// Public keys of members given as hex (from `qubits key show`).
        #[arg(long = "public-key")]
        public_keys: Vec<String>,
        /// Where to write the policy (JSON), needed for the account's first transaction.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum VaultCommand {
    /// Turn the account into a vault.
    Create {
        /// Delay before owner actions take effect, in seconds.
        #[arg(long)]
        delay_secs: u64,
        /// Key file of the recovery key (only its public key is read). Keep this key offline;
        /// it can cancel pending actions and replace the owner key at once.
        #[arg(long)]
        recovery_key: Option<PathBuf>,
        #[command(flatten)]
        tx: TxArgs,
    },
    /// Stop being a vault (itself delayed).
    Remove {
        #[command(flatten)]
        tx: TxArgs,
    },
    /// Cancel a pending action.
    Cancel {
        /// Pending action id.
        #[arg(long)]
        id: u64,
        /// Sign with the vault's recovery key (`--key`) instead of the owner key.
        #[arg(long, requires = "account")]
        recovery: bool,
        #[command(flatten)]
        tx: TxArgs,
    },
    /// Execute an unlocked pending action of any vault. Your account pays the fee.
    Execute {
        /// Vault address.
        #[arg(long)]
        vault: Address,
        /// Pending action id.
        #[arg(long)]
        id: u64,
        #[command(flatten)]
        tx: TxArgs,
    },
}

/// Options shared by every command that sends a transaction.
#[derive(clap::Args)]
struct TxArgs {
    /// Key file that signs.
    #[arg(long, required_unless_present = "unsigned_out")]
    key: Option<PathBuf>,
    /// Account that sends. Defaults to the address of `--key`; needed after rotating keys
    /// (the address stays the same), for recovery, and for multisig accounts.
    #[arg(long, required_unless_present = "key")]
    account: Option<Address>,
    /// Don't sign: write the transaction to this file so several keys can sign it with
    /// `qubits tx sign`, then send it with `qubits tx submit` (multisig).
    #[arg(long)]
    unsigned_out: Option<PathBuf>,
    /// Policy file from `qubits policy new`, for a multisig account's first transaction.
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Seconds the transaction stays valid. Defaults to an hour, or a week with
    /// `--unsigned-out`, to leave signers time.
    #[arg(long)]
    valid_for: Option<u64>,
    /// Wait until the transaction is in a block.
    #[arg(long)]
    wait: bool,
    #[command(flatten)]
    password: PasswordArgs,
}

#[derive(Subcommand)]
enum KeyCommand {
    /// Generate a new key and save it encrypted with a password.
    New {
        /// Where to write the key file. Refuses to overwrite an existing file.
        #[arg(long)]
        out: PathBuf,
        /// Signature scheme: `ml-dsa-65` (default) or `slh-dsa-sha2-192s` (hash-only, cold
        /// storage; signing takes about a second).
        #[arg(long, default_value_t = SchemeId::MlDsa65)]
        scheme: SchemeId,
        #[command(flatten)]
        password: PasswordArgs,
    },
    /// Show the scheme and public key of a key file. Does not need the password.
    Show {
        /// Key file.
        #[arg(long)]
        key: PathBuf,
    },
    /// Replace the account's owner key with the key in `--new-key`. The address stays the same.
    /// Delayed for vaults unless `--recovery` signs.
    Rotate {
        /// Key file of the new owner key (only its public key is read).
        #[arg(long)]
        new_key: PathBuf,
        /// Sign with the vault's recovery key (`--key`): takes effect immediately.
        #[arg(long, requires = "account")]
        recovery: bool,
        #[command(flatten)]
        tx: TxArgs,
    },
}

#[derive(clap::Args)]
struct PasswordArgs {
    /// Read the password from the first line of this file instead of prompting.
    #[arg(long)]
    password_file: Option<PathBuf>,
}

impl PasswordArgs {
    fn read(&self, prompt: &str) -> Result<Zeroizing<String>> {
        match &self.password_file {
            Some(path) => {
                let contents = Zeroizing::new(
                    fs::read_to_string(path)
                        .with_context(|| format!("reading password file {}", path.display()))?,
                );
                let line = contents.lines().next().unwrap_or_default();
                Ok(Zeroizing::new(line.to_owned()))
            }
            None => Ok(Zeroizing::new(
                rpassword::prompt_password(prompt).context("reading password")?,
            )),
        }
    }

    fn read_new(&self) -> Result<Zeroizing<String>> {
        let password = self.read("New password: ")?;
        if password.chars().count() < MIN_PASSWORD_LEN {
            bail!("password must be at least {MIN_PASSWORD_LEN} characters");
        }
        if self.password_file.is_none() {
            let again = self.read("Repeat password: ")?;
            if *again != *password {
                bail!("passwords do not match");
            }
        }
        Ok(password)
    }
}

fn read_message(path: Option<&Path>) -> Result<Vec<u8>> {
    match path {
        Some(p) if p != Path::new("-") => {
            fs::read(p).with_context(|| format!("reading {}", p.display()))
        }
        _ => {
            let mut buf = Vec::new();
            io::stdin()
                .read_to_end(&mut buf)
                .context("reading standard input")?;
            Ok(buf)
        }
    }
}

fn read_hex_arg(name: &str, value: &str) -> Result<Vec<u8>> {
    let text = match value.strip_prefix('@') {
        Some(path) => fs::read_to_string(path).with_context(|| format!("reading {path}"))?,
        None => value.to_owned(),
    };
    hex::decode(text.trim()).with_context(|| format!("{name} is not valid hex"))
}

fn load_key_file(path: &Path) -> Result<EncryptedKey> {
    let json =
        fs::read_to_string(path).with_context(|| format!("reading key file {}", path.display()))?;
    EncryptedKey::from_json(&json).with_context(|| format!("parsing key file {}", path.display()))
}

fn write_private_file(path: &Path, contents: &str) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

const VALID_FOR_SECS: u64 = 60 * 60;
const MULTISIG_VALID_FOR_SECS: u64 = 7 * 24 * 60 * 60;

fn valid_until(seconds: u64) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    now.saturating_add(seconds.saturating_mul(1000))
}

fn key_address(path: &Path) -> Result<Address> {
    Ok(AuthPolicy::single(load_key_file(path)?.public_key()?).address())
}

fn send(client: &Client, args: TxArgs, role: Role, payload: Payload) -> Result<()> {
    let account = match (args.account, &args.key) {
        (Some(a), _) => a,
        (None, Some(key)) => key_address(key)?,
        (None, None) => bail!("give --account or --key"),
    };
    if let Some(out) = &args.unsigned_out {
        let initial = match &args.policy {
            Some(path) => Some(read_policy(path)?),
            None => None,
        };
        let partial = PartialTransaction::new(
            &client.status()?,
            &client.account(&account)?,
            role,
            payload,
            initial,
            valid_until(args.valid_for.unwrap_or(MULTISIG_VALID_FOR_SECS)),
        )
        .with_context(|| format!("{account}"))?;
        write_new_file(out, &serde_json::to_string_pretty(&partial)?)?;
        println!(
            "wrote {} (fee {}); it needs {} of {} signatures: run `qubits tx sign --file {}`",
            out.display(),
            partial.tx.fee,
            partial.policy.threshold,
            partial.policy.keys.len(),
            out.display()
        );
        return Ok(());
    }
    let key_path = args
        .key
        .as_ref()
        .expect("clap requires --key without --unsigned-out");
    let file = load_key_file(key_path)?;
    let password = args.password.read("Password: ")?;
    let key = file.decrypt(password.as_bytes())?;
    let valid_until_ms = valid_until(args.valid_for.unwrap_or(VALID_FOR_SECS));
    let stx = chain::build(client, &key, account, role, payload, valid_until_ms)?;
    let id = client.submit(&stx)?;
    println!("transaction {id} submitted (fee {})", stx.tx.fee);
    if args.wait {
        wait_for(client, &id)?;
    }
    Ok(())
}

fn wait_for(client: &Client, id: &Hash) -> Result<()> {
    let height = client.wait_included(id, Duration::from_secs(60))?;
    println!("included in block {height}");
    match client.transaction(id)?.receipt {
        Some(receipt) => contract::report(&receipt),
        None => Ok(()),
    }
}

fn read_policy(path: &Path) -> Result<AuthPolicy> {
    let json = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let policy: AuthPolicy =
        serde_json::from_str(&json).with_context(|| format!("parsing {}", path.display()))?;
    policy.validate()?;
    Ok(policy)
}

fn read_partial(path: &Path) -> Result<PartialTransaction> {
    let json = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&json)
        .with_context(|| format!("{} is not a transaction file", path.display()))
}

fn write_new_file(path: &Path, contents: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(contents.as_bytes())?;
    Ok(())
}

fn describe(partial: &PartialTransaction) {
    println!("from:       {}", partial.tx.sender);
    println!("nonce:      {}", partial.tx.nonce);
    println!("fee:        {}", partial.tx.fee);
    println!(
        "signed by:  {} key",
        match partial.tx.role {
            Role::Owner => "owner",
            Role::Recovery => "recovery",
        }
    );
    println!(
        "action:     {}",
        serde_json::to_string(&partial.tx.payload).unwrap_or_default()
    );
    let signed: Vec<String> = partial
        .signatures
        .iter()
        .map(|s| s.index.to_string())
        .collect();
    println!(
        "signatures: {} of {} needed (key indices signed: {})",
        partial.signatures.len(),
        partial.policy.threshold,
        if signed.is_empty() {
            "none".into()
        } else {
            signed.join(", ")
        }
    );
}

fn print_json(value: &impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn run(cli: Cli) -> Result<()> {
    let client = Client::new(&cli.rpc);
    match cli.command {
        Command::Key(KeyCommand::New {
            out,
            scheme,
            password,
        }) => {
            if out.exists() {
                bail!(
                    "{} already exists; refusing to overwrite a key file",
                    out.display()
                );
            }
            let password = password.read_new()?;
            let key = SecretKey::generate(scheme)?;
            let file = EncryptedKey::encrypt(&key, password.as_bytes(), KdfParams::DEFAULT)?;
            write_private_file(&out, &file.to_json())?;
            println!("scheme:     {scheme}");
            println!(
                "public key: {}",
                hex::encode(key.public_key().to_tagged_bytes())
            );
            eprintln!(
                "Saved encrypted key to {}. Back it up: it cannot be recovered.",
                out.display()
            );
        }
        Command::Key(KeyCommand::Show { key }) => {
            let public = load_key_file(&key)?.public_key()?;
            println!("scheme:     {}", public.scheme());
            println!("public key: {}", hex::encode(public.to_tagged_bytes()));
        }
        Command::Sign {
            key,
            message,
            password,
        } => {
            let file = load_key_file(&key)?;
            let msg = read_message(message.as_deref())?;
            let password = password.read("Password: ")?;
            let key = file.decrypt(password.as_bytes())?;
            let sig = key.sign(Domain::Message, &msg)?;
            println!("{}", hex::encode(sig.to_tagged_bytes()));
        }
        Command::Verify {
            public_key,
            signature,
            message,
        } => {
            let public = PublicKey::from_tagged_bytes(&read_hex_arg("public key", &public_key)?)
                .context("decoding public key")?;
            let sig = Signature::from_tagged_bytes(&read_hex_arg("signature", &signature)?)
                .context("decoding signature")?;
            let msg = read_message(message.as_deref())?;
            public.verify(Domain::Message, &msg, &sig)?;
            println!("OK: valid {} signature", sig.scheme());
        }
        Command::Key(KeyCommand::Rotate {
            new_key,
            recovery,
            tx,
        }) => {
            let auth = AuthPolicy::single(load_key_file(&new_key)?.public_key()?);
            let role = if recovery {
                Role::Recovery
            } else {
                Role::Owner
            };
            send(&client, tx, role, Payload::SetAuth { auth })?;
        }
        Command::Address { key } => println!("{}", key_address(&key)?),
        Command::Account {
            command:
                Some(AccountCommand::History {
                    address,
                    limit,
                    before,
                    json,
                }),
            ..
        } => {
            if let Some(cursor) = &before
                && !history::is_cursor(cursor)
            {
                bail!("--before takes the cursor an earlier page ended with, like 1234-0");
            }
            let page = client.history(&address, limit, before.as_deref())?;
            if json {
                print_json(&page)?;
            } else {
                history::print(&address, &page);
            }
        }
        Command::Account {
            command: Some(AccountCommand::Watch { address, json }),
            ..
        } => {
            let base = client.base().to_owned();
            watch::watch(
                &base,
                &address,
                || eprintln!("watching {address} on {base}; Ctrl-C to stop"),
                |t| {
                    if json {
                        println!("{}", serde_json::to_string(&t)?);
                    } else {
                        println!("{}", history::line(&address, &t));
                    }
                    io::stdout().flush()?;
                    Ok(())
                },
            )?;
        }
        Command::Account {
            address: Some(address),
            command: None,
        } => print_json(&client.account(&address)?)?,
        Command::Account { .. } => bail!("give an address"),
        Command::Tx(TxCommand::Status { id }) => print_json(&client.transaction(&id)?)?,
        Command::Tx(TxCommand::Show { file }) => describe(&read_partial(&file)?),
        Command::Tx(TxCommand::Sign {
            file,
            key,
            password,
        }) => {
            let mut partial = read_partial(&file)?;
            let key_file = load_key_file(&key)?;
            let password = password.read("Password: ")?;
            let secret = key_file.decrypt(password.as_bytes())?;
            partial.sign(&secret)?;
            // write then rename, so a crash can't leave half a file
            let tmp = file.with_extension("signing");
            fs::write(&tmp, serde_json::to_string_pretty(&partial)?)?;
            fs::rename(&tmp, &file)?;
            describe(&partial);
        }
        Command::Tx(TxCommand::Submit { file, wait }) => {
            let stx = read_partial(&file)?.finish()?;
            let id = client.submit(&stx)?;
            println!("transaction {id} submitted (fee {})", stx.tx.fee);
            if wait {
                wait_for(&client, &id)?;
            }
        }
        Command::Validators(ValidatorsCommand::Show) => print_json(&client.validators()?)?,
        Command::Validators(ValidatorsCommand::Rewards { payout: None }) => {
            print_json(&client.rewards()?)?
        }
        Command::Validators(ValidatorsCommand::Rewards {
            payout: Some(payout),
        }) => print_json(&client.reward(&payout)?)?,
        Command::Validators(ValidatorsCommand::Claim { payout, tx }) => {
            send(&client, tx, Role::Owner, Payload::ClaimRewards { payout })?
        }
        Command::Validators(ValidatorsCommand::Propose {
            public_keys,
            keys,
            payouts,
            out,
        }) => {
            let mut members = Vec::new();
            for path in &keys {
                members.push(load_key_file(path)?.public_key()?);
            }
            for hex_key in &public_keys {
                members.push(PublicKey::from_tagged_bytes(&read_hex_arg(
                    "public key",
                    hex_key,
                )?)?);
            }
            if payouts.len() != members.len() {
                bail!(
                    "{} validators but {} payout addresses: give one --payout for each",
                    members.len(),
                    payouts.len()
                );
            }
            let validators = members
                .into_iter()
                .zip(payouts)
                .map(|(key, payout)| Validator { key, payout })
                .collect();
            let governance = qubits_types::governance_address();
            let partial = PartialTransaction::new(
                &client.status()?,
                &client.account(&governance)?,
                Role::Owner,
                Payload::SetValidators { validators },
                None,
                valid_until(MULTISIG_VALID_FOR_SECS),
            )
            .context("governance account")?;
            write_new_file(&out, &serde_json::to_string_pretty(&partial)?)?;
            println!(
                "wrote {} (fee {}); {} of the {} current validators must sign it with `qubits tx sign --file {}`",
                out.display(),
                partial.tx.fee,
                partial.policy.threshold,
                partial.policy.keys.len(),
                out.display()
            );
        }
        Command::Contract(ContractCommand::Deploy {
            code,
            args,
            gas,
            out,
        }) => {
            let code = fs::read(&code).with_context(|| format!("reading {}", code.display()))?;
            let args = contract::encode_all(args.iter().map(String::as_str))?;
            let governance = qubits_types::governance_address();
            let state = client.account(&governance)?;
            let partial = PartialTransaction::new(
                &client.status()?,
                &state,
                Role::Owner,
                Payload::Deploy {
                    code,
                    args,
                    gas_limit: gas,
                },
                None,
                valid_until(MULTISIG_VALID_FOR_SECS),
            )
            .context("governance account")?;
            write_new_file(&out, &serde_json::to_string_pretty(&partial)?)?;
            println!(
                "wrote {} (fee {}); {} of the {} current validators must sign it with `qubits tx sign --file {}`",
                out.display(),
                partial.tx.fee,
                partial.policy.threshold,
                partial.policy.keys.len(),
                out.display()
            );
            println!(
                "if nothing else is sent from that account first, the contract will be at {}",
                qubits_types::contract_address(&governance, state.nonce)
            );
        }
        Command::Contract(ContractCommand::Call {
            call,
            amount,
            gas,
            tx,
        }) => {
            let call = contract::parse(&call)?;
            let payload = Payload::Call {
                contract: call.contract,
                function: call.function,
                args: call.args,
                amount,
                gas_limit: gas,
            };
            send(&client, tx, Role::Owner, payload)?;
        }
        Command::Contract(ContractCommand::View { call, shape }) => {
            let call = contract::parse(&call)?;
            let request = ViewRequest {
                function: call.function,
                args: call.args,
                caller: None,
                amount: 0,
            };
            let receipt = client.view(&call.contract, &request)?;
            if receipt.outcome != Outcome::Done {
                contract::report(&receipt)?;
            }
            println!("{}", contract::show(&receipt.output, shape)?);
        }
        Command::Contract(ContractCommand::Show { address }) => {
            print_json(&client.contract(&address)?)?;
        }
        Command::Policy(PolicyCommand::New {
            threshold,
            keys,
            public_keys,
            out,
        }) => {
            let mut members = Vec::new();
            for path in &keys {
                members.push(load_key_file(path)?.public_key()?);
            }
            for hex_key in &public_keys {
                members.push(PublicKey::from_tagged_bytes(&read_hex_arg(
                    "public key",
                    hex_key,
                )?)?);
            }
            let policy = AuthPolicy {
                threshold,
                keys: members,
            };
            policy.validate()?;
            write_new_file(&out, &serde_json::to_string_pretty(&policy)?)?;
            println!("{}", policy.address());
            eprintln!(
                "Wrote {}. Keep it: the account's first transaction needs it.",
                out.display()
            );
        }
        Command::Transfer {
            to,
            amount,
            asset,
            tx,
        } => send(
            &client,
            tx,
            Role::Owner,
            Payload::Transfer {
                to,
                asset: AssetId(asset),
                amount,
            },
        )?,
        Command::Vault(VaultCommand::Create {
            delay_secs,
            recovery_key,
            tx,
        }) => {
            let recovery = match recovery_key {
                Some(path) => Some(AuthPolicy::single(load_key_file(&path)?.public_key()?)),
                None => None,
            };
            let delay_ms = delay_secs.checked_mul(1000).context("delay too long")?;
            let vault = VaultPolicy { delay_ms, recovery };
            vault.validate()?;
            send(
                &client,
                tx,
                Role::Owner,
                Payload::SetVault { vault: Some(vault) },
            )?;
        }
        Command::Vault(VaultCommand::Remove { tx }) => {
            send(&client, tx, Role::Owner, Payload::SetVault { vault: None })?
        }
        Command::Vault(VaultCommand::Cancel { id, recovery, tx }) => {
            let role = if recovery {
                Role::Recovery
            } else {
                Role::Owner
            };
            send(&client, tx, role, Payload::CancelPending { id })?;
        }
        Command::Vault(VaultCommand::Execute { vault, id, tx }) => send(
            &client,
            tx,
            Role::Owner,
            Payload::ExecutePending { account: vault, id },
        )?,
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
