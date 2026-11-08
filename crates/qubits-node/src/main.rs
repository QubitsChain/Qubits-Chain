use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use qubits_crypto::PublicKey;
use qubits_crypto::keystore::EncryptedKey;
use qubits_node::network::NoPeers;
use qubits_node::p2p::{self, P2pConfig};
use qubits_node::sync::Follower;
use qubits_node::{Node, Timing, Validator};
use qubits_types::Genesis;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "qubits-node", version, about = "Qubits node")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a chain database from a genesis file.
    Init {
        /// Genesis JSON.
        #[arg(long)]
        genesis: PathBuf,
        /// Database directory.
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Run the node and its HTTP API.
    Run {
        /// Database directory.
        #[arg(long)]
        data_dir: PathBuf,
        /// HTTP API address.
        #[arg(long, default_value = "127.0.0.1:8545")]
        rpc_addr: SocketAddr,
        /// Encrypted validator key file. Without it the node only serves the API.
        #[arg(long, requires = "password_file")]
        validator_key: Option<PathBuf>,
        /// File whose first line is the validator key password.
        #[arg(long)]
        password_file: Option<PathBuf>,
        /// Shortest time between two blocks, whoever proposes them.
        #[arg(long, default_value_t = 100)]
        block_interval_ms: u64,
        /// Consensus round timeout (grows when rounds fail).
        #[arg(long, default_value_t = 1500)]
        round_timeout_ms: u64,
        /// Address to accept connections from other validators on.
        #[arg(long, default_value = "0.0.0.0:9545")]
        p2p_addr: SocketAddr,
        /// Another validator, as `KEY=HOST:PORT`, where `KEY` is its public key (hex, from
        /// `qubits key show`) or its position in the genesis validators. Repeat for each,
        /// including validators expected to join later.
        #[arg(long = "peer", value_parser = parse_peer)]
        peers: Vec<(String, SocketAddr)>,
        /// HTTP API of another node to sync committed blocks from (verified, not trusted).
        /// Without a validator key the node follows the chain this way and passes submitted
        /// transactions on; with one, it catches up this way before joining consensus.
        #[arg(long = "follow")]
        follow: Vec<String>,
        /// Keep state for only the newest N blocks and prune older state (blocks are kept).
        /// Without it the node keeps all state (archive node).
        #[arg(long, value_parser = clap::value_parser!(u64).range(100..))]
        prune_keep: Option<u64>,
        /// A fresh node this many blocks behind takes the state from a snapshot instead of
        /// replaying every block.
        #[arg(long, default_value_t = qubits_node::sync::SNAPSHOT_IF_BEHIND)]
        snapshot_if_behind: u64,
        /// How long to keep blocks: `7d`, `12h`, `30m`, or `all` for an archive node. Epoch
        /// ends and one block in 8192 are kept whatever this says.
        #[arg(long, default_value = "7d", value_parser = parse_keep)]
        history_keep: HistoryKeep,
        /// WebSocket connections open at once on `/v1/ws`.
        #[arg(long, default_value_t = qubits_node::ws::MAX_CONNECTIONS)]
        ws_limit: usize,
        /// Blocks per era file. Only for tests: every node of a chain must agree on it.
        #[arg(long, hide = true, default_value_t = qubits_node::history::CHECKPOINT_EVERY)]
        era_length: u64,
    },
    /// Era files: history in verifiable pieces, to fetch from an archive node and put back.
    Era {
        #[command(subcommand)]
        command: EraCommand,
    },
}

#[derive(Subcommand)]
enum EraCommand {
    /// Download eras from a node's HTTP API into a directory.
    Fetch {
        /// The node, like `http://127.0.0.1:8545`.
        #[arg(long)]
        from: String,
        /// Directory to write the files into.
        #[arg(long)]
        out: PathBuf,
        /// Era indexes; without any, every era the node offers that isn't there yet.
        eras: Vec<u64>,
        /// Fetch what a node holding blocks from this height on needs to get its history back:
        /// the part of that era up to the height, then every complete era below.
        #[arg(long, conflicts_with = "eras")]
        to: Option<u64>,
    },
    /// Check era files against a genesis file, from the genesis validators up.
    Verify {
        #[arg(long)]
        genesis: PathBuf,
        files: Vec<PathBuf>,
    },
    /// Take era files into a stopped node's database: executed after the head, or put back
    /// below the oldest block held. Import them in order.
    Import {
        #[arg(long)]
        data_dir: PathBuf,
        files: Vec<PathBuf>,
    },
}

/// Milliseconds to keep blocks for, `None` for all of them.
#[derive(Clone, Copy, Debug)]
struct HistoryKeep(Option<u64>);

fn parse_keep(s: &str) -> Result<HistoryKeep, String> {
    qubits_node::history::parse_keep(s).map(HistoryKeep)
}

fn era(command: EraCommand) -> Result<()> {
    use qubits_node::era;
    match command {
        EraCommand::Fetch {
            from,
            out,
            eras,
            to,
        } => {
            let from = from.trim_end_matches('/').to_string();
            let agent: ureq::Agent = ureq::Agent::config_builder()
                .timeout_global(None)
                .build()
                .into();
            let status: qubits_types::rpc::StatusResponse = agent
                .get(format!("{from}/v1/status"))
                .call()?
                .body_mut()
                .read_json()?;
            let offered: qubits_types::rpc::ErasResponse = agent
                .get(format!("{from}/v1/eras"))
                .call()?
                .body_mut()
                .read_json()?;
            fs::create_dir_all(&out)?;
            let mut wanted: Vec<(u64, Option<u64>)> = match to {
                Some(0) => bail!("--to must be a block height"),
                Some(to) => {
                    let index = (to - 1) / offered.length;
                    let mut list = vec![(index, Some(to))];
                    list.extend((0..index).rev().map(|i| (i, None)));
                    list
                }
                None if eras.is_empty() => offered.eras.iter().map(|i| (*i, None)).collect(),
                None => eras.into_iter().map(|i| (i, None)).collect(),
            };
            wanted.dedup();
            for (index, to) in wanted {
                let (name, query) = match to {
                    Some(to) => (
                        era::partial_file_name(&status.chain_id, &status.genesis_hash, index, to),
                        format!("?to={to}"),
                    ),
                    None => {
                        if !offered.eras.contains(&index) {
                            bail!("{from} does not offer era {index}");
                        }
                        (
                            era::file_name(&status.chain_id, &status.genesis_hash, index),
                            String::new(),
                        )
                    }
                };
                let path = out.join(&name);
                if path.exists() {
                    println!("{name}: already here");
                    continue;
                }
                let partial = out.join(format!("{name}.part"));
                let mut file = fs::File::create(&partial)?;
                let mut body = agent.get(format!("{from}/v1/eras/{index}{query}")).call()?;
                let bytes = std::io::copy(&mut body.body_mut().as_reader(), &mut file)?;
                file.sync_all()?;
                fs::rename(&partial, &path)?;
                println!("{name}: {} MB", bytes / 1_000_000);
            }
            Ok(())
        }
        EraCommand::Verify { genesis, files } => {
            let json = fs::read_to_string(&genesis)
                .with_context(|| format!("reading {}", genesis.display()))?;
            let genesis: Genesis = serde_json::from_str(&json).context("parsing genesis")?;
            let mut failed = false;
            for path in files {
                let file = std::io::BufReader::with_capacity(
                    1 << 20,
                    fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?,
                );
                let result =
                    era::Reader::open(file).and_then(|reader| era::verify(&genesis, reader));
                match result {
                    Ok(s) => println!(
                        "{}: ok, blocks {}..={}, {} transactions, {} proofs",
                        path.display(),
                        s.first_height,
                        s.last_height,
                        s.transactions,
                        s.proofs
                    ),
                    Err(e) => {
                        failed = true;
                        println!("{}: INVALID: {e}", path.display());
                    }
                }
            }
            if failed {
                bail!("some files failed");
            }
            Ok(())
        }
        EraCommand::Import { data_dir, files } => {
            let node = Node::open(&data_dir)?;
            for path in files {
                let file = std::io::BufReader::with_capacity(
                    1 << 20,
                    fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?,
                );
                let reader = era::Reader::open(file)
                    .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
                match era::import(&node, reader)
                    .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?
                {
                    era::Imported::Appended(s) => println!(
                        "{}: executed blocks {}..={}",
                        path.display(),
                        s.first_height,
                        s.last_height
                    ),
                    era::Imported::Restored(s) => println!(
                        "{}: put back blocks {}..={}",
                        path.display(),
                        s.first_height,
                        s.last_height
                    ),
                }
            }
            let head = node.head()?;
            println!(
                "height {}, blocks held from {}",
                head.height,
                node.store().blocks_from()?
            );
            Ok(())
        }
    }
}

fn parse_peer(s: &str) -> Result<(String, SocketAddr), String> {
    let (who, addr) = s.split_once('=').ok_or("expected KEY=HOST:PORT")?;
    let addr = addr
        .parse()
        .map_err(|_| "HOST:PORT must be an IP address and port")?;
    Ok((who.to_owned(), addr))
}

fn peer_key(genesis: &Genesis, who: &str) -> Result<PublicKey> {
    if let Ok(index) = who.parse::<usize>() {
        return genesis
            .validators
            .get(index)
            .map(|v| v.key.clone())
            .with_context(|| format!("genesis has no validator {index}"));
    }
    let bytes = hex::decode(who)
        .with_context(|| format!("peer `{who}` is neither an index nor a hex key"))?;
    Ok(PublicKey::from_tagged_bytes(&bytes)?)
}

fn main() -> Result<()> {
    // exit on any panic rather than keep serving the API without consensus
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        eprintln!("fatal: stopping the node");
        std::process::exit(101);
    }));

    tracing_subscriber::fmt()
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    match Cli::parse().command {
        Command::Init { genesis, data_dir } => {
            let json = fs::read_to_string(&genesis)
                .with_context(|| format!("reading {}", genesis.display()))?;
            let genesis: Genesis = serde_json::from_str(&json).context("parsing genesis")?;
            Node::init(&data_dir, &genesis)?;
            println!(
                "initialized chain `{}` in {}",
                genesis.chain_id,
                data_dir.display()
            );
            println!("genesis hash: {}", genesis.hash());
            Ok(())
        }
        Command::Era { command } => era(command),
        Command::Run {
            data_dir,
            rpc_addr,
            validator_key,
            password_file,
            block_interval_ms,
            round_timeout_ms,
            p2p_addr,
            peers,
            follow,
            prune_keep,
            snapshot_if_behind,
            history_keep,
            ws_limit,
            era_length,
        } => {
            let node = Arc::new(Node::open(&data_dir)?);
            node.set_ws_limit(ws_limit);
            if let Some(keep) = prune_keep {
                node.set_keep_versions(keep);
            }
            node.set_era_length(era_length)?;
            let _pruner = history_keep
                .0
                .map(|keep_ms| qubits_node::history::spawn_history_pruner(node.clone(), keep_ms));
            let timing = Timing {
                round_timeout_ms,
                min_block_interval_ms: block_interval_ms,
                ..Timing::DEFAULT
            };
            let key = match (validator_key, password_file) {
                (Some(key), Some(password)) => {
                    let json = fs::read_to_string(&key)
                        .with_context(|| format!("reading {}", key.display()))?;
                    let password = zeroize::Zeroizing::new(
                        fs::read_to_string(&password)
                            .with_context(|| format!("reading {}", password.display()))?,
                    );
                    let password = password.lines().next().unwrap_or_default();
                    Some(EncryptedKey::from_json(&json)?.decrypt(password.as_bytes())?)
                }
                _ => None,
            };
            let runtime = tokio::runtime::Runtime::new()?;
            // before catching up: validators starting together follow each other's APIs
            let listener = runtime
                .block_on(tokio::net::TcpListener::bind(rpc_addr))
                .with_context(|| format!("binding {rpc_addr}"))?;
            let server = runtime.spawn(qubits_node::serve(node.clone(), listener));
            let member = match &key {
                Some(key) => node.validators()?.has_key(key.public_key()),
                None => false,
            };
            if member && !follow.is_empty() {
                tracing::info!("catching up before joining consensus");
                let caught_up = Follower::new(node.clone(), follow.clone())?
                    .snapshot_if_behind(snapshot_if_behind)
                    .catch_up(2, Duration::from_secs(3600));
                if let Err(e) = caught_up {
                    tracing::warn!(error = %e, "could not catch up; joining consensus anyway");
                }
            }
            let _follower = match (&key, follow.is_empty()) {
                (None, false) => {
                    node.forward_to(follow.clone());
                    Some(
                        Follower::new(node.clone(), follow.clone())?
                            .snapshot_if_behind(snapshot_if_behind)
                            .spawn(Duration::from_millis(500)),
                    )
                }
                _ => None,
            };
            if let Some(key) = &key
                && !node.validators()?.has_key(key.public_key())
                && follow.is_empty()
            {
                bail!(
                    "{} is not in the current validator set; add --follow to wait for a validator-set change that adds it",
                    hex::encode(key.public_key().to_tagged_bytes())
                );
            }
            runtime.block_on(async {
                let _validator = match key {
                    None => None,
                    Some(key) if peers.is_empty() && node.validators()?.validators.len() == 1 && member => {
                        let validator = Validator::start(node.clone(), key, Arc::new(NoPeers), timing)?;
                        let (keep_open, inbox) = std::sync::mpsc::channel();
                        Some((validator.spawn(inbox), Some(keep_open)))
                    }
                    Some(key) => {
                        let mut peer_map = std::collections::BTreeMap::new();
                        for (who, addr) in peers {
                            peer_map.insert(peer_key(node.genesis(), &who)?, addr);
                        }
                        let unknown = node
                            .validators()?
                            .keys()
                            .iter()
                            .filter(|k| *k != key.public_key() && !peer_map.contains_key(*k))
                            .count();
                        if unknown > 0 {
                            bail!("{unknown} current validators have no --peer address");
                        }
                        let config = P2pConfig { listen: p2p_addr, peers: peer_map };
                        let (transport, inbox, addr) = p2p::connect(&node, key.clone(), config).await?;
                        tracing::info!("accepting validator connections on {addr}");
                        if member {
                            let mut validator = Validator::start(node.clone(), key, transport, timing)?;
                            if !follow.is_empty() {
                                validator.follow(Follower::new(node.clone(), follow.clone())?.snapshot_if_behind(snapshot_if_behind));
                            }
                            Some((validator.spawn(inbox), None))
                        } else {
                            tracing::info!("not a validator yet: following the chain until a validator-set change adds this key");
                            let follower = Follower::new(node.clone(), follow.clone())?.snapshot_if_behind(snapshot_if_behind);
                            Some((qubits_node::spawn_standby(node.clone(), key, transport, timing, follower, inbox), None))
                        }
                    }
                };
                tracing::info!(
                    chain = %node.genesis().chain_id,
                    height = node.head()?.height,
                    validator = _validator.is_some(),
                    "serving HTTP API on http://{rpc_addr}"
                );
                tokio::select! {
                    result = server => result.context("server task")?.context("server failed"),
                    _ = tokio::signal::ctrl_c() => {
                        tracing::info!("shutting down");
                        Ok(())
                    }
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    #[test]
    fn the_command_line_is_consistent() {
        super::Cli::command().debug_assert();
    }
}
