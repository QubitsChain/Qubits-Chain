use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::Duration;

use qubits_crypto::keystore::EncryptedKey;
use qubits_node::network::{Envelope, NoPeers};
use qubits_node::{Node, Timing, Validator, ValidatorHandle};
use qubits_types::rpc::AccountResponse;
use qubits_types::{AssetId, ChainParams, Genesis, GenesisAccount};
use std::sync::mpsc::Sender;

const PASSWORD: &str = "a long enough password";

struct Env {
    dir: tempfile::TempDir,
    rpc: String,
    _chain: Option<(ValidatorHandle, Sender<Envelope>)>,
}

impl Env {
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_qubits"))
            .current_dir(self.dir.path())
            .env("QUBITS_RPC", &self.rpc)
            .args(args)
            .output()
            .unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "`qubits {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn err(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            !out.status.success(),
            "`qubits {}` unexpectedly succeeded",
            args.join(" ")
        );
        String::from_utf8(out.stderr).unwrap()
    }

    fn new_key(&self, name: &str, scheme: &str) -> String {
        let file = format!("{name}.json");
        self.ok(&[
            "key",
            "new",
            "--out",
            &file,
            "--scheme",
            scheme,
            "--password-file",
            "pw",
        ]);
        self.ok(&["address", "--key", &file]).trim().to_owned()
    }

    fn account(&self, address: &str) -> AccountResponse {
        serde_json::from_str(&self.ok(&["account", address])).unwrap()
    }

    fn balance(&self, address: &str) -> u128 {
        let account = self.account(address);
        account
            .balances
            .iter()
            .find(|b| b.asset == AssetId::NATIVE)
            .map_or(0, |b| b.amount)
    }
}

fn setup() -> (Env, String) {
    setup_with(0)
}

fn setup_with(governance_funds: u128) -> (Env, String) {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("pw"), format!("{PASSWORD}\n")).unwrap();
    let mut env = Env {
        dir,
        rpc: String::new(),
        _chain: None,
    };
    let alice = env.new_key("alice", "ml-dsa-65");
    env.new_key("producer", "ml-dsa-65");

    let producer_file = fs::read_to_string(env.path("producer.json")).unwrap();
    let producer = EncryptedKey::from_json(&producer_file)
        .unwrap()
        .decrypt(PASSWORD.as_bytes())
        .unwrap();
    let genesis = Genesis {
        chain_id: "qubits-devnet".into(),
        timestamp_ms: qubits_node::now_ms() - 1_000,
        params: ChainParams {
            min_fee_per_byte: 1,
            max_block_transactions: 100,
        },
        validators: vec![qubits_types::Validator::self_paid(
            producer.public_key().clone(),
        )],
        accounts: vec![
            GenesisAccount {
                address: alice.parse().unwrap(),
                balance: 10_000_000,
            },
            GenesisAccount {
                address: qubits_types::governance_address(),
                balance: governance_funds,
            },
        ],
    };
    let data = env.path("data");
    Node::init(&data, &genesis).unwrap();
    let node = Arc::new(Node::open(&data).unwrap());
    let timing = Timing {
        round_timeout_ms: 1_000,
        min_block_interval_ms: 50,
        ..Timing::DEFAULT
    };
    let validator = Validator::start(node.clone(), producer, Arc::new(NoPeers), timing).unwrap();
    let (keep_open, inbox) = std::sync::mpsc::channel();
    env._chain = Some((validator.spawn(inbox), keep_open));

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    env.rpc = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                qubits_node::serve(node, listener).await.unwrap();
            });
    });
    (env, alice)
}

#[test]
fn transfers_vault_recovery_and_rotation() {
    let (env, alice) = setup();
    let bob = env.new_key("bob", "ml-dsa-65");
    let pw = ["--password-file", "pw", "--wait"];

    let out = env.ok(&[
        &[
            "transfer",
            "--key",
            "alice.json",
            "--to",
            &bob,
            "--amount",
            "200000",
        ][..],
        &pw,
    ]
    .concat());
    assert!(out.contains("included in block"), "{out}");
    assert_eq!(env.balance(&bob), 200_000);
    assert!(
        env.account(&alice).auth.is_some(),
        "first transaction revealed the policy"
    );

    env.new_key("recovery", "slh-dsa-sha2-192s");
    env.ok(&[
        &[
            "vault",
            "create",
            "--key",
            "alice.json",
            "--delay-secs",
            "2",
            "--recovery-key",
            "recovery.json",
        ][..],
        &pw,
    ]
    .concat());
    assert_eq!(env.account(&alice).vault.unwrap().delay_ms, 2_000);

    env.ok(&[
        &[
            "transfer",
            "--key",
            "alice.json",
            "--to",
            &bob,
            "--amount",
            "500",
        ][..],
        &pw,
    ]
    .concat());
    assert_eq!(env.account(&alice).pending.len(), 1);
    assert_eq!(env.balance(&bob), 200_000);
    env.ok(&[
        &[
            "vault",
            "cancel",
            "--id",
            "0",
            "--recovery",
            "--key",
            "recovery.json",
            "--account",
            &alice,
        ][..],
        &pw,
    ]
    .concat());
    assert!(env.account(&alice).pending.is_empty());

    env.new_key("alice2", "ml-dsa-65");
    env.ok(&[
        &[
            "key",
            "rotate",
            "--new-key",
            "alice2.json",
            "--recovery",
            "--key",
            "recovery.json",
            "--account",
            &alice,
        ][..],
        &pw,
    ]
    .concat());
    let stderr = env.err(
        &[
            &[
                "transfer",
                "--key",
                "alice.json",
                "--to",
                &bob,
                "--amount",
                "1",
            ][..],
            &pw,
        ]
        .concat(),
    );
    assert!(
        stderr.contains("not part of the account's owner policy"),
        "{stderr}"
    );

    env.ok(&[
        &[
            "transfer",
            "--key",
            "alice2.json",
            "--account",
            &alice,
            "--to",
            &bob,
            "--amount",
            "700",
        ][..],
        &pw,
    ]
    .concat());
    let pending = env.account(&alice).pending;
    assert_eq!(pending.len(), 1);
    let id = pending[0].id.to_string();
    let stderr = env.err(
        &[
            &[
                "vault", "execute", "--vault", &alice, "--id", &id, "--key", "bob.json",
            ][..],
            &pw,
        ]
        .concat(),
    );
    assert!(stderr.contains("locked until"), "{stderr}");
    std::thread::sleep(Duration::from_millis(2_100));
    let before = env.balance(&bob);
    let out = env.ok(&[
        &[
            "vault", "execute", "--vault", &alice, "--id", &id, "--key", "bob.json",
        ][..],
        &pw,
    ]
    .concat());
    assert!(out.contains("included in block"), "{out}");
    let fee: u128 = out
        .split("fee ")
        .nth(1)
        .unwrap()
        .split(')')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(env.balance(&bob), before + 700 - fee);

    let tx_id = out.split_whitespace().nth(1).unwrap();
    let shown = env.ok(&["tx", "status", tx_id]);
    assert!(shown.contains(r#""status": "included""#), "{shown}");
}

#[test]
fn an_accounts_history_reads_newest_first() {
    let (env, alice) = setup();
    let bob = env.new_key("bob", "ml-dsa-65");
    let pw = ["--password-file", "pw", "--wait"];
    let send = |key: &str, to: &str, amount: &str| {
        let out = env.ok(&[
            &["transfer", "--key", key, "--to", to, "--amount", amount][..],
            &pw,
        ]
        .concat());
        out.split_whitespace().nth(1).unwrap().to_owned()
    };
    let first = send("alice.json", &bob, "300000");
    let second = send("alice.json", &bob, "200000");
    let back = send("bob.json", &alice, "1000");

    let out = env.ok(&["account", "history", &bob]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3, "{out}");
    assert!(lines[0].contains(&back) && lines[0].contains(&format!("sent 1000 to {alice}")));
    assert!(
        lines[1].contains(&second) && lines[1].contains(&format!("received 200000 from {alice}"))
    );
    assert!(
        lines[2].contains(&first) && lines[2].contains(" UTC "),
        "{out}"
    );

    // a page of one ends with the command for the next
    let out = env.ok(&["account", "history", &bob, "--limit", "1"]);
    let next = out.lines().last().unwrap();
    assert!(
        next.starts_with(&format!("older: qubits account history {bob} --before ")),
        "{out}"
    );
    let cursor = next.rsplit(' ').next().unwrap();
    let out = env.ok(&[
        "account", "history", &bob, "--limit", "1", "--before", cursor,
    ]);
    assert!(out.lines().next().unwrap().contains(&second), "{out}");

    let page: qubits_types::rpc::AccountTransactionsResponse =
        serde_json::from_str(&env.ok(&["account", "history", &alice, "--json"])).unwrap();
    assert_eq!(page.transactions.len(), 3);
    assert_eq!(page.next, None);

    let stranger = env.new_key("stranger", "ml-dsa-65");
    assert_eq!(
        env.ok(&["account", "history", &stranger]),
        "no transactions\n"
    );
    assert!(
        env.err(&["account", "history", &bob, "--before", "soon"])
            .contains("--before takes")
    );
}

#[test]
fn an_address_is_watched_as_transactions_land() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;

    let (env, alice) = setup();
    let bob = env.new_key("bob", "ml-dsa-65");
    let mut child = Command::new(env!("CARGO_BIN_EXE_qubits"))
        .current_dir(env.dir.path())
        .env("QUBITS_RPC", &env.rpc)
        .args(["account", "watch", &bob])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut said = String::new();
    BufReader::new(child.stderr.take().unwrap())
        .read_line(&mut said)
        .unwrap();
    assert!(said.starts_with(&format!("watching {bob}")), "{said}");

    let (lines, landed) = std::sync::mpsc::channel();
    let stdout = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if lines.send(line.unwrap()).is_err() {
                return;
            }
        }
    });
    let out = env.ok(&[
        "transfer",
        "--key",
        "alice.json",
        "--to",
        &bob,
        "--amount",
        "4321",
        "--password-file",
        "pw",
        "--wait",
    ]);
    let id = out.split_whitespace().nth(1).unwrap().to_owned();
    let line = landed.recv_timeout(Duration::from_secs(20));
    child.kill().unwrap();
    child.wait().unwrap();
    let line = line.expect("no line within 20 s");
    assert!(line.contains(&id), "{line}");
    assert!(
        line.contains(&format!("received 4321 from {alice}")),
        "{line}"
    );
}

#[test]
fn chain_errors_are_reported() {
    let (env, alice) = setup();
    let carol = env.new_key("carol", "ml-dsa-65");

    let stderr = env.err(&[
        "transfer",
        "--key",
        "carol.json",
        "--to",
        &alice,
        "--amount",
        "1",
        "--password-file",
        "pw",
    ]);
    assert!(stderr.contains("does not exist yet"), "{stderr}");

    let stderr = env.err(&[
        "transfer",
        "--key",
        "carol.json",
        "--account",
        &alice,
        "--to",
        &carol,
        "--amount",
        "1",
        "--password-file",
        "pw",
    ]);
    assert!(stderr.contains("does not control"), "{stderr}");

    let stderr = env.err(&[
        "transfer",
        "--key",
        "alice.json",
        "--to",
        &carol,
        "--amount",
        "999999999",
        "--password-file",
        "pw",
    ]);
    assert!(stderr.contains("insufficient balance"), "{stderr}");

    let mut typo = carol.clone();
    typo.replace_range(10..11, if &carol[10..11] == "q" { "p" } else { "q" });
    let stderr = env.err(&["account", &typo]);
    assert!(stderr.contains("invalid address"), "{stderr}");

    let out = Command::new(env!("CARGO_BIN_EXE_qubits"))
        .args(["--rpc", "http://127.0.0.1:1", "account", &alice])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("connecting to"));
}

#[test]
fn multisig_account_signs_offline_and_submits() {
    let (env, alice) = setup();
    let bob = env.new_key("bob", "ml-dsa-65");
    for (name, scheme) in [
        ("k1", "ml-dsa-65"),
        ("k2", "slh-dsa-sha2-192s"),
        ("k3", "ml-dsa-65"),
    ] {
        env.new_key(name, scheme);
    }
    let multisig = env
        .ok(&[
            "policy",
            "new",
            "--threshold",
            "2",
            "--key",
            "k1.json",
            "--key",
            "k2.json",
            "--key",
            "k3.json",
            "--out",
            "policy.json",
        ])
        .trim()
        .to_owned();
    assert!(multisig.starts_with("qb1"));
    env.ok(&[
        "transfer",
        "--key",
        "alice.json",
        "--to",
        &multisig,
        "--amount",
        "500000",
        "--password-file",
        "pw",
        "--wait",
    ]);
    assert_eq!(env.balance(&multisig), 500_000);

    let out = env.ok(&[
        "transfer",
        "--account",
        &multisig,
        "--policy",
        "policy.json",
        "--to",
        &bob,
        "--amount",
        "10",
        "--unsigned-out",
        "t1.json",
    ]);
    assert!(out.contains("needs 2 of 3 signatures"), "{out}");
    let stderr = env.err(&["tx", "submit", "--file", "t1.json"]);
    assert!(stderr.contains("needs 2 signatures, has 0"), "{stderr}");

    let shown = env.ok(&[
        "tx",
        "sign",
        "--file",
        "t1.json",
        "--key",
        "k1.json",
        "--password-file",
        "pw",
    ]);
    assert!(shown.contains("1 of 2 needed"), "{shown}");
    let stderr = env.err(&[
        "tx",
        "sign",
        "--file",
        "t1.json",
        "--key",
        "k1.json",
        "--password-file",
        "pw",
    ]);
    assert!(stderr.contains("already signed"), "{stderr}");
    let stderr = env.err(&[
        "tx",
        "sign",
        "--file",
        "t1.json",
        "--key",
        "alice.json",
        "--password-file",
        "pw",
    ]);
    assert!(stderr.contains("not part of"), "{stderr}");
    env.ok(&[
        "tx",
        "sign",
        "--file",
        "t1.json",
        "--key",
        "k2.json",
        "--password-file",
        "pw",
    ]);
    assert!(
        env.ok(&["tx", "show", "--file", "t1.json"])
            .contains("2 of 2 needed")
    );
    let out = env.ok(&["tx", "submit", "--file", "t1.json", "--wait"]);
    assert!(out.contains("included in block"), "{out}");
    assert_eq!(env.balance(&bob), 10);
    assert_eq!(env.account(&multisig).auth.unwrap().threshold, 2);

    env.ok(&[
        "transfer",
        "--account",
        &multisig,
        "--to",
        &bob,
        "--amount",
        "5",
        "--unsigned-out",
        "t2.json",
    ]);
    env.ok(&[
        "tx",
        "sign",
        "--file",
        "t2.json",
        "--key",
        "k3.json",
        "--password-file",
        "pw",
    ]);
    env.ok(&[
        "tx",
        "sign",
        "--file",
        "t2.json",
        "--key",
        "k1.json",
        "--password-file",
        "pw",
    ]);
    env.ok(&["tx", "submit", "--file", "t2.json", "--wait"]);
    assert_eq!(env.balance(&bob), 15);

    env.ok(&[
        "policy",
        "new",
        "--threshold",
        "1",
        "--key",
        "k1.json",
        "--out",
        "other.json",
    ]);
    let fresh = env.new_key("fresh", "ml-dsa-65");
    env.ok(&[
        "transfer",
        "--key",
        "alice.json",
        "--to",
        &fresh,
        "--amount",
        "100000",
        "--password-file",
        "pw",
        "--wait",
    ]);
    let stderr = env.err(&[
        "transfer",
        "--account",
        &fresh,
        "--policy",
        "other.json",
        "--to",
        &alice,
        "--amount",
        "1",
        "--unsigned-out",
        "t3.json",
    ]);
    assert!(stderr.contains("does not control"), "{stderr}");
}

#[test]
fn validators_change_the_set_through_the_cli() {
    let (env, _alice) = setup();
    let shown: serde_json::Value = serde_json::from_str(&env.ok(&["validators", "show"])).unwrap();
    assert_eq!(shown["epoch"], 0);
    assert_eq!(shown["validators"].as_array().unwrap().len(), 1);
    let governance = shown["governance"].as_str().unwrap().to_owned();

    env.ok(&[
        "transfer",
        "--key",
        "alice.json",
        "--to",
        &governance,
        "--amount",
        "1000000",
        "--password-file",
        "pw",
        "--wait",
    ]);

    let stderr = env.err(&[
        "validators",
        "propose",
        "--key",
        "producer.json",
        "--out",
        "change.json",
    ]);
    assert!(stderr.contains("one --payout for each"), "{stderr}");
    let payout = env.new_key("payout", "ml-dsa-65");
    let out = env.ok(&[
        "validators",
        "propose",
        "--key",
        "producer.json",
        "--payout",
        &payout,
        "--out",
        "change.json",
    ]);
    assert!(out.contains("1 of the 1 current validators"), "{out}");
    let stderr = env.err(&[
        "tx",
        "sign",
        "--file",
        "change.json",
        "--key",
        "alice.json",
        "--password-file",
        "pw",
    ]);
    assert!(
        stderr.contains("not part of"),
        "only validators can sign: {stderr}"
    );
    env.ok(&[
        "tx",
        "sign",
        "--file",
        "change.json",
        "--key",
        "producer.json",
        "--password-file",
        "pw",
    ]);
    env.ok(&["tx", "submit", "--file", "change.json", "--wait"]);

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let shown: serde_json::Value =
            serde_json::from_str(&env.ok(&["validators", "show"])).unwrap();
        if shown["epoch"] == 1 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the epoch did not change"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let bob = env.new_key("bob", "ml-dsa-65");
    env.ok(&[
        "transfer",
        "--key",
        "alice.json",
        "--to",
        &bob,
        "--amount",
        "1",
        "--password-file",
        "pw",
        "--wait",
    ]);
    assert_eq!(env.balance(&bob), 1);

    let old = env
        .ok(&["address", "--key", "producer.json"])
        .trim()
        .to_owned();
    let reward: serde_json::Value =
        serde_json::from_str(&env.ok(&["validators", "rewards", &old])).unwrap();
    assert_eq!(reward["seated"], false);
    let earned: u128 = reward["claimable"].as_str().unwrap().parse().unwrap();
    assert!(earned > 0);
    let sent = env.ok(&[
        "validators",
        "claim",
        "--payout",
        &old,
        "--key",
        "alice.json",
        "--password-file",
        "pw",
        "--wait",
    ]);
    assert!(sent.contains("included in block"), "{sent}");
    assert_eq!(env.balance(&old), earned);

    let rewards: serde_json::Value =
        serde_json::from_str(&env.ok(&["validators", "rewards"])).unwrap();
    assert_eq!(rewards["validators"][0]["payout"], payout.as_str());
    assert!(
        rewards["balance"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap()
            > 0
    );
    let err = env.err(&[
        "validators",
        "claim",
        "--payout",
        &bob,
        "--key",
        "alice.json",
        "--password-file",
        "pw",
    ]);
    assert!(err.contains("nothing to claim"), "{err}");
}

#[test]
fn a_contract_is_deployed_called_and_read() {
    let (env, alice) = setup_with(10_000_000);
    let bob = env.new_key("bob", "ml-dsa-65");
    let pw = ["--password-file", "pw", "--wait"];
    let wasm = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/token.wasm"
    );

    let stderr = env.err(&[
        "contract",
        "deploy",
        wasm,
        "--arg",
        "nonsense",
        "--out",
        "token.json",
    ]);
    assert!(stderr.contains("not an address"), "{stderr}");

    env.ok(&[
        "contract",
        "deploy",
        wasm,
        "--arg",
        &alice,
        "--arg",
        "1000",
        "--arg",
        "\"Test Token\"",
        "--arg",
        "\"TUSD\"",
        "--arg",
        "u64:6",
        "--out",
        "token.json",
    ]);
    env.ok(&[
        "tx",
        "sign",
        "--file",
        "token.json",
        "--key",
        "producer.json",
        "--password-file",
        "pw",
    ]);
    let out = env.ok(&["tx", "submit", "--file", "token.json", "--wait"]);
    let contract = out
        .lines()
        .find_map(|line| line.strip_prefix("contract "))
        .unwrap_or_else(|| panic!("no contract in: {out}"))
        .to_owned();

    let shown: serde_json::Value =
        serde_json::from_str(&env.ok(&["contract", "show", &contract])).unwrap();
    assert!(shown["code_size"].as_u64().unwrap() > 1_000);

    let read = |function: String| env.ok(&["contract", "view", &function, "--as", "u128"]);
    assert_eq!(
        read(format!("{contract}.balance_of({alice})")).trim(),
        "1000"
    );

    let out = env.ok(&[
        &[
            "contract",
            "call",
            &format!("{contract}.transfer({bob}, 300)"),
        ],
        &["--key", "alice.json"][..],
        &pw[..],
    ]
    .concat());
    assert!(out.contains("event transfer"), "{out}");
    assert_eq!(
        read(format!("{contract}.balance_of({alice})")).trim(),
        "700"
    );
    assert_eq!(read(format!("{contract}.balance_of({bob})")).trim(), "300");

    let stderr = env.err(
        &[
            &[
                "contract",
                "call",
                &format!("{contract}.transfer({bob}, 5000)"),
            ],
            &["--key", "alice.json"][..],
            &pw[..],
        ]
        .concat(),
    );
    assert!(stderr.contains("reverted: balance too low"), "{stderr}");
    assert_eq!(read(format!("{contract}.total_supply()")).trim(), "1000");
    let name = env.ok(&[
        "contract",
        "view",
        &format!("{contract}.symbol()"),
        "--as",
        "text",
    ]);
    assert_eq!(name.trim(), "TUSD");

    let stderr = env.err(&["contract", "view", &format!("{alice}.balance_of({alice})")]);
    assert!(stderr.contains("no contract at that address"), "{stderr}");
}
