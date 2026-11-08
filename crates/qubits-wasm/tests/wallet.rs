use qubits_crypto::keystore::KdfParams;
use qubits_execution::{BlockEnv, Executor, genesis_writes, read_account};
use qubits_state::MemoryState;
use qubits_types::rpc::{AccountResponse, BalanceView, StatusResponse};
use qubits_types::*;
use qubits_wasm::*;

const PASSWORD: &str = "a long enough password";

fn fast() -> KdfParams {
    KdfParams::new(256, 1, 1).unwrap()
}

const VALID_UNTIL: u64 = 1 << 53;

fn new_key(scheme: &str) -> CreatedKey {
    create_key_with(scheme, PASSWORD, fast()).unwrap()
}

fn status() -> StatusResponse {
    StatusResponse {
        chain_id: "qubits-test".into(),
        genesis_hash: Hash::ZERO,
        height: 0,
        latest_hash: Hash::ZERO,
        latest_timestamp_ms: 1_000,
        state_root: Hash::ZERO,
        min_fee_per_byte: 2,
        mempool_size: 0,
        state_from: 0,
        blocks_from: 0,
    }
}

fn fresh_account(address: Address) -> AccountResponse {
    AccountResponse {
        address,
        exists: true,
        nonce: 0,
        auth: None,
        vault: None,
        balances: vec![BalanceView {
            asset: AssetId::NATIVE,
            amount: 1_000_000,
        }],
        pending: vec![],
    }
}

fn to_json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap()
}

#[test]
fn created_key_round_trips_through_key_info() {
    for scheme in ["ml-dsa-65", "slh-dsa-sha2-192s"] {
        let key = new_key(scheme);
        let info: KeyInfo = serde_json::from_str(&key_info(&key.keystore).unwrap()).unwrap();
        assert_eq!(info, key.info);
        assert_eq!(info.scheme.name(), scheme);
        assert!(info.address.to_string().starts_with("qb1"));
        assert!(qubits_crypto::keystore::EncryptedKey::from_json(&key.keystore).is_ok());
    }
}

#[test]
fn key_creation_checks_input() {
    assert!(
        create_key_with("ml-dsa-65", "short", fast())
            .unwrap_err()
            .contains("at least 12")
    );
    assert!(
        create_key_with("ed25519", PASSWORD, fast())
            .unwrap_err()
            .contains("unknown")
    );
    assert!(key_info("{}").is_err());
}

#[test]
fn wrong_password_is_reported_plainly() {
    let key = new_key("ml-dsa-65");
    assert_eq!(
        unlock(&key.keystore, "not the password").unwrap_err(),
        "wrong password"
    );
    assert!(unlock(&key.keystore, PASSWORD).is_ok());
}

#[test]
fn signed_transfer_is_valid_on_chain() {
    let key = new_key("ml-dsa-65");
    let bob = new_key("ml-dsa-65").info.address;
    let payload = Payload::Transfer {
        to: bob,
        asset: AssetId::NATIVE,
        amount: 1234,
    };

    let signed: Signed = serde_json::from_str(
        &sign(
            &to_json(&status()),
            &to_json(&fresh_account(key.info.address)),
            &key.keystore,
            PASSWORD,
            "owner",
            &to_json(&payload),
            VALID_UNTIL,
        )
        .unwrap(),
    )
    .unwrap();

    let stx = SignedTransaction::decode(&hex::decode(&signed.transaction).unwrap()).unwrap();
    assert_eq!(stx.id().to_string(), signed.id);
    assert_eq!(stx.tx.payload, payload);
    assert!(stx.reveal.is_some(), "first transaction reveals the policy");
    let size = signed.transaction.len() / 2;
    assert_eq!(
        signed.fee,
        (2 * size as u128).to_string(),
        "min_fee_per_byte × size"
    );

    let genesis = Genesis {
        chain_id: "qubits-test".into(),
        timestamp_ms: 1_000,
        params: ChainParams {
            min_fee_per_byte: 2,
            max_block_transactions: 10,
        },
        validators: vec![qubits_types::Validator::self_paid(
            qubits_crypto::SecretKey::generate(qubits_crypto::SchemeId::MlDsa65)
                .unwrap()
                .public_key()
                .clone(),
        )],
        accounts: vec![GenesisAccount {
            address: key.info.address,
            balance: 1_000_000,
        }],
    };
    let mut state = MemoryState::new();
    state.apply(&genesis_writes(&genesis));
    let env = BlockEnv {
        genesis_hash: Hash::ZERO,
        height: 1,
        timestamp_ms: 2_000,
        params: genesis.params.clone(),
    };
    let mut executor = Executor::new(&state, env);
    executor.apply(&stx).unwrap();
    state.apply(&executor.into_writes());
    let bob_account = read_account(&state, &bob).unwrap().unwrap();
    assert_eq!(bob_account.balance(AssetId::NATIVE), 1234);
}

#[test]
fn decode_shows_what_was_signed() {
    let key = new_key("ml-dsa-65");
    let payload = Payload::SetVault {
        vault: Some(VaultPolicy {
            delay_ms: 86_400_000,
            recovery: None,
        }),
    };
    let signed: Signed = serde_json::from_str(
        &sign(
            &to_json(&status()),
            &to_json(&fresh_account(key.info.address)),
            &key.keystore,
            PASSWORD,
            "owner",
            &to_json(&payload),
            VALID_UNTIL,
        )
        .unwrap(),
    )
    .unwrap();
    let decoded: serde_json::Value =
        serde_json::from_str(&decode_transaction(&signed.transaction).unwrap()).unwrap();
    assert_eq!(decoded["id"], signed.id);
    assert_eq!(
        decoded["tx"]["payload"]["set_vault"]["vault"]["delay_ms"],
        86_400_000
    );
    assert_eq!(decoded["tx"]["fee"], signed.fee);
    assert!(decode_transaction("zz").is_err());
    assert!(decode_transaction("00").is_err());
}

#[test]
fn signing_errors_are_readable() {
    let key = new_key("ml-dsa-65");
    let other = new_key("ml-dsa-65");
    let payload = to_json(&Payload::CancelPending { id: 0 });
    let st = to_json(&status());

    let wrong_account = to_json(&fresh_account(other.info.address));
    let err = sign(
        &st,
        &wrong_account,
        &key.keystore,
        PASSWORD,
        "owner",
        &payload,
        VALID_UNTIL,
    )
    .unwrap_err();
    assert!(err.contains("does not control"), "{err}");

    let mine = to_json(&fresh_account(key.info.address));
    let err = sign(
        &st,
        &mine,
        &key.keystore,
        PASSWORD,
        "recovery",
        &payload,
        VALID_UNTIL,
    )
    .unwrap_err();
    assert!(err.contains("no recovery policy"), "{err}");

    let err = sign(
        &st,
        &mine,
        &key.keystore,
        "nope nope nope",
        "owner",
        &payload,
        VALID_UNTIL,
    )
    .unwrap_err();
    assert_eq!(err, "wrong password");

    let err = sign(
        &st,
        &mine,
        &key.keystore,
        PASSWORD,
        "admin",
        &payload,
        VALID_UNTIL,
    )
    .unwrap_err();
    assert!(err.contains("invalid role"), "{err}");

    let err = sign(
        &st,
        &mine,
        &key.keystore,
        PASSWORD,
        "owner",
        r#"{"mint":{}}"#,
        VALID_UNTIL,
    )
    .unwrap_err();
    assert!(err.contains("invalid payload"), "{err}");

    let mut missing = fresh_account(key.info.address);
    missing.exists = false;
    let err = sign(
        &st,
        &to_json(&missing),
        &key.keystore,
        PASSWORD,
        "owner",
        &payload,
        VALID_UNTIL,
    )
    .unwrap_err();
    assert!(err.contains("does not exist yet"), "{err}");
}

#[test]
fn addresses_and_public_keys_are_checked() {
    let key = new_key("slh-dsa-sha2-192s");
    let addr = key.info.address.to_string();
    assert_eq!(
        check_address(&format!("  {}  ", addr.to_uppercase())).unwrap(),
        addr
    );
    let mut typo = addr.clone();
    typo.replace_range(8..9, if &addr[8..9] == "q" { "p" } else { "q" });
    assert!(check_address(&typo).is_err());

    let info: KeyInfo =
        serde_json::from_str(&public_key_info(&key.info.public_key).unwrap()).unwrap();
    assert_eq!(info, key.info);
    assert!(public_key_info("01abcd").unwrap_err().contains("length"));
    assert!(public_key_info("xyz").is_err());
}
