use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use qubits_crypto::SecretKey;
use qubits_types::client::build_transaction;
use qubits_types::rpc::{
    AccountResponse, ContractResponse, ErrorResponse, RewardResponse, RewardsResponse,
    StatusResponse, SubmitRequest, SubmitResponse, TransactionResponse, TxStatus,
    ValidatorsResponse, ViewRequest,
};
use qubits_types::{Address, Hash, Payload, Receipt, Role, SignedTransaction};
use serde::de::DeserializeOwned;

pub struct Client {
    base: String,
    agent: ureq::Agent,
}

impl Client {
    pub fn new(base: &str) -> Self {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        Client {
            base: base.trim_end_matches('/').to_owned(),
            agent,
        }
    }

    fn read<T: DeserializeOwned>(&self, mut resp: ureq::http::Response<ureq::Body>) -> Result<T> {
        let status = resp.status();
        let body = resp
            .body_mut()
            .read_to_string()
            .context("reading node response")?;
        if status.is_success() {
            serde_json::from_str(&body).with_context(|| format!("unexpected node response: {body}"))
        } else {
            let message = serde_json::from_str::<ErrorResponse>(&body)
                .map(|e| e.error)
                .unwrap_or(body);
            Err(anyhow!("node refused ({}): {message}", status.as_u16()))
        }
    }

    fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{path}", self.base);
        let resp = self
            .agent
            .get(&url)
            .call()
            .with_context(|| format!("connecting to {url}"))?;
        self.read(resp)
    }

    pub fn status(&self) -> Result<StatusResponse> {
        self.get("/v1/status")
    }

    pub fn account(&self, address: &Address) -> Result<AccountResponse> {
        self.get(&format!("/v1/accounts/{address}"))
    }

    pub fn validators(&self) -> Result<ValidatorsResponse> {
        self.get("/v1/validators")
    }

    pub fn rewards(&self) -> Result<RewardsResponse> {
        self.get("/v1/rewards")
    }

    pub fn reward(&self, payout: &Address) -> Result<RewardResponse> {
        self.get(&format!("/v1/rewards/{payout}"))
    }

    pub fn contract(&self, address: &Address) -> Result<ContractResponse> {
        self.get(&format!("/v1/contracts/{address}"))
    }

    pub fn view(&self, address: &Address, request: &ViewRequest) -> Result<Receipt> {
        let url = format!("{}/v1/contracts/{address}/view", self.base);
        let resp = self
            .agent
            .post(&url)
            .send_json(request)
            .with_context(|| format!("connecting to {url}"))?;
        self.read(resp)
    }

    pub fn transaction(&self, id: &Hash) -> Result<TransactionResponse> {
        self.get(&format!("/v1/transactions/{id}"))
    }

    pub fn submit(&self, stx: &SignedTransaction) -> Result<Hash> {
        let url = format!("{}/v1/transactions", self.base);
        let body = SubmitRequest {
            transaction: hex::encode(stx.encode()),
        };
        let resp = self
            .agent
            .post(&url)
            .send_json(&body)
            .with_context(|| format!("connecting to {url}"))?;
        Ok(self.read::<SubmitResponse>(resp)?.id)
    }

    pub fn wait_included(&self, id: &Hash, timeout: Duration) -> Result<u64> {
        let start = Instant::now();
        loop {
            match self.transaction(id) {
                Ok(tx) if tx.status == TxStatus::Included => {
                    return tx
                        .block_height
                        .ok_or_else(|| anyhow!("included without a height"));
                }
                Ok(_) => {}
                Err(e) if start.elapsed() > timeout => return Err(e),
                Err(_) => {}
            }
            if start.elapsed() > timeout {
                bail!("transaction {id} not included after {}s", timeout.as_secs());
            }
            sleep(Duration::from_millis(200));
        }
    }
}

pub fn build(
    client: &Client,
    key: &SecretKey,
    account: Address,
    role: Role,
    payload: Payload,
    valid_until_ms: u64,
) -> Result<SignedTransaction> {
    let status = client.status()?;
    let state = client.account(&account)?;
    build_transaction(&status, &state, key, role, payload, valid_until_ms)
        .with_context(|| format!("{account}"))
}
