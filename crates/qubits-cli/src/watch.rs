use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use qubits_types::Address;
use qubits_types::rpc::{TransactionResponse, WsEvent, WsRequest};
use tungstenite::Message;

/// Well over the node's 30 s between pings: silence this long means the connection is gone.
const QUIET: Duration = Duration::from_secs(75);

trait Io: Read + Write {}
impl<T: Read + Write> Io for T {}

/// Opens `/v1/ws` on the node at `base`, watches `address`, calls `ready` once the request is
/// sent and `each` for every transaction that names the address, until the connection ends.
pub fn watch(
    base: &str,
    address: &Address,
    ready: impl FnOnce(),
    mut each: impl FnMut(TransactionResponse) -> Result<()>,
) -> Result<()> {
    let (secure, rest) = match base.split_once("://") {
        Some(("https", rest)) => (true, rest),
        Some(("http", rest)) => (false, rest),
        _ => bail!("--rpc must start with http:// or https://"),
    };
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    // "[::1]" has colons but no port
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => authority,
    };
    let target = if host.len() == authority.len() {
        format!("{authority}:{}", if secure { 443 } else { 80 })
    } else {
        authority.to_owned()
    };
    let tcp = TcpStream::connect(&target).with_context(|| format!("connecting to {base}"))?;
    tcp.set_read_timeout(Some(QUIET))?;
    let stream: Box<dyn Io> = if secure {
        Box::new(tls(
            host.trim_start_matches('[').trim_end_matches(']'),
            tcp,
        )?)
    } else {
        Box::new(tcp)
    };
    let prefix = if path.is_empty() {
        String::new()
    } else {
        format!("/{path}")
    };
    let url = format!(
        "{}://{authority}{prefix}/v1/ws",
        if secure { "wss" } else { "ws" }
    );
    let (mut socket, _) =
        tungstenite::client(url.as_str(), stream).map_err(|e| anyhow!("opening {url}: {e}"))?;
    let request = WsRequest::WatchAddress { address: *address };
    socket.send(Message::text(serde_json::to_string(&request)?))?;
    ready();
    loop {
        let message = socket.read().map_err(|e| match e {
            tungstenite::Error::Io(io)
                if matches!(io.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                anyhow!("the node went quiet for {} s", QUIET.as_secs())
            }
            other => anyhow!("the connection to {url} failed: {other}"),
        })?;
        match message {
            Message::Text(text) => match serde_json::from_str::<WsEvent>(&text) {
                Ok(WsEvent::AddressTransaction { transaction, .. }) => each(*transaction)?,
                Ok(WsEvent::Error { error }) if error.contains("unknown variant") => {
                    bail!("the node at {base} can't watch addresses; it needs 0.2.7 or later")
                }
                Ok(WsEvent::Error { error }) => bail!("node refused: {error}"),
                Ok(_) => {}
                Err(e) => bail!("unexpected message from the node: {e}"),
            },
            Message::Close(frame) => bail!(
                "the node closed the connection{}",
                frame.map(|f| format!(": {}", f.reason)).unwrap_or_default()
            ),
            _ => {}
        }
    }
}

/// The same TLS as the HTTP requests: rustls with ring and the webpki roots.
fn tls(
    host: &str,
    tcp: TcpStream,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .with_context(|| format!("{host} is not a host name"))?;
    let connection = rustls::ClientConnection::new(Arc::new(config), name)?;
    Ok(rustls::StreamOwned::new(connection, tcp))
}
