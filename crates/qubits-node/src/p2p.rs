//! Validator networking: TLS 1.3 with X25519MLKEM768, peers authenticated by an ML-DSA
//! signature over the TLS exporter.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Sender as InboxSender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use borsh::{BorshDeserialize, BorshSerialize};
use qubits_crypto::{Domain, PublicKey, SecretKey, Signature};
use qubits_types::Hash;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::network::{Envelope, Frame, MAX_MESSAGE_BYTES, Transport};

const QUEUE: usize = 4096;
const MAX_QUEUED_BYTES: usize = 256 * 1024 * 1024;
const MAX_UNHANDLED_BYTES: usize = 2 * 1024 * 1024;
const MAX_HELLO_BYTES: usize = 8 * 1024;
const MAX_HANDSHAKES: usize = 64;
const MAX_HANDSHAKES_PER_ADDRESS: usize = 4;
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
const SERVER_NAME: &str = "qubits-validator";
const EXPORTER_LABEL: &[u8] = b"EXPORTER-qubits-p2p-v1";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct P2pConfig {
    pub listen: SocketAddr,
    pub peers: BTreeMap<PublicKey, SocketAddr>,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
struct Hello {
    key: PublicKey,
    signature: Signature,
}

#[derive(BorshSerialize)]
struct HelloBytes<'a> {
    tag: &'static [u8],
    chain: &'a Hash,
    dialer: bool,
    key: &'a PublicKey,
    exporter: &'a [u8; 32],
}

fn hello_bytes(chain: &Hash, dialer: bool, key: &PublicKey, exporter: &[u8; 32]) -> Vec<u8> {
    let msg = HelloBytes {
        tag: b"qubits p2p hello v1",
        chain,
        dialer,
        key,
        exporter,
    };
    borsh::to_vec(&msg).expect("encoding cannot fail")
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        cipher_suites: vec![
            aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
            aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ],
        kx_groups: vec![aws_lc_rs::kx_group::X25519MLKEM768],
        ..aws_lc_rs::default_provider()
    })
}

fn server_config() -> std::io::Result<Arc<ServerConfig>> {
    let cert = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()])
        .map_err(std::io::Error::other)?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(std::io::Error::other)?
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .map_err(std::io::Error::other)?;
    Ok(Arc::new(config))
}

#[derive(Debug)]
// certificates are throwaway, identity comes from the hello signature
struct ExporterAuthenticated(Arc<CryptoProvider>);

impl ServerCertVerifier for ExporterAuthenticated {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not allowed".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn client_config() -> std::io::Result<Arc<ClientConfig>> {
    let provider = provider();
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(std::io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ExporterAuthenticated(provider)))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> std::io::Result<()> {
    w.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    w.write_all(bytes).await?;
    w.flush().await
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, max_len: usize) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > max_len {
        return Err(std::io::Error::other("frame too large"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

#[derive(Clone)]
pub(crate) struct Identity {
    pub(crate) chain: Hash,
    pub(crate) key: SecretKey,
    pub(crate) peers: BTreeSet<PublicKey>,
}

impl Identity {
    fn me(&self) -> &PublicKey {
        self.key.public_key()
    }

    fn hello(&self, dialer: bool, exporter: &[u8; 32]) -> Vec<u8> {
        let bytes = hello_bytes(&self.chain, dialer, self.me(), exporter);
        let signature = self
            .key
            .sign(Domain::Handshake, &bytes)
            .expect("signing cannot fail");
        borsh::to_vec(&Hello {
            key: self.me().clone(),
            signature,
        })
        .expect("encoding cannot fail")
    }

    fn check(
        &self,
        frame: &[u8],
        peer_dialed: bool,
        exporter: &[u8; 32],
    ) -> std::io::Result<PublicKey> {
        let hello: Hello =
            borsh::from_slice(frame).map_err(|_| std::io::Error::other("malformed hello"))?;
        if !self.peers.contains(&hello.key) {
            return Err(std::io::Error::other("not a configured validator"));
        }
        let bytes = hello_bytes(&self.chain, peer_dialed, &hello.key, exporter);
        hello
            .key
            .verify(Domain::Handshake, &bytes, &hello.signature)
            .map_err(|_| std::io::Error::other("bad hello signature"))?;
        Ok(hello.key)
    }
}

fn exporter<T>(conn: &rustls::ConnectionCommon<T>) -> std::io::Result<[u8; 32]> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, EXPORTER_LABEL, None)
        .map_err(std::io::Error::other)?;
    Ok(out)
}

pub(crate) type Stream = tokio_rustls::TlsStream<TcpStream>;

pub(crate) async fn dial(
    id: &Identity,
    addr: SocketAddr,
    expected: &PublicKey,
) -> std::io::Result<Stream> {
    let work = async {
        let tcp = TcpStream::connect(addr).await?;
        tcp.set_nodelay(true)?;
        let name = ServerName::try_from(SERVER_NAME).expect("valid server name");
        let mut tls = TlsConnector::from(client_config()?)
            .connect(name, tcp)
            .await?;
        let exporter = exporter(tls.get_ref().1)?;
        write_frame(&mut tls, &id.hello(true, &exporter)).await?;
        let hello = read_frame(&mut tls, MAX_HELLO_BYTES).await?;
        let peer = id.check(&hello, false, &exporter)?;
        if peer != *expected {
            return Err(std::io::Error::other(
                "connected to a different validator than expected",
            ));
        }
        Ok(tokio_rustls::TlsStream::Client(tls))
    };
    tokio::time::timeout(HANDSHAKE_TIMEOUT, work)
        .await
        .map_err(|_| std::io::Error::other("handshake timed out"))?
}

pub(crate) async fn accept(
    id: &Identity,
    tcp: TcpStream,
    config: Arc<ServerConfig>,
) -> std::io::Result<(PublicKey, Stream)> {
    let work = async {
        tcp.set_nodelay(true)?;
        let mut tls = TlsAcceptor::from(config).accept(tcp).await?;
        let exporter = exporter(tls.get_ref().1)?;
        let hello = read_frame(&mut tls, MAX_HELLO_BYTES).await?;
        let peer = id.check(&hello, true, &exporter)?;
        if peer > *id.me() {
            return Err(std::io::Error::other("validator should not dial us"));
        }
        write_frame(&mut tls, &id.hello(false, &exporter)).await?;
        Ok((peer, tokio_rustls::TlsStream::Server(tls)))
    };
    tokio::time::timeout(HANDSHAKE_TIMEOUT, work)
        .await
        .map_err(|_| std::io::Error::other("handshake timed out"))?
}

struct AddressSlot {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl AddressSlot {
    fn take(counts: &Arc<Mutex<HashMap<IpAddr, usize>>>, ip: IpAddr) -> Option<AddressSlot> {
        let mut held = crate::lock(counts);
        let count = held.entry(ip).or_default();
        if *count >= MAX_HANDSHAKES_PER_ADDRESS {
            return None;
        }
        *count += 1;
        Some(AddressSlot {
            counts: counts.clone(),
            ip,
        })
    }
}

impl Drop for AddressSlot {
    fn drop(&mut self) {
        let mut held = crate::lock(&self.counts);
        if let Some(count) = held.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                held.remove(&self.ip);
            }
        }
    }
}

struct Outgoing {
    queue: mpsc::Sender<Vec<u8>>,
    bytes: Arc<AtomicUsize>,
}

impl Outgoing {
    fn push(&self, frame: Vec<u8>) {
        let len = frame.len();
        if self.bytes.fetch_add(len, Ordering::Relaxed) + len > MAX_QUEUED_BYTES
            || self.queue.try_send(frame).is_err()
        {
            self.bytes.fetch_sub(len, Ordering::Relaxed);
        }
    }
}

pub struct TcpTransport {
    peers: BTreeMap<PublicKey, Outgoing>,
    connected: Arc<AtomicUsize>,
}

impl Transport for TcpTransport {
    fn send(&self, to: &PublicKey, bytes: Vec<u8>) {
        if let Some(peer) = self.peers.get(to) {
            peer.push(bytes);
        }
    }

    fn broadcast(&self, bytes: Vec<u8>) {
        for peer in self.peers.values() {
            peer.push(bytes.clone());
        }
    }

    fn connected(&self) -> usize {
        self.connected.load(Ordering::Relaxed)
    }
}

async fn run_connection(
    peer: PublicKey,
    stream: Stream,
    queue: &mut mpsc::Receiver<Vec<u8>>,
    queued: &AtomicUsize,
    replacements: &mut mpsc::Receiver<Stream>,
    inbox: &InboxSender<Envelope>,
) -> Option<Stream> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let inbox = inbox.clone();
    let mut reading = tokio::spawn(async move {
        let unhandled = Arc::new(AtomicUsize::new(0));
        while let Ok(frame) = read_frame(&mut reader, MAX_MESSAGE_BYTES).await {
            unhandled.fetch_add(frame.len(), Ordering::Relaxed);
            let frame = Frame::counted(frame, unhandled.clone());
            if inbox.send((peer.clone(), frame)).is_err() {
                return;
            }
            while unhandled.load(Ordering::Relaxed) > MAX_UNHANDLED_BYTES {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    });
    let next = loop {
        tokio::select! {
            frame = queue.recv() => match frame {
                Some(frame) => {
                    queued.fetch_sub(frame.len(), Ordering::Relaxed);
                    if write_frame(&mut writer, &frame).await.is_err() {
                        break None;
                    }
                }
                None => break None,
            },
            replacement = replacements.recv() => break replacement,
            _ = &mut reading => break None,
        }
    };
    reading.abort();
    next
}

pub(crate) async fn start(
    id: Identity,
    config: P2pConfig,
    inbox: InboxSender<Envelope>,
) -> std::io::Result<(Arc<TcpTransport>, SocketAddr)> {
    let listener = TcpListener::bind(config.listen).await?;
    let local = listener.local_addr()?;
    let server = server_config()?;
    let id = Arc::new(id);

    let connected = Arc::new(AtomicUsize::new(0));
    let mut outgoing = BTreeMap::new();
    let mut accepted = BTreeMap::new();
    for (peer, addr) in config.peers.clone() {
        if peer == *id.me() {
            continue;
        }
        let (queue_tx, mut queue_rx) = mpsc::channel::<Vec<u8>>(QUEUE);
        let (conn_tx, mut conn_rx) = mpsc::channel::<Stream>(4);
        let queued = Arc::new(AtomicUsize::new(0));
        outgoing.insert(
            peer.clone(),
            Outgoing {
                queue: queue_tx,
                bytes: queued.clone(),
            },
        );
        accepted.insert(peer.clone(), conn_tx);
        let label = short(&peer);
        let id = id.clone();
        let inbox = inbox.clone();
        let connected = connected.clone();
        tokio::spawn(async move {
            let mut backoff = Duration::from_millis(100);
            let mut next: Option<Stream> = None;
            loop {
                let stream = match next.take() {
                    Some(stream) => stream,
                    None if peer > *id.me() => match dial(&id, addr, &peer).await {
                        Ok(stream) => stream,
                        Err(e) => {
                            tracing::debug!(peer = %label, error = %e, "dial failed");
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(Duration::from_secs(5));
                            continue;
                        }
                    },
                    None => match conn_rx.recv().await {
                        Some(stream) => stream,
                        None => return,
                    },
                };
                backoff = Duration::from_millis(100);
                tracing::info!(peer = %label, "validator connected");
                connected.fetch_add(1, Ordering::Relaxed);
                next = run_connection(
                    peer.clone(),
                    stream,
                    &mut queue_rx,
                    &queued,
                    &mut conn_rx,
                    &inbox,
                )
                .await;
                connected.fetch_sub(1, Ordering::Relaxed);
                if next.is_none() {
                    tracing::info!(peer = %label, "validator disconnected");
                }
            }
        });
    }

    let accept_id = id.clone();
    let handshakes = Arc::new(Semaphore::new(MAX_HANDSHAKES));
    let addresses = Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn(async move {
        loop {
            let (tcp, from) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(e) => {
                    tracing::warn!(error = %e, "could not accept a connection");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                    continue;
                }
            };
            let Ok(permit) = handshakes.clone().try_acquire_owned() else {
                continue;
            };
            let Some(slot) = AddressSlot::take(&addresses, from.ip()) else {
                continue;
            };
            let id = accept_id.clone();
            let server = server.clone();
            let accepted = accepted.clone();
            tokio::spawn(async move {
                let authenticated = accept(&id, tcp, server).await;
                drop((permit, slot));
                match authenticated {
                    Ok((peer, stream)) => {
                        if let Some(conn) = accepted.get(&peer) {
                            let _ = conn.send(stream).await;
                        }
                    }
                    Err(e) => tracing::debug!(%from, error = %e, "refused connection"),
                }
            });
        }
    });

    let transport = TcpTransport {
        peers: outgoing,
        connected,
    };
    Ok((Arc::new(transport), local))
}

fn short(key: &PublicKey) -> String {
    hex::encode(&key.as_raw()[..6])
}

pub async fn connect(
    node: &crate::Node,
    key: SecretKey,
    config: P2pConfig,
) -> Result<(Arc<TcpTransport>, crate::network::Inbox, SocketAddr), crate::NodeError> {
    let peers = config.peers.keys().cloned().collect();
    let id = Identity {
        chain: node.genesis_hash(),
        key,
        peers,
    };
    let (inbox_tx, inbox) = std::sync::mpsc::channel();
    let (transport, addr) = start(id, config, inbox_tx)
        .await
        .map_err(|e| crate::NodeError::Config(format!("network: {e}")))?;
    Ok((transport, inbox, addr))
}

#[cfg(test)]
mod tests {
    use qubits_crypto::SchemeId;

    use super::*;

    fn identities(n: usize) -> Vec<Identity> {
        let mut keys: Vec<SecretKey> = (0..n)
            .map(|i| SecretKey::from_seed(SchemeId::MlDsa65, &[i as u8 + 40; 32]).unwrap())
            .collect();
        keys.sort_by(|a, b| a.public_key().cmp(b.public_key()));
        let peers: BTreeSet<PublicKey> = keys.iter().map(|k| k.public_key().clone()).collect();
        keys.into_iter()
            .map(|key| Identity {
                chain: Hash([3; 32]),
                key,
                peers: peers.clone(),
            })
            .collect()
    }

    async fn listen() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    }

    async fn serve_once(
        id: Identity,
    ) -> (
        SocketAddr,
        tokio::task::JoinHandle<std::io::Result<(PublicKey, Stream)>>,
    ) {
        let (listener, addr) = listen().await;
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            accept(&id, tcp, server_config().unwrap()).await
        });
        (addr, task)
    }

    #[tokio::test]
    async fn handshake_uses_hybrid_pq_key_exchange_and_authenticates_both_sides() {
        let ids = identities(3);
        let (addr, server) = serve_once(ids[2].clone()).await;
        let stream = dial(&ids[0], addr, ids[2].me()).await.unwrap();
        let (peer, _) = server.await.unwrap().unwrap();
        assert_eq!(peer, *ids[0].me());
        let group = stream
            .get_ref()
            .1
            .negotiated_key_exchange_group()
            .unwrap()
            .name();
        assert_eq!(group, rustls::NamedGroup::X25519MLKEM768);
        assert_eq!(
            stream.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        let suite = stream.get_ref().1.negotiated_cipher_suite().unwrap();
        assert!(
            [
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            ]
            .contains(&suite.suite())
        );
    }

    fn classical() -> Arc<CryptoProvider> {
        Arc::new(CryptoProvider {
            kx_groups: vec![aws_lc_rs::kx_group::X25519],
            ..aws_lc_rs::default_provider()
        })
    }

    #[tokio::test]
    async fn a_client_without_the_hybrid_key_exchange_is_refused() {
        let ids = identities(2);
        let (addr, server) = serve_once(ids[1].clone()).await;
        let provider = classical();
        let config = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ExporterAuthenticated(provider)))
            .with_no_client_auth();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from(SERVER_NAME).unwrap();
        let connected = TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await;
        assert!(connected.is_err());
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn a_server_without_the_hybrid_key_exchange_is_refused() {
        let ids = identities(2);
        let (listener, addr) = listen().await;
        let cert = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()]).unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let config = ServerConfig::builder_with_provider(classical())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)
            .unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            TlsAcceptor::from(Arc::new(config))
                .accept(tcp)
                .await
                .is_ok()
        });
        assert!(dial(&ids[0], addr, ids[1].me()).await.is_err());
        assert!(!server.await.unwrap());
    }

    #[tokio::test]
    async fn a_hello_may_not_be_large() {
        let (client, server) = tokio::io::duplex(64);
        let (mut r, mut w) = (server, client);
        w.write_all(&((MAX_HELLO_BYTES as u32) + 1).to_be_bytes())
            .await
            .unwrap();
        assert!(read_frame(&mut r, MAX_HELLO_BYTES).await.is_err());
        assert!(MAX_HELLO_BYTES >= identities(1)[0].hello(true, &[0; 32]).len());
    }

    #[test]
    fn handshakes_are_limited_per_address() {
        let counts = Arc::new(Mutex::new(HashMap::new()));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let held: Vec<_> = (0..MAX_HANDSHAKES_PER_ADDRESS)
            .map(|_| AddressSlot::take(&counts, ip).unwrap())
            .collect();
        assert!(AddressSlot::take(&counts, ip).is_none());
        assert!(AddressSlot::take(&counts, "10.0.0.2".parse().unwrap()).is_some());
        drop(held);
        assert!(crate::lock(&counts).is_empty());
        assert!(AddressSlot::take(&counts, ip).is_some());
    }

    #[test]
    fn the_send_queue_is_limited_in_bytes() {
        let (queue, mut rx) = mpsc::channel(QUEUE);
        let out = Outgoing {
            queue,
            bytes: Arc::new(AtomicUsize::new(0)),
        };
        let chunk = MAX_MESSAGE_BYTES;
        for _ in 0..MAX_QUEUED_BYTES / chunk {
            out.push(vec![0; chunk]);
        }
        let full = out.bytes.load(Ordering::Relaxed);
        assert!(full <= MAX_QUEUED_BYTES);
        out.push(vec![0; chunk]);
        assert_eq!(
            out.bytes.load(Ordering::Relaxed),
            full,
            "over the limit: dropped"
        );
        rx.close();
    }

    #[tokio::test]
    async fn dialing_the_wrong_validator_fails() {
        let ids = identities(3);
        let (addr, _server) = serve_once(ids[2].clone()).await;
        let err = dial(&ids[0], addr, ids[1].me()).await.unwrap_err();
        assert!(err.to_string().contains("different validator"), "{err}");
    }

    #[tokio::test]
    async fn outsiders_and_impersonators_are_refused() {
        let ids = identities(3);
        let mut outsider = ids[0].clone();
        outsider.key = SecretKey::from_seed(SchemeId::MlDsa65, &[1; 32]).unwrap();
        let (addr, server) = serve_once(ids[2].clone()).await;
        let _ = dial(&outsider, addr, ids[2].me()).await;
        assert!(
            server
                .await
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("not a configured validator")
        );

        let mut other_chain = ids[0].clone();
        other_chain.chain = Hash([4; 32]);
        let (addr, server) = serve_once(ids[2].clone()).await;
        let _ = dial(&other_chain, addr, ids[2].me()).await;
        assert!(
            server
                .await
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("bad hello signature")
        );
    }

    #[tokio::test]
    async fn the_higher_key_may_not_dial_the_lower_one() {
        let ids = identities(3);
        let (addr, server) = serve_once(ids[1].clone()).await;
        let _ = dial(&ids[2], addr, ids[1].me()).await;
        assert!(
            server
                .await
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("should not dial")
        );
    }

    #[tokio::test]
    async fn oversized_frames_are_refused() {
        let (client, server) = tokio::io::duplex(64);
        let (mut r, mut w) = (server, client);
        w.write_all(&((MAX_MESSAGE_BYTES as u32) + 1).to_be_bytes())
            .await
            .unwrap();
        assert!(read_frame(&mut r, MAX_MESSAGE_BYTES).await.is_err());
    }
}
