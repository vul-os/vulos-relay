//! The box↔adapter reverse tunnel (REACH profile §2, REACH-1/-2/-5).
//!
//! Shape, mirrored from the Go relay this replaces (`tunnel/server/control.go`
//! dials `yamux.Client(conn, ...)`): the box dials the adapter and holds the
//! connection open; the **adapter is the yamux client** and opens one stream
//! per inbound public connection it needs to forward, the box accepts each as
//! an inbound yamux stream and connects it to its own allow-listed local
//! service. This is inverted from a "server accepts streams" mental model on
//! purpose — the box, not the adapter, is unreachable/NATed, so the box must be
//! the one holding the long-lived outbound connection open.
//!
//! What is different from the Go relay (the content-blindness fix, REACH-1):
//! the adapter never terminates TLS and never parses anything past the
//! ClientHello's SNI (`crate::sni`). Every byte placed on a tunnel stream is
//! ciphertext the adapter forwards, not HTTP it parses and re-emits.
//!
//! ## REACH-2 status — TODO, tracked honestly
//!
//! REACH-2 mandates the box↔adapter leg be mutually authenticated to the box's
//! `IK` via DMTAP-Auth over a libp2p Noise-secured transport. That requires
//! `kotva-core` identity types, which are not yet pinned in this workspace
//! (`lib.rs` module table, HANDOVER §Guardrails-1). **This first cut accepts a
//! plain TCP control connection with no cryptographic authentication of the
//! box's identity at all** — any TCP client that completes the tiny
//! [`Registration`] handshake below can register a name. This is a real,
//! unfixed gap versus REACH-2, not a partial mitigation; it MUST be closed
//! before this crate is used against a public listener. Tracked for the
//! `auth` module in `lib.rs`'s module-plan table.
//!
//! Similarly, REACH-5's allow-list is carried today as free-form strings
//! declared by the box in its own [`Registration`] frame with no independent
//! verification — a box can currently declare whatever it likes. Real
//! enforcement (the adapter refusing to honor a service claim it cannot trust)
//! also waits on the `auth` seam.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::task::Poll;

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use yamux::{Config as YamuxConfig, Connection, ConnectionError, Mode};

/// A single yamux stream opened on a box's tunnel, wrapped so it can be used
/// with `tokio::io` (splicing, `copy_bidirectional`) directly. It carries
/// ciphertext only — the adapter never inspects it (REACH-1).
pub type TunnelStream = Compat<yamux::Stream>;

/// Bound on the length of any string field in the registration handshake
/// (REACH-6-style fail-closed guard against an adversarial/broken box holding
/// the control connection half-open while trickling an unbounded name).
const MAX_REGISTRATION_FIELD_BYTES: usize = 4096;
/// Bound on how many service entries one registration may declare.
const MAX_REGISTRATION_SERVICES: usize = 256;

#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("tunnel connection is closed")]
    Closed,
    #[error("yamux connection error: {0}")]
    Yamux(#[from] ConnectionError),
    #[error("I/O error on tunnel control connection: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed registration frame: {0}")]
    MalformedRegistration(&'static str),
}

/// What a box declares when it dials in to establish its reverse tunnel
/// (REACH-5: the box, not the adapter, states the service allow-list). Framed
/// as a tiny length-prefixed wire format directly on the TCP control
/// connection, before the yamux session starts on the same socket:
///
/// ```text
/// u16 name_len            | name bytes (UTF-8 SNI hostname this tunnel serves)
/// u16 service_count       | for each: u16 service_len | service bytes (UTF-8)
/// ```
#[derive(Debug, Clone)]
pub struct Registration {
    /// The SNI hostname this tunnel is willing to serve.
    pub name: String,
    /// The explicit allow-list of local services the box will forward
    /// tunneled streams to (REACH-5, default-deny — anything not listed here
    /// is out of scope for this tunnel). Opaque identifiers from the
    /// adapter's point of view (e.g. `"443"`, `"git-ssh"`); the adapter does
    /// not interpret them, it only checks membership (`ingress.rs`).
    pub allowed_services: HashSet<String>,
}

async fn read_length_prefixed_string(
    stream: &mut TcpStream,
) -> Result<String, TunnelError> {
    let len = stream.read_u16().await? as usize;
    if len > MAX_REGISTRATION_FIELD_BYTES {
        return Err(TunnelError::MalformedRegistration("field exceeds max length"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    String::from_utf8(buf).map_err(|_| TunnelError::MalformedRegistration("field is not UTF-8"))
}

/// Read a [`Registration`] frame off a freshly-accepted box control connection.
/// The socket is left positioned exactly at the first byte after the frame,
/// ready to be handed to yamux — no buffering layer is introduced that could
/// strand bytes the mux needs to see.
pub async fn read_registration(stream: &mut TcpStream) -> Result<Registration, TunnelError> {
    let name = read_length_prefixed_string(stream).await?;
    if name.is_empty() {
        return Err(TunnelError::MalformedRegistration("name is empty"));
    }
    let service_count = stream.read_u16().await? as usize;
    if service_count > MAX_REGISTRATION_SERVICES {
        return Err(TunnelError::MalformedRegistration("too many declared services"));
    }
    let mut allowed_services = HashSet::with_capacity(service_count);
    for _ in 0..service_count {
        allowed_services.insert(read_length_prefixed_string(stream).await?);
    }
    Ok(Registration {
        name,
        allowed_services,
    })
}

/// Write a [`Registration`] frame — the box side of the handshake. Exposed so
/// tests (and, eventually, the real box agent) can drive the same wire format
/// `read_registration` expects.
pub async fn write_registration(
    stream: &mut TcpStream,
    reg: &Registration,
) -> Result<(), TunnelError> {
    stream.write_u16(reg.name.len() as u16).await?;
    stream.write_all(reg.name.as_bytes()).await?;
    stream.write_u16(reg.allowed_services.len() as u16).await?;
    for svc in &reg.allowed_services {
        stream.write_u16(svc.len() as u16).await?;
        stream.write_all(svc.as_bytes()).await?;
    }
    Ok(())
}

type OpenReply = oneshot::Sender<Result<yamux::Stream, TunnelError>>;

/// A live handle to one box's reverse tunnel: cloneable, cheap, and the only
/// thing callers need to open a new stream onto the box (REACH-1's "adapter
/// opens one stream per inbound connection"). The actual yamux `Connection` is
/// owned and driven exclusively by a background task spawned in
/// [`TunnelHandle::spawn`] — nothing outside that task ever touches it
/// directly, which is what makes this handle `Clone + Send + Sync` despite
/// yamux's `Connection` itself requiring `&mut` for everything.
#[derive(Clone)]
pub struct TunnelHandle {
    open_tx: mpsc::UnboundedSender<OpenReply>,
}

impl TunnelHandle {
    /// Take ownership of an already-accepted box control connection (with the
    /// [`Registration`] frame already consumed off the front of it) and spawn
    /// the background task that drives its yamux session. The adapter acts as
    /// the yamux **client** on this connection (see module docs) — it is the
    /// side that opens streams; the box accepts them.
    ///
    /// Returns the handle plus a [`tokio::task::JoinHandle`] that resolves
    /// when the underlying connection ends (box disconnect, I/O error, or the
    /// last clone of the returned handle being dropped) — callers use this to
    /// know when to deregister the tunnel (see `ingress::AdapterServer::accept_box_connection`).
    pub fn spawn(socket: TcpStream) -> (Self, tokio::task::JoinHandle<()>) {
        let io = socket.compat();
        let conn = Connection::new(io, YamuxConfig::default(), Mode::Client);
        let (open_tx, open_rx) = mpsc::unbounded_channel();
        let join = tokio::spawn(drive(conn, open_rx));
        (Self { open_tx }, join)
    }

    /// Open a new yamux stream on this tunnel — one call per inbound public
    /// connection the ingress listener is forwarding (REACH-1). Ready to be
    /// used directly as a `tokio::io::AsyncRead + AsyncWrite` via
    /// [`TunnelStream`]'s `Compat` wrapper.
    pub async fn open_stream(&self) -> Result<TunnelStream, TunnelError> {
        let (tx, rx) = oneshot::channel();
        self.open_tx
            .send(tx)
            .map_err(|_| TunnelError::Closed)?;
        let stream = rx.await.map_err(|_| TunnelError::Closed)??;
        Ok(stream.compat())
    }
}

/// Drives one box's yamux `Connection` to completion. This is the sole task
/// that ever calls into the `Connection` — yamux's `poll_next_inbound` is
/// documented as needing to be polled repeatedly for *any* stream on the
/// connection (inbound or outbound) to make progress, since stream reads/
/// writes are relayed through the connection's internal actor loop rather
/// than touching the socket directly. So this loop is not merely "wait for
/// inbound streams" — it is the engine that also flushes bytes queued by
/// outbound streams opened via [`TunnelHandle::open_stream`].
async fn drive(
    mut conn: Connection<Compat<TcpStream>>,
    mut open_rx: mpsc::UnboundedReceiver<OpenReply>,
) {
    let mut pending: VecDeque<OpenReply> = VecDeque::new();
    let mut open_rx_closed = false;

    std::future::poll_fn(move |cx| -> Poll<()> {
        loop {
            let mut progressed = false;

            // Pull in any newly-requested stream opens (non-blocking).
            if !open_rx_closed {
                match open_rx.poll_recv(cx) {
                    Poll::Ready(Some(reply)) => {
                        pending.push_back(reply);
                        progressed = true;
                    }
                    Poll::Ready(None) => {
                        // The last TunnelHandle was dropped: no more opens will
                        // ever be requested. Keep driving existing streams
                        // (poll_next_inbound below) until the connection itself
                        // ends; just stop polling this channel again.
                        open_rx_closed = true;
                        progressed = true;
                    }
                    Poll::Pending => {}
                }
            }

            // Service the oldest pending open request, if any.
            if !pending.is_empty() {
                match conn.poll_new_outbound(cx) {
                    Poll::Ready(res) => {
                        let reply = pending.pop_front().expect("checked non-empty above");
                        let _ = reply.send(res.map_err(TunnelError::from));
                        progressed = true;
                    }
                    Poll::Pending => {}
                }
            }

            // Drive the connection's actor loop. This both delivers inbound
            // streams (none expected in this design; see below) and is what
            // actually pumps queued writes/reads for every outbound stream
            // onto the socket.
            match conn.poll_next_inbound(cx) {
                Poll::Ready(Some(Ok(stream))) => {
                    // The box never opens a stream toward the adapter in this
                    // design (REACH-5: the adapter is the sole initiator, one
                    // stream per inbound public connection). Drop anything
                    // unexpected rather than serve it — fail closed, not
                    // fail open, on a protocol violation from the box side.
                    drop(stream);
                    progressed = true;
                }
                Poll::Ready(Some(Err(_))) | Poll::Ready(None) => {
                    while let Some(reply) = pending.pop_front() {
                        let _ = reply.send(Err(TunnelError::Closed));
                    }
                    return Poll::Ready(());
                }
                Poll::Pending => {}
            }

            if !progressed {
                return Poll::Pending;
            }
        }
    })
    .await;
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("name {0:?} is already registered to a live tunnel")]
    AlreadyRegistered(String),
}

/// The adapter's registration map: SNI hostname → the box tunnel serving it,
/// plus its declared service allow-list (REACH-5). Single-writer per name —
/// registering an already-live name is refused outright rather than silently
/// replacing the incumbent, so one box can never hijack another's name out
/// from under it (RESERVE, REACH-7's single-writer discipline applied to the
/// adapter's in-memory session table, the same shape as the Go relay's
/// `registry.add`).
#[derive(Clone, Default)]
pub struct TunnelRegistry {
    inner: Arc<Mutex<HashMap<String, RegisteredTunnel>>>,
}

#[derive(Clone)]
struct RegisteredTunnel {
    handle: TunnelHandle,
    allowed_services: HashSet<String>,
}

/// A registered tunnel as seen by a lookup: the handle to open streams on,
/// plus the service allow-list the ingress path must check before forwarding
/// (REACH-5 — the adapter never chooses the backend, it only forwards onto a
/// tunnel the box already declared for a specific service).
#[derive(Clone)]
pub struct TunnelLookup {
    pub handle: TunnelHandle,
    pub allowed_services: HashSet<String>,
}

impl TunnelRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a freshly-spawned tunnel for `registration.name`. Fails if the
    /// name already has a live tunnel — no hijacking, single-writer per name.
    /// Returns a guard whose drop deregisters the name; callers should hold it
    /// for the tunnel's lifetime (e.g. alongside the task driving its control
    /// connection).
    pub async fn register(
        &self,
        registration: &Registration,
        handle: TunnelHandle,
    ) -> Result<RegistrationGuard, RegistryError> {
        let mut map = self.inner.lock().await;
        if map.contains_key(&registration.name) {
            return Err(RegistryError::AlreadyRegistered(registration.name.clone()));
        }
        map.insert(
            registration.name.clone(),
            RegisteredTunnel {
                handle,
                allowed_services: registration.allowed_services.clone(),
            },
        );
        Ok(RegistrationGuard {
            registry: self.clone(),
            name: registration.name.clone(),
        })
    }

    /// Look up the live tunnel for `sni_name`, if any. Case-insensitive
    /// (DNS names are), matching the normalization a real zone lookup would
    /// need to do.
    pub async fn lookup(&self, sni_name: &str) -> Option<TunnelLookup> {
        let map = self.inner.lock().await;
        let key = sni_name.to_ascii_lowercase();
        map.get(&key).map(|t| TunnelLookup {
            handle: t.handle.clone(),
            allowed_services: t.allowed_services.clone(),
        })
    }

    async fn deregister(&self, name: &str) {
        self.inner.lock().await.remove(name);
    }
}

/// Holding this keeps `name` registered; dropping it removes the registration.
/// Deregistration on drop runs on a spawned task since `Drop` cannot be async —
/// acceptable here because the removal is a best-effort cleanup of in-memory,
/// rebuildable state (REACH profile §6: "subdomain registration is rebuildable
/// adapter operational state"), not a durable write.
pub struct RegistrationGuard {
    registry: TunnelRegistry,
    name: String,
}

impl std::fmt::Debug for RegistrationGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationGuard").field("name", &self.name).finish()
    }
}

impl Drop for RegistrationGuard {
    fn drop(&mut self) {
        let registry = self.registry.clone();
        let name = std::mem::take(&mut self.name);
        tokio::spawn(async move {
            registry.deregister(&name).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn registration_round_trips_over_a_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let reg = read_registration(&mut sock).await.unwrap();
            // Echo back what we saw as a sanity signal on the same socket
            // (unrelated to the wire format), then close.
            sock.write_all(b"ok").await.unwrap();
            reg
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut services = HashSet::new();
        services.insert("8443".to_string());
        services.insert("git-ssh".to_string());
        let reg = Registration {
            name: "svc.alice.reach.example".to_string(),
            allowed_services: services.clone(),
        };
        write_registration(&mut client, &reg).await.unwrap();

        let mut ack = [0u8; 2];
        client.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack, b"ok");

        let seen = server.await.unwrap();
        assert_eq!(seen.name, "svc.alice.reach.example");
        assert_eq!(seen.allowed_services, services);
    }

    #[tokio::test]
    async fn registry_refuses_a_second_writer_for_the_same_name() {
        let registry = TunnelRegistry::new();

        // register() only needs a TunnelHandle, which needs a real TcpStream to
        // spawn on.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client_sock = TcpStream::connect(addr).await.unwrap();
        let server_sock = accept.await.unwrap();
        let (handle1, _join) = TunnelHandle::spawn(server_sock);
        drop(client_sock);

        let reg = Registration {
            name: "dup.example".to_string(),
            allowed_services: HashSet::new(),
        };
        let _guard = registry.register(&reg, handle1.clone()).await.unwrap();

        let err = registry.register(&reg, handle1).await.unwrap_err();
        assert!(matches!(err, RegistryError::AlreadyRegistered(name) if name == "dup.example"));
    }

    #[tokio::test]
    async fn deregistering_frees_the_name_for_reuse() {
        let registry = TunnelRegistry::new();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client_sock = TcpStream::connect(addr).await.unwrap();
        let server_sock = accept.await.unwrap();
        let (handle, _join) = TunnelHandle::spawn(server_sock);
        drop(client_sock);

        let reg = Registration {
            name: "reuse.example".to_string(),
            allowed_services: HashSet::new(),
        };
        let guard = registry.register(&reg, handle.clone()).await.unwrap();
        assert!(registry.lookup("reuse.example").await.is_some());
        drop(guard);

        // Deregistration happens on a spawned task; give it a moment.
        for _ in 0..50 {
            if registry.lookup("reuse.example").await.is_none() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(registry.lookup("reuse.example").await.is_none());

        // The name can now be claimed again.
        let _guard2 = registry.register(&reg, handle).await.unwrap();
        assert!(registry.lookup("reuse.example").await.is_some());
    }
}
