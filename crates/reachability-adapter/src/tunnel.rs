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
//! ## REACH-2 status — key-auth closed, transport security still open
//!
//! REACH-2 mandates the box↔adapter leg be mutually authenticated to the
//! box's `IK` over a libp2p Noise-secured transport. As of `src/auth.rs`
//! (`kotva-core` is now tag-pinned in this workspace) the **key-authentication**
//! half is closed: [`crate::ingress::AdapterServer::accept_box_connection`]
//! runs the REACH-2 challenge-response handshake ([`crate::auth::authenticate_box_connection`])
//! before any [`Registration`] is honored, and [`TunnelRegistry::register`]
//! below binds the name to the *authenticated* `IK` it returns, never the
//! bare claim. A box that cannot sign the adapter's nonce under the `IK` it
//! claims is rejected before its yamux session ever starts (fail closed,
//! REACH-6).
//!
//! **Still open, stated plainly (see `crate::auth` module docs for the full
//! disclosure):** the control connection carrying that handshake — and the
//! yamux session after it — is still **plain, unencrypted TCP**. Key-auth
//! proves *who* is on the other end; it does not make the channel itself
//! confidential or tamper-evident. The libp2p Noise transport-security layer
//! REACH-2 also calls for is not implemented by this crate. Do not point
//! this control listener at a network an on-path attacker can observe
//! without accepting that residual (which does not include impersonation —
//! only observation/DoS of the control leg — see `crate::auth`).
//!
//! REACH-5's allow-list is now carried inside the *authenticated*
//! [`Registration`] (the adapter knows which `IK` declared it), but its
//! contents remain a free-form, self-declared string set with no independent
//! verification beyond "the box that holds this `IK` said so" — the adapter
//! still does not check the declared services against anything external.

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
    /// `name` is already registered to a live tunnel owned by a **different** authenticated
    /// `IK` — refused outright, never silently replaced (REACH-7-style single-writer, RESERVE).
    /// This is the hijack case: a box that cannot prove it holds the incumbent's `IK` can never
    /// take over its name, no matter how it phrases the request.
    #[error("name {0:?} is already registered to a live tunnel owned by a different identity")]
    OwnedByDifferentIdentity(String),
}

/// The adapter's registration map: SNI hostname → the box tunnel serving it,
/// its declared service allow-list (REACH-5), and the **authenticated** `IK`
/// that owns the name (REACH-2). Single-writer *per (name, owning IK)*: a
/// different `IK` can never hijack or overwrite a name another `IK` holds
/// ([`RegistryError::OwnedByDifferentIdentity`]), but the **same** `IK`
/// re-registering (a reconnect/refresh after a network blip) is honored —
/// it has just re-proven possession of that exact key via a fresh REACH-2
/// handshake (`crate::auth`), so this is the legitimate owner reclaiming its
/// own name, not a hijack. This is RESERVE / REACH-7's single-writer
/// discipline applied to the adapter's in-memory session table, extended
/// from "per name" to "per name, bound to the identity that proved it".
#[derive(Clone, Default)]
pub struct TunnelRegistry {
    inner: Arc<Mutex<RegistryState>>,
}

#[derive(Default)]
struct RegistryState {
    tunnels: HashMap<String, RegisteredTunnel>,
    /// Monotonic counter, one value handed out per successful `register()` call. Lets
    /// [`RegistrationGuard::drop`] tell "the registration I own is still the live one" apart
    /// from "a same-IK refresh has since replaced it" — without this, a stale guard's
    /// best-effort cleanup could delete a newer, live registration out from under it (see
    /// `deregister` below).
    next_generation: u64,
}

struct RegisteredTunnel {
    handle: TunnelHandle,
    allowed_services: HashSet<String>,
    /// The authenticated owner (REACH-2) — raw Ed25519 public key bytes, the same
    /// representation `kotva_core::identity::IdentityKey::public()` returns.
    owner_ik: Vec<u8>,
    generation: u64,
}

/// A registered tunnel as seen by a lookup: the handle to open streams on,
/// plus the service allow-list the ingress path must check before forwarding
/// (REACH-5 — the adapter never chooses the backend, it only forwards onto a
/// tunnel the box already declared for a specific service). The owning `IK`
/// is deliberately not exposed here: the public ingress path authorizes on
/// name + service only (REACH-2 "authorize, never classify"), it has no use
/// for — and should never need — the identity behind a name it is routing.
#[derive(Clone)]
pub struct TunnelLookup {
    pub handle: TunnelHandle,
    pub allowed_services: HashSet<String>,
}

impl TunnelRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a freshly-spawned tunnel for `registration.name`, owned by the **authenticated**
    /// `owner_ik` (the `authenticated_ik` a successful `crate::auth::authenticate_box_connection`
    /// returned — never a bare, unverified claim). Fails with
    /// [`RegistryError::OwnedByDifferentIdentity`] if the name already has a live tunnel owned by
    /// a *different* `IK`; succeeds (replacing the entry) if it is owned by the *same* `IK` — a
    /// same-identity refresh, not a hijack. Returns a guard whose drop deregisters the name
    /// (unless a newer registration has since taken over, see `deregister`); callers should hold
    /// it for the tunnel's lifetime (e.g. alongside the task driving its control connection).
    pub async fn register(
        &self,
        registration: &Registration,
        owner_ik: &[u8],
        handle: TunnelHandle,
    ) -> Result<RegistrationGuard, RegistryError> {
        let mut state = self.inner.lock().await;
        if let Some(existing) = state.tunnels.get(&registration.name) {
            if existing.owner_ik != owner_ik {
                return Err(RegistryError::OwnedByDifferentIdentity(registration.name.clone()));
            }
        }
        let generation = state.next_generation;
        state.next_generation += 1;
        state.tunnels.insert(
            registration.name.clone(),
            RegisteredTunnel {
                handle,
                allowed_services: registration.allowed_services.clone(),
                owner_ik: owner_ik.to_vec(),
                generation,
            },
        );
        Ok(RegistrationGuard {
            registry: self.clone(),
            name: registration.name.clone(),
            generation,
        })
    }

    /// Look up the live tunnel for `sni_name`, if any. Case-insensitive
    /// (DNS names are), matching the normalization a real zone lookup would
    /// need to do.
    pub async fn lookup(&self, sni_name: &str) -> Option<TunnelLookup> {
        let state = self.inner.lock().await;
        let key = sni_name.to_ascii_lowercase();
        state.tunnels.get(&key).map(|t| TunnelLookup {
            handle: t.handle.clone(),
            allowed_services: t.allowed_services.clone(),
        })
    }

    /// Remove `name`'s registration, but only if it is still the exact registration this guard
    /// was issued for (`generation` matches). A same-`IK` refresh bumps the generation on its way
    /// in (`register` above), so the *old* connection's eventual cleanup here becomes a safe
    /// no-op instead of deleting the *new*, live registration it would otherwise collide with.
    async fn deregister(&self, name: &str, generation: u64) {
        let mut state = self.inner.lock().await;
        if let Some(existing) = state.tunnels.get(name) {
            if existing.generation == generation {
                state.tunnels.remove(name);
            }
        }
    }
}

/// Holding this keeps `name` registered; dropping it removes the registration
/// — unless a same-`IK` refresh has since re-registered the name (a newer
/// `generation`), in which case the drop is a safe no-op (see
/// [`TunnelRegistry::deregister`]). Deregistration on drop runs on a spawned
/// task since `Drop` cannot be async — acceptable here because the removal is
/// a best-effort cleanup of in-memory, rebuildable state (REACH profile §6:
/// "subdomain registration is rebuildable adapter operational state"), not a
/// durable write.
pub struct RegistrationGuard {
    registry: TunnelRegistry,
    name: String,
    generation: u64,
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
        let generation = self.generation;
        tokio::spawn(async move {
            registry.deregister(&name, generation).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// A live `TunnelHandle` backed by a real (throwaway) socket pair — `TunnelHandle::spawn`
    /// needs a real `TcpStream`, but these registry tests only care about registration bookkeeping,
    /// not the tunnel actually carrying traffic.
    async fn dummy_handle() -> TunnelHandle {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client_sock = TcpStream::connect(addr).await.unwrap();
        let server_sock = accept.await.unwrap();
        let (handle, _join) = TunnelHandle::spawn(server_sock);
        drop(client_sock);
        handle
    }

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
    async fn different_ik_cannot_hijack_a_name_registered_to_another_ik() {
        let registry = TunnelRegistry::new();
        let owner_a = vec![0xAA; 32];
        let owner_b = vec![0xBB; 32];

        let reg = Registration {
            name: "dup.example".to_string(),
            allowed_services: HashSet::new(),
        };
        let _guard = registry
            .register(&reg, &owner_a, dummy_handle().await)
            .await
            .unwrap();

        // A DIFFERENT authenticated identity trying to claim the same name — REACH-7-style
        // no-hijack, this MUST be refused, not silently replace the incumbent.
        let err = registry
            .register(&reg, &owner_b, dummy_handle().await)
            .await
            .unwrap_err();
        assert!(matches!(err, RegistryError::OwnedByDifferentIdentity(name) if name == "dup.example"));
    }

    #[tokio::test]
    async fn same_ik_can_refresh_its_own_registration() {
        let registry = TunnelRegistry::new();
        let owner = vec![0xCC; 32];

        let reg = Registration {
            name: "refresh.example".to_string(),
            allowed_services: HashSet::new(),
        };
        let _guard1 = registry
            .register(&reg, &owner, dummy_handle().await)
            .await
            .unwrap();

        // The SAME authenticated identity re-registering (a reconnect/refresh) is not a hijack
        // and MUST succeed — REACH-2 requires re-registration to re-authenticate to the same IK,
        // which this simulates by presenting the identical `owner` bytes.
        let _guard2 = registry
            .register(&reg, &owner, dummy_handle().await)
            .await
            .expect("a same-IK refresh must be permitted, not treated as a hijack");
        assert!(registry.lookup("refresh.example").await.is_some());
    }

    #[tokio::test]
    async fn stale_guard_from_a_superseded_registration_does_not_evict_the_refresh() {
        let registry = TunnelRegistry::new();
        let owner = vec![0xDD; 32];

        let reg = Registration {
            name: "stale.example".to_string(),
            allowed_services: HashSet::new(),
        };
        let guard1 = registry
            .register(&reg, &owner, dummy_handle().await)
            .await
            .unwrap();
        let _guard2 = registry
            .register(&reg, &owner, dummy_handle().await)
            .await
            .unwrap();

        // Drop the FIRST (now-superseded) guard. Its best-effort cleanup must recognize a newer
        // generation has since taken the name over and must NOT delete the live registration.
        drop(guard1);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            registry.lookup("stale.example").await.is_some(),
            "a stale guard's drop must not evict a newer same-IK refresh"
        );
    }

    #[tokio::test]
    async fn deregistering_frees_the_name_for_reuse() {
        let registry = TunnelRegistry::new();
        let owner = vec![0xEE; 32];

        let reg = Registration {
            name: "reuse.example".to_string(),
            allowed_services: HashSet::new(),
        };
        let guard = registry
            .register(&reg, &owner, dummy_handle().await)
            .await
            .unwrap();
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

        // The name can now be claimed again, including by a different identity — it is free.
        let other_owner = vec![0xFF; 32];
        let _guard2 = registry
            .register(&reg, &other_owner, dummy_handle().await)
            .await
            .unwrap();
        assert!(registry.lookup("reuse.example").await.is_some());
    }
}
