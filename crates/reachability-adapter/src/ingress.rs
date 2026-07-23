//! The public ingress: accept plain TCP on the public port (443 in
//! production), peek the ClientHello's SNI without terminating TLS
//! ([`crate::sni`]), look up the box tunnel registered for that name
//! ([`crate::tunnel::TunnelRegistry`]), and — only if the name is registered
//! *and* the requesting service is on that tunnel's allow-list (REACH-5) —
//! open a yamux stream and splice the raw byte stream end to end, ciphertext
//! in, ciphertext out, verbatim. The adapter never completes a TLS handshake
//! and never holds a certificate for a name it routes this way (REACH-1).
//!
//! Every rejection path here — unregistered name, non-allow-listed service,
//! an unparseable/absent SNI, a tunnel that failed to open a stream — ends the
//! same way: [`fail_closed`] resets the TCP connection (`SO_LINGER(0)`, which
//! makes the kernel send RST instead of a graceful FIN on close). This is
//! REACH-6's *only* legal failure action here: the adapter holds no cert for
//! any blind-routed name, so it can complete no handshake and therefore emit
//! no TLS alert and no application-layer error — never a guess, never a
//! fallback to a different name.

use std::collections::HashSet;

use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::sni::{peek_client_hello, SniError};
use crate::tunnel::{
    read_registration, Registration, RegistrationGuard, RegistryError, TunnelError, TunnelHandle,
    TunnelRegistry,
};

#[derive(Debug, Error)]
pub enum IngressError {
    #[error("no usable SNI (REACH-6 fail-closed trigger): {0}")]
    Sni(#[from] SniError),
    #[error("no tunnel registered for {0:?}")]
    UnregisteredName(String),
    #[error("service {service:?} is not allow-listed on the tunnel for {name:?} (REACH-5)")]
    ServiceNotAllowed { name: String, service: String },
    #[error("could not open a stream on the box tunnel: {0}")]
    Tunnel(#[from] TunnelError),
}

#[derive(Debug, Error)]
pub enum TunnelAcceptError {
    #[error(transparent)]
    Tunnel(#[from] TunnelError),
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

/// The reachability-adapter's transport core: composes the control listener
/// (box registrations) and the public ingress listener (SNI-passthrough
/// forwarding) over one shared [`TunnelRegistry`]. `Clone` is cheap (the
/// registry is `Arc`-backed) so a handle can be freely passed into spawned
/// per-connection tasks.
#[derive(Clone, Default)]
pub struct AdapterServer {
    registry: TunnelRegistry,
}

impl AdapterServer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Direct access to the registration map — mainly useful for tests and
    /// for an operator surface that wants to list live tunnels without going
    /// through the wire protocol.
    pub fn registry(&self) -> &TunnelRegistry {
        &self.registry
    }

    /// Accept box control connections on `listener` forever, spawning one
    /// task per connection. Never returns under normal operation; a single
    /// misbehaving box cannot block others (each gets its own task).
    pub async fn run_control_listener(&self, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((socket, peer)) => {
                    let this = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = this.accept_box_connection(socket).await {
                            tracing::warn!(%peer, error = %e, "box control connection rejected");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "control listener accept failed");
                }
            }
        }
    }

    /// Handle one already-accepted box control connection: read its
    /// [`Registration`] frame (REACH-2 TODO: currently unauthenticated, see
    /// `tunnel.rs` module docs), spawn the yamux driver, and register the
    /// tunnel. Registration is single-writer per name (REACH-7 discipline
    /// applied to the in-memory session table) — a name already held by a
    /// live tunnel is refused, not hijacked.
    pub async fn accept_box_connection(&self, mut socket: TcpStream) -> Result<(), TunnelAcceptError> {
        let registration: Registration = read_registration(&mut socket).await?;
        let (handle, driver_join) = TunnelHandle::spawn(socket);
        let guard: RegistrationGuard = self.registry.register(&registration, handle).await?;
        // Deregister automatically once the tunnel's driver task ends (box
        // disconnect, I/O error, or every TunnelHandle clone dropped) — the
        // registration is rebuildable adapter operational state (REACH
        // profile §6), never a durable write, so best-effort cleanup here is
        // the correct posture.
        tokio::spawn(async move {
            let _ = driver_join.await;
            drop(guard);
        });
        Ok(())
    }

    /// Accept public client connections on `listener` forever, forwarding
    /// each onto the box tunnel its ClientHello's SNI names, for the declared
    /// `service_id` (REACH-5: this ingress instance represents one allow-list
    /// entry, e.g. `"https"` for a plain :443 listener — a box exposing
    /// multiple distinct services would run one ingress listener per service
    /// id, each checked against its own allow-list entry).
    pub async fn run_ingress_listener(&self, listener: TcpListener, service_id: String) {
        loop {
            match listener.accept().await {
                Ok((socket, peer)) => {
                    let this = self.clone();
                    let service_id = service_id.clone();
                    tokio::spawn(async move {
                        if let Err(e) = this.handle_ingress_connection(socket, &service_id).await {
                            tracing::debug!(%peer, error = %e, "ingress connection failed closed");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "ingress listener accept failed");
                }
            }
        }
    }

    /// Handle one inbound public TCP connection end to end: peek SNI, look up
    /// and authorize the tunnel, open a stream, replay the buffered
    /// ClientHello verbatim, then splice the remainder of the stream
    /// bidirectionally until either side closes. On any failure the
    /// connection is reset (REACH-6) before returning `Err`; the `Err` value
    /// is purely observability (REACH permits seeing *that* a connection was
    /// refused and *why*, never payload) — nothing about the fail-closed
    /// action itself depends on the caller inspecting it.
    pub async fn handle_ingress_connection(
        &self,
        mut socket: TcpStream,
        service_id: &str,
    ) -> Result<(), IngressError> {
        let peek = match peek_client_hello(&mut socket).await {
            Ok(peek) => peek,
            Err(e) => {
                fail_closed(socket).await;
                return Err(IngressError::Sni(e));
            }
        };

        let lookup = match self.registry.lookup(&peek.server_name).await {
            Some(l) => l,
            None => {
                fail_closed(socket).await;
                return Err(IngressError::UnregisteredName(peek.server_name));
            }
        };

        if !service_allowed(&lookup.allowed_services, service_id) {
            fail_closed(socket).await;
            return Err(IngressError::ServiceNotAllowed {
                name: peek.server_name,
                service: service_id.to_string(),
            });
        }

        let mut tunnel_stream = match lookup.handle.open_stream().await {
            Ok(s) => s,
            Err(e) => {
                fail_closed(socket).await;
                return Err(IngressError::Tunnel(e));
            }
        };

        // Replay the ClientHello bytes verbatim onto the tunnel before
        // splicing anything else — the box's TLS stack needs to see exactly
        // the bytes the client sent, unmodified, from the very first byte of
        // the handshake (the adapter re-serializes nothing it parsed).
        if let Err(e) = tunnel_stream.write_all(&peek.raw).await {
            fail_closed(socket).await;
            return Err(IngressError::Tunnel(TunnelError::Io(e)));
        }

        match tokio::io::copy_bidirectional(&mut socket, &mut tunnel_stream).await {
            Ok((client_to_box, box_to_client)) => {
                // Connection addresses, byte sizes, and timing are within the
                // declared `blind-routing` visibility (profiles/reachability.md
                // §7); payload content never is, and none is read here.
                tracing::debug!(
                    name = %peek.server_name,
                    client_to_box,
                    box_to_client,
                    "ingress connection spliced and closed"
                );
            }
            Err(e) => {
                tracing::debug!(name = %peek.server_name, error = %e, "ingress splice ended with an I/O error");
            }
        }
        Ok(())
    }
}

fn service_allowed(allowed_services: &HashSet<String>, service_id: &str) -> bool {
    allowed_services.contains(service_id)
}

/// REACH-6's only legal failure action for a blind-routing adapter: reset the
/// TCP connection. Setting `SO_LINGER(0)` makes the kernel emit RST instead of
/// a graceful FIN/ACK close, which is the closest a content-blind adapter
/// (with no cert, hence no TLS alert, hence no application-layer error) can
/// get to signalling failure at all. Never a fallback to another name, never
/// a best-effort guess.
async fn fail_closed(socket: TcpStream) {
    // Zero-linger is the one `SO_LINGER` setting Tokio does not deprecate:
    // unlike a nonzero linger, it does not block the thread on drop, and it
    // is exactly the "emit RST, not a graceful FIN" behavior REACH-6 wants.
    if let Err(e) = socket.set_zero_linger() {
        tracing::debug!(error = %e, "SO_LINGER(0) failed; falling back to a plain close (not a true RST)");
    }
    drop(socket);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::write_registration;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    async fn spawn_fake_box(
        control_listener: TcpListener,
        name: &str,
        service: &str,
    ) -> tokio::task::JoinHandle<()> {
        let name = name.to_string();
        let service = service.to_string();
        tokio::spawn(async move {
            let (mut ctrl, _) = control_listener.accept().await.unwrap();
            let mut services = HashSet::new();
            services.insert(service);
            write_registration(
                &mut ctrl,
                &Registration {
                    name,
                    allowed_services: services,
                },
            )
            .await
            .unwrap();

            // From here the control socket carries the yamux session; the box
            // is the yamux **server** side (accepts streams the adapter
            // opens). Drive it with the same crate the adapter uses so this
            // fake box exercises the real wire framing end to end.
            use tokio_util::compat::TokioAsyncReadCompatExt;
            let io = ctrl.compat();
            let mut conn = yamux::Connection::new(io, yamux::Config::default(), yamux::Mode::Server);
            loop {
                let stream = match std::future::poll_fn(|cx| conn.poll_next_inbound(cx)).await {
                    Some(Ok(s)) => s,
                    _ => break,
                };
                // Echo everything back verbatim — the "known SNI" service
                // this fake box exposes just reflects whatever ciphertext
                // bytes it receives, so the test can assert byte-identical
                // passthrough without needing a real TLS terminator.
                tokio::spawn(async move {
                    use tokio_util::compat::FuturesAsyncReadCompatExt;
                    let mut s = stream.compat();
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        })
    }

    #[tokio::test]
    async fn known_sni_splices_bytes_end_to_end_verbatim() {
        let control_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = control_listener.local_addr().unwrap();
        let _box_task = spawn_fake_box(control_listener, "svc.alice.reach.example", "https").await;

        let server = AdapterServer::new();
        let control_client = TcpStream::connect(control_addr).await.unwrap();
        server.accept_box_connection(control_client).await.unwrap();

        // Give the fake box's registration + tunnel spawn a moment to land in
        // the registry before the ingress connection looks it up.
        wait_until_registered(&server, "svc.alice.reach.example").await;

        let ingress_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingress_addr = ingress_listener.local_addr().unwrap();
        let ingress_server = server.clone();
        tokio::spawn(async move {
            let (socket, _) = ingress_listener.accept().await.unwrap();
            ingress_server
                .handle_ingress_connection(socket, "https")
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(ingress_addr).await.unwrap();
        let client_hello = build_client_hello("svc.alice.reach.example");
        client.write_all(&client_hello).await.unwrap();

        // The fake box echoes verbatim, so we must read back at least the
        // ClientHello bytes we just sent, byte-for-byte.
        let mut echoed = vec![0u8; client_hello.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, client_hello, "spliced bytes must be byte-identical passthrough");

        // And an application-shaped chunk sent after the handshake bytes
        // round-trips too, proving the splice continues past the ClientHello.
        let payload = b"this looks like ciphertext but is just test bytes";
        client.write_all(payload).await.unwrap();
        let mut echoed_payload = vec![0u8; payload.len()];
        client.read_exact(&mut echoed_payload).await.unwrap();
        assert_eq!(&echoed_payload, payload);
    }

    #[tokio::test]
    async fn unknown_sni_is_reset_and_forwards_nothing() {
        let server = AdapterServer::new();
        // No box registered at all for this name.

        let ingress_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingress_addr = ingress_listener.local_addr().unwrap();
        let ingress_server = server.clone();
        let handled = tokio::spawn(async move {
            let (socket, _) = ingress_listener.accept().await.unwrap();
            ingress_server.handle_ingress_connection(socket, "https").await
        });

        let mut client = TcpStream::connect(ingress_addr).await.unwrap();
        let client_hello = build_client_hello("nobody-home.reach.example");
        client.write_all(&client_hello).await.unwrap();

        let result = handled.await.unwrap();
        assert!(
            matches!(result, Err(IngressError::UnregisteredName(name)) if name == "nobody-home.reach.example")
        );

        // Fail-closed: no bytes come back, and the connection ends — REACH-6
        // resets it (SO_LINGER 0), which surfaces to the client's next read as
        // either a hard ECONNRESET or (platform/timing dependent) a clean EOF;
        // either way, zero application bytes were forwarded.
        assert_forwarded_nothing(&mut client).await;
    }

    #[tokio::test]
    async fn service_not_allow_listed_is_reset_and_forwards_nothing() {
        let control_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = control_listener.local_addr().unwrap();
        // The box only allow-lists "https", not "git-ssh".
        let _box_task = spawn_fake_box(control_listener, "svc.alice.reach.example", "https").await;

        let server = AdapterServer::new();
        let control_client = TcpStream::connect(control_addr).await.unwrap();
        server.accept_box_connection(control_client).await.unwrap();
        wait_until_registered(&server, "svc.alice.reach.example").await;

        let ingress_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingress_addr = ingress_listener.local_addr().unwrap();
        let ingress_server = server.clone();
        let handled = tokio::spawn(async move {
            let (socket, _) = ingress_listener.accept().await.unwrap();
            // This ingress listener represents "git-ssh", which the box never
            // allow-listed for this name (REACH-5 default-deny).
            ingress_server
                .handle_ingress_connection(socket, "git-ssh")
                .await
        });

        let mut client = TcpStream::connect(ingress_addr).await.unwrap();
        let client_hello = build_client_hello("svc.alice.reach.example");
        client.write_all(&client_hello).await.unwrap();

        let result = handled.await.unwrap();
        assert!(matches!(result, Err(IngressError::ServiceNotAllowed { .. })));

        assert_forwarded_nothing(&mut client).await;
    }

    /// Assert a fail-closed connection forwarded zero application bytes. A
    /// `SO_LINGER(0)` reset surfaces to the peer's next read as either a
    /// clean EOF (`Ok(0)`) or `ECONNRESET`, depending on OS/timing; both mean
    /// "nothing was forwarded", so both are accepted here.
    async fn assert_forwarded_nothing(client: &mut TcpStream) {
        let mut buf = [0u8; 16];
        match client.read(&mut buf).await {
            Ok(0) => {}
            Ok(n) => panic!("expected zero forwarded bytes, got {n} bytes: {:?}", &buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(e) => panic!("unexpected error reading fail-closed connection: {e}"),
        }
    }

    async fn wait_until_registered(server: &AdapterServer, name: &str) {
        for _ in 0..100 {
            if server.registry().lookup(name).await.is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("tunnel for {name:?} never appeared in the registry");
    }

    /// Same minimal-ClientHello builder as `sni::tests`, duplicated locally
    /// (kept private to each test module) so this module's integration tests
    /// don't need to reach into `sni`'s private test helpers.
    fn build_client_hello(host_name: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x42; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02]);
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);

        let mut server_name_list = Vec::new();
        server_name_list.push(0u8); // host_name
        server_name_list.extend_from_slice(&(host_name.len() as u16).to_be_bytes());
        server_name_list.extend_from_slice(host_name.as_bytes());
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&(server_name_list.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(&server_name_list);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x0000u16.to_be_bytes());
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);

        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        let body_len = body.len() as u32;
        handshake.extend_from_slice(&body_len.to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16); // handshake
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }
}
