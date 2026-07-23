//! A **real** MX listener (spec §7.2): a `TcpListener` SMTP server that runs the
//! `greeting → EHLO → [STARTTLS] → MAIL/RCPT/DATA` dialog and feeds the assembled RFC 5322 into the
//! verified [`MxSession`] pipeline (anti-abuse gate, recipient resolution, seal, attest,
//! ack-before-`250`). The socket layer here adds only framing + STARTTLS; every protocol decision
//! stays in [`crate::inbound`]. STARTTLS is advertised when a server cert is configured; MAIL/RCPT/
//! DATA and the terminating `.` are delegated verbatim to `MxSession` so its behaviour is identical
//! to the in-process `accept_message` tests.

use std::io::{self, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use kotva_core::TimestampMs;

use crate::inbound::{InboundGateway, MxSession, SmtpReply};
use crate::net::{crypto_provider, read_line, write_all, ConnLimiter};

/// The per-I/O-operation socket timeout applied to every accepted MX connection (§2 in the security
/// review — the "MX listener DoS" finding): a single idle or trickle-fed peer must never be able to
/// block a `read`/`write` forever and, with it, the thread serving it. Each connection now runs on
/// its own spawned thread (see [`MxListener`] docs), so this bound no longer protects every OTHER
/// inbound sender from one stalled peer directly — that is [`DEFAULT_MAX_CONNECTIONS`]'s job — but it
/// still bounds how long any single stalled syscall can hang a thread, and how long that thread's
/// [`ConnLimiter`] slot stays held. 120 s comfortably covers a legitimate legacy MTA's think-time
/// between SMTP command/reply round-trips.
const MX_IO_TIMEOUT: Duration = Duration::from_secs(120);

/// A hard ceiling on how long any ONE inbound MX transaction (greeting through `QUIT`/disconnect) may
/// run, even if the peer keeps sending just often enough to dodge [`MX_IO_TIMEOUT`] on every
/// individual read (a classic slow-trickle/slowloris pattern the per-op timeout alone does not stop).
/// 10 minutes is generous for a legitimate transaction (SMTP command timeouts are typically minutes,
/// not tens of minutes) and short enough that one abusive connection cannot hold its
/// [`ConnLimiter`] slot indefinitely.
const MX_MAX_TRANSACTION: Duration = Duration::from_secs(600);

/// Build a rustls [`ServerConfig`] from a certificate chain + private key (both DER). Used to offer
/// STARTTLS on the inbound listener. In production the operator supplies real cert/key material
/// (load via [`load_certs`] / [`load_private_key`] from PEM files); tests pass a self-signed pair.
pub fn server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, rustls::Error> {
    let config = ServerConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default protocol versions")
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    Ok(Arc::new(config))
}

/// Load a PEM certificate chain (operator-supplied TLS cert for the MX).
pub fn load_certs(pem: &mut dyn io::BufRead) -> io::Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(pem).collect()
}

/// Load the first PEM private key (PKCS#8 / SEC1 / PKCS#1).
pub fn load_private_key(pem: &mut dyn io::BufRead) -> io::Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(pem)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key in PEM"))
}

/// The concurrent-connection cap applied by [`MxListener::serve_forever`]/[`MxListener::serve_until`]
/// (mirroring `AdminServer`/`ImapAccessServer`/`Pop3AccessServer`/`SubmissionServer`'s
/// [`ConnLimiter`]s): the per-op [`MX_IO_TIMEOUT`]/[`MX_MAX_TRANSACTION`] bounds cap how long any ONE
/// connection can occupy a thread, but say nothing about how MANY may be open at once — without a
/// cap an attacker could open thousands of idling connections and exhaust the process's thread/fd
/// budget one thread-spawn at a time. Override via [`MxListener::with_max_connections`].
const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// A listening MX socket. Stateless (§7.4): each accepted connection is an independent transaction,
/// and — since `InboundGateway` is `Send + Sync` (§7.2, [`crate::inbound::KeyDirectory`] et al.) —
/// [`Self::serve_forever`]/[`Self::serve_until`] hand each accepted connection to its own spawned
/// thread rather than serving one at a time. This is the thread-per-connection model
/// `AdminServer`/`ImapAccessServer`/`Pop3AccessServer`/`SubmissionServer` already use: a single
/// slow-but-not-timed-out peer (bounded by [`MX_IO_TIMEOUT`]/[`MX_MAX_TRANSACTION`] regardless) no
/// longer delays every OTHER inbound sender behind it in the accept loop.
pub struct MxListener {
    listener: TcpListener,
    tls: Option<Arc<ServerConfig>>,
    io_timeout: Duration,
    max_transaction: Duration,
    limiter: ConnLimiter,
}

impl MxListener {
    /// Bind an MX listener. `tls = Some(cfg)` advertises and terminates STARTTLS; `None` is a
    /// plaintext dev listener (no STARTTLS offered). Uses the production
    /// [`MX_IO_TIMEOUT`]/[`MX_MAX_TRANSACTION`] slowloris bounds and [`DEFAULT_MAX_CONNECTIONS`];
    /// override with [`Self::with_io_timeout`]/[`Self::with_max_transaction`]/
    /// [`Self::with_max_connections`] (tests use a short timeout so the idle-connection regression
    /// test does not have to wait minutes).
    pub fn bind(
        addr: impl std::net::ToSocketAddrs,
        tls: Option<Arc<ServerConfig>>,
    ) -> io::Result<Self> {
        Ok(MxListener {
            listener: TcpListener::bind(addr)?,
            tls,
            io_timeout: MX_IO_TIMEOUT,
            max_transaction: MX_MAX_TRANSACTION,
            limiter: ConnLimiter::new(DEFAULT_MAX_CONNECTIONS),
        })
    }

    /// Override the per-read/write socket timeout applied to every accepted connection (production
    /// default [`MX_IO_TIMEOUT`]).
    pub fn with_io_timeout(mut self, t: Duration) -> Self {
        self.io_timeout = t;
        self
    }

    /// Override the max-transaction-duration ceiling (production default [`MX_MAX_TRANSACTION`]).
    pub fn with_max_transaction(mut self, t: Duration) -> Self {
        self.max_transaction = t;
        self
    }

    /// Override the concurrent-connection cap applied by [`Self::serve_forever`]/[`Self::serve_until`]
    /// (production default [`DEFAULT_MAX_CONNECTIONS`]). Has no effect on [`Self::serve_once`], which
    /// never consults the limiter.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.limiter = ConnLimiter::new(max);
        self
    }

    /// The address actually bound (useful with an ephemeral `:0` port in tests).
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept exactly one connection and drive its SMTP transaction against `gw` **on this thread**,
    /// stamping messages with `now`. Returns after the peer `QUIT`s or disconnects (or the connection
    /// is cut off by the idle/max-transaction guard). For tests and single-shot use; the daemon uses
    /// [`Self::serve_until`], which handles each connection on its own spawned thread.
    pub fn serve_once(&self, gw: &InboundGateway, now: TimestampMs) -> io::Result<()> {
        let (stream, peer) = self.listener.accept()?;
        let peer_ip = peer.ip().to_string();
        handle_connection(
            stream,
            gw,
            &peer_ip,
            now,
            self.tls.clone(),
            self.io_timeout,
            self.max_transaction,
        )
    }

    /// Serve connections forever, each on its own spawned thread, stamping each with the current
    /// wall-clock time. A per-connection error is logged to stderr and does not stop the listener
    /// (statelessness means a dropped connection loses nothing — the legacy sender retries). This
    /// variant never returns; prefer [`Self::serve_until`] for a daemon that must shut down
    /// gracefully.
    pub fn serve_forever(&self, gw: Arc<InboundGateway>) -> io::Result<()> {
        for stream in self.listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("gateway: accept error: {e}");
                    continue;
                }
            };
            let peer_ip = stream
                .peer_addr()
                .map(|a| a.ip().to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            // Concurrent-connection cap (mirrors the other three access servers): refuse outright
            // (drop the just-accepted socket with no reply) rather than spawn a thread when already
            // at capacity — a legitimate retrying MTA treats a refused connection like any other
            // transient failure and requeues.
            let Some(guard) = self.limiter.try_acquire() else {
                eprintln!("gateway: {peer_ip}: at the concurrent-connection limit, refusing");
                continue;
            };
            let gw = gw.clone();
            let tls = self.tls.clone();
            let io_timeout = self.io_timeout;
            let max_transaction = self.max_transaction;
            std::thread::spawn(move || {
                let _guard = guard; // held for the connection's lifetime, released on drop
                if let Err(e) = handle_connection(
                    stream,
                    &gw,
                    &peer_ip,
                    now_ms(),
                    tls,
                    io_timeout,
                    max_transaction,
                ) {
                    eprintln!("gateway: session with {peer_ip} ended: {e}");
                }
            });
        }
        Ok(())
    }

    /// Serve connections — each on its own spawned thread — until `shutdown` flips to `true`, then
    /// return cleanly — the long-running daemon loop with **graceful shutdown**. The listener is
    /// switched to non-blocking and the accept loop polls `shutdown` between connections (and while
    /// idle), so a `SIGINT`/`SIGTERM` handler that sets the flag makes the daemon stop accepting and
    /// return without aborting any in-flight transaction. `gw` is `Arc`'d once by the caller and
    /// cloned (cheaply — an `Arc` bump) into each spawned thread; every accepted connection runs
    /// concurrently, bounded by the [`ConnLimiter`] concurrent-connection cap and each individually
    /// bounded by [`MX_IO_TIMEOUT`]/[`MX_MAX_TRANSACTION`] (statelessness: an interrupted connection
    /// loses nothing — the legacy sender retries). A per-connection error is logged and does not stop
    /// the loop. Detached session threads may still be finishing their current transaction when this
    /// returns (bounded by [`MX_MAX_TRANSACTION`]); the caller does not block on them, exactly as
    /// `ImapAccessServer`/`Pop3AccessServer`/`SubmissionServer` already behave.
    pub fn serve_until(&self, gw: Arc<InboundGateway>, shutdown: &AtomicBool) -> io::Result<()> {
        self.listener.set_nonblocking(true)?;
        // Idle poll cadence: small enough that shutdown is near-instant, large enough not to spin.
        let idle = Duration::from_millis(100);
        let outcome = loop {
            if shutdown.load(Ordering::SeqCst) {
                break Ok(());
            }
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    // accept(2) does not inherit the listener's non-blocking flag on every platform;
                    // force blocking so the per-connection SMTP dialog uses ordinary blocking I/O.
                    if let Err(e) = stream.set_nonblocking(false) {
                        eprintln!("gateway: could not set connection blocking: {e}");
                        continue;
                    }
                    let peer_ip = peer.ip().to_string();
                    let Some(guard) = self.limiter.try_acquire() else {
                        eprintln!(
                            "gateway: {peer_ip}: at the concurrent-connection limit, refusing"
                        );
                        continue;
                    };
                    let gw = gw.clone();
                    let tls = self.tls.clone();
                    let io_timeout = self.io_timeout;
                    let max_transaction = self.max_transaction;
                    std::thread::spawn(move || {
                        let _guard = guard; // held for the connection's lifetime, released on drop
                        if let Err(e) = handle_connection(
                            stream,
                            &gw,
                            &peer_ip,
                            now_ms(),
                            tls,
                            io_timeout,
                            max_transaction,
                        ) {
                            eprintln!("gateway: session with {peer_ip} ended: {e}");
                        }
                    });
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(idle);
                }
                Err(e) => {
                    eprintln!("gateway: accept error: {e}");
                    std::thread::sleep(idle);
                }
            }
        };
        // Restore blocking mode so a caller that reuses the listener is not surprised.
        let _ = self.listener.set_nonblocking(false);
        outcome
    }
}

/// Current wall-clock time in ms since the Unix epoch.
fn now_ms() -> TimestampMs {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as TimestampMs).unwrap_or(0)
}

/// Drive one SMTP transaction. EHLO/STARTTLS/QUIT are handled at the socket layer (framing +
/// TLS upgrade); MAIL/RCPT/DATA and all data lines are delegated verbatim to [`MxSession`].
fn handle_connection(
    tcp: TcpStream,
    gw: &InboundGateway,
    peer_ip: &str,
    now: TimestampMs,
    tls: Option<Arc<ServerConfig>>,
    io_timeout: Duration,
    max_transaction: Duration,
) -> io::Result<()> {
    // Slowloris / MX-DoS guard (§2 in the security review): bound every read/write on this socket,
    // and cap the transaction's total wall-clock duration so a peer trickling bytes just inside the
    // per-op timeout still gets cut off. Set on the raw `TcpStream` BEFORE any TLS wrapping — the
    // timeout is a socket-level attribute that keeps applying to every read/write the TLS stream
    // performs on the same underlying fd, so STARTTLS does not reset or bypass it.
    tcp.set_read_timeout(Some(io_timeout))?;
    tcp.set_write_timeout(Some(io_timeout))?;
    let deadline = Instant::now() + max_transaction;

    let mut conn = ServerStream::Plain(tcp);
    let mut session = MxSession::new(gw, peer_ip, now);
    write_all(&mut conn, &session.greeting().wire())?;

    let mut in_data = false;
    let mut secured = false;

    // `read_line` yields raw line bytes (`None` on peer disconnect, which ends the session).
    while let Some(line) = read_line(&mut conn)? {
        if Instant::now() >= deadline {
            // Best-effort courtesy reply (ignored if the write itself times out / fails) before
            // dropping the connection — a legitimate retrying MTA treats this exactly like any other
            // 421 and requeues.
            let _ = write_all(
                &mut conn,
                &SmtpReply::new(421, "4.4.2 transaction timed out, closing connection").wire(),
            );
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "inbound MX transaction exceeded the max transaction duration",
            ));
        }
        if in_data {
            // Everything is message content until the terminating '.'; feed the RAW bytes straight
            // through — a DATA line is arbitrary 8-bit content (ISO-8859-x, GB18030, …) and must
            // reach DKIM verification / the sealed MOTE byte-exact, never through a UTF-8 decode.
            let reply = session.feed_line_bytes(&line);
            if reply.code != 0 {
                write_all(&mut conn, &reply.wire())?;
                in_data = false;
            }
            continue;
        }

        // Command phase: RFC 5321 commands are ASCII, so this decode is lossless for any
        // conforming client (a broken peer at worst garbles its own 502).
        let line = String::from_utf8_lossy(&line);
        let verb = line.split(' ').next().unwrap_or("").to_ascii_uppercase();
        match verb.as_str() {
            "EHLO" | "HELO" => {
                if tls.is_some() && !secured {
                    write_all(&mut conn, "250-envoir-gateway at your service\r\n")?;
                    write_all(&mut conn, "250 STARTTLS\r\n")?;
                } else {
                    write_all(&mut conn, "250 envoir-gateway at your service\r\n")?;
                }
            }
            "STARTTLS" => match (&tls, secured) {
                (Some(cfg), false) => {
                    write_all(&mut conn, &SmtpReply::new(220, "2.0.0 ready to start TLS").wire())?;
                    conn.upgrade(cfg.clone())?;
                    secured = true;
                    // RFC 3207 §4.2: discard SMTP state established before TLS.
                    session = MxSession::new(gw, peer_ip, now);
                }
                (Some(_), true) => {
                    write_all(&mut conn, &SmtpReply::new(503, "5.5.1 already secured").wire())?;
                }
                (None, _) => {
                    write_all(
                        &mut conn,
                        &SmtpReply::new(502, "5.5.1 STARTTLS not available").wire(),
                    )?;
                }
            },
            "QUIT" => {
                write_all(&mut conn, &session.feed_line("QUIT").wire())?;
                break;
            }
            "DATA" => {
                let reply = session.feed_line("DATA");
                let code = reply.code;
                write_all(&mut conn, &reply.wire())?;
                if code == 354 {
                    in_data = true;
                }
            }
            _ => {
                let reply = session.feed_line(&line);
                write_all(&mut conn, &reply.wire())?;
            }
        }
    }
    Ok(())
}

/// A server stream upgradable from plaintext to rustls TLS in place (STARTTLS termination).
enum ServerStream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ServerConnection, TcpStream>>),
    /// Transient state only while swapping Plain → Tls; never observed by I/O.
    Taken,
}

impl ServerStream {
    /// Terminate STARTTLS: take the underlying TCP socket and wrap it in a rustls server session,
    /// completing the handshake eagerly so a failure surfaces here.
    fn upgrade(&mut self, config: Arc<ServerConfig>) -> io::Result<()> {
        let tcp = match std::mem::replace(self, ServerStream::Taken) {
            ServerStream::Plain(t) => t,
            other => {
                *self = other;
                return Err(io::Error::other("already TLS"));
            }
        };
        let conn = ServerConnection::new(config).map_err(io::Error::other)?;
        let mut tls = StreamOwned::new(conn, tcp);
        tls.conn.complete_io(&mut tls.sock)?;
        *self = ServerStream::Tls(Box::new(tls));
        Ok(())
    }
}

impl Read for ServerStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ServerStream::Plain(t) => t.read(buf),
            ServerStream::Tls(s) => s.read(buf),
            ServerStream::Taken => Err(io::Error::other("stream in transition")),
        }
    }
}
impl Write for ServerStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            ServerStream::Plain(t) => t.write(buf),
            ServerStream::Tls(s) => s.write(buf),
            ServerStream::Taken => Err(io::Error::other("stream in transition")),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            ServerStream::Plain(t) => t.flush(),
            ServerStream::Tls(s) => s.flush(),
            ServerStream::Taken => Ok(()),
        }
    }
}

/// Convenience: read PEM cert + key from byte slices (e.g. embedded config) into a [`ServerConfig`].
pub fn server_config_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> io::Result<Arc<ServerConfig>> {
    let certs = load_certs(&mut BufReader::new(cert_pem))?;
    let key = load_private_key(&mut BufReader::new(key_pem))?;
    server_config(certs, key).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
