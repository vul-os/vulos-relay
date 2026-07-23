//! Optional **legacy IMAP access server** (DMTAP spec §8.2): serves a mailbox store to
//! authenticated legacy clients (Thunderbird, Apple Mail, Outlook, mutt) alongside the SMTP bridge.
//!
//! ## What this is — and is not
//! The gateway itself is a **stateless SMTP↔MOTE bridge** ([`crate`] docs, spec §7.4): it holds no
//! queue and no durable mailbox. IMAP, by contrast, is *inherently* a store surface — a client LISTs
//! folders and FETCHes messages that must exist *somewhere*. So this server does **not** invent a
//! stateless proxy; it is **store-backed**, and the store is the operator's own DMTAP mailbox
//! projection ([`kotva_mail::store::MailStore`]) — the SAME projection the co-located node uses.
//!
//! Two honest ways the store is supplied:
//! - **Co-located node / library use**: [`ImapAccessServer::serve_until`] is generic over any
//!   [`MailStore`] factory, so a node that owns the live mailbox hands its store straight in. This is
//!   the real deployment seam (spec §8.5: the surface lives on the user's own node).
//! - **Personal daemon (this crate's `personal` mode)**: the operator hands the gateway a mailbox
//!   snapshot on disk — a directory of RFC 5322 `.eml` files ([`seed_store_from_maildir`]) — which is
//!   projected into an in-process [`MemoryStore`]. This is a *read-mostly projection*: because the
//!   gateway is not the mailbox authority, session mutations (flag changes, APPEND, EXPUNGE) are
//!   **session-local and not persisted back** to the DMTAP MOTE store. That authority is the node.
//!   The limitation is documented, not faked.
//!
//! ## Transport & auth (fail-closed)
//! Every session runs over TLS reusing the gateway's existing rustls [`ServerConfig`]
//! ([`crate::inbound_tcp::server_config`]): [`ImapTls::Implicit`] wraps the socket immediately;
//! [`ImapTls::StartTls`] advertises `STARTTLS`/`LOGINDISABLED` in cleartext and upgrades in place on
//! the `STARTTLS` command (rejecting any pipelined post-`STARTTLS` bytes — the command-injection
//! guard). Authentication is `dmtap-mail`'s app-password path ([`Authenticator`] /
//! [`StaticAuthenticator`], constant-time compared) — the exact scheme SMTP submission uses; no
//! weaker scheme is invented. Before STARTTLS the state machine withholds `LOGIN` (`LOGINDISABLED`),
//! and an unknown user or wrong app-password resolves to `None` → tagged `NO` (fail closed).
//!
//! The listener is **off by default** ([`crate::PersonalConfig`]'s `imap_enable`).

use std::cell::RefCell;
use std::io::{self, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustls::{ServerConfig, ServerConnection, StreamOwned};

use kotva_mail::auth::Authenticator;
use kotva_mail::imap::{Session, State};
use kotva_mail::net::read_imap_command;
use kotva_mail::store::{Flag, MailStore, MemoryStore};

use crate::net::ConnLimiter;

/// The per-read/write socket idle timeout applied to every IMAP connection (§4 in the security
/// review — the slowloris finding). Longer than the POP3/submission surfaces'
/// [`crate::legacy_net`] timeout because IMAP `IDLE` (RFC 2177) is a legitimate long-lived wait for
/// server-push; RFC 2177 itself expects clients to re-issue `IDLE` roughly every ~29 minutes, so 15
/// minutes still bounds an actually-idle/attacking connection without cutting off normal `IDLE` use.
const IMAP_IO_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Default cap on concurrent IMAP connections one [`ImapAccessServer`] serves — the other half of
/// the slowloris mitigation (bounds how many connections can be open at once, not just how long any
/// one can idle). Override with [`ImapAccessServer::with_max_connections`].
const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// How the IMAP access server presents TLS. There is no cleartext option: legacy IMAP auth carries a
/// reusable app-password, so a confidential channel is mandatory (spec §8.2). Both modes reuse the
/// gateway's own cert/key ([`crate::PersonalConfig::tls_cert`]/`tls_key`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImapTls {
    /// Cleartext port that advertises `STARTTLS` (+ `LOGINDISABLED`) and upgrades in place on the
    /// `STARTTLS` command (the classic ports-143 model).
    StartTls,
    /// TLS from the first byte (the implicit-TLS ports-993 model).
    Implicit,
}

impl ImapTls {
    /// Parse the config spelling (`starttls` / `implicit`). Case-insensitive.
    pub fn parse(v: &str) -> Option<ImapTls> {
        match v.trim().to_ascii_lowercase().as_str() {
            "starttls" | "start-tls" | "start_tls" => Some(ImapTls::StartTls),
            "implicit" | "implicit-tls" | "tls" | "993" => Some(ImapTls::Implicit),
            _ => None,
        }
    }
}

/// A bound IMAP access listener. Serves one [`Session`] per accepted connection on its own thread
/// (IMAP connections are long-lived — IDLE — so they cannot be handled one-at-a-time like the short
/// SMTP MX transactions). The store and authenticator are (re)built per connection via factories, so
/// each session owns its own snapshot exactly as [`kotva_mail::net::serve_imap`] does.
pub struct ImapAccessServer {
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    mode: ImapTls,
    limiter: ConnLimiter,
}

impl ImapAccessServer {
    /// Bind an IMAP access listener with the gateway's TLS config and the chosen TLS mode. Concurrent
    /// connections default to [`DEFAULT_MAX_CONNECTIONS`]; override with
    /// [`Self::with_max_connections`].
    pub fn bind(
        addr: impl std::net::ToSocketAddrs,
        tls: Arc<ServerConfig>,
        mode: ImapTls,
    ) -> io::Result<Self> {
        Ok(ImapAccessServer {
            listener: TcpListener::bind(addr)?,
            tls,
            mode,
            limiter: ConnLimiter::new(DEFAULT_MAX_CONNECTIONS),
        })
    }

    /// Override the concurrent-connection cap (default [`DEFAULT_MAX_CONNECTIONS`]).
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.limiter = ConnLimiter::new(max);
        self
    }

    /// The address actually bound (useful with an ephemeral `:0` port in tests).
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept exactly one connection, run its IMAP session to completion, and return. For tests and
    /// single-shot use; the daemon uses [`Self::serve_until`].
    pub fn serve_once<S, A>(&self, store: S, auth: A) -> io::Result<()>
    where
        S: MailStore,
        A: Authenticator,
    {
        let (stream, _peer) = self.listener.accept()?;
        stream.set_nonblocking(false)?;
        handle_connection(stream, self.tls.clone(), self.mode, store, auth)
    }

    /// Serve connections until `shutdown` flips to `true`, then stop accepting and return — the
    /// long-running daemon loop with **graceful shutdown**, mirroring
    /// [`crate::inbound_tcp::MxListener::serve_until`]. Each accepted connection is handled on its own
    /// detached thread; `make_store` / `make_auth` build that session's store and authenticator. A
    /// per-connection error is logged and never stops the accept loop.
    pub fn serve_until<S, A, MkStore, MkAuth>(
        &self,
        make_store: MkStore,
        make_auth: MkAuth,
        shutdown: &AtomicBool,
    ) -> io::Result<()>
    where
        S: MailStore + Send + 'static,
        A: Authenticator + Send + 'static,
        MkStore: Fn() -> S + Send + Sync + 'static,
        MkAuth: Fn() -> A + Send + Sync + 'static,
    {
        self.listener.set_nonblocking(true)?;
        let make_store = Arc::new(make_store);
        let make_auth = Arc::new(make_auth);
        let idle = Duration::from_millis(100);
        loop {
            if shutdown.load(Ordering::SeqCst) {
                return Ok(());
            }
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    // Concurrent-connection cap (§4 in the security review — the other half of the
                    // slowloris mitigation alongside the idle timeout below): refuse outright rather
                    // than spawn a thread when already at capacity.
                    let Some(guard) = self.limiter.try_acquire() else {
                        eprintln!(
                            "gateway[imap]: {peer}: at the concurrent-connection limit, refusing"
                        );
                        continue;
                    };
                    if let Err(e) = stream.set_nonblocking(false) {
                        eprintln!("gateway[imap]: {peer}: cannot set blocking: {e}");
                        continue;
                    }
                    let tls = self.tls.clone();
                    let mode = self.mode;
                    let make_store = make_store.clone();
                    let make_auth = make_auth.clone();
                    std::thread::spawn(move || {
                        let _guard = guard; // held for the session's lifetime, released on drop
                        if let Err(e) =
                            handle_connection(stream, tls, mode, make_store(), make_auth())
                        {
                            // A dropped IMAP connection loses nothing durable here (the mailbox
                            // authority is the node); log at the session level and move on.
                            if e.kind() != io::ErrorKind::UnexpectedEof {
                                eprintln!("gateway[imap]: session with {peer} ended: {e}");
                            }
                        }
                    });
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(idle);
                }
                Err(e) => {
                    eprintln!("gateway[imap]: accept error: {e}");
                    std::thread::sleep(idle);
                }
            }
        }
    }
}

/// Drive one IMAP session over `stream` to completion. The [`Session`] is created with the TLS flag
/// that matches the transport: implicit TLS terminates the handshake before the greeting and starts
/// `tls=true` (so `LOGIN` is permitted and `STARTTLS` is not offered); STARTTLS starts `tls=false`
/// and lets the state machine flip the flag on the `STARTTLS` command as we upgrade the socket in
/// place. The literal-aware command framing is reused from [`kotva_mail::net::read_imap_command`].
fn handle_connection<S, A>(
    stream: TcpStream,
    tls: Arc<ServerConfig>,
    mode: ImapTls,
    store: S,
    auth: A,
) -> io::Result<()>
where
    S: MailStore,
    A: Authenticator,
{
    // Slowloris guard (§4 in the security review): bound every read/write BEFORE any TLS wrapping —
    // the timeout is a socket-level attribute that keeps applying across the STARTTLS boundary too.
    stream.set_read_timeout(Some(IMAP_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IMAP_IO_TIMEOUT))?;

    // Build the (possibly already-encrypted) transport. Implicit TLS terminates before the greeting.
    let (imap_stream, mut session, mut secured) = match mode {
        ImapTls::Implicit => {
            let conn = ServerConnection::new(tls.clone()).map_err(io::Error::other)?;
            let mut tls_stream = StreamOwned::new(conn, stream);
            tls_stream.conn.complete_io(&mut tls_stream.sock)?;
            (ImapStream::Tls(Box::new(tls_stream)), Session::new(store, auth, true), true)
        }
        ImapTls::StartTls => (ImapStream::Plain(stream), Session::new(store, auth, false), false),
    };

    // One shared handle to the upgradable stream: `read_imap_command` needs an owned BufRead reader
    // and a separate Write, so we hand it two clones of an `Rc<RefCell<..>>` (single-threaded per
    // connection — the Rc never leaves this thread). Upgrading TLS mutates the cell in place, so the
    // reader/writer keep working across the STARTTLS boundary.
    let cell = Rc::new(RefCell::new(imap_stream));
    let mut reader = BufReader::new(SharedStream(cell.clone()));
    let mut writer = SharedStream(cell.clone());

    writer.write_all(&session.greeting())?;
    writer.flush()?;

    while let Some(cmd) = read_imap_command(&mut reader, &mut writer)? {
        let wants_starttls = !secured && is_starttls_command(&cmd);
        let resp = session.process(&cmd);
        let accepted = response_is_ok(&resp);
        writer.write_all(&resp)?;
        writer.flush()?;

        if wants_starttls && accepted {
            // Command-injection guard (the classic STARTTLS plaintext-injection flaw): the client
            // must NOT have pipelined any bytes after `STARTTLS`. If our buffered reader already
            // holds post-command data, drop the connection fail-closed rather than treat it as TLS.
            if !reader.buffer().is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pipelined data after STARTTLS — possible command injection",
                ));
            }
            cell.borrow_mut().upgrade(tls.clone())?;
            secured = true;
        }

        if session.state() == State::Logout {
            break;
        }
    }
    Ok(())
}

/// Whether a raw client command line is a `STARTTLS` command (tag then `STARTTLS`), case-insensitive.
fn is_starttls_command(cmd: &[u8]) -> bool {
    let text = String::from_utf8_lossy(cmd);
    let mut parts = text.split_whitespace();
    let _tag = parts.next();
    matches!(parts.next(), Some(word) if word.eq_ignore_ascii_case("STARTTLS"))
}

/// Whether a tagged IMAP response is an affirmative completion (`<tag> OK ...`). Used to gate the
/// STARTTLS upgrade on the state machine having actually accepted the command.
fn response_is_ok(resp: &[u8]) -> bool {
    String::from_utf8_lossy(resp)
        .lines()
        .any(|l| !l.starts_with('*') && !l.starts_with('+') && l.contains(" OK"))
}

/// A cheaply-cloneable handle to the per-connection stream. Both the buffered reader and the writer
/// hold one; reads and writes are strictly sequential within a single thread, so the `RefCell` is
/// never double-borrowed and the `Rc` never crosses a thread boundary.
struct SharedStream(Rc<RefCell<ImapStream>>);

impl Read for SharedStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.borrow_mut().read(buf)
    }
}
impl Write for SharedStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.borrow_mut().flush()
    }
}

/// A server stream upgradable from plaintext to rustls TLS in place (STARTTLS termination) — the same
/// shape the inbound MX uses ([`crate::inbound_tcp`]), kept private to the IMAP module.
enum ImapStream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ServerConnection, TcpStream>>),
    /// Transient state only while swapping Plain → Tls; never observed by I/O.
    Taken,
}

impl ImapStream {
    /// Terminate STARTTLS: take the underlying TCP socket and wrap it in a rustls server session,
    /// completing the handshake eagerly so a failure surfaces here (fail-closed).
    fn upgrade(&mut self, config: Arc<ServerConfig>) -> io::Result<()> {
        let tcp = match std::mem::replace(self, ImapStream::Taken) {
            ImapStream::Plain(t) => t,
            other => {
                *self = other;
                return Err(io::Error::other("STARTTLS on an already-secured stream"));
            }
        };
        let conn = ServerConnection::new(config).map_err(io::Error::other)?;
        let mut tls = StreamOwned::new(conn, tcp);
        tls.conn.complete_io(&mut tls.sock)?;
        *self = ImapStream::Tls(Box::new(tls));
        Ok(())
    }
}

impl Read for ImapStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ImapStream::Plain(t) => t.read(buf),
            ImapStream::Tls(s) => s.read(buf),
            ImapStream::Taken => Err(io::Error::other("stream in transition")),
        }
    }
}
impl Write for ImapStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            ImapStream::Plain(t) => t.write(buf),
            ImapStream::Tls(s) => s.write(buf),
            ImapStream::Taken => Err(io::Error::other("stream in transition")),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            ImapStream::Plain(t) => t.flush(),
            ImapStream::Tls(s) => s.flush(),
            ImapStream::Taken => Ok(()),
        }
    }
}

/// Read a directory of RFC 5322 `.eml` files into `(raw-bytes, internal-date-ms)` pairs in stable
/// filename order — the "operator hands the gateway their mailbox snapshot" path for the personal
/// daemon. Each file is one message, dated by its filesystem mtime. Non-`.eml` entries are ignored;
/// a missing directory is an error (fail-closed: a mis-typed path must not silently serve an empty
/// mailbox).
///
/// The pairs are plain owned bytes — `Send + Sync` — so the daemon can hold one snapshot behind an
/// `Arc` and rebuild a fresh per-session [`MemoryStore`] from it on every connection (the store
/// itself is `!Sync` because its parse cache is a `OnceCell`, so it cannot be shared directly).
pub fn load_maildir_messages(dir: impl AsRef<std::path::Path>) -> io::Result<Vec<(Vec<u8>, u64)>> {
    let dir = dir.as_ref();
    let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x.eq_ignore_ascii_case("eml")).unwrap_or(false))
        .collect();
    // Deterministic delivery order (UIDs assigned in filename order) regardless of readdir order.
    entries.sort();
    let mut out = Vec::with_capacity(entries.len());
    for path in entries {
        let raw = std::fs::read(&path)?;
        out.push((raw, file_mtime_ms(&path)));
    }
    Ok(out)
}

/// File the `(raw, internal-date)` snapshot into a store's `INBOX` (each message `\Recent`), the way
/// a fresh per-session store is built from a maildir snapshot. Returns the number filed.
///
/// This is a snapshot: mutations made by IMAP clients are session-local and are NOT written back to
/// the source files (the gateway is not the mailbox authority — see the module docs).
pub fn seed_inbox(store: &mut MemoryStore, messages: &[(Vec<u8>, u64)]) -> usize {
    let mut loaded = 0usize;
    for (raw, ts) in messages {
        if store.deliver_raw("INBOX", raw.clone(), vec![Flag::Recent], *ts).is_some() {
            loaded += 1;
        }
    }
    loaded
}

/// Convenience: load a maildir and seed a store's `INBOX` in one call. Returns the count loaded.
pub fn seed_store_from_maildir(
    store: &mut MemoryStore,
    dir: impl AsRef<std::path::Path>,
) -> io::Result<usize> {
    let messages = load_maildir_messages(dir)?;
    Ok(seed_inbox(store, &messages))
}

/// The file's modification time in epoch-milliseconds, or `0` when it cannot be read.
fn file_mtime_ms(path: &std::path::Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tls_mode_spellings() {
        assert_eq!(ImapTls::parse("starttls"), Some(ImapTls::StartTls));
        assert_eq!(ImapTls::parse("STARTTLS"), Some(ImapTls::StartTls));
        assert_eq!(ImapTls::parse("implicit"), Some(ImapTls::Implicit));
        assert_eq!(ImapTls::parse("993"), Some(ImapTls::Implicit));
        assert_eq!(ImapTls::parse("plaintext"), None);
    }

    #[test]
    fn detects_starttls_command() {
        assert!(is_starttls_command(b"a1 STARTTLS\r\n"));
        assert!(is_starttls_command(b"x starttls\r\n"));
        assert!(!is_starttls_command(b"a1 LOGIN u p\r\n"));
        assert!(!is_starttls_command(b"a1 CAPABILITY\r\n"));
    }

    #[test]
    fn recognizes_affirmative_response() {
        assert!(response_is_ok(b"a1 OK Begin TLS negotiation now\r\n"));
        assert!(!response_is_ok(b"a1 NO nope\r\n"));
        assert!(!response_is_ok(b"a1 BAD malformed\r\n"));
        // An untagged "* OK" preamble alone must not count as completion.
        assert!(!response_is_ok(b"* OK server ready\r\n"));
    }

    #[test]
    fn maildir_seed_is_fail_closed_and_ordered() {
        let dir = std::env::temp_dir().join(format!("eg-imap-seed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("2.eml"), b"Subject: Second\r\n\r\ntwo\r\n").unwrap();
        std::fs::write(dir.join("1.eml"), b"Subject: First\r\n\r\none\r\n").unwrap();
        std::fs::write(dir.join("note.txt"), b"ignored").unwrap();

        let mut store = MemoryStore::new();
        let n = seed_store_from_maildir(&mut store, &dir).unwrap();
        assert_eq!(n, 2, "only the two .eml files load");
        let inbox = store.mailbox("INBOX").unwrap();
        assert_eq!(inbox.exists(), 2);
        // Sorted filename order → UID 1 is "First", UID 2 is "Second".
        assert!(String::from_utf8_lossy(&inbox.messages[0].raw).contains("First"));
        assert!(String::from_utf8_lossy(&inbox.messages[1].raw).contains("Second"));

        // A missing directory fails closed rather than serving an empty mailbox.
        assert!(seed_store_from_maildir(&mut MemoryStore::new(), dir.join("nope")).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
