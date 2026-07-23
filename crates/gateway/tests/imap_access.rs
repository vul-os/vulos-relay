//! Real-socket integration tests for the OPTIONAL legacy IMAP access server (spec §8.2): a rustls
//! IMAP client authenticates over TLS to the gateway's [`ImapAccessServer`] and LISTs / SELECTs /
//! FETCHes a seeded mailbox. Proves:
//!   - implicit-TLS: a valid app-password logs in and reads a seeded message end-to-end;
//!   - a wrong app-password is refused fail-closed (tagged `NO`), and an unknown user too;
//!   - STARTTLS: the cleartext port advertises `LOGINDISABLED`, upgrades in place on `STARTTLS`, and
//!     then serves LOGIN → SELECT over the negotiated TLS channel;
//!   - the server is store-backed by the operator's mailbox snapshot (a seeded `MemoryStore`).
//!
//! The "off by default" contract is a config-level guarantee, asserted in
//! `personal.rs`/`imap_access.rs` unit tests (a fresh `PersonalConfig` has `imap_enable == false`).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use kotva_core::identity::IdentityKey;
use kotva_mail::auth::StaticAuthenticator;
use kotva_mail::store::MemoryStore;

use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use gateway::{ImapAccessServer, ImapTls};

const HOST: &str = "localhost";
const USER: &str = "owner@dmtap.local";
const APP_PW: &str = "app-password-xyz";

/// A self-signed cert for `localhost` plus the matching gateway TLS server config and the DER cert
/// (so the test client can trust it as its sole root).
fn self_signed() -> (CertificateDer<'static>, Arc<rustls::ServerConfig>) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec![HOST.to_string()]).expect("self-signed cert");
    let cert_der: CertificateDer<'static> = cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    let cfg =
        gateway::server_config(vec![cert_der.clone()], key.into()).expect("server config");
    (cert_der, cfg)
}

/// A client TLS config that trusts exactly the test's self-signed cert.
fn client_config(cert_der: CertificateDer<'static>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(cert_der).expect("add self-signed root");
    let cfg =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
    Arc::new(cfg)
}

/// A store seeded with one message in INBOX (the operator's mailbox snapshot) + owner credentials.
fn seed() -> (MemoryStore, StaticAuthenticator) {
    let mut store = MemoryStore::new();
    store.deliver_raw(
        "INBOX",
        b"Subject: Project kickoff\r\nFrom: sender@example.com\r\n\r\nLet's meet on Tuesday.\r\n"
            .to_vec(),
        vec![],
        1_752_000_000_000,
    );
    let mut auth = StaticAuthenticator::new();
    auth.issue(USER, APP_PW, IdentityKey::generate().public(), "thunderbird");
    (store, auth)
}

/// Read one CRLF line from `s` (byte-at-a-time, so no bytes are read past it — important across a
/// STARTTLS upgrade where the next bytes are a TLS ClientHello).
fn read_line<S: Read>(s: &mut S) -> String {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while s.read(&mut byte).expect("read") == 1 {
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    String::from_utf8_lossy(&line).into_owned()
}

/// Send `cmd` (already CRLF-terminated) and collect the response up to and including the line that
/// begins with `tag ` (the tagged completion). Our test commands use no literals, so no `+`
/// continuation is expected.
fn command<S: Read + Write>(s: &mut S, cmd: &str, tag: &str) -> String {
    s.write_all(cmd.as_bytes()).expect("write cmd");
    s.flush().expect("flush");
    let mut acc = String::new();
    loop {
        let line = read_line(s);
        if line.is_empty() {
            break;
        }
        let done = line.starts_with(&format!("{tag} "));
        acc.push_str(&line);
        if done {
            break;
        }
    }
    acc
}

// ---------------------------------------------------------------------------------------------
// 1. Implicit TLS: a valid app-password logs in and reads the seeded mailbox (LIST/SELECT/FETCH).
// ---------------------------------------------------------------------------------------------

#[test]
fn implicit_tls_login_list_select_fetch() {
    let (cert_der, server_cfg) = self_signed();
    let server =
        ImapAccessServer::bind("127.0.0.1:0", server_cfg, ImapTls::Implicit).expect("bind");
    let addr = server.local_addr().expect("addr");
    let (store, auth) = seed();
    let srv = thread::spawn(move || server.serve_once(store, auth));

    let tcp = TcpStream::connect(addr).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let conn = ClientConnection::new(client_config(cert_der), ServerName::try_from(HOST).unwrap())
        .expect("client conn");
    let mut tls = StreamOwned::new(conn, tcp);

    // Greeting.
    let greeting = read_line(&mut tls);
    assert!(greeting.contains("* OK") && greeting.contains("IMAP4rev2"), "greeting: {greeting}");

    // LOGIN with the valid app-password (channel is confidential → LOGIN permitted).
    let login = command(&mut tls, &format!("a1 LOGIN {USER} {APP_PW}\r\n"), "a1");
    assert!(login.contains("a1 OK"), "login: {login}");

    // LIST shows the projected folder layout incl. INBOX.
    let list = command(&mut tls, "a2 LIST \"\" \"*\"\r\n", "a2");
    assert!(list.contains("INBOX"), "list: {list}");
    assert!(list.contains("a2 OK"), "list tagged ok: {list}");

    // SELECT INBOX — the seeded message is present.
    let select = command(&mut tls, "a3 SELECT INBOX\r\n", "a3");
    assert!(select.contains("1 EXISTS"), "select: {select}");
    assert!(select.contains("a3 OK"), "select ok: {select}");

    // FETCH the envelope + subject header — the seeded content comes back over the TLS channel.
    let fetch = command(
        &mut tls,
        "a4 FETCH 1 (UID FLAGS ENVELOPE BODY.PEEK[HEADER.FIELDS (SUBJECT)])\r\n",
        "a4",
    );
    assert!(fetch.contains("Project kickoff"), "fetch subject: {fetch}");
    assert!(fetch.contains("UID 1"), "fetch uid: {fetch}");
    assert!(fetch.contains("a4 OK"), "fetch ok: {fetch}");

    let _ = command(&mut tls, "a5 LOGOUT\r\n", "a5");
    srv.join().expect("server thread").expect("served one connection");
}

// ---------------------------------------------------------------------------------------------
// 2. Bad credentials are rejected fail-closed (wrong password AND unknown user → tagged NO).
// ---------------------------------------------------------------------------------------------

#[test]
fn bad_credentials_are_rejected_fail_closed() {
    let (cert_der, server_cfg) = self_signed();
    let server =
        ImapAccessServer::bind("127.0.0.1:0", server_cfg, ImapTls::Implicit).expect("bind");
    let addr = server.local_addr().expect("addr");
    let (store, auth) = seed();
    let srv = thread::spawn(move || server.serve_once(store, auth));

    let tcp = TcpStream::connect(addr).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let conn = ClientConnection::new(client_config(cert_der), ServerName::try_from(HOST).unwrap())
        .expect("client conn");
    let mut tls = StreamOwned::new(conn, tcp);
    let _ = read_line(&mut tls); // greeting

    // Right user, wrong password → NO (never OK).
    let wrong_pw = command(&mut tls, &format!("b1 LOGIN {USER} not-the-password\r\n"), "b1");
    assert!(wrong_pw.contains("b1 NO"), "wrong password must be NO: {wrong_pw}");
    assert!(!wrong_pw.contains("b1 OK"));

    // Unknown user → NO as well (fail-closed, no user enumeration difference in verdict).
    let unknown = command(&mut tls, "b2 LOGIN nobody@dmtap.local whatever\r\n", "b2");
    assert!(unknown.contains("b2 NO"), "unknown user must be NO: {unknown}");

    let _ = command(&mut tls, "b3 LOGOUT\r\n", "b3");
    srv.join().expect("server thread").expect("served one connection");
}

// ---------------------------------------------------------------------------------------------
// 3. STARTTLS: cleartext port advertises LOGINDISABLED, upgrades in place, then serves the session.
// ---------------------------------------------------------------------------------------------

#[test]
fn starttls_upgrades_in_place_then_logs_in() {
    let (cert_der, server_cfg) = self_signed();
    let server =
        ImapAccessServer::bind("127.0.0.1:0", server_cfg, ImapTls::StartTls).expect("bind");
    let addr = server.local_addr().expect("addr");
    let (store, auth) = seed();
    let srv = thread::spawn(move || server.serve_once(store, auth));

    // Phase 1: cleartext.
    let mut tcp = TcpStream::connect(addr).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let greeting = read_line(&mut tcp);
    assert!(greeting.contains("* OK"), "greeting: {greeting}");

    // Before STARTTLS the server withholds LOGIN (RFC 9051 §5.1 security note).
    let caps = command(&mut tcp, "c1 CAPABILITY\r\n", "c1");
    assert!(caps.contains("STARTTLS"), "must advertise STARTTLS pre-TLS: {caps}");
    assert!(caps.contains("LOGINDISABLED"), "must advertise LOGINDISABLED pre-TLS: {caps}");

    // Issue STARTTLS; the server acks, then we drive the TLS handshake on the same socket.
    let start = command(&mut tcp, "c2 STARTTLS\r\n", "c2");
    assert!(start.contains("c2 OK"), "starttls ack: {start}");

    let conn = ClientConnection::new(client_config(cert_der), ServerName::try_from(HOST).unwrap())
        .expect("client conn");
    let mut tls = StreamOwned::new(conn, tcp);

    // Phase 2 (encrypted): LOGIN now permitted, SELECT the seeded mailbox.
    let login = command(&mut tls, &format!("c3 LOGIN {USER} {APP_PW}\r\n"), "c3");
    assert!(login.contains("c3 OK"), "post-STARTTLS login: {login}");
    let select = command(&mut tls, "c4 SELECT INBOX\r\n", "c4");
    assert!(select.contains("1 EXISTS"), "select after starttls: {select}");
    assert!(select.contains("c4 OK"));

    let _ = command(&mut tls, "c5 LOGOUT\r\n", "c5");
    srv.join().expect("server thread").expect("served one connection");
}
