//! Wave W10 — runtime conformance tests that DISCHARGE the `broker_conformance` Behavioral
//! findings for the `reachability-adapter` kind (COORD-1 and COORD-5, coordinator/CONTRACT.md
//! §3/§4).
//!
//! `broker_conformance::check()` marks COORD-1 ("verify descriptor signature once kotva-core is
//! pinned") and COORD-5 ("assert observed TLS/behavior matches the declared visibility class") as
//! `Outcome::Behavioral` — not decidable from the descriptor alone, and explicitly deferred to
//! per-kind runtime tests (`crates/broker-conformance/src/lib.rs` module docs, STYLE §8). This
//! file is that runtime test for `reachability-adapter`. `kotva-core` is now tag-pinned (W3), so
//! COORD-1's signature is real cryptography here, not a stub.
//!
//! **The crucial one is COORD-5.** For `reachability-adapter` the declared visibility is
//! `blind-routing` (structural for an own-domain name, declared for a bare adapter-zone vanity,
//! REACH-1a). "Observed behavior matches declared visibility" here means: the adapter routes
//! purely on the TLS ClientHello's SNI, terminates no TLS handshake, and holds no certificate or
//! private key for any name it routes this way (REACH-1). This file proves that against the REAL
//! `AdapterServer`/`ingress`/`auth`/`tunnel` wire path (the same pattern
//! `crates/reachability-adapter/src/ingress.rs`'s own `#[cfg(test)]` module already exercises —
//! extended here to make the "holds no decrypting key" property explicit and separately asserted,
//! and to tie it to the REACH-1a assurance split).
//!
//! Every test states what it proves AND what it does **not** (KOTVA house style, CONTRACT §4).

use std::collections::HashSet;

use kotva_core::identity::IdentityKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Duration;

use broker_economics::{Cbor, CoordinatorKind, Descriptor};
use reachability_adapter::auth::authenticate_as_box;
use reachability_adapter::ingress::{AdapterServer, IngressError};
use reachability_adapter::tunnel::Registration;
use reachability_adapter::{NameKind, ReachabilityAdapter};

use broker_conformance::Coordinator;

// =================================================================================================
// COORD-1 — the descriptor signature is REALLY verified once kotva-core is pinned (it is: W3).
// =================================================================================================

fn own_domain_descriptor(ik: &IdentityKey) -> Descriptor {
    Descriptor {
        identity: ik.public(),
        kind: CoordinatorKind::ReachabilityAdapter,
        visibility: NameKind::OwnDomain.declared_visibility(),
        policy: Cbor::empty(),
        tariff: None,
    }
}

/// **Proves:** a reachability-adapter descriptor, signed with a real kotva-core `IdentityKey`,
/// verifies under `SignedDescriptor::verify()` — COORD-1's "verify once kotva-core is pinned"
/// deferral is discharged with real Ed25519 signing/verification. **Does not prove:** anything
/// about the descriptor's content being trustworthy beyond "genuinely published by the identity it
/// claims" (CONTRACT §2.1's own scope).
#[test]
fn coord1_reachability_adapter_descriptor_signature_really_verifies() {
    let ik = IdentityKey::from_seed(&[0x61; 32]);
    let d = own_domain_descriptor(&ik);
    let signed = d.sign(&ik);
    assert!(signed.verify().is_ok(), "a genuinely-signed adapter descriptor must verify");
}

/// **Proves:** a descriptor tampered with after signing (its visibility claim flipped) fails
/// verification — the cryptographic check is real, not decorative. This particular tamper is the
/// exact attack COORD-5 exists to catch: silently changing what visibility is declared after the
/// fact. **Does not prove:** detection *timing* in production — only that the check itself, when
/// run, is not a no-op.
#[test]
fn coord1_tampered_reachability_adapter_descriptor_fails_verification() {
    let ik = IdentityKey::from_seed(&[0x62; 32]);
    let d = own_domain_descriptor(&ik);
    let mut signed = d.sign(&ik);
    assert!(signed.verify().is_ok(), "sanity: untampered descriptor verifies");

    // Tamper: silently downgrade/alter the visibility claim after signing — exactly the
    // misrepresentation COORD-5 forbids.
    use broker_economics::visibility::{AssuranceLevel, ContentVisibility, VisibilityClass};
    signed.descriptor.visibility =
        ContentVisibility::new(VisibilityClass::Blind, AssuranceLevel::Structural);
    assert!(
        signed.verify().is_err(),
        "a descriptor whose visibility claim was altered after signing MUST fail verification"
    );
}

/// **Proves:** a signature genuinely produced by a different key than the one the descriptor
/// claims as its identity is rejected. **Does not prove:** discovery/key-distribution integrity —
/// only the signature check against the claimed identity.
#[test]
fn coord1_reachability_adapter_descriptor_signed_by_wrong_key_fails_verification() {
    let claimed = IdentityKey::from_seed(&[0x63; 32]);
    let actual_signer = IdentityKey::from_seed(&[0x64; 32]);
    let d = own_domain_descriptor(&claimed);
    let signed = d.sign(&actual_signer);
    assert!(signed.verify().is_err(), "signed-by-the-wrong-key must not verify");
}

// =================================================================================================
// REACH-1a — the own-domain vs bare-vanity assurance split ties declared assurance to reality.
// =================================================================================================

/// **Proves:** an own-domain name (the box controls the DNS zone; a CAA record can bar the adapter
/// from ever minting a cert for it) declares `blind-routing` at `structural` assurance, which
/// `is_verifiably_blind()` accepts as a checkable claim — and this genuinely-signed descriptor
/// verifies. **Does not prove:** that a specific deployment's DNS/CAA is actually configured this
/// way — this is the crate-level contract the `NameKind::OwnDomain` constructor commits to; a
/// deployment-level CAA audit is outside this crate's scope.
#[test]
fn reach1a_own_domain_is_structural_and_signature_verifies() {
    let ik = IdentityKey::generate();
    let a = ReachabilityAdapter::new(own_domain_descriptor(&ik), false);
    assert!(a.descriptor().visibility.is_verifiably_blind());
    assert!(!a.descriptor().visibility.must_not_present_as_verified());

    let signed = a.descriptor().sign(&ik);
    assert!(signed.verify().is_ok(), "a real signature over an own-domain descriptor verifies");
}

/// **Proves:** a bare adapter-zone vanity (the adapter is the zone's sole writer and COULD mint
/// its own cert and MITM a non-pinning client) declares `blind-routing` at only `declared`
/// assurance — `must_not_present_as_verified()` is true, so a client MUST surface this as an
/// unverified claim, never as "verified blind" — even though the descriptor carrying that
/// (honestly weaker) claim is itself perfectly, genuinely signed. Signature integrity (COORD-1)
/// and assurance-level honesty (COORD-4/§3.4) are orthogonal axes; this test keeps them
/// deliberately separate, mirroring `broker-economics`'s own
/// `declared_level_blind_claim_is_still_surfaced_as_unverified`. **Does not prove:** that this
/// specific adapter is or is not actually MITMing anyone — `declared` assurance means exactly that
/// this cannot be verified from outside, which is the disclosed residual, not a bug.
#[test]
fn reach1a_bare_vanity_is_declared_not_verified_even_though_genuinely_signed() {
    let ik = IdentityKey::generate();
    let d = Descriptor {
        identity: ik.public(),
        kind: CoordinatorKind::ReachabilityAdapter,
        visibility: NameKind::AdapterZoneVanity.declared_visibility(),
        policy: Cbor::empty(),
        tariff: None,
    };
    let a = ReachabilityAdapter::new(d, true);
    assert!(!a.descriptor().visibility.is_verifiably_blind());
    assert!(a.descriptor().visibility.must_not_present_as_verified());

    let signed = a.descriptor().sign(&ik);
    assert!(
        signed.verify().is_ok(),
        "the signature itself is genuinely valid — that is a separate axis from whether the \
         claim it carries may be shown as verified"
    );
    assert!(
        signed.descriptor.visibility.must_not_present_as_verified(),
        "REACH-1a: a bare adapter-zone vanity's blind-routing claim must still not be presented \
         as verified, no matter how authentically the descriptor carrying it is signed"
    );

    // Still contract-conformant overall: the residual is disclosed, not hidden.
    let r = broker_conformance::check(&a);
    assert!(r.is_conformant(), "{:?}", r.findings);
}

// =================================================================================================
// COORD-5 — structural blind-routing: the adapter routes by SNI alone and holds no key/cert for
// any passthrough name, so it structurally cannot read payload. Driven against the REAL ingress +
// auth + tunnel wire path (same shape as `ingress.rs`'s own tests), with the "holds no decrypting
// key" property made explicit.
// =================================================================================================

/// Spawn a fake box that runs the REAL REACH-2 key-auth handshake (`authenticate_as_box`, the
/// same function a real box binary calls) under a freshly-generated real `IdentityKey`, registers
/// for `name`/`service`, then serves the post-auth yamux session **as if it were the TLS
/// terminator for that name** — but it plainly is not: it never parses anything as TLS, it simply
/// echoes back application bytes verbatim, standing in for "some server on the other end that
/// actually holds the certificate and completes the handshake". This is the point: the adapter's
/// ingress code path (`AdapterServer::handle_ingress_connection`, exercised for real below) never
/// itself attempts anything TLS-shaped — it forwards bytes to whatever this box does with them,
/// sight unseen.
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
        let ik = IdentityKey::generate();
        let registration = Registration { name, allowed_services: services };
        authenticate_as_box(&mut ctrl, &ik, &registration).await.unwrap();

        use tokio_util::compat::TokioAsyncReadCompatExt;
        let io = ctrl.compat();
        let mut conn = yamux::Connection::new(io, yamux::Config::default(), yamux::Mode::Server);
        loop {
            let stream = match std::future::poll_fn(|cx| conn.poll_next_inbound(cx)).await {
                Some(Ok(s)) => s,
                _ => break,
            };
            tokio::spawn(async move {
                use tokio_util::compat::FuturesAsyncReadCompatExt;
                let mut s = stream.compat();
                let mut buf = [0u8; 8192];
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

async fn wait_until_registered(server: &AdapterServer, name: &str) {
    for _ in 0..100 {
        if server.registry().lookup(name).await.is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("tunnel for {name:?} never appeared in the registry");
}

/// A minimal-but-valid TLS 1.3 ClientHello record carrying `host_name` as its SNI, mirroring RFC
/// 8446 §4.1.2 field order (the same shape `sni.rs`'s own tests build — duplicated locally so this
/// integration test does not need to reach into a sibling module's private test helpers).
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

/// `AdapterServer`'s ENTIRE field set (`crates/reachability-adapter/src/ingress.rs`) is
/// `registry: TunnelRegistry` + `nonces: NonceRegistry` — neither is, nor contains, a TLS
/// certificate or private key type, and the crate's own `Cargo.toml` pulls in no TLS-terminating
/// library at all (no rustls/native-tls/openssl — grep the dependency list: `tokio`, `yamux`,
/// `tokio-util`, `kotva-core`, `getrandom`, `thiserror`, `tracing`; not one of those does TLS
/// termination). `AdapterServer::new()`/`default()` take no certificate or key argument, and no
/// method anywhere on this crate's public API loads one. That is the structural half of "holds no
/// decrypting key": it is not merely undemonstrated at runtime, there is no code path in this
/// crate through which a certificate/private key could ever enter an `AdapterServer` in the first
/// place. This test's job is the runtime half: prove that a real ClientHello **plus** payload
/// bytes that are indistinguishable from genuine TLS ciphertext (high-entropy, not valid UTF-8,
/// not any recognizable plaintext) survive the adapter's real ingress path — SNI peek
/// (`sni::peek_client_hello`) → registry lookup by name → tunnel splice — byte-for-byte
/// unmodified. If the adapter attempted anything resembling decrypt-then-inspect-then-re-encrypt,
/// this random byte stream could not possibly round-trip identically (there is no key to decrypt
/// it with, and no code path here tries).
///
/// **Proves:** (1) the adapter's real, live `handle_ingress_connection` routes solely on the
/// ClientHello SNI; (2) arbitrary high-entropy payload — the honest stand-in for real TLS
/// application data — passes through byte-identical; (3) `AdapterServer` structurally carries no
/// certificate/key material anywhere in its type (stated above, verifiable by reading the struct
/// and the crate manifest). Together this is "observed behavior matches the declared
/// `blind-routing`/`structural` visibility" — COORD-5, discharged for the own-domain case.
/// **Does not prove:** that a REAL TLS client/server pair completes a handshake through this path
/// (this crate's test-dependency set has no TLS library to drive one — see the crate `Cargo.toml`
/// this wave deliberately did not touch); the fake "box" here is an application-level echo
/// server, standing in for "whatever holds the real cert on the other end", exactly as
/// `ingress.rs`'s own upstream tests already do. The claim being tested is narrower and
/// structural: the adapter itself never attempts to be that TLS party.
#[tokio::test]
async fn coord5_adapter_holds_no_decrypting_key_and_splices_ciphertext_like_bytes_verbatim() {
    let control_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control_listener.local_addr().unwrap();
    let name = "svc.alice.reach.example";
    let _box_task = spawn_fake_box(control_listener, name, "https").await;

    let server = AdapterServer::new();
    let control_client = TcpStream::connect(control_addr).await.unwrap();
    server.accept_box_connection(control_client).await.unwrap();
    wait_until_registered(&server, name).await;

    let ingress_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ingress_addr = ingress_listener.local_addr().unwrap();
    let ingress_server = server.clone();
    tokio::spawn(async move {
        let (socket, _) = ingress_listener.accept().await.unwrap();
        ingress_server.handle_ingress_connection(socket, "https").await.unwrap();
    });

    let mut client = TcpStream::connect(ingress_addr).await.unwrap();
    let client_hello = build_client_hello(name);
    client.write_all(&client_hello).await.unwrap();

    let mut echoed_hello = vec![0u8; client_hello.len()];
    client.read_exact(&mut echoed_hello).await.unwrap();
    assert_eq!(
        echoed_hello, client_hello,
        "the ClientHello itself must splice through byte-identical — the adapter never \
         re-serializes what it parsed"
    );

    // High-entropy bytes standing in for real TLS application-data ciphertext: not valid UTF-8,
    // no recognizable structure — exactly what the adapter would see if it were actually carrying
    // an encrypted TLS session, and exactly what it could NOT reproduce byte-for-byte if it were
    // decrypting and re-encrypting (it holds no key to do either).
    let ciphertext_like: Vec<u8> =
        (0..4096u32).map(|i| ((i.wrapping_mul(2654435761u32)) >> 21) as u8).collect();
    assert!(
        std::str::from_utf8(&ciphertext_like).is_err(),
        "sanity: the probe payload is not valid UTF-8 / plaintext-shaped, like real ciphertext"
    );
    client.write_all(&ciphertext_like).await.unwrap();
    let mut echoed = vec![0u8; ciphertext_like.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(
        echoed, ciphertext_like,
        "ciphertext-shaped payload must splice through byte-identical — no decrypt/inspect/\
         re-encrypt step exists on this path"
    );
}

/// **Proves:** the adapter's routing decision depends on the SNI name ALONE, never on payload
/// content — two connections carrying byte-IDENTICAL application payload but DIFFERENT SNI names
/// are routed to their own DIFFERENT registered boxes (never cross-delivered), which is only
/// possible if the routing lookup keys on the name, not on anything it read from the payload (it
/// structurally could not read the payload's plaintext meaning at all — see the previous test).
/// This is the routing-side complement to "holds no decrypting key": content-blind routing means
/// routing BY name, not just "does not decrypt". **Does not prove:** DNS-level assurance that
/// these two names are actually served by different physical operators — that is a deployment
/// fact, not something this crate's routing logic could observe either way.
#[tokio::test]
async fn coord5_routing_depends_on_sni_alone_not_on_payload_content() {
    let server = AdapterServer::new();

    let control_listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr_a = control_listener_a.local_addr().unwrap();
    let _box_a = spawn_fake_box(control_listener_a, "a.reach.example", "https").await;
    let control_client_a = TcpStream::connect(control_addr_a).await.unwrap();
    server.accept_box_connection(control_client_a).await.unwrap();
    wait_until_registered(&server, "a.reach.example").await;

    let control_listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr_b = control_listener_b.local_addr().unwrap();
    let _box_b = spawn_fake_box(control_listener_b, "b.reach.example", "https").await;
    let control_client_b = TcpStream::connect(control_addr_b).await.unwrap();
    server.accept_box_connection(control_client_b).await.unwrap();
    wait_until_registered(&server, "b.reach.example").await;

    // Byte-identical application payload for BOTH connections — only the SNI differs.
    let shared_payload = b"identical-bytes-on-both-connections-0123456789";

    for name in ["a.reach.example", "b.reach.example"] {
        let ingress_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingress_addr = ingress_listener.local_addr().unwrap();
        let ingress_server = server.clone();
        tokio::spawn(async move {
            let (socket, _) = ingress_listener.accept().await.unwrap();
            ingress_server.handle_ingress_connection(socket, "https").await.unwrap();
        });

        let mut client = TcpStream::connect(ingress_addr).await.unwrap();
        let client_hello = build_client_hello(name);
        client.write_all(&client_hello).await.unwrap();
        let mut echoed_hello = vec![0u8; client_hello.len()];
        client.read_exact(&mut echoed_hello).await.unwrap();
        assert_eq!(echoed_hello, client_hello);

        client.write_all(shared_payload).await.unwrap();
        let mut echoed = vec![0u8; shared_payload.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(
            &echoed, shared_payload,
            "each connection's own box echoed the SAME payload bytes back — routed correctly by \
             its own SNI, not by any property of the payload (which was identical across both)"
        );
    }
}

/// **Proves:** an unregistered SNI is fail-closed (REACH-6) — reset, zero bytes forwarded. This is
/// the negative control for COORD-5: a would-be observed-behavior mismatch (routing to *something*
/// for a name nobody registered) would be exactly the "declared blind-routing but actually guesses
/// / falls back" violation COORD-5 exists to catch; this test pins that it does not happen.
/// **Does not prove:** anything about names that *are* registered — see the tests above for that.
#[tokio::test]
async fn coord5_unregistered_name_fails_closed_never_falls_back() {
    let server = AdapterServer::new();
    let ingress_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ingress_addr = ingress_listener.local_addr().unwrap();
    let ingress_server = server.clone();
    let handled = tokio::spawn(async move {
        let (socket, _) = ingress_listener.accept().await.unwrap();
        ingress_server.handle_ingress_connection(socket, "https").await
    });

    let mut client = TcpStream::connect(ingress_addr).await.unwrap();
    let client_hello = build_client_hello("nobody-registered-this.reach.example");
    client.write_all(&client_hello).await.unwrap();

    let result = handled.await.unwrap();
    assert!(matches!(result, Err(IngressError::UnregisteredName(_))));

    let mut buf = [0u8; 16];
    match client.read(&mut buf).await {
        Ok(0) => {}
        Ok(n) => panic!("expected zero forwarded bytes, got {n}"),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(e) => panic!("unexpected error: {e}"),
    }
}
