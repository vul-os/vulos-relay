//! REACH-2 — mutual key-authentication of the box↔adapter control connection
//! to the box's real identity key (`IK`), mirroring DMTAP-Auth's
//! challenge-response ceremony (kotva `13-identity-auth.md` §13.3) applied to
//! a node-held key rather than a browser/WebAuthn login:
//!
//! ```text
//! box -> adapter   AuthAnnounce { claimed_ik, name, allowed_services }
//! adapter -> box   Challenge { nonce }                    (fresh, single-use)
//! box -> adapter   Response { sig }     sig = Sign_ik(DS ‖ nonce ‖ name)
//! ```
//!
//! The adapter verifies `sig` against the box's own *claimed* `claimed_ik`
//! via [`kotva_core::identity::verify_domain`]. On success the box has proven
//! — with the same confidence as any Ed25519 signature — that it holds the
//! private key for `claimed_ik`, and [`TunnelRegistry`](crate::tunnel::TunnelRegistry)
//! binds the SNI registration to that authenticated key (`tunnel.rs`). On any
//! failure (malformed frame, unknown/already-consumed nonce, bad signature)
//! this module fails closed: the caller MUST drop the connection without
//! proceeding to the yamux session (REACH-6 applied to the control leg).
//!
//! Binding the signature to `nonce ‖ name` (not just `nonce`) is what stops a
//! signature obtained for one name from being lifted to register a different
//! one: an attacker who somehow captures a valid `(nonce, sig)` pair for
//! `alice.reach.example` cannot replay it to claim `bob.reach.example` — the
//! preimage would not match, so [`verify_domain`] rejects it.
//!
//! ## Replay-inertness
//!
//! The nonce is drawn from the OS CSPRNG ([`getrandom`]) fresh per
//! connection, and [`NonceRegistry`] marks it **consumed exactly once**
//! ([`NonceRegistry::consume`]) the instant a `Response` frame is read — a
//! second presentation of the same nonce bytes, from any connection, is
//! rejected as [`AuthError::NonceReplayed`]. In the ordinary case this is
//! belt-and-suspenders (a fresh per-connection nonce already makes a captured
//! signature useless against any *other* connection's differently-nonced
//! challenge, since the preimage differs); the registry closes the
//! degenerate case of a nonce value being issued twice (an RNG defect, or a
//! future refactor that stops drawing fresh nonces per connection) rather
//! than relying on "the RNG never repeats" alone.
//!
//! ## What REACH-2 this closes, and what it does not (honest disclosure)
//!
//! **Closed:** mutual **key-authentication** — the adapter never accepts a
//! registration it cannot cryptographically attribute to a specific `IK`,
//! and (`tunnel.rs`) a name once registered to one `IK` can never be
//! hijacked or silently overwritten by a different `IK` (REACH-7-style
//! single-writer, now scoped to `(name, owning IK)` instead of bare `name`).
//! Wrong-key signatures, replayed nonces, and cross-name signature reuse all
//! fail closed.
//!
//! **NOT closed — the residual, stated plainly:** this is key-auth **only**.
//! The handshake frames (`AuthAnnounce`, `Challenge`, `Response`) — and every
//! byte on the control connection after them, including the yamux session
//! itself — travel over the **same plain, unencrypted TCP connection**
//! `tunnel.rs` always used. There is no Noise/TLS wrapper here. The REACH
//! profile's long-term target for this leg is **libp2p Noise**
//! (profiles/reachability.md §2, "a libp2p-secured stream"); that transport-
//! security layer is still **not implemented** by this crate. Concretely, an
//! on-path attacker between box and adapter can:
//!
//! - **observe** every frame — the claimed public `IK`, the registered name,
//!   the service allow-list, the nonce, and the signature — none of this is
//!   confidential on the wire;
//! - **tamper with or drop** frames — a MITM can flip, truncate, or delay
//!   bytes, forcing a handshake failure (denial of service on that
//!   connection attempt);
//!
//! but such an attacker **cannot forge a valid signature** for an `IK` it
//! does not hold the private key for, so it **cannot impersonate the box**,
//! cannot register a name under an identity it does not own, and cannot
//! splice a captured signature onto a different nonce or name. What key-auth
//! alone buys is exactly that: proof of identity, not confidentiality or
//! tamper-detection of the channel carrying it. Do not present this module,
//! or the crate, as "fully REACH-2 compliant" — REACH-2 mandates the tunnel
//! be mutually authenticated **over** a libp2p-Noise-secured transport, and
//! only the authentication half is done here.
//!
//! REACH-5's allow-list continues to ride the same free-form-string
//! declaration inside the (now authenticated) [`Registration`] — REACH-2
//! proves *who* is declaring it, not that the declared services are
//! independently verified against anything external; that remains future
//! work, unaffected by this module.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use kotva_core::identity::{verify_domain, IdentityKey};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::tunnel::{read_registration, write_registration, Registration, TunnelError};

/// DMTAP/kotva-core domain-separation convention (§18.9.3 in the KOTVA spec, applied here
/// as `WAKALA-REACH-v0/...`, matching `broker-economics/src/descriptor.rs`'s own
/// per-object-type tag convention): an ASCII string terminated by one `0x00` byte, distinct
/// from every other signed object type in this workspace so a tunnel-auth signature can
/// never be replayed as a descriptor, tariff, receipt, or any other signed object.
pub const TUNNEL_AUTH_DS: &[u8] = b"WAKALA-REACH-v0/tunnel-auth\x00";

/// Raw Ed25519 public key length (kotva-core suite `0x01`, classical).
const IK_LEN: usize = 32;
/// Challenge nonce length — 32 bytes of OS CSPRNG output (128-bit security margin and then
/// some; matches the content-address/key sizes used elsewhere in this workspace).
const NONCE_LEN: usize = 32;
/// Raw Ed25519 signature length.
const SIG_LEN: usize = 64;

/// Bound on how many outstanding (issued, not-yet-consumed) nonces the adapter will track at
/// once. A box that starts but never finishes the handshake ties up one slot until either it
/// completes or this cap forces an eviction of the oldest still-pending entry — never
/// unbounded growth from a client that opens connections and never responds.
const MAX_PENDING_NONCES: usize = 10_000;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("I/O error during tunnel auth handshake: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed auth frame: {0}")]
    Malformed(&'static str),
    #[error(transparent)]
    Registration(#[from] TunnelError),
    #[error(
        "challenge nonce was not a live, adapter-issued value awaiting exactly one response \
         (unknown, already consumed, or replayed) — REACH-6 fail-closed"
    )]
    NonceReplayed,
    #[error("signature does not verify against the claimed IK — REACH-6 fail-closed")]
    BadSignature,
}

/// What the box announces before the adapter has verified anything: a *claimed* identity, plus
/// the same [`Registration`] declaration `tunnel.rs` always carried (REACH-5's name + service
/// allow-list). Nothing in this type is trusted yet — that is exactly what the rest of the
/// handshake establishes.
#[derive(Debug, Clone)]
pub struct AuthAnnounce {
    /// The box's claimed Ed25519 `IK` public key. Unverified until [`authenticate_box_connection`]
    /// returns `Ok`.
    pub claimed_ik: [u8; IK_LEN],
    pub registration: Registration,
}

/// The result of a successful REACH-2 handshake: the box's declared registration, now bound to
/// the `IK` that was cryptographically proven (not merely claimed) to have signed it.
#[derive(Debug, Clone)]
pub struct AuthenticatedRegistration {
    pub registration: Registration,
    /// The verified Ed25519 public key, raw bytes — the same representation
    /// `kotva_core::identity::IdentityKey::public()` returns and `broker-economics/descriptor.rs`
    /// carries as `Descriptor.identity`.
    pub authenticated_ik: Vec<u8>,
}

/// The exact bytes the box signs and the adapter re-derives to verify: `nonce ‖ name`. Binding
/// the claimed name into the preimage (not just the nonce) is what stops a signature obtained
/// for one name being lifted to register a different one under the same key.
fn signing_preimage(nonce: &[u8; NONCE_LEN], name: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(NONCE_LEN + name.len());
    m.extend_from_slice(nonce);
    m.extend_from_slice(name.as_bytes());
    m
}

async fn read_fixed<const N: usize>(stream: &mut TcpStream) -> Result<[u8; N], std::io::Error> {
    let mut buf = [0u8; N];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Read an [`AuthAnnounce`] frame: the fixed-length claimed `IK` followed by the existing
/// length-prefixed [`Registration`] frame (`tunnel::read_registration`, with its own bounded-length
/// guards against an adversarial box trickling an unbounded field). The socket is left positioned
/// exactly at the first byte after the frame, ready for [`write_challenge`]/[`read_challenge`].
pub async fn read_announce(stream: &mut TcpStream) -> Result<AuthAnnounce, AuthError> {
    let claimed_ik = read_fixed::<IK_LEN>(stream).await?;
    let registration = read_registration(stream).await?;
    Ok(AuthAnnounce {
        claimed_ik,
        registration,
    })
}

/// Write an [`AuthAnnounce`] frame — the box side. Exposed for tests and for a future real box
/// agent to drive the same wire format [`read_announce`] expects.
pub async fn write_announce(stream: &mut TcpStream, announce: &AuthAnnounce) -> Result<(), AuthError> {
    stream.write_all(&announce.claimed_ik).await?;
    write_registration(stream, &announce.registration).await?;
    Ok(())
}

/// Read a [`Challenge`] nonce — fixed-length, no framing needed.
pub async fn read_challenge(stream: &mut TcpStream) -> Result<[u8; NONCE_LEN], AuthError> {
    Ok(read_fixed::<NONCE_LEN>(stream).await?)
}

/// Write a [`Challenge`] nonce — the adapter side.
pub async fn write_challenge(stream: &mut TcpStream, nonce: &[u8; NONCE_LEN]) -> Result<(), AuthError> {
    stream.write_all(nonce).await?;
    Ok(())
}

/// Read a `Response` signature — fixed-length, no framing needed.
pub async fn read_response(stream: &mut TcpStream) -> Result<[u8; SIG_LEN], AuthError> {
    Ok(read_fixed::<SIG_LEN>(stream).await?)
}

/// Write a `Response` signature — the box side.
pub async fn write_response(stream: &mut TcpStream, sig: &[u8; SIG_LEN]) -> Result<(), AuthError> {
    stream.write_all(sig).await?;
    Ok(())
}

/// The adapter's set of issued-but-not-yet-consumed challenge nonces (REACH-2, "single-use,
/// replay-inert"). `Clone` is cheap ([`Arc`]-backed) so one instance can be shared across every
/// spawned per-connection control-handling task, exactly like [`TunnelRegistry`](crate::tunnel::TunnelRegistry).
#[derive(Clone, Default)]
pub struct NonceRegistry {
    inner: Arc<Mutex<NonceState>>,
}

#[derive(Default)]
struct NonceState {
    pending: HashSet<[u8; NONCE_LEN]>,
    order: VecDeque<[u8; NONCE_LEN]>,
}

impl NonceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Draw a fresh nonce from the OS CSPRNG and register it as live/pending. Bounded: at
    /// capacity, the oldest still-pending nonce is evicted first (that connection's handshake
    /// will simply fail its eventual [`NonceRegistry::consume`] and must reconnect) rather than
    /// growing without limit for a client population that opens many connections and stalls.
    pub async fn issue(&self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).expect("OS CSPRNG unavailable");
        let mut state = self.inner.lock().await;
        if state.order.len() >= MAX_PENDING_NONCES {
            if let Some(oldest) = state.order.pop_front() {
                state.pending.remove(&oldest);
            }
        }
        state.pending.insert(nonce);
        state.order.push_back(nonce);
        nonce
    }

    /// Consume `nonce` exactly once. Returns `true` iff it was live/pending (issued by
    /// [`Self::issue`] and not previously consumed or evicted) — the single-use, replay-inert
    /// check: a second call with the same bytes, from any connection, always returns `false`.
    pub async fn consume(&self, nonce: &[u8; NONCE_LEN]) -> bool {
        self.inner.lock().await.pending.remove(nonce)
    }
}

/// Run the **adapter** side of the REACH-2 challenge-response handshake on a freshly-accepted
/// box control connection, fail-closed on every path (REACH-6): a malformed frame, an
/// unknown/already-consumed nonce, or a signature that does not verify against the *claimed* IK
/// all return `Err`, and the caller MUST NOT proceed to spawn the yamux session or touch the
/// [`TunnelRegistry`](crate::tunnel::TunnelRegistry) — just drop the connection.
///
/// This function only **authenticates identity**; it never inspects, and has nothing to do
/// with, anything past the control-frame preamble (REACH-2's "authorize, never classify" —
/// there is no tunneled payload in scope here at all, only the box's own signed claim about
/// itself).
pub async fn authenticate_box_connection(
    stream: &mut TcpStream,
    nonces: &NonceRegistry,
) -> Result<AuthenticatedRegistration, AuthError> {
    let announce = read_announce(stream).await?;

    let nonce = nonces.issue().await;
    write_challenge(stream, &nonce).await?;

    let sig = read_response(stream).await?;

    // Single-use: this also rejects a resent/duplicated Response for a nonce this connection
    // (or, in the RNG-collision/refactor-defect case, a different one) already consumed.
    if !nonces.consume(&nonce).await {
        return Err(AuthError::NonceReplayed);
    }

    let preimage = signing_preimage(&nonce, &announce.registration.name);
    verify_domain(&announce.claimed_ik, TUNNEL_AUTH_DS, &preimage, &sig)
        .map_err(|_| AuthError::BadSignature)?;

    Ok(AuthenticatedRegistration {
        registration: announce.registration,
        authenticated_ik: announce.claimed_ik.to_vec(),
    })
}

/// Run the **box** side of the handshake over an already-connected control socket: announce the
/// claimed `IK` + [`Registration`], then sign the adapter's challenge under `ik` and send the
/// response. Exposed so tests (and, eventually, the real box agent) can drive the exact wire
/// format [`authenticate_box_connection`] expects. Returns once the response has been written —
/// the caller then proceeds to speak yamux on the same socket exactly as before REACH-2 (auth is
/// a preamble, not a new session layer).
pub async fn authenticate_as_box(
    stream: &mut TcpStream,
    ik: &IdentityKey,
    registration: &Registration,
) -> Result<(), AuthError> {
    let announce = AuthAnnounce {
        claimed_ik: ik.public_array(),
        registration: registration.clone(),
    };
    write_announce(stream, &announce).await?;

    let nonce = read_challenge(stream).await?;
    let sig = ik.sign_domain(TUNNEL_AUTH_DS, &signing_preimage(&nonce, &registration.name));
    let sig: [u8; SIG_LEN] = sig
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::Malformed("IK signature was not 64 bytes"))?;
    write_response(stream, &sig).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet as StdHashSet;
    use tokio::net::TcpListener;

    fn registration(name: &str) -> Registration {
        let mut services = StdHashSet::new();
        services.insert("https".to_string());
        Registration {
            name: name.to_string(),
            allowed_services: services,
        }
    }

    #[tokio::test]
    async fn successful_handshake_authenticates_and_returns_the_registration() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ik = IdentityKey::generate();
        let expected_pub = ik.public();

        let reg = registration("svc.alice.reach.example");
        let box_reg = reg.clone();
        let box_task = tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            authenticate_as_box(&mut client, &ik, &box_reg).await.unwrap();
        });

        let (mut sock, _) = listener.accept().await.unwrap();
        let nonces = NonceRegistry::new();
        let authed = authenticate_box_connection(&mut sock, &nonces).await.unwrap();

        assert_eq!(authed.authenticated_ik, expected_pub);
        assert_eq!(authed.registration.name, "svc.alice.reach.example");
        box_task.await.unwrap();
    }

    #[tokio::test]
    async fn wrong_key_signature_is_rejected_fail_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // The box CLAIMS `claimed_ik`'s public key but signs with a completely different key
        // (`signing_ik`) — an attacker who does not hold `claimed_ik`'s private key trying to
        // register in its name.
        let claimed_ik = IdentityKey::generate();
        let signing_ik = IdentityKey::generate();
        let reg = registration("svc.alice.reach.example");

        let box_task = tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            let announce = AuthAnnounce {
                claimed_ik: claimed_ik.public_array(),
                registration: reg,
            };
            write_announce(&mut client, &announce).await.unwrap();
            let nonce = read_challenge(&mut client).await.unwrap();
            // Signed under the WRONG key.
            let sig = signing_ik.sign_domain(TUNNEL_AUTH_DS, &signing_preimage(&nonce, &announce.registration.name));
            let sig: [u8; SIG_LEN] = sig.as_slice().try_into().unwrap();
            write_response(&mut client, &sig).await.unwrap();
        });

        let (mut sock, _) = listener.accept().await.unwrap();
        let nonces = NonceRegistry::new();
        let err = authenticate_box_connection(&mut sock, &nonces).await.unwrap_err();
        assert!(matches!(err, AuthError::BadSignature));
        box_task.await.unwrap();
    }

    #[tokio::test]
    async fn nonce_is_single_use_a_second_consume_is_rejected() {
        let nonces = NonceRegistry::new();
        let nonce = nonces.issue().await;

        assert!(nonces.consume(&nonce).await, "first consume of a live nonce must succeed");
        assert!(
            !nonces.consume(&nonce).await,
            "a second consume of the SAME nonce bytes must be rejected — replay-inert"
        );
    }

    #[tokio::test]
    async fn unknown_nonce_never_issued_is_rejected() {
        let nonces = NonceRegistry::new();
        let forged = [0x42u8; NONCE_LEN];
        assert!(
            !nonces.consume(&forged).await,
            "a nonce the registry never issued must not be consumable"
        );
    }

    #[tokio::test]
    async fn replayed_signature_from_an_earlier_challenge_is_rejected_by_a_fresh_one() {
        // Simulate an attacker who captured a fully valid (nonce, sig) pair from one legitimate
        // handshake and tries to replay just the signature against a SECOND connection's
        // independently-issued challenge nonce. Because the preimage is `nonce ‖ name` and the
        // second connection's adapter-issued nonce necessarily differs, the captured signature
        // must not verify — replay-inertness holds even without hitting the exact same nonce
        // value twice.
        let ik = IdentityKey::generate();
        let reg = registration("svc.alice.reach.example");

        // First (legitimate) handshake — capture the nonce actually issued and its valid sig.
        let first_nonce = [0x11u8; NONCE_LEN];
        let captured_sig = ik.sign_domain(TUNNEL_AUTH_DS, &signing_preimage(&first_nonce, &reg.name));
        let captured_sig: [u8; SIG_LEN] = captured_sig.as_slice().try_into().unwrap();

        // Second connection: adapter issues a genuinely fresh nonce (guaranteed different here
        // since it's drawn from the CSPRNG, astronomically unlikely to collide with the fixed
        // `first_nonce` above) and the attacker replays the captured signature against it.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let claimed_ik_pub = ik.public_array();
        let reg_for_box = reg.clone();
        let box_task = tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            let announce = AuthAnnounce {
                claimed_ik: claimed_ik_pub,
                registration: reg_for_box,
            };
            write_announce(&mut client, &announce).await.unwrap();
            let _fresh_nonce = read_challenge(&mut client).await.unwrap();
            // Replay the OLD signature regardless of the fresh nonce just issued.
            write_response(&mut client, &captured_sig).await.unwrap();
        });

        let (mut sock, _) = listener.accept().await.unwrap();
        let nonces = NonceRegistry::new();
        let err = authenticate_box_connection(&mut sock, &nonces).await.unwrap_err();
        assert!(matches!(err, AuthError::BadSignature));
        box_task.await.unwrap();
    }
}
