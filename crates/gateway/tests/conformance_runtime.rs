//! Wave W10 — runtime conformance tests that DISCHARGE the `broker_conformance` Behavioral
//! findings for the `gateway` kind (COORD-1 and COORD-5, coordinator/CONTRACT.md §3/§4), plus a
//! COORD-6 runtime demonstration.
//!
//! `broker_conformance::check()` marks COORD-1 ("verify descriptor signature once kotva-core is
//! pinned") and COORD-5 ("assert observed TLS/behavior matches the declared visibility class") as
//! `Outcome::Behavioral` — not decidable from the descriptor alone, and explicitly deferred to
//! per-kind runtime tests (`crates/broker-conformance/src/lib.rs` module docs, STYLE §8). This
//! file is that runtime test for `gateway`. `kotva-core` is now tag-pinned (W3), so COORD-1's
//! signature is real cryptography here, not a stub.
//!
//! Every test below states what it proves AND what it does **not** (KOTVA house style,
//! coordinator/CONTRACT.md §4): the honest residuals are left visible, never quietly assumed away.

use broker_conformance::Coordinator;
use gateway::attestation::{Attestation, AttestationKey};
use gateway::coordinator::GatewayCoordinator;
use gateway::inbound::{
    AbuseDecision, AntiAbuse, DeliveryOutcome, DkimPolicy, DmarcHandling, InboundGateway,
    KeyDirectory, MeshDelivery, MxSession, RecipientKey, SpfPolicy,
};
use gateway::spf::InMemorySpfResolver;
use kotva_core::identity::IdentityKey;
use kotva_core::mote::Envelope;

use broker_economics::visibility::VisibilityClass;
use broker_economics::Cbor;

const NOW: u64 = 1_752_600_000_000;
const DOMAIN: &str = "example.org";
const GW_SELECTOR: &str = "gw1";

// =================================================================================================
// COORD-1 — the descriptor signature is REALLY verified once kotva-core is pinned (it is: W3).
// =================================================================================================

/// **Proves:** a `GatewayCoordinator`'s descriptor, signed with a real kotva-core `IdentityKey`,
/// verifies under `SignedDescriptor::verify()` — the harness's "verify once kotva-core is pinned"
/// deferral (COORD-1, CONTRACT §2.1) is discharged with real Ed25519 signing/verification, not a
/// stub. **Does not prove:** anything about the descriptor's *content* being trustworthy — only
/// that it was genuinely published by the identity it claims (CONTRACT §2.1's own scope: a signed,
/// discovery-only descriptor, nothing more).
#[test]
fn coord1_gateway_descriptor_signature_really_verifies() {
    let ik = IdentityKey::from_seed(&[0x51; 32]);
    let g = GatewayCoordinator::new(&ik, Cbor(Vec::new()), false);
    let signed = g.sign(&ik);
    assert!(
        signed.verify().is_ok(),
        "a genuinely-signed gateway descriptor must verify under its own declared identity"
    );
}

/// **Proves:** a tampered descriptor (content mutated after signing) fails verification —
/// `SignedDescriptor::verify()` is not a no-op, it actually checks the signature against the
/// current bytes (fail-closed, SEC-1). **Does not prove:** anything about detection latency or
/// who would catch the tamper in production — only that the cryptographic check itself is real.
#[test]
fn coord1_tampered_gateway_descriptor_fails_verification() {
    let ik = IdentityKey::from_seed(&[0x52; 32]);
    let g = GatewayCoordinator::new(&ik, Cbor(Vec::new()), false);
    let mut signed = g.sign(&ik);
    assert!(signed.verify().is_ok(), "sanity: the untampered descriptor verifies");

    // Mutate the signed body after signing (policy bytes) — the signature no longer covers this.
    signed.descriptor.policy = Cbor(vec![0xde, 0xad, 0xbe, 0xef]);
    assert!(
        signed.verify().is_err(),
        "a descriptor mutated after signing MUST fail verification — the signature is not \
         decorative"
    );
}

/// **Proves:** a signature genuinely produced by a *different* key than the one the descriptor
/// claims as its identity is rejected — verification is checked against the claimed identity, not
/// merely "some valid signature exists". **Does not prove:** key-distribution / discovery
/// integrity (how a relying party learns the *correct* identity in the first place) — that is
/// outside a single descriptor's signature check.
#[test]
fn coord1_gateway_descriptor_signed_by_the_wrong_key_fails_verification() {
    let claimed = IdentityKey::from_seed(&[0x53; 32]);
    let actual_signer = IdentityKey::from_seed(&[0x54; 32]);
    let g = GatewayCoordinator::new(&claimed, Cbor(Vec::new()), false);
    // Sign with a DIFFERENT key than the one embedded as `descriptor.identity`.
    let signed = g.sign(&actual_signer);
    assert!(
        signed.verify().is_err(),
        "a descriptor signed under a key other than its own declared identity must not verify"
    );
}

// =================================================================================================
// COORD-5 — the gateway's declared visibility (`terminating`/`declared`) matches reality: it is
// disclosed, not misrepresented as verified-blind.
// =================================================================================================

/// **Proves:** the gateway declares `terminating` at assurance `declared` (the one Wakala kind
/// that is NOT content-blind — the legacy SMTP leg is unavoidably plaintext, CONTRACT §3.1), and
/// this declaration is honestly surfaced: `is_verifiably_blind()` is false (it never claims to be
/// blind at all) and `must_not_present_as_verified()` is also false — because that flag exists to
/// catch a *blind* claim being shown as verified when it isn't (§3.4); a `terminating` boundary
/// is a different, honestly-disclosed thing entirely, not a downgraded blind claim. Together these
/// discharge COORD-5's "observed behavior matches declared visibility class": the ONE thing this
/// coordinator kind's runtime posture can show is that its declaration is what it actually is —
/// terminating, admitted plainly — not a blind claim wearing a terminating implementation
/// underneath.
///
/// **Does not prove:** that the operator handles the plaintext it can read correctly, safely, or
/// honestly once received — that is the disclosed residual of a `terminating` trust boundary
/// (CONTRACT §3.1's whole point: this is a deliberate, admitted boundary, not a guarantee about
/// what happens on the other side of it). This crate has no way to observe operator conduct after
/// the message leaves its own process, and does not claim to.
#[test]
fn coord5_gateway_declares_terminating_not_verified_blind() {
    let ik = IdentityKey::from_seed(&[0x55; 32]);
    let g = GatewayCoordinator::new(&ik, Cbor(Vec::new()), false);

    assert_eq!(
        g.descriptor().visibility.class,
        VisibilityClass::Terminating,
        "the gateway's legacy SMTP leg is plaintext by construction — it MUST declare terminating"
    );
    assert!(
        !g.descriptor().visibility.is_verifiably_blind(),
        "a terminating gateway must never present itself as blind (verified or otherwise)"
    );
    assert!(
        !g.descriptor().visibility.must_not_present_as_verified(),
        "must_not_present_as_verified() only fires for a BLIND claim at declared assurance \
         (§3.4) — a terminating boundary is a different, honestly-disclosed thing, not a \
         downgraded blind claim, so this flag correctly does not fire for it"
    );
}

/// **Proves:** the gateway's real inbound wire path (`accept_message` — the same code an actual
/// SMTP session drives) is where the `terminating` declaration cashes out: the recipient key is
/// resolved and the message is wrapped from **plaintext** RFC 5322 bytes the gateway itself held
/// in memory — there is no code path here that receives already-encrypted payload it merely
/// forwards blind. This is the "observed behavior" half of COORD-5, exercised against the real
/// `InboundGateway`, not merely asserted from the descriptor. **Does not prove:** what the operator
/// does with that plaintext beyond this call — see the residual noted on the test above.
#[test]
fn coord5_inbound_wire_path_actually_handles_plaintext() {
    let gw_ik = IdentityKey::generate();
    let att_key = AttestationKey::generate(DOMAIN, GW_SELECTOR);
    let recip_ik = IdentityKey::generate();
    let recip_seal = kotva_core::mote::SealKeypair::generate();
    let recip_email = "alice@example.org";

    struct OneUser {
        email: String,
        key: RecipientKey,
    }
    impl KeyDirectory for OneUser {
        fn resolve(&self, rcpt: &str) -> Option<RecipientKey> {
            if rcpt.eq_ignore_ascii_case(&self.email) {
                Some(self.key.clone())
            } else {
                None
            }
        }
    }
    struct AlwaysAck;
    impl MeshDelivery for AlwaysAck {
        fn deliver(&self, _env: &Envelope, _att: &Attestation) -> DeliveryOutcome {
            DeliveryOutcome::Acked
        }
    }
    struct AllowAll;
    impl AntiAbuse for AllowAll {
        fn check(&self, _peer_ip: &str, _mail_from: &str) -> AbuseDecision {
            AbuseDecision::Accept
        }
    }

    let gw = InboundGateway::new(
        gw_ik,
        vec![att_key],
        Box::new(OneUser {
            email: recip_email.to_string(),
            key: RecipientKey { ik: recip_ik.public(), seal_pub: recip_seal.public().to_vec() },
        }),
        Box::new(AlwaysAck),
        Box::new(AllowAll),
    );

    // A body carrying a plaintext secret that only makes sense if the gateway actually read it
    // (a blind relay could never observe or act on this — it only ever sees ciphertext).
    let plaintext_body =
        b"From: sender@gmail.com\r\nTo: alice@example.org\r\nSubject: hi\r\n\r\nthe secret plaintext body\r\n";
    let reply = gw.accept_message("sender@gmail.com", recip_email, plaintext_body, NOW);
    assert_eq!(reply.code, 250, "the gateway read, wrapped, and delivered the plaintext body");
}

// =================================================================================================
// COORD-6 — authorize, never classify (CONTRACT §4): the inbound delivery-path gate is sender
// identity + rate, NOT content. Two runtime demonstrations, driven against the real
// `InboundGateway`/`MxSession` wire path:
//
//   (a) SAME sender authorization, DIFFERENT content  ⇒ SAME gate outcome.
//   (b) SAME content, DIFFERENT sender authorization  ⇒ the gate outcome tracks authorization,
//       not content — proving the differentiator really is identity/rate, not what's in the body.
// =================================================================================================

struct OneUserAuthz {
    email: String,
    key: RecipientKey,
}
impl KeyDirectory for OneUserAuthz {
    fn resolve(&self, rcpt: &str) -> Option<RecipientKey> {
        if rcpt.eq_ignore_ascii_case(&self.email) {
            Some(self.key.clone())
        } else {
            None
        }
    }
}
struct AlwaysAckAuthz;
impl MeshDelivery for AlwaysAckAuthz {
    fn deliver(&self, _env: &Envelope, _att: &Attestation) -> DeliveryOutcome {
        DeliveryOutcome::Acked
    }
}
struct AllowAllAuthz;
impl AntiAbuse for AllowAllAuthz {
    fn check(&self, _peer_ip: &str, _mail_from: &str) -> AbuseDecision {
        AbuseDecision::Accept
    }
}

fn recipient() -> (String, RecipientKey) {
    let ik = IdentityKey::generate();
    let seal = kotva_core::mote::SealKeypair::generate();
    ("alice@example.org".to_string(), RecipientKey { ik: ik.public(), seal_pub: seal.public().to_vec() })
}

fn build_gw(recip_email: &str, recip_key: RecipientKey, spf_authorized_cidr: &str) -> InboundGateway {
    let gw = InboundGateway::new(
        IdentityKey::generate(),
        vec![AttestationKey::generate(DOMAIN, GW_SELECTOR)],
        Box::new(OneUserAuthz { email: recip_email.to_string(), key: recip_key }),
        Box::new(AlwaysAckAuthz),
        Box::new(AllowAllAuthz),
    );
    let spf = InMemorySpfResolver::new()
        .with_txt("legit-sender.example", &[&format!("v=spf1 ip4:{spf_authorized_cidr} -all")]);
    gw.with_spf(Box::new(spf), SpfPolicy::Enforce)
        .with_dkim(Box::new(gateway::dkim::StaticDkimKeys::new()), DkimPolicy::Annotate)
        .with_dmarc(Box::new(gateway::dmarc::InMemoryDmarcResolver::new()), DmarcHandling::Annotate)
}

fn run_transaction(gw: &InboundGateway, peer_ip: &str, mail_from: &str, to: &str, body: &str) -> u16 {
    let mut s = MxSession::new(gw, peer_ip, NOW);
    assert_eq!(s.feed_line("EHLO gmail.com").code, 250);
    let mail_reply = s.feed_line(&format!("MAIL FROM:<{mail_from}>"));
    if mail_reply.code != 250 {
        return mail_reply.code; // rejected before RCPT/DATA — the (a) gate refused here
    }
    assert_eq!(s.feed_line(&format!("RCPT TO:<{to}>")).code, 250);
    assert_eq!(s.feed_line("DATA").code, 354);
    for line in body.lines() {
        s.feed_line(line);
    }
    s.feed_line(".").code
}

/// **Proves:** two messages from the SAME authorized sender (identical `MAIL FROM`, identical
/// authorized peer IP — i.e. identical sender-authorization state) reach the IDENTICAL SMTP
/// outcome (`250`, durably delivered) regardless of how different their body content is — one
/// entirely benign, the other loaded with classic spam-trigger words a content classifier would
/// flag. The delivery-path gate this crate runs (SPF/DKIM/DMARC authentication + the pre-`DATA`
/// anti-abuse check) never inspects the message body at all: `AntiAbuse::check(peer_ip,
/// mail_from)` and the SPF/DMARC evaluation are called BEFORE `DATA` is even read
/// (`MxSession::cmd_mail`/`cmd_rcpt`, `crates/gateway/src/inbound.rs`), so the body literally
/// cannot influence the gate decision — this test demonstrates that structural fact end to end,
/// not just by type inspection.
///
/// **Does not prove:** that no *other*, separately-configured layer (e.g. a downstream mailbox
/// spam filter the recipient runs at the edge) ever looks at content — CONTRACT §4's carve-out is
/// explicitly for the coordinator's own delivery/authoritative path, which is exactly what this
/// test exercises; a client's own opt-in filtering is untouched by this claim.
#[test]
fn coord6_same_authorization_different_content_same_outcome() {
    let (recip_email, recip_key) = recipient();
    let gw = build_gw(&recip_email, recip_key, "203.0.113.0/24");

    let benign =
        "From: legit@legit-sender.example\r\nTo: alice@example.org\r\nSubject: hi\r\n\r\nlet's meet for coffee\r\n";
    let spammy = "From: legit@legit-sender.example\r\nTo: alice@example.org\r\nSubject: FREE MONEY\r\n\r\nCLICK NOW!!! FREE VIAGRA CASINO WINNER CLAIM YOUR PRIZE!!!\r\n";

    let benign_code = run_transaction(&gw, "203.0.113.9", "legit@legit-sender.example", &recip_email, benign);
    let spammy_code = run_transaction(&gw, "203.0.113.9", "legit@legit-sender.example", &recip_email, spammy);

    assert_eq!(benign_code, 250, "the benign message from an authorized sender is delivered");
    assert_eq!(
        spammy_code, 250,
        "the spam-shaped message from the SAME authorized sender is delivered identically — the \
         delivery-path gate does not classify content"
    );
    assert_eq!(
        benign_code, spammy_code,
        "COORD-6: identical sender authorization must yield an identical gate outcome regardless \
         of content"
    );
}

/// **Proves:** the flip side — two messages with byte-IDENTICAL content but DIFFERENT sender
/// authorization (one from an SPF-authorized peer IP, one from an unauthorized IP for the same
/// claimed sender domain) get DIFFERENT outcomes. Combined with the test above, this pins down
/// that the gate's differentiator really is sender identity/rate authorization, not content: same
/// content + different auth ⇒ different outcome; same auth + different content ⇒ same outcome.
///
/// **Does not prove:** SPF/DKIM/DMARC are individually complete anti-forgery mechanisms (documented
/// narrowings exist in `gateway::spf`/`dkim`/`dmarc`'s own module docs) — only that the delivery
/// path's gate/no-gate decision here tracks the authorization signal, not the body.
#[test]
fn coord6_same_content_different_authorization_different_outcome() {
    let (recip_email, recip_key) = recipient();
    let gw = build_gw(&recip_email, recip_key, "203.0.113.0/24");
    let body = "From: legit@legit-sender.example\r\nTo: alice@example.org\r\nSubject: hi\r\n\r\nidentical body\r\n";

    let authorized_code =
        run_transaction(&gw, "203.0.113.9", "legit@legit-sender.example", &recip_email, body);
    let unauthorized_code =
        run_transaction(&gw, "198.51.100.9", "legit@legit-sender.example", &recip_email, body);

    assert_eq!(authorized_code, 250, "the authorized-IP sender is delivered");
    assert_eq!(
        unauthorized_code, 550,
        "the SAME content from an unauthorized IP for the claimed domain is refused (SPF hard \
         fail) — before DATA is ever inspected"
    );
    assert_ne!(
        authorized_code, unauthorized_code,
        "COORD-6: identical content with different sender authorization must NOT yield the same \
         outcome — the gate is authorization-based, not content-based"
    );
}
