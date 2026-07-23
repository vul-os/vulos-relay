//! DMTAP §7 gateway-conformance cases relocated from envoir.
//!
//! **Provenance.** These cases originally lived as `construction-todo` drivers in envoir's
//! `crates/conformance-runner/src/construction.rs`, executed against `envoir_gateway` (the
//! `dmtap-core`-flavored predecessor of this crate). Wave W1 (envoir commit `620a68c`, "envoir:
//! node-only — drop the gateway + its conformance/fuzz coverage; consume kotva-core@tag") removed
//! both the gateway crate and its conformance/fuzz coverage from envoir, since the gateway itself
//! moved here, to Wakala's `gateway` crate. Wave W2 (this file) retrieves those cases from envoir's
//! git history (`620a68c^`) and re-homes them here, driven against the REAL, current wakala
//! `gateway` public API (not a copy or a stub) — `kotva_core` in place of `dmtap_core`, `gateway::`
//! in place of `envoir_gateway::`, and each case's calls updated wherever the API surface drifted
//! (see the per-case doc comment below for what changed, if anything). The §7 spec citations in
//! each case's doc comment are preserved from the original.
//!
//! **What did NOT come along**, and why (see the module docs of `crates/gateway/src/attestation.rs`
//! / `src/provenance.rs` for the current shape):
//!
//! - `DMTAP-GWATT-04` ("a high-value-recipient policy requires the KT-anchored attestation form"):
//!   this was *already* a documented **skip**, not an executable case, in envoir's own
//!   `construction.rs` — envoir-gateway's attestation/provenance modules modeled exactly one
//!   assurance tier (a flat DNS-published `_dmtap-gw` key), with no KT-anchored second tier and no
//!   "high-value recipient" policy concept to select between. Wakala's `gateway::attestation` /
//!   `gateway::provenance` modules inherited that same single-tier design (one DNS-published
//!   `_dmtap-gw` key, verified via `Attestation::verify` / `GatewayAttestation::verify`) — there is
//!   still no second, KT-anchored verification path to construct this case against, so it stays a
//!   documented non-case here too rather than a faked pass.
//!
//! Everything else in the relocated set (`DMTAP-GWALIAS-01/02`, `DMTAP-GWATT-05`,
//! `DMTAP-GWNAME-02`, `DMTAP-LEG-01/02/03`) maps cleanly onto the current API — in most cases the
//! call shapes are unchanged (`gateway::provenance::GatewayAttestation::{sign,verify}`,
//! `gateway::provenance::chain_append`, `gateway::outbound::OutboundGateway::{translate_and_sign,
//! send_authenticated}`, `gateway::outbound_guard::OutboundSenderGuard`, `gateway::authz::
//! AliasAllocator`, `gateway::alias_map::GatewayAliasMap`, `gateway::forwarded_addr::{encode,
//! decode}` are the same names doing the same job); the one real rename is envoir's flat
//! `envoir_gateway::attestation::Attestation` verify signature (`domain, key, rfc5322_bytes`) vs.
//! wakala's `gateway::attestation::Attestation::verify` (`expected_domain, published_key,
//! wrapped_mote_id: &ContentId`) — the §7.2a attestation here binds to the wrapped MOTE's content
//! address rather than to raw legacy bytes directly, so `DMTAP-LEG-01` below binds against a
//! `ContentId` instead of an `&[u8]`.

use kotva_core::id::ContentId;
use kotva_core::identity::IdentityKey;
use kotva_core::mote::{Headers, Payload};

use gateway::attestation::{AttestationError, AttestationKey};
use gateway::authz::{AliasAllocator, AliasError};
use gateway::alias_map::{AliasTarget, GatewayAliasError, GatewayAliasMap};
use gateway::forwarded_addr::{decode as fwd_decode, encode as fwd_encode, ForwardedAddrError};
use gateway::outbound::{
    AlwaysRequireTls, GovernedSend, OutboundError, OutboundGateway, OutboundTransport,
    TransportResult,
};
use gateway::outbound_guard::{OutboundSenderGuard, SenderVerdict};
use gateway::provenance::{chain_append, GatewayAttestation, ProvenanceError};

// ================================================================================================
// GWALIAS — the forwarded-address (SRS-style) codec and the stateful random-alias store.
// ================================================================================================

/// DMTAP-GWALIAS-01: "an encoded gateway alias `localpart.nativedomain@gateway.domain` that does
/// not reversibly decode to exactly one `(localpart, nativedomain)` (ambiguous escaping) or exceeds
/// RFC 5321 limits is rejected — the gateway MUST NOT guess a native address" (§7.10.2, §18.3.12).
/// Drives the real SRS-style `gateway::forwarded_addr` codec: a dangling/ambiguous escape decodes
/// to nothing (no guess), and an over-64-octet encoding is refused `TooLong`.
#[test]
fn dmtap_gwalias_01_encoding_invalid_rejected() {
    // (a) A dangling escape (`-` with no following `-`/`.`) — the gateway MUST NOT guess a native
    // address; decode fails closed to `None` rather than inventing a split.
    assert_eq!(
        fwd_decode("imran-x.mydomain-.com"),
        None,
        "an ambiguous/dangling-escape local-part must decode to None (fail-closed)"
    );
    // (b) A bare dot inside the domain component (a second, spurious separator) is not reversible.
    assert_eq!(
        fwd_decode("imran.my.domain.com"),
        None,
        "a non-canonical split must decode to None (only the canonical single-separator form \
         round-trips)"
    );
    // (c) An encoding whose escaped join would exceed the RFC 5321 §4.5.3.1.1 64-octet local-part
    // limit is refused `TooLong` — each label stays within the 63-octet DNS limit (so the domain
    // itself is valid), but the escaped join runs well past 64 octets.
    let long_domain = format!("{}.{}", "a".repeat(50), "a".repeat(50));
    match fwd_encode("user", &long_domain) {
        Err(ForwardedAddrError::TooLong(_)) => {}
        other => panic!(
            "expected ForwardedAddrError::TooLong for an over-64-octet encoded local-part, got \
             {other:?}"
        ),
    }
}

/// DMTAP-GWALIAS-02 (§7.10.3, §18.3.12): inbound legacy mail to a random-mode gateway alias whose
/// `GatewayAliasMap` row is missing / expired / burned resolves to `ERR_GATEWAY_ALIAS_UNMAPPED`
/// (`0x0605`, RETURN_SENDER_SMTP `550 5.1.1`) rather than being silently dropped. Positive control:
/// a live row resolves to its bound native target.
#[test]
fn dmtap_gwalias_02_unmapped_rejected() {
    let mut map = GatewayAliasMap::new();
    let now = 1_700_000_000_000u64;
    let target = AliasTarget::Native { local: "imran".into(), domain: "mydomain.com".into() };

    // Positive control: a freshly-minted, live row resolves to its target.
    let live = map.mint(target.clone());
    assert_eq!(
        map.resolve(&live, now),
        Ok(target.clone()),
        "positive control: a live alias must resolve to its target"
    );

    // Negative (missing): a never-minted token has no row.
    assert_eq!(
        map.resolve("nosuchaliastoken", now),
        Err(GatewayAliasError::Unmapped),
        "a missing alias must be Unmapped"
    );

    // Negative (expired): a TTL'd row resolved past its expiry.
    let expiring = map.mint_with(target.clone(), None, Some(1_000), false, now);
    assert_eq!(
        map.resolve(&expiring, now + 2_000),
        Err(GatewayAliasError::Unmapped),
        "an expired alias must be Unmapped"
    );

    // Negative (burned): an explicitly-burned row, checked for the exact wire code.
    let burned = map.mint(target.clone());
    assert!(map.burn(&burned), "burn() must report that the minted row existed");
    let err = map.resolve(&burned, now).unwrap_err();
    assert_eq!(err, GatewayAliasError::Unmapped);
    assert_eq!(err.code(), 0x0605);
}

// ================================================================================================
// GWNAME — vanity local-part allocation rules (§7.10.5, §3.13.1).
// ================================================================================================

/// DMTAP-GWNAME-02 (§7.10.5/§3.13.1): a gateway vanity is a user-chosen local-part scoped to the
/// gateway's own domain — it MUST be dot-free (dots are reserved for the `local.nativedomain`
/// forwarded-address encoding, §7.10.2) and MUST be meaningful only fully-qualified
/// (`vanity@gatewaydomain`), never as a bare handle (no flat-namespace registry to allocate a
/// global name from). `AliasAllocator::allocate_vanity` refuses a dotted local-part
/// (`AliasError::ContainsDot`) fail-closed rather than stripping the dot, and every allocated /
/// resolved form is qualified with the gateway's own domain (`AliasAllocator::resolve` refuses a
/// bare handle with no `@` at all). Positive control: a clean, dot-free vanity allocates and
/// resolves only in its fully-qualified form.
#[test]
fn dmtap_gwname_02_vanity_dotfree_and_fully_qualified_only() {
    let mut allocator =
        AliasAllocator::for_domain("gw.example").expect("gw.example is a valid gateway domain");
    let key = IdentityKey::generate().public();

    // Positive control: a clean vanity allocates to its fully-qualified form.
    let fq = allocator
        .allocate_vanity(&key, "imran")
        .expect("positive control: a clean vanity must allocate");
    assert_eq!(fq, "imran@gw.example");

    // It resolves ONLY fully-qualified; the bare local-part alone has no anchor.
    assert!(
        allocator.resolve("imran", std::slice::from_ref(&key)).is_none(),
        "a bare, un-anchored local-part (no '@') must never resolve"
    );
    assert_eq!(
        allocator.resolve(&fq, std::slice::from_ref(&key)),
        Some(key.clone()),
        "the fully-qualified vanity must resolve back to its bound key"
    );

    // Negative: a dotted local-part is refused — reserved for the forwarded-address encoding.
    let other_key = IdentityKey::generate().public();
    match allocator.allocate_vanity(&other_key, "bob.smith") {
        Err(AliasError::ContainsDot(_)) => {}
        other => panic!("expected Err(ContainsDot) for a dotted vanity, got {other:?}"),
    }
}

// ================================================================================================
// GWATT — gateway attestation / provenance (§7.2a, §7.8.3, §18.3.11).
// ================================================================================================

/// DMTAP-GWATT-05 (§7.8.3/§18.3.11): a multi-gateway `GatewayAttestation` chain verifies **entry by
/// entry**, each against the domain it is actually anchored to — `verify`'s `expected_domain` is
/// per-call, so a caller walking the chain naturally checks the entry that bridged mail *for the
/// recipient* against the recipient's own domain (accept) while an entry anchored to some other
/// domain the recipient has no key for is REJECTED for that domain (`KeyUntrusted`) rather than
/// silently accepted as if it were recipient-anchored too.
#[test]
fn dmtap_gwatt_05_chain_per_entry_domain_verified() {
    const RFC: &[u8] = b"From: a@gmail.com\r\nTo: alice@recipient.example\r\nSubject: hi\r\n\r\nbody\r\n";
    let recipient_key = AttestationKey::generate("recipient.example", "gw1");
    let other_key = AttestationKey::generate("relay-gateway.example", "gw1");

    // Entry 0: the hop that bridged mail for the recipient — anchored to the recipient's own domain.
    let entry0 = GatewayAttestation::sign(&recipient_key, RFC, Some("a@gmail.com"), 1_700_000_000_000, 0);
    // Entry 1: an earlier relay hop, anchored to a DIFFERENT domain the recipient has no key for.
    let entry1 = GatewayAttestation::sign(&other_key, RFC, Some("a@gmail.com"), 1_700_000_000_050, 1);
    let chain = chain_append(std::slice::from_ref(&entry0), entry1.clone());
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0], entry0);
    assert_eq!(chain[1], entry1);

    // The recipient-facing entry verifies against the recipient's own domain.
    chain[0]
        .verify("recipient.example", Some(&recipient_key.public()), RFC)
        .expect("entry 0 (recipient-anchored) must verify");

    // The other-domain entry is REJECTED when the recipient has no key published for it (not in
    // the recipient's trusted gateway set) — it must never be silently treated as recipient-anchored.
    assert_eq!(
        chain[1].verify("recipient.example", None, RFC),
        Err(ProvenanceError::KeyUntrusted),
        "an other-domain hop the recipient has no key for must be rejected KeyUntrusted"
    );
}

// ================================================================================================
// LEG — the legacy SMTP gateway (spec §7, §7.2a, §7.3).
// ================================================================================================

/// DMTAP-LEG-01: "a gateway attestation that fails to verify under a trusted key is rejected"
/// (`ERR_GATEWAY_ATTESTATION_INVALID`). Issues a genuine domain-anchored `Attestation`, tampers its
/// signature after signing, and confirms the recipient-side `Attestation::verify` rejects it under
/// the (correct) published key rather than accepting a forged/corrupted attestation.
///
/// **Adapted from envoir**: envoir's `Attestation::verify` took `(domain, key, rfc5322_bytes:
/// &[u8])`; wakala's binds to the wrapped MOTE's content address instead, so `verify` here takes
/// `(expected_domain, published_key, wrapped_mote_id: &ContentId)` — otherwise unchanged.
#[test]
fn dmtap_leg_01_gateway_attestation_invalid_rejected() {
    let key = AttestationKey::generate("recipient.example", "sel1");
    let mote_id = ContentId::of(b"conformance-leg-01 wrapped mote");
    let mut att = key.attest(&mote_id, "sender@legacy.example", "alice@recipient.example", 1_700_000_000_000);
    att.sig[0] ^= 0xff; // tamper after signing

    match att.verify("recipient.example", Some(&key.public()), &mote_id) {
        Err(AttestationError::BadSignature(_)) => {}
        other => panic!("expected Err(BadSignature) (attestation invalid, rejected), got {other:?}"),
    }
}

/// A no-op [`OutboundTransport`]: DMTAP-LEG-02 only exercises `translate_and_sign` (the
/// delegation-refusal gate), which returns before any transport call, so this stub is never
/// actually invoked — it exists only to satisfy `OutboundGateway::new`'s constructor shape.
struct UnusedTransport;
impl OutboundTransport for UnusedTransport {
    fn deliver(&self, _dest_domain: &str, _message: &[u8], _require_tls: bool) -> TransportResult {
        TransportResult::Permanent { code: 550, text: "unused in this construction".into() }
    }
}

fn leg_payload(body: &[u8]) -> Payload {
    Payload {
        from: IdentityKey::generate().public(),
        sig: Vec::new(),
        headers: Headers::default(),
        body: body.to_vec(),
        refs: vec![],
        attach: vec![],
        expires: None,
    }
}

/// DMTAP-LEG-02: "invalid DKIM delegation is rejected" (`ERR_DKIM_DELEGATION_INVALID`). The gateway
/// MUST refuse to DKIM-sign for a domain it holds no delegated selector for (§7.3's hard refusal,
/// `OutboundGateway::translate_and_sign`) — attempts to sign outbound mail for a domain absent from
/// its delegated-key set and confirms it is refused (`OutboundError::NotDelegated`) rather than
/// signing with some other domain's key or skipping the check.
#[test]
fn dmtap_leg_02_dkim_undelegated_domain_rejected() {
    let gateway = OutboundGateway::new(
        vec![], // no delegated DKIM keys at all — this gateway is delegated for NOTHING
        Box::new(AlwaysRequireTls),
        Box::new(UnusedTransport),
    );
    let payload = leg_payload(b"conformance-runner leg-02 outbound body");
    match gateway.translate_and_sign(&payload, "alice@undelegated.example", "bob@dest.example", 1_700_000_000_000) {
        Err(OutboundError::NotDelegated(domain)) => {
            assert_eq!(
                domain, "undelegated.example",
                "NotDelegated named the wrong domain"
            );
        }
        other => panic!(
            "expected Err(NotDelegated) (the gateway MUST refuse to sign for an undelegated \
             domain), got {other:?}"
        ),
    }
}

/// DMTAP-LEG-03: "an outbound DMTAP->legacy relay from a sender the gateway has neither
/// authenticated (no GatewayAuthz / key-registered relationship) nor been paid by (no valid
/// redeemable postage) is refused fail-closed; a valid mesh sender_sig alone does NOT authorize
/// egress (open-relay prevention)" (§7.11.2, §9.10, §7.12). `OutboundGateway::send_authenticated`
/// is the mesh-ingest entry point named by this case's own doc comment: with an
/// `OutboundSenderGuard` configured via `require_registered` (the authenticated-senders-only
/// allowlist, §7.3, §9), an account NOT in that set is refused by the guard BEFORE any DKIM/SMTP
/// work is attempted — even though the payload itself is a perfectly well-formed mail `Payload`,
/// mirroring "a valid mesh sender_sig alone does NOT authorize egress": nothing about the
/// payload's own authenticity is in question here, only the sender's egress authorization. Mirrors
/// `outbound_guard.rs`'s own unit test `unauthenticated_sender_is_refused_no_open_outbound_relay`,
/// driven through the `OutboundGateway` construction this case names.
#[test]
fn dmtap_leg_03_outbound_open_relay_refused() {
    let guard = OutboundSenderGuard::new().require_registered(["acct-registered-sender"]);
    let gateway = OutboundGateway::new(
        vec![], // no delegated DKIM keys needed: the guard refuses before translate_and_sign runs
        Box::new(AlwaysRequireTls),
        Box::new(UnusedTransport),
    )
    .with_sender_guard(guard);

    let payload = leg_payload(b"conformance-runner leg-03 outbound relay attempt");

    // "acct-stranger" has no GatewayAuthz relationship and no postage — exactly the open-relay
    // scenario this case forbids, regardless of the mail payload's own well-formedness.
    match gateway.send_authenticated(
        &payload,
        "alice@undelegated.example",
        "bob@legacy.example",
        "acct-stranger",
        1_700_000_000_000,
    ) {
        GovernedSend::Blocked(SenderVerdict::Refuse { .. }) => {}
        other => panic!(
            "expected GovernedSend::Blocked(SenderVerdict::Refuse) (open-relay refused \
             fail-closed), got {other:?}"
        ),
    }
}

// DMTAP-GWATT-04 ("a high-value-recipient policy requires the KT-anchored attestation form") is
// intentionally NOT a test here — see the module doc comment at the top of this file for why: it
// was already a documented skip in envoir (no KT-anchored second assurance tier existed there
// either), and `gateway::attestation` / `gateway::provenance` still model exactly the one flat
// DNS-published-key tier, so there is no second code path to construct this case against.
