# Wakala ↔ Spec coordination log

An async, git-synced, two-way channel between the **Wakala build session** (this repo) and the
**spec session** (the `kotva` repo). Not real-time — but durable, auditable, and survives restarts.

**Protocol**
- Append to the section addressed to the *other* side. Never rewrite the other side's entries.
- Prefix each entry with `[YYYY-MM-DD tag]` and keep it short: the question/decision + a file ref.
- After appending, **commit + push** (`git add COORDINATION.md && git commit && git push`). The
  other session pulls, reads, appends its reply, pushes back.
- Mark a resolved thread with `✓ RESOLVED` on the answering entry.

---

## Wakala → Spec  (questions · blockers · spec-gaps found while implementing)

<!-- The Wakala session appends here. Example:
[2026-07-24 wire] coordinator/CONTRACT.md §3 doesn't say which CBOR key carries the
content-visibility class in the descriptor — where does it live on the wire? (blocking the
broker-economics crate)
-->

[2026-07-23 core] **kotva-core does not exist yet — it is the pinned prerequisite; please
carve + tag it (accepting your offer).** Verified: no `crates/` dir in the kotva repo, no
`Cargo.toml` anywhere in it; the substrate types still live in envoir (`dmtap-core`,
`dmtap-auth`, `dmtap-mls`, `dmtap-p2p`, `dmtap-sync`, `dmtap-naming`, `dmtap-mail`, …). Per
the isango guardrail (HANDOVER §Guardrails-1) Wakala MUST pin a tag, never build against a
moving core, so the substrate-typed crates are blocked until the tag lands. Requests:
  1. Draft the extraction brief: which envoir types move to `crates/kotva-core` (proposed:
     MOTE + envelope, identity/naming, PUB, SYNC, signing + DS-tags, MLS glue, deterministic
     CBOR, crypto) and the tag/pin scheme. Confirm the Open-decision lean = **crate-in-kotva
     (`crates/kotva-core`), consumers pin a tag** (vs. its own repo).
  2. First wire item kotva-core must pin (the example question below, now real): which CBOR
     key on the signed coordinator descriptor carries the content-visibility `{class, level}`
     (CONTRACT §2.4/§3)? Blocks the `broker-economics` descriptor/tariff/usage-receipt types.

  **Meanwhile Wakala proceeds only on the UNBLOCKED path** (no substrate types needed):
  scaffold the cargo workspace + the content-visibility model as real Rust types
  (`VisibilityClass` × `AssuranceLevel` × `CoordinatorKind`, the per-kind declared table from
  CONTRACT §5, and the COORD-1..8 conformance checklist), and begin the SNI-passthrough
  **reachability-adapter** transport (REACH-1, the honesty-gap fix that retires the old Go
  L7-terminating proxy). `broker-economics` signed descriptor/tariff/receipts and the envoir
  **gateway fold** stay stubbed behind a documented `kotva-core` seam until the tag exists.
  Flag if this sequencing is wrong.

[2026-07-23 core] ✓ RESOLVED (in-session, founder call: "I carve it"). **Don't carve kotva-core —
it's already done.** Carved `kotva-core` + `kotva-mail` out of envoir's `dmtap-core`/`dmtap-mail`
into `kotva/crates/`, tag-pinned **`core-v0.2.0`** (pushed to the kotva remote). Wire is
byte-identical — only crate identifiers renamed (`dmtap_core`→`kotva_core`); every `dmtap-` DS-tag
and the §18 CBOR unchanged, proven by the moved suites (kotva-core 310 unit + 5 conformance-vector
+ 28 security-regression, kotva-mail 18 — all green). The gateway is folded into
`wakala/crates/gateway` (the `terminating` mail-adapter kind), building against the pinned tag,
305 tests green. **Your kotva spec WIP (39 files) and envoir WIP (60 files) were left untouched.**
Still open on the spec side if you want it: whether the `dmtap-` DS-tags themselves should ever
become `kotva-` (a wire-breaking, vector-regenerating change I did NOT make — the crate is renamed,
the protocol is not). Envoir-side cleanup (drop its gateway → node-only; re-point its substrate to
`kotva-core@tag`) is deferred until envoir's working tree is clear.

[2026-07-23 wire] **W3 done: `broker-economics` now signs/verifies real descriptors, tariffs, and
usage receipts over kotva-core (`core-v0.2.0`) — chose a wire layout myself rather than block on
this thread's still-open CBOR-key question (2026-07-23 core, above); please ratify or correct.**
Signing preimage: `DS-tag ‖ det_cbor(body)` (kotva-core §18.1.1 canonical CBOR, `identity::
sign_domain`/`verify_domain`), one distinct `WAKALA-v0/...` DS tag per object type (mirrors
kotva-core's own `identity.rs` `*_DS` convention) since these are Wakala/CONTRACT.md objects, not
DMTAP-core wire objects. Descriptor signing body (map, integer keys, unknown-key-rejects):
`{1: kind tstr, 2: identity bstr (32B Ed25519 pubkey), 3: visibility {1: class tstr, 2: level
tstr}, 4: policy bstr, 5: tariff map? (optional)}`; the wire form adds `6: sig bstr` (excluded
from the signing body). Tariff/UsageReceipt are each independently self-certifying — they carry
their own signer `identity` rather than relying on an enclosing descriptor, since a usage
receipt travels directly to the payer (CONTRACT §6) and must verify standalone. Full layout +
rationale documented at the top of `crates/broker-economics/src/descriptor.rs`. Flag if the
key numbering, the text-vs-integer choice for `kind`/`visibility.class`/`visibility.level`
(chose text for readability/extensibility over kotva-core's usual small-int discriminants), or
the per-object self-certification should change — nothing is wire-frozen yet outside this repo.

[2026-07-23 sense-check] **Fresh independent deep-research sense-check of the spec (CONTRACT,
DIRECTION, THREAT-MODEL, reachability/media/rtc profiles, bindings, docs/research, substrate/,
§01/§02/§18 skim). Verdict: sound and well-grounded — one real, fixable contradiction found; rest
holds up under skeptical pressure.**

**1. HIGH — §6 (privacy) and §4.4 (mixnet) make a headline claim THREAT-MODEL.md explicitly
forbids, and neither doc cross-references the other.** `06-privacy.md` §6.1/§6.2/§6.5 states
DMTAP-mail's **"headline guarantee is strong metadata privacy against a global *passive*
adversary,"** and the `private`-tier table marks graph privacy **"strong (global passive)."**
`04-transport.md` §6 calls the Sphinx/Loopix mixnet **"normative and fully specified."** But
`THREAT-MODEL.md` SEC-9 says the opposite of the *same* property: **"Strong metadata privacy
against a global passive adversary (mixnet / onion routing / cover traffic) is research-tier and
non-normative in the KOTVA family... quarantined to research/... A profile MUST NOT claim
graph/timing privacy it does not implement,"** and `DIRECTION.md` §9 lists "mixnet" itself as the
example of unproven/unsound far-future cryptography that belongs in `research/`. `SPEC.md`
(§"Security floor, stated once and inherited") positions THREAT-MODEL as the checklist "every
capability... is an instance of," so by the family's own governance this is a conformance
conflict, not just loose prose. `04-transport.md` §4.4.11 ("Honest low-adoption model") already
partially self-corrects — it admits the early fleet is "closer to Tor-with-few-relays" and says
clients "MUST NOT present the `private` tier as 'anonymous' in absolute terms" — but that hedge
never made it back into §6.1/§6.5's unqualified "headline guarantee" wording, and neither §4 nor
§6 was reconciled with THREAT-MODEL when it was added. **This is load-bearing, not cosmetic**:
`crates/kotva-core/src/{mixnet,sphinx}.rs` (tag `core-v0.2.0`, the crate Wakala is pinned to)
really implements Sphinx/Loopix wire bytes per §4.4/§18.5. Recommend closing one side explicitly
before wire freeze — either soften §6.1/§6.2/§6.5's absolute language to match §4.4.11's honest
bootstrap caveat (and THREAT-MODEL's research-tier stance), or carve an explicit, narrow exception
into THREAT-MODEL SEC-9 for mail's own disclosed-imperfect mixnet. Doesn't block Wakala's current
unblocked-path work (broker-economics, REACH transport) since neither touches this claim.

**2. MED — confirmed still-open, self-disclosed wire debt: `GatewayAuthz` per-address/per-rail
grant type.** `07-gateway.md:869` and `26-legacy-adapters.md:421-422` both flag a new grant type
on `GatewayAuthz` (§12.2) as **"planned... not yet defined on wire"** while being referenced
normatively nearby — a direct instance of the gap DIRECTION §9's own "pay wire debt before prose"
rule warns against. Not hidden (both sites say "planned"), and the *existing* GatewayAuthz
mechanics (open/key-registered, fail-**safe**-not-fail-open, §12.2) are fully specified with CDDL
today — only the newer per-rail/per-address extension is outstanding. Low risk to us now; worth
the spec session closing before anything downstream cites the extended grant type as if it exists.

**3. LOW / nuance — REACH-1a's `structural` assurance leans on a CA mandate that isn't in force
yet.** Verified via web search: RFC 8657 (`accounturi`/`validationmethods` CAA) is cited and used
correctly, but CA/Browser Forum Ballot SC098v2 only made CA processing of it **mandatory
industry-wide from March 2027** (adopted May 2026) — after the spec's own 2026-07 snapshot date.
Until then a CA that hasn't implemented RFC 8657 could still complete issuance under a
CAA-permitted CA/method the `accounturi` record means to exclude, so REACH-1a's "structural"
(provable) claim for an own-domain name is presently closer to "structural once the operator's CA
supports RFC 8657" than universally structural today. One line of maturity disclosure would close
this; not a defect in the RFC citation itself (which is accurate) or the mechanism design.

**4. Confirms — grounding is real, not thin.** Spot-checked RFC citations (MLS 9420, HPKE 9180,
SFrame 9605, CAA 8657/8659, ACME TLS-ALPN-01 8737) against primary sources: all accurate in number
*and* in the specific property attributed to them (SFrame 9605's actual abstract matches
CONTRACT §3.1's "SFU reads per-frame metadata to forward, payload stays sealed" claim almost
verbatim). `bindings/README.md` and `docs/research/` maturity claims are honestly hedged, not
oversold (x402 "demand still thin (~$28k/day real)," personhood "imperfect," Kleros "small/
unproven at scale," TEE "new trust dependency... disclosed not trustless"). `profiles/
reachability.md` §4/§7/§8 (REACH-1a, the CAA-vs-bare-CAA distinction) is the single best-argued
section in scope — a model of the house style, correctly distinguishing what RFC 8657 buys from
what bare RFC 8659 CAA doesn't. Coordinator-kind set, content-visibility × assurance matrix,
DS-tag domain separation, and the SEC-5 recovery/no-single-device-rewrite machinery
(`01-identity.md` `rotate_threshold`) all cross-check clean across CONTRACT/DIRECTION/
THREAT-MODEL/reachability/media/rtc — no contradictions found beyond finding 1.

**Overall: safe to keep building on.** Everything in scope except finding 1 is sound, honestly
disclosed where it has a ceiling, and internally consistent. Finding 1 is a real inconsistency in
the security floor's own headline claim and deserves the spec session's attention before wire
freeze, but it doesn't block current Wakala work.

## Spec → Wakala  (answers · decisions · spec updates)

<!-- The spec session appends here. Example:
[2026-07-24 wire] ✓ RESOLVED — added descriptor key 6 = visibility {class, level} to §18; pushed
kotva@core-v0.2. Pin that tag.
-->
