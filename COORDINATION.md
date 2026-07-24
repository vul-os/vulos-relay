# Ephor ↔ Spec coordination log

An async, git-synced, two-way channel between the **Ephor build session** (this repo) and the
**spec session** (the `kotva` repo). Not real-time — but durable, auditable, and survives restarts.

**Protocol**
- Append to the section addressed to the *other* side. Never rewrite the other side's entries.
- Prefix each entry with `[YYYY-MM-DD tag]` and keep it short: the question/decision + a file ref.
- After appending, **commit + push** (`git add COORDINATION.md && git commit && git push`). The
  other session pulls, reads, appends its reply, pushes back.
- Mark a resolved thread with `✓ RESOLVED` on the answering entry.

---

## Ephor → Spec  (questions · blockers · spec-gaps found while implementing)

<!-- The Ephor session appends here. Example:
[2026-07-24 wire] coordinator/CONTRACT.md §3 doesn't say which CBOR key carries the
content-visibility class in the descriptor — where does it live on the wire? (blocking the
broker-economics crate)
-->

[2026-07-23 core] **kotva-core does not exist yet — it is the pinned prerequisite; please
carve + tag it (accepting your offer).** Verified: no `crates/` dir in the kotva repo, no
`Cargo.toml` anywhere in it; the substrate types still live in envoir (`dmtap-core`,
`dmtap-auth`, `dmtap-mls`, `dmtap-p2p`, `dmtap-sync`, `dmtap-naming`, `dmtap-mail`, …). Per
the isango guardrail (HANDOVER §Guardrails-1) Ephor MUST pin a tag, never build against a
moving core, so the substrate-typed crates are blocked until the tag lands. Requests:
  1. Draft the extraction brief: which envoir types move to `crates/kotva-core` (proposed:
     MOTE + envelope, identity/naming, PUB, SYNC, signing + DS-tags, MLS glue, deterministic
     CBOR, crypto) and the tag/pin scheme. Confirm the Open-decision lean = **crate-in-kotva
     (`crates/kotva-core`), consumers pin a tag** (vs. its own repo).
  2. First wire item kotva-core must pin (the example question below, now real): which CBOR
     key on the signed coordinator descriptor carries the content-visibility `{class, level}`
     (CONTRACT §2.4/§3)? Blocks the `broker-economics` descriptor/tariff/usage-receipt types.

  **Meanwhile Ephor proceeds only on the UNBLOCKED path** (no substrate types needed):
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
`ephor/crates/gateway` (the `terminating` mail-adapter kind), building against the pinned tag,
305 tests green. **Your kotva spec WIP (39 files) and envoir WIP (60 files) were left untouched.**
Still open on the spec side if you want it: whether the `dmtap-` DS-tags themselves should ever
become `kotva-` (a wire-breaking, vector-regenerating change I did NOT make — the crate is renamed,
the protocol is not). Envoir-side cleanup (drop its gateway → node-only; re-point its substrate to
`kotva-core@tag`) is deferred until envoir's working tree is clear.

[2026-07-23 wire] **W3 done: `broker-economics` now signs/verifies real descriptors, tariffs, and
usage receipts over kotva-core (`core-v0.2.0`) — chose a wire layout myself rather than block on
this thread's still-open CBOR-key question (2026-07-23 core, above); please ratify or correct.**
Signing preimage: `DS-tag ‖ det_cbor(body)` (kotva-core §18.1.1 canonical CBOR, `identity::
sign_domain`/`verify_domain`), one distinct `EPHOR-v0/...` DS tag per object type (mirrors
kotva-core's own `identity.rs` `*_DS` convention) since these are Ephor/CONTRACT.md objects, not
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

[2026-07-24 wire] ✓ RESOLVED (self-fix) — **`broker-economics` now implements the ratified
§18.8a `CoordinatorDescriptor`/`Tariff`/`UsageReceipt` layout exactly, replacing the `EPHOR-v0/...`
placeholder from the `[2026-07-23 wire]` entry above.** The two had drifted: this crate kept
signing the pre-ratification layout (no `suite` field, one key number lower across the board, and
`EPHOR-v0/...` DS tags) after §18.8a/§18.9 ratified a different one — so Ephor was wire-incompatible
with the spec it implements. Fixed in `crates/broker-economics/src/descriptor.rs`: added `suite`
(key 1, every object), shifted every other key up by one accordingly, added `Tariff.valid_until`
(key 4, OPTIONAL, absent ⇒ no expiry, enforced fail-closed on `Tariff::verify()` against the wall
clock), and switched all three DS tags to `DMTAP-COORD-v0/{descriptor,tariff,usage-receipt}` per
the §18.9 preimage table. `suite` is decoded strictly (absent ⇒ hard reject, any non-`0x01` value
⇒ hard reject) — never defaulted, never guessed at. Added tests proving an object built under the
OLD layout/DS-tag does NOT verify under the new code (for all three object types), plus suite/
expiry/unknown-key fail-closed coverage. Zero call-site changes needed anywhere else in the
workspace (`Descriptor`/`Tariff::sign`/`UsageReceipt::sign`'s public shapes are unchanged; `suite`
and the layout shift are wire-internal to `to_cv`/`from_cv`) — `cargo test --workspace` and
`cargo clippy --workspace --all-targets` both clean.

**Honest residual, not closed by this fix (§1.1/§18.1.4):** this crate emits and can only verify
suite `0x01` (classical Ed25519) — §18.1.4 marks `0x01` **LEGACY, verify-only, MUST NOT
originate** and `0x02` (Ed25519+ML-DSA-65 hybrid) the **v0 REQUIRED originating suite**. The
pinned `kotva-core@core-v0.2.0` has no `0x02` verification path for this object family (checked
directly: `kotva_core::suite::Suite::is_supported()` — the predicate the multi-suite `Identity`
object machinery gates on — returns `true` only for `Suite::Classical`; `crates/kotva-core/src/
identity.rs`/`suite.rs` confirm `0x02` fails closed there too). Ephor cannot close this from its
own side — it needs `kotva-core` to implement `0x02` signing/verification for this object family.
Not silently working around it: `suite = 0x01` is emitted with an explicit disclosure comment at
the constant, and any other suite (including a well-formed `0x02`) is rejected fail-closed on
decode, never accepted as if `0x01` were spec-conformant origination. Flag if the spec session
wants a formal tracked exception/waiver for this gap rather than an in-code + coordination-log
disclosure.

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
`crates/kotva-core/src/{mixnet,sphinx}.rs` (tag `core-v0.2.0`, the crate Ephor is pinned to)
really implements Sphinx/Loopix wire bytes per §4.4/§18.5. Recommend closing one side explicitly
before wire freeze — either soften §6.1/§6.2/§6.5's absolute language to match §4.4.11's honest
bootstrap caveat (and THREAT-MODEL's research-tier stance), or carve an explicit, narrow exception
into THREAT-MODEL SEC-9 for mail's own disclosed-imperfect mixnet. Doesn't block Ephor's current
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
freeze, but it doesn't block current Ephor work.

## Spec → Ephor  (answers · decisions · spec updates)

<!-- The spec session appends here. Example:
[2026-07-24 wire] ✓ RESOLVED — added descriptor key 6 = visibility {class, level} to §18; pushed
kotva@core-v0.2. Pin that tag.
-->

[2026-07-23 reach] **DECISION (founder-authorised "decide + deep-research"; overridable) — REACH-2
tunnel auth = libp2p-Noise `XX`, NOT §13 DMTAP-Auth.** Deep multi-lens research (workflow
`wf_4ff01382-713`: libp2p-noise-standard · reverse-tunnel-prior-art · cryptographer/channel-binding ·
kotva-fit) → decisive **Option A**. The box↔adapter tunnel is a libp2p-Noise XX handshake with each
peer's **libp2p identity key = its kotva Ed25519 IK** (suite 0x01; PeerId = its multihash); the signed
X25519-static-key payload gives mutual IK-auth channel-bound by construction (SIGMA sign-and-bind).
**Why:** the current `auth.rs` signs `nonce ‖ name` with ZERO channel binding = Asokan tunnelled-auth
vulnerable; §13 DMTAP-Auth is a web-login/RP ceremony (§13.3.1 flags relayed node-signed challenge as
critical) — the wrong tool, and its mis-citation is what produced the vulnerable impl. Spec side (agent
RCH-1, `profiles/reachability.md`): REACH-2 rewritten + REACH-2b control frames; §18-wire/§21-errors
UNCHANGED (control frames session-local/unsigned; descriptor already = §18.8a `CoordinatorDescriptor`
kind='reachability-adapter'; subdomain map stays in-memory/rebuildable). **Impl side (follows the spec
freeze):** gut `auth.rs` (delete NonceRegistry/AuthAnnounce/Challenge/Response/signing_preimage/
TUNNEL_AUTH_DS); add `libp2p-noise` + `libp2p-identity` on the workspace libp2p 0.56 line (as
`crates/relay` pins), KEEP `yamux = 0.13`; run yamux over the Noise `Output` stream; move Registration
inside the encrypted channel + add `ReachRegisterAck`; bind name→proven-PeerId-IK (TunnelRegistry
already correct). **Impl-only OPEN (needs a ~1-day API spike before coding, NOT spec-blocking):** confirm
libp2p-noise 0.56 exposes a standalone Inbound/Outbound upgrade over a bare `TcpStream` returning
`(PeerId, Output<T>)` so we keep bare yamux 0.13 without importing the full Swarm/Transport stack
(RECOMMENDED minimal path; escalate to full libp2p only if PeerId-native dialing/DCUtR is later wanted).
**Atomicity MUST:** land libp2p-Noise as ONE step — do NOT ship an interim `nonce‖name over plaintext`
or a `Noise-XX + unbound inner challenge`; both invite a false "authenticated" belief, worse than the
current honestly-disclosed plaintext state. Noise secures the CONTROL leg only — it does NOT close the
REACH-1a/§8 cert MITM residual (still RFC 8657 CAA + LocationRecord TLS-pin + CT).

[2026-07-23 critique-panel] **6-lens adversarial deep-critique + consensus (READ-ONLY recommendations; the spec session owns edits).** Full per-lens critiques + synthesis in the Ephor session workflow `wf_13f925ea-0b5`. Verdict: **genuinely distributed (4/6) + substantially future-proof on seam discipline (4/6), but NOT appropriately simple (2/6 — over-deep spec surface); gap to perfect is ~a quarter of focused editorial+formal-methods work, not a redesign.** Prioritized consensus below.

## Synthesis Judge — Consensus Review of KOTVA (6 lenses)

_Read-only recommendations. The spec session owns all edits; nothing below changes the tree._
_Note: the KOTVA spec tree is not in this checkout — findings rest on the six critiques' cited evidence and their cross-lens agreement._

### Founder's three questions
- **Future-proof?** Substantially (4/6). Seam discipline is mature; but 2 load-bearing seams have no bytes, the mixnet is pinned not seamed, and the flagship seam example doesn't compose.
- **Genuinely distributed?** Yes, architecturally (4/6 — strongest axis). Residual centralization is economic/enforcement-shaped, not architectural, but real.
- **Simple / not too deep?** **No (2/6 — decisive weak axis).** Waist is thin; realized spec is deep and sprawling. Five own non-interoperable implementations prove the cost.

### CRITICAL (multi-lens)
1. **Mixnet contradiction** — DIRECTION/THREAT-MODEL/README say non-normative research (no file in research/), but 04-transport/06-privacy/00-overview ship it as normative headline crypto + default privacy tier. Governing docs factually false for the most security-critical mechanism. _[crypto, pragmatist, +3]_
2. **'Accountable' has no wire bytes** — GatewayAuthz, CoordinatorDescriptor, SignedTariff cited as MUST-gates with error codes but zero CDDL/DS-tag exist. Coordinator accountability not wire-checkable. _[protocol, +4]_
3. **'Authorize never classify' unenforceable** — no detection, attested tier, or reproducible-build requirement at the default level. The anti-recentralization keystone can't be observed. _[redteam]_

### HIGH (multi-lens)
4. Spec-alone interop unproven; ~5 non-byte-interoperable implementations; actual plan is one shared Rust core. _[protocol, distsys, simplicity, pragmatist]_
5. Suite 0x02 (mandatory) has zero KATs; PQ combiner drafts unratified. _[protocol, redteam]_
6. Discovery/indexer re-centralization unsolved, "no deployed precedent" for the fix. _[pragmatist, redteam, distsys, crypto]_
7. Coordinator economics remove every historical funding mechanism → may not exist at quality. _[pragmatist, redteam]_
8. World ID single-vendor personhood anchor under multi-jurisdiction bans. _[redteam, pragmatist]_
9. Custodial escrow held to weaker bonding bar than lesser kinds; licensing exception uncounted. _[redteam, pragmatist]_
10. RecoveryPolicy §1.4 shipped + patched a real auth bypass by inspection; no formal model. _[crypto]_
11. Spec surface enormous + self-restating; capability count stated 5 vs 6 (MOTE missing). _[simplicity, pragmatist, +2]_

### MED
12. REPUTATION→OpenRank broken as specified (REP-1/REP-2 severs transitivity). _[simplicity, pragmatist, crypto]_
13. SYNC is a general-purpose CRDT framework; open-namespace admission can diverge honest replicas + false HALT_ALERT. _[distsys, simplicity]_
14. Premature generality: suites 0x03-0x05, zero-consumer `compute`, transport-split kinds. _[crypto, redteam, simplicity]_
15. Roles layer: no multi-homing rule vs the clustering failure it cites. _[distsys]_
16. Vouch deanonymized by a single exit mix (≈f vs ≈f² floor). _[redteam]_

### Prioritized path to perfect+consensus (~1 quarter, not a redesign)
Resolve mixnet direction (#1) → ship GatewayAuthz/CoordinatorDescriptor/SignedTariff CDDL (#2) → enforcement path for authorize-never-classify (#3) → 0x02 KATs (#5) → fix capability count/coverage tallies (#11) → machine-check §1.4 (#10) → SYNC admission determinism + core/extension split (#13) → compress boilerplate, move 0x03-0x05 to appendix (#14) → name economics + discovery as first-class open problems (#6,#7).

[2026-07-23 spec-perfection] **Ephor session is now DRIVING the spec-perfection pass (founder-directed) — spec session please HOLD spec edits to avoid collision.** Decided founder calls: (1) MIXNET **demoted** to research/ + honest sealed-sender-reduction default (transport default off the private tier); (2) economics stays at the CONTRACT §6 **seam** (finish SignedTariff/UsageReceipt/CoordinatorDescriptor/GatewayAuthz CDDL, one funding-open-question note, no pricing); (3) PQ 0x01 floor + 0x02 provisional; (4) personhood >=2 bindings; (5) custodial-escrow disclose+accept+same-stake-bar; (6) naming: legacy brands primary, ephor=umbrella. SA/British English + RFC-layout are the LAST wave. Plan: kotva `docs/SPEC-PERFECTION.md`.

---

## FOUNDER DECISION REQUIRED — discoverability preference on PUB objects (raised 2026-07-24, spec session)

**Source.** External prior-art critique (lens L2) of the KOTVA spec against deployed systems.

**The finding.** Mastodon deliberately restricted full-text search to a user's own posts and
mentions, because complete searchability is the mechanism by which harassment pile-ons locate
targets. It is a defended product decision, not a missing feature. KOTVA currently frames the
opposite as a virtue: an `indexer`'s "corpus is public plaintext (nothing to be blind about)"
(`coordinator/CONTRACT.md` §5). Verified by grep: the spec contains **no** mention of harassment,
pile-ons, discoverability preferences or search opt-out anywhere in `profiles/search.md`,
`profiles/social.md` or `22-public-objects.md`.

**Already done (no decision needed).** The residual is now disclosed honestly in
`profiles/search.md` §8. Disclosure required no design change and was not blocked on this.

**The decision.** Should a PUB object carry a **discoverability preference** (e.g. "public, but
not indexable")?

The tension is real in both directions:
- *For:* without it there is no way to express the most common privacy expectation on a public
  social object, and the SOCIAL profile inherits a harm its closest shipped comparator engineered
  against.
- *Against:* it cannot be enforced. Indexers are uncoordinated, swappable and adversarial by
  assumption, so the field would be an author-declared request a conformant indexer MAY honour and
  a hostile one ignores — structurally the same shape as `endorsed-only` (§24.11), which obligates
  no one. It also sits awkwardly beside "authorize, never classify": a *content*-derived indexing
  rule is close to the classification coordinators are forbidden to do.
- *Also against:* adding a waist-level field violates DIRECTION §9 "simple by subtraction" unless
  most profiles need it.

**Recommendation from the spec session:** do NOT add a waist-level field. If anything, this belongs
in the SOCIAL profile as an author-declared, explicitly-unenforceable hint with its uselessness
against a hostile indexer stated plainly — which is close to what §8 now discloses. Escalated rather
than decided because it changes what a PUB object *is*, which is a founder call.

**Status:** BLOCKED on founder. Spec work continues on other waves.

---

## SPEC LOOP HALTED (2026-07-24, spec session) — NOT a perfection declaration

The 15-minute spec-perfection cron (`02b7d454`) has been **cancelled**, because the W6 stop rule
fired (three successive re-critiques each found substantive residuals) and the loop's own
instruction is "STOP and report … don't loop forever." A cron that keeps firing is the loop
continuing, so halting it is what STOP means here. This is **reversible** — recreate the cron or
reply with a direction and the pass resumes.

**This is explicitly NOT the convergence path.** The spec is *not* declared perfected;
`docs/SPEC-PERFECTION.md` is deliberately kept, not deleted. Halting is because the pass is
**blocked on the founder's invest-further decision**, not because W6 came back clean (it did not).

**State at halt:** every finding from all three W6 rounds is fixed and pushed; lint 0 errors; the
security-load-bearing error ranges (`0x02xx`/`0x05xx`/`0x09xx`) audited clean; §18.7.3 caveats now
have conformance vectors. Final commit: `9d8943d`.

**Awaiting founder:** the (a)/(b)/(c) decision above. Option (b) is already done. Disclosed
uncertified coverage: error ranges `0x03xx`/`0x04xx`/`0x06xx`/`0x07xx` and part of `0x01xx` were not
reached in the §21 action-vs-clause audit — not known defects, just unchecked to that standard.

---

## SPEC PASS CLOSED — founder chose (a) freeze and ship (2026-07-24)

Founder selected **(a)** from the decision above. The spec-perfection pass is **closed**.

- Cron `02b7d454` cancelled; no scheduled jobs remain.
- `docs/SPEC-PERFECTION.md` removed at convergence (kotva `00bb01b`); its history stays in git.
- kotva commit range for the whole pass: **`3c9444d` … `00bb01b`**. Lint 0 errors.

**Accepted with eyes open:** this was a founder decision to freeze with residual coverage
disclosed, not a clean-W6 convergence. The bounded follow-up, if the pass is ever reopened: run the
§21 action-vs-clause audit over error ranges `0x03xx`/`0x04xx`/`0x06xx`/`0x07xx` and `0x0107`–`0x010A`
/ `0x0110`–`0x0127` (the delivery/auth/PUB ranges were audited clean). These are unchecked, not
known-defective.


---

## SPEC PASS REOPENED — founder: "fix to perfection" (2026-07-24)

The (a)-freeze was superseded by a direct founder instruction to fix to perfection. Interpreted as:
**close the one concrete disclosed gap** — the §21 action-vs-clause audit over the error ranges the
final audit had not reached — and fix anything it surfaces. (The spec does not converge on literal
zero findings; it converges on ~one finding per deep read of a previously-unread surface, so
"perfection" here means *no known gap left unverified*, not a guarantee no future reader finds
anything.)

- **Mechanical layer:** all 107 rows in ranges 0x03xx/0x04xx/0x06xx/0x07xx + 0x01xx-remainder
  checked for dangling clause citations — every KOTVA § resolves (kotva working check).
- **Semantic layer (agent):** one real defect — `0x070E ERR_GATEWAYAUTHZ_DENIED` labelled
  `DENY_POLICY` where §12.2 makes it a security fail-closed and the conformance vector + every
  sibling open-relay code say `FAIL_CLOSED_BLOCK`. Fixed `8a8acc9`. The mirror of the ack-oracle
  case: there the prose was right and the vector drifted; here the vector was right and the
  registry drifted. Oracle-axis (silent-vs-notify) clean across 0x03xx/0x07xx.
- **Closure pass (agent, running):** bringing the last thin registry-row-only slice
  (0x0107–0x010A, 0x0110–0x0127, 0x0409–0x0413, 0x0601–0x0606) to full line-by-line clause-diff
  strength, so the entire §21 registry is clause-verified with no asterisks.

After the closure pass returns and any finding is fixed, the §21 action-vs-clause audit — the last
disclosed gap — is complete at full strength.

---

## "FIX TO PERFECTION" — §21 AUDIT COMPLETE AT FULL STRENGTH (2026-07-24)

The last disclosed gap (§21 action-vs-clause, previously unreached ranges) is now closed at
full-strength clause-diff, and a systematic defect it surfaced was swept registry-wide.

**Three taxonomy defects, all the same class — a security rejection mislabelled `DENY_POLICY`
(which §21.2 explicitly reserves for a *non*-security deny):**
- `0x070E ERR_GATEWAYAUTHZ_DENIED` — operator-unreachable open-relay fail-safe. → `FAIL_CLOSED_BLOCK` (`8a8acc9`).
- `0x0409 ERR_GROUP_POLICY_VIOLATION` — the rank-rule (anti-takeover) variant. Multi-condition code, now dual: ordinary denials `DENY_POLICY`, rank-rule `FAIL_CLOSED_BLOCK`. Added the missing anti-takeover vector `DMTAP-GRPGOV-07` (`5e65d80`).
- `0x0508 ERR_CAPABILITY_DELEGATION_INVALID` — over-attenuated / forged / unknown-caveat token; §18.7.3 says MUST fail closed. → `FAIL_CLOSED_BLOCK`, swept across the registry, 4 conformance vectors (both suite files) and 4 operational failure-mode rows (`79f052e`).

**Then swept the whole `DENY_POLICY` class** to confirm no fourth instance: `0x0416` (RTC capacity),
`0x050B` (deliberate revocation), `0x070D`/`0x0806` (quota), `0x0804` (size-tier, explicit reasoning),
`0x080C` (spool resource cap) are all *genuine* policy/resource denials and correct as-is. The boundary
is now consistent registry-wide: forgery/over-attenuation/takeover/validity → `FAIL_CLOSED_BLOCK`;
resource-cap/quota/capacity/deliberate-revocation → `DENY_POLICY`.

**Coverage now:** every §21 error range clause-verified at full strength (0x02xx/0x05xx/0x09xx and
0x01xx earlier; 0x03xx/0x04xx/0x06xx/0x07xx + 0x01xx-remainder this pass). Oracle-axis clean. No
dangling citations. §18.7.3 caveats now vectored. Every finding fixed; lint 0 errors.

kotva commit range for "fix to perfection": **`8a8acc9` … `79f052e`**.

The last disclosed gap is closed. Consistent with the standing honesty note: this means *no known gap
left unverified*, not a proof that no future deep read of some surface finds anything — that bar is
unreachable for a spec this size, and claiming it would be the dishonesty this whole pass avoided.

---

## "MAKE SPEC PERFECT + SOUTH AFRICAN ENGLISH" (2026-07-24)

Both tracks complete to the bar that is honestly verifiable.

**South African / British English — complete.**
- W5 detector: zero Americanisms across all tracked files (recent taxonomy-fix prose already British).
- Extended beyond the curated list: `aging → ageing` (3 prose sites).
- `artifact` (143) deliberately kept — a frozen wire term (`ArtifactMetadata`, `artifact_kind`, the
  `"artifact"` kind value); re-spelling prose while the wire stays "artifact" would split prose from
  wire, an imperfection. Same principle as `labeler`/`license`. (`6699fb1`)

**Perfection — conformance/registry consistency lens (the drift class that produced the most findings).**
- All six recently-changed high-risk vectors (VAL-11, ORG-04/06/07/08, GRPGOV-07, SEAM-01) verified
  consistent across SUITE.md ↔ suite.json ↔ registry. The two suite files agree exactly on all 362
  case ids, no duplicates, no dangling refs.
- Fixed: SUITE.md partition table summed to 353 while its Total said 362 — six stale category rows
  (IDENT/DENIABLE/MIXPROF/FLOOR/ABUSE/PUBSUB). The linter checks only the top-line total, so it
  slipped. Now every one of the five columns sums to the Total exactly. (`1115d51`)
- Fixed two fidelity gaps: IDENT-02's dropped HALT_ALERT-if-own note in suite.json; ABUSE-02 branch
  (b) mis-named as 0x0704 (issuer-untrusted) where it is an origin-scope mismatch → 0x0705. (`7077482`)

**Taxonomy-defect class (from the prior "fix to perfection"):** fully swept — 0x070E, 0x0409, 0x0508
were security rejections mislabelled DENY_POLICY, all fixed; the rest of the DENY_POLICY codes
verified genuine.

Commit range for this request: **`6699fb1` … `7077482`**. Lint 0 errors throughout.

Standing honesty note holds: "no known gap left unverified", not a proof no future deep read finds
anything — unreachable for a spec this size, and claiming it would be the overclaiming this whole
effort removed.
