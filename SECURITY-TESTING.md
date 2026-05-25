# Security Testing — Vulos Relay

This document describes the **pentest / adversarial test suite** for vulos-relay
and how to run it.

## What this suite is

The suite in [`security/`](./security) is a set of **attacker-style** Go tests.
Each test *attempts* a concrete attack against a real relay surface and *asserts
that the attack is blocked*. A passing run is the proof that none of the
modelled attacks succeed. Every "rejected" test also asserts the **canary**
(the local delivery sink / queue / SMTP sink) stays empty — so the test fails
loudly with a `VULN:` message if a forged or unauthorised message ever slips
through.

The suite is intentionally **black-box**: it drives only the exported relay API
the way a hostile peer or client would, reusing the production wiring:

- `peering.Receiver` behind `peering.IngressHandler` served over `httptest`
  (the real peering HTTP ingress).
- `relay.SubmitHandler` served over `httptest` (the real submission gate).
- `sending.SMTPSender` against a hostile in-process SMTP sink.
- `sending.Pipeline` driven end-to-end for the suppression send-gate.
- `sending.DKIMSigner` verified by an **independent** relaxed/relaxed
  RSA-SHA256 verifier (not the signer's own helpers), so a passing roundtrip
  proves real interoperable DKIM rather than a self-marked artefact.

Because it tests at the boundary an attacker actually sees, a regression that
opens a hole is caught even if internal refactors move things around.

## How to run

```sh
cd vulos-relay

# the suite, verbose
CGO_ENABLED=0 go test ./security/ -count=1 -v

# the suite, quiet
CGO_ENABLED=0 go test ./security/ -count=1

# full project gate (build + vet + every package incl. the pentest suite)
CGO_ENABLED=0 go build ./... && CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...
```

All tests run with `CGO_ENABLED=0` and touch no network outside `127.0.0.1`
loopback (httptest servers + in-process SMTP sinks). The federation wire format
is untouched.

## Coverage (8 attack classes, 42 tests)

| # | Attack class | File | Tests | What is proven |
|---|---|---|---|---|
| 1 | Open-relay / submission auth | `submit_auth_test.go` | 8 | No-credential, forged-HMAC, unknown-account, expired and replayed credentials, and malformed/`Basic`/`Bearer` schemes are all rejected and **never enqueued**. Wrong path/method never enqueues. A valid credential *is* accepted (control). |
| 2 | Peering ingress auth | `peering_ingress_test.go` | 12 | Forged signature → `unauthenticated`; replay → `replay`; unknown/unpinned peer → `unauthorized`; sender-domain impersonation → `unauthorized`; wrong-receiver target & relay-through-foreign-recipient → `misrouted`; AEAD tamper → rejected; garbage wire → `corrupt`; **forged key-rotation** (not signed by the held pin) → `unauthorized` and the pin is unchanged; rotation cannot bootstrap trust for an unpinned domain; non-POST → 405. A valid envelope *is* delivered exactly once (control). |
| 3 | Replay-nonce guard | `replay_nonce_test.go` | 4 | Same `(sender,nonce)` within the window → `ErrReplay`; stale/future timestamp → rejected on the window alone; a **distinct-nonce flood keeps the dedup cache bounded** by `MaxSeen` (memory-exhaustion DoS fails); replay of an in-window nonce is still caught after cache churn. |
| 4 | Per-IP rate cap | `rate_cap_test.go` | 4 | A flood from one IP gets **429 before auth**; a different IP is unaffected; rotating **`X-Forwarded-For` does NOT bypass** the cap (only the real `RemoteAddr` counts); the cap is enforced before the authenticator runs. |
| 5 | Trust-segment gating | `trust_segment_test.go` | 4 | A new/untrusted sender is **never placed on a warm/established IP** (lands on cold/ramp); when the warm IP is the *only* one, a low-trust account **defers** (`ErrNoAvailableIP`) rather than being promoted; a nil `TrustSource` fails closed to the coldest tier; an established account *does* ride warm (control). |
| 6 | MTA-STS enforcement | `mtasts_test.go` | 3 | Under an `enforce` policy: a STARTTLS downgrade/MITM, an MX that offers no STARTTLS, and a DNS-substituted off-policy MX all **DEFER with zero plaintext delivery** (the SMTP sink never receives DATA). |
| 7 | Suppression send-gate | `suppression_test.go` | 3 | A hard-bounce/complaint recipient is dropped at the gate seam; the real `Pipeline` **never asks the Sender to deliver to a suppressed recipient**; an all-suppressed message never reaches the Sender at all. |
| 8 | DKIM signing integrity | `dkim_test.go` | 4 | Outbound carries a verifiable `DKIM-Signature` (sign→verify roundtrip against the rotator's published key); **tampering the body**, **tampering a signed header**, and **substituting an unrelated key** all break verification. |

### Note on `RELAY_SUBMIT_DISABLE` (queue-only mode)

The queue-only mode is wired in `cmd/relay/main.go` and already covered by
`cmd/relay/submit_test.go` (`TestSubmit_DisabledViaEnv_NoListenerBound` — no
listener binds when the flag is set). The pentest suite additionally pins the
deeper invariant it relies on: the **only** code path that enqueues a message is
`relay.SubmitHandler`, and that handler *always* runs the authenticator before
enqueue (attack class 1). So queue-only mode cannot open an unauthenticated
injection path — there is no second enqueue route to exploit.

## Findings

**No live vulnerabilities were found.** Every modelled attack is blocked by
existing relay controls; all 42 pentest tests pass.

### Supporting change

One small, non-behavioural addition was made to support black-box assertion of
the replay-cache bound:

- `peering.ReplayGuard.SeenLen()` — an exported accessor returning the number of
  retained dedup entries, so attack class 3 can assert the `MaxSeen` cap holds
  under a flood without reaching into unexported state. It does not affect the
  wire protocol or any decision logic.

## Threat model alignment

The classes above map to the in-scope surfaces in [`SECURITY.md`](./SECURITY.md)
and [`THREAT-MODEL.md`](./THREAT-MODEL.md): the submission listener (class 1, 4),
peering / federation (class 2, 3), the sending pipeline and deliverability
controls (class 5, 6, 7, 8). Operational high-volume DoS remains out of scope
per `SECURITY.md`, but the per-IP cap (class 4) and the bounded replay cache
(class 3) are still asserted because they are code-level abuse mitigations.
