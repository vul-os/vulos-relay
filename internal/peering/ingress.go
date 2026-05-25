// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"context"
	"crypto/ed25519"
	"io"
	"log"
	"net/http"
)

// DeliverySink receives a successfully-opened, fully-authenticated peer message
// and hands it to the local delivery path (mailbox/spool). It is the seam the
// relay's HTTP surface wires to relay.Router.RouteInbound. A non-nil error is a
// transient local failure (e.g. spool unavailable) and is reported to the
// sending peer as a 503 so it retries.
type DeliverySink interface {
	// Deliver injects a recovered RFC 822 message for the given envelope sender
	// and recipients into the local mailbox/spool.
	Deliver(ctx context.Context, mailFrom string, rcptTo []string, rawRFC822 []byte) error
}

// DeliverySinkFunc adapts a function to the DeliverySink interface.
type DeliverySinkFunc func(ctx context.Context, mailFrom string, rcptTo []string, rawRFC822 []byte) error

// Deliver calls f.
func (f DeliverySinkFunc) Deliver(ctx context.Context, mailFrom string, rcptTo []string, raw []byte) error {
	return f(ctx, mailFrom, rcptTo, raw)
}

// Receiver is the receiving-peer side of the peering protocol: it holds this
// node's identity, the authority predicates, a single shared ReplayGuard
// (spec §7 note — one guard per receiver box), the pinned-key lookup, and the
// local delivery sink. It opens inbound envelopes through the full §7–§8 checks
// and, on success, hands the plaintext to the sink.
//
// Receiver is the cross-process analogue of LoopbackEndpoint: the LoopbackEndpoint
// validates and appends to an in-memory log; the Receiver validates and injects
// into the real local mailbox via the sink.
type Receiver struct {
	// Identity is this node's long-term key material (holds the X25519 private
	// key needed to open envelopes addressed to it).
	Identity *Identity

	// Authorized reports whether this receiver is authoritative for a recipient
	// domain (spec §8.3).
	Authorized func(domain string) bool

	// PinnedKey returns the pinned Ed25519 identity key for a claimed sender
	// domain (spec §8.2), or ok=false if the domain is unknown. Backed by the
	// resolver's pin table in production.
	PinnedKey func(domain string) (ed25519.PublicKey, bool)

	// Guard is the shared §7 replay guard. MUST be the single guard instance
	// used by every handler on this box that opens envelopes (spec §7 note).
	Guard *ReplayGuard

	// Sink is the local delivery path for opened mail.
	Sink DeliverySink

	// Reputation, when non-nil, receives validated reputation attestations that
	// arrive on the ingress side-channel (reputation.go). Optional.
	Reputation *ReputationStore

	// Resolver, when non-nil, applies verified key-rotation attestations
	// (spec §3.2) that arrive on the ingress side-channel. Optional.
	Resolver *StaticResolver

	// Observer, if non-nil, receives peer-ingress delivery outcomes for metrics
	// (a mail envelope delivered to the local sink, or rejected). It does not
	// affect the wire protocol. Optional.
	Observer PeerObserver

	// Logf, if non-nil, logs rejections (for operator visibility). Optional.
	Logf func(format string, args ...any)
}

// PeerObserver receives Vulos↔Vulos peer-ingress mail outcomes for metrics. It
// must be non-blocking and concurrency-safe. Nil disables observation.
type PeerObserver interface {
	// PeerDelivered reports that a peer mail envelope passed all checks and was
	// handed to local delivery.
	PeerDelivered()
	// PeerRejected reports that a peer mail envelope was rejected (permanent or
	// transient). reason is a short classifier.
	PeerRejected(reason string)
}

// Accept processes one inbound wire blob. It dispatches reputation and rotation
// side-channel frames, otherwise treats wire as a mail envelope: parse, run the
// full §7–§8 receiver checks via Open, and on success hand the recovered
// message to the local delivery sink.
//
// It returns nil on acceptance. On rejection it returns the matching sentinel
// (ErrUnauthenticated / ErrUnauthorized / ErrMisrouted / ErrReplay /
// ErrUnsupported / ErrCorrupt) for a permanent failure, or a wrapped local
// error for a transient delivery failure.
func (rc *Receiver) Accept(ctx context.Context, wire []byte) error {
	// Side-channel: reputation attestation (privacy-preserving aggregate counts).
	if IsReputationFrame(wire) {
		payload, err := ParseReputationFrame(wire)
		if err != nil {
			return ErrCorrupt
		}
		att, err := UnmarshalAttestation(payload)
		if err != nil {
			return ErrCorrupt
		}
		if rc.Reputation != nil {
			// Receive verifies the attestation signature + trust set itself.
			if rerr := rc.Reputation.Receive(att); rerr != nil {
				rc.logf("peering: rejected reputation attestation: %v", rerr)
			}
		}
		return nil
	}

	// Side-channel: key-rotation attestation (spec §3.2). We verify it chains to
	// the pinned outgoing key and re-pin; an unsigned/unchained change is
	// rejected, never silently accepted.
	if IsRotationFrame(wire) {
		payload, err := ParseRotationFrame(wire)
		if err != nil {
			return ErrCorrupt
		}
		att, err := UnmarshalRotation(payload)
		if err != nil {
			return ErrCorrupt
		}
		if rc.Resolver == nil {
			rc.logf("peering: ignoring rotation attestation (no resolver wired)")
			return nil
		}
		if rerr := rc.Resolver.ApplyRotation(att); rerr != nil {
			rc.logf("peering: rejected rotation for %q: %v", att.Domain, rerr)
			return ErrUnauthorized
		}
		rc.logf("peering: applied key rotation for %q", att.Domain)
		return nil
	}

	// Mail envelope path.
	env, err := UnmarshalEnvelope(wire)
	if err != nil {
		rc.observeReject("corrupt")
		return ErrCorrupt
	}
	plain, err := Open(env, OpenParams{
		Receiver:         rc.Identity,
		AuthorizedDomain: rc.Authorized,
		PinnedSenderKey:  rc.PinnedKey,
	}, rc.Guard)
	if err != nil {
		rc.logf("peering: rejected envelope from %q: %v", env.Header.SenderDomain, err)
		rc.observeReject("checks_failed")
		return err
	}

	// All §7–§8 checks passed; hand to local delivery.
	if err := rc.Sink.Deliver(ctx, env.Header.MailFrom, env.Header.RcptTo, plain); err != nil {
		// Local delivery failed — transient; the sending peer should retry.
		rc.logf("peering: local delivery failed for %q: %v", env.Header.MailFrom, err)
		rc.observeReject("local_delivery_failed")
		return err
	}
	if rc.Observer != nil {
		rc.Observer.PeerDelivered()
	}
	return nil
}

func (rc *Receiver) observeReject(reason string) {
	if rc.Observer != nil {
		rc.Observer.PeerRejected(reason)
	}
}

func (rc *Receiver) logf(format string, args ...any) {
	if rc.Logf != nil {
		rc.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// maxIngressBytes bounds the request body the ingress handler will read. An
// envelope carries one RFC 822 message; 32 MiB is comfortably above any
// realistic mail size while preventing a memory-exhaustion injection.
const maxIngressBytes = 32 << 20

// IngressHandler is the HTTP handler for the peering ingress endpoint
// (POST PeeringPath). It reads the wire blob, runs Receiver.Accept, and maps
// the outcome to an HTTP status + the X-Vulos-Peer-Outcome header that the
// HTTPTransport sender uses to classify permanent vs. transient.
//
// It is authenticated ingress: there is NO open injection. Every mail envelope
// must pass the full §8 checks (signature against the pinned sender key,
// sender-domain authority, receiver targeting, replay window, AEAD integrity)
// inside Accept before anything is delivered.
func IngressHandler(rc *Receiver) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxIngressBytes+1))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		if len(body) > maxIngressBytes {
			http.Error(w, "envelope too large", http.StatusRequestEntityTooLarge)
			return
		}

		switch aerr := rc.Accept(r.Context(), body); {
		case aerr == nil:
			w.WriteHeader(http.StatusAccepted) // 202: accepted into local delivery
		default:
			writeRejection(w, aerr)
		}
	})
}

// writeRejection maps an Accept error to a status code and advertises the
// machine-readable outcome so the sender classifies it (spec §10).
//
//   - Permanent receiver rejections → 422 with X-Vulos-Peer-Outcome set; the
//     sender bounces (no SMTP retry).
//   - Anything else (transient local delivery failure) → 503; the sender
//     defers and retries on the peer path.
func writeRejection(w http.ResponseWriter, err error) {
	if outcome, ok := errorToOutcome(err); ok {
		w.Header().Set(outcomeHeader, outcome)
		http.Error(w, outcome, http.StatusUnprocessableEntity)
		return
	}
	// Transient (local delivery) failure.
	http.Error(w, "temporary failure", http.StatusServiceUnavailable)
}
