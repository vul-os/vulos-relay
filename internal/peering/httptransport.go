// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// PeeringPath is the ingress route a receiver peer exposes for envelope
// delivery (spec/PEERING.md §2 — the carrier address). An HTTPTransport POSTs
// the marshaled envelope here.
const PeeringPath = "/peering/v1/deliver"

// contentTypePeerEnvelope is the media type for a marshaled VULOS-PEER/1 wire
// blob (an opaque, encrypted, authenticated envelope — the carrier neither
// reads nor adds confidentiality).
const contentTypePeerEnvelope = "application/vulos-peer-envelope"

// HTTPTransport is a real, cross-process PeerTransport (spec §2): it carries a
// marshaled envelope to a peer relay by POSTing it to that peer's peering
// ingress endpoint. It performs NO public DNS MX lookup and NO blocklist
// exposure — the endpoint comes from the resolved peer descriptor, and the
// envelope is end-to-end authenticated and encrypted, so the carrier provides
// neither confidentiality nor authenticity of its own.
//
// HTTPTransport is safe for concurrent use.
type HTTPTransport struct {
	// Client is the HTTP client used for delivery. If nil a default client with
	// a bounded timeout is used. Operators wire a TLS-enforcing client here for
	// transport-level privacy; confidentiality of the mail does NOT depend on it.
	Client *http.Client

	// UserAgent is sent on each request. Defaults to "vulos-relay-peer".
	UserAgent string
}

// NewHTTPTransport constructs an HTTPTransport with a sane default client.
func NewHTTPTransport() *HTTPTransport {
	return &HTTPTransport{
		Client:    &http.Client{Timeout: 30 * time.Second},
		UserAgent: "vulos-relay-peer",
	}
}

// Deliver implements PeerTransport: it POSTs wire to the peer's ingress URL.
//
// endpoint is the carrier address from the resolved descriptor. It may be a
// full URL (https://peer.example/peering/v1/deliver) or a bare authority
// (peer.example:8443), in which case the default scheme (https) and the
// canonical PeeringPath are applied.
//
// A 2xx response means the receiver accepted the envelope. A permanent
// receiver rejection (4xx with a recognised peering outcome header) is mapped
// back to the matching sentinel so the sender pipeline bounces rather than
// retries (spec §10). Any other non-2xx, or a network failure, is a transient
// handoff error and the caller defers/retries on the peer path.
func (t *HTTPTransport) Deliver(ctx context.Context, endpoint string, wire []byte) error {
	url, err := normalizeEndpoint(endpoint)
	if err != nil {
		return fmt.Errorf("peering: bad endpoint %q: %w", endpoint, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return fmt.Errorf("peering: build request: %w", err)
	}
	req.Header.Set("Content-Type", contentTypePeerEnvelope)
	ua := t.UserAgent
	if ua == "" {
		ua = "vulos-relay-peer"
	}
	req.Header.Set("User-Agent", ua)

	client := t.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		// Network/transport failure → transient; the pipeline retries on the
		// peer path (never silently downgraded to SMTP per spec §10).
		return fmt.Errorf("peering: handoff to %s: %w", url, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	// Map a recognised permanent outcome back to its sentinel so classifyHandoff
	// bounces it. The receiver advertises the outcome in a header so the sender
	// does not have to parse a body.
	if outcome := resp.Header.Get(outcomeHeader); outcome != "" {
		if sentinel := outcomeToError(outcome); sentinel != nil {
			return sentinel
		}
	}
	// 4xx without a recognised outcome is still permanent; 5xx is transient.
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return fmt.Errorf("peering: receiver rejected (%d): %w", resp.StatusCode, ErrCorrupt)
	}
	return fmt.Errorf("peering: receiver returned %d (transient)", resp.StatusCode)
}

// outcomeHeader carries the machine-readable receiver outcome on a rejection so
// the sender can classify permanent vs. transient without a body parse.
const outcomeHeader = "X-Vulos-Peer-Outcome"

// outcomeToError maps a receiver outcome string to the matching sentinel error,
// or nil if it is unknown / transient.
func outcomeToError(outcome string) error {
	switch outcome {
	case "unauthenticated":
		return ErrUnauthenticated
	case "unauthorized":
		return ErrUnauthorized
	case "misrouted":
		return ErrMisrouted
	case "replay":
		return ErrReplay
	case "unsupported":
		return ErrUnsupported
	case "corrupt":
		return ErrCorrupt
	default:
		return nil
	}
}

// errorToOutcome maps a sentinel error to its receiver outcome string for the
// ingress side to advertise on a rejection.
func errorToOutcome(err error) (string, bool) {
	switch {
	case errors.Is(err, ErrUnauthenticated):
		return "unauthenticated", true
	case errors.Is(err, ErrUnauthorized):
		return "unauthorized", true
	case errors.Is(err, ErrMisrouted):
		return "misrouted", true
	case errors.Is(err, ErrReplay):
		return "replay", true
	case errors.Is(err, ErrUnsupported):
		return "unsupported", true
	case errors.Is(err, ErrCorrupt):
		return "corrupt", true
	default:
		return "", false
	}
}

// normalizeEndpoint turns a descriptor endpoint into a delivery URL. Accepts a
// full http(s) URL (used verbatim), or a bare host[:port] (https + the
// canonical PeeringPath are applied). It rejects an empty endpoint.
func normalizeEndpoint(endpoint string) (string, error) {
	e := strings.TrimSpace(endpoint)
	if e == "" {
		return "", errors.New("empty endpoint")
	}
	if strings.HasPrefix(e, "http://") || strings.HasPrefix(e, "https://") {
		// If the operator gave only an authority with a scheme, append the path.
		if !strings.Contains(strings.TrimPrefix(strings.TrimPrefix(e, "http://"), "https://"), "/") {
			return strings.TrimRight(e, "/") + PeeringPath, nil
		}
		return e, nil
	}
	// Bare authority: default to HTTPS and the canonical path.
	return "https://" + strings.TrimRight(e, "/") + PeeringPath, nil
}
