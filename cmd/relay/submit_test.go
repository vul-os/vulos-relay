// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/queue"
	"github.com/vul-os/vulos-relay/internal/relay"
)

// submitTestRig constructs a SubmitHandler wired to a MemQueue and an
// in-memory account registry seeded with a single test account. It is used by
// the proofs below to drive the listener as a real http.Handler without
// binding a TCP port.
type submitTestRig struct {
	auth    *relay.SharedSecretAuth
	router  *relay.Router
	queue   *queue.MemQueue
	enq     *queueEnqueuerAdapter
	handler *relay.SubmitHandler
	now     time.Time
	secret  []byte
	account string
}

func newSubmitTestRig(t *testing.T) *submitTestRig {
	t.Helper()
	reg := relay.NewMemAccountRegistry()
	secret := []byte("submit-test-secret")
	account := "submit-acct-1"
	reg.Register(relay.AccountRecord{
		AccountID:    account,
		SharedSecret: secret,
	})
	auth := relay.NewSharedSecretAuth(reg)
	now := time.Unix(1_800_000_000, 0)
	auth.SetClock(func() time.Time { return now })

	router := relay.NewRouter(relay.RouterConfig{MaxMessageBytes: 1 << 20})
	q := queue.NewMemQueue()
	enq, err := newQueueEnqueuerAdapter(q)
	if err != nil {
		t.Fatalf("newQueueEnqueuerAdapter: %v", err)
	}

	h := relay.NewSubmitHandler(relay.SubmitHandlerConfig{
		Authenticator: auth,
		Router:        router,
		Queue:         enq,
		Now:           func() time.Time { return now },
		IDGen:         func() string { return "fixed-test-id" },
	})

	return &submitTestRig{
		auth:    auth,
		router:  router,
		queue:   q,
		enq:     enq,
		handler: h,
		now:     now,
		secret:  secret,
		account: account,
	}
}

// authHeader returns an Authorization header for the given message ID,
// minted with the rig's secret and clock.
func (r *submitTestRig) authHeader(messageID string) string {
	tok := relay.ComputeHMACToken(r.secret, r.account, messageID, r.now.Unix())
	return fmt.Sprintf("VulosShared %s:%s:%d:%s",
		tok.AccountID, tok.MessageID, tok.Timestamp, tok.Signature)
}

func validBody(t *testing.T) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{
		"from": "sender@example.com",
		"to":   []string{"rcpt@example.org"},
		"raw":  []byte("Subject: hi\r\n\r\nhello"),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return body
}

func doSubmit(t *testing.T, h http.Handler, header, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(body))
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeError(t *testing.T, body []byte) (string, string) {
	t.Helper()
	var er struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &er); err != nil {
		t.Fatalf("decode error body %q: %v", string(body), err)
	}
	return er.Code, er.Message
}

// ─── Proof 1: Unauthenticated request → 401 unauthenticated ──────────────────

func TestSubmit_Unauthenticated_Returns401Unauthenticated(t *testing.T) {
	rig := newSubmitTestRig(t)
	rec := doSubmit(t, rig.handler, "", string(validBody(t)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: want 401, got %d", rec.Code)
	}
	code, _ := decodeError(t, rec.Body.Bytes())
	if code != "unauthenticated" {
		t.Errorf("code: want unauthenticated, got %q", code)
	}
	// Queue must remain empty — the open-relay gate refused.
	if _, err := rig.queue.Lease(context.Background(), 10); err != queue.ErrEmpty {
		t.Errorf("queue must be empty after unauth refusal, got err=%v", err)
	}
}

// ─── Proof 2: Wrong HMAC → 401 invalid_signature ─────────────────────────────

func TestSubmit_WrongHMAC_Returns401InvalidSignature(t *testing.T) {
	rig := newSubmitTestRig(t)
	// Mint a valid token then corrupt the signature.
	header := rig.authHeader("msg-bad-sig")
	bad := header[:len(header)-2] + "00" // flip last byte of hex sig
	rec := doSubmit(t, rig.handler, bad, string(validBody(t)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: want 401, got %d body=%s", rec.Code, rec.Body.String())
	}
	code, _ := decodeError(t, rec.Body.Bytes())
	if code != "invalid_signature" {
		t.Errorf("code: want invalid_signature, got %q", code)
	}
	if _, err := rig.queue.Lease(context.Background(), 10); err != queue.ErrEmpty {
		t.Errorf("queue must remain empty after bad-sig refusal, got err=%v", err)
	}
}

// ─── Proof 3: Replayed nonce → 401 replay_detected ───────────────────────────

func TestSubmit_ReplayedNonce_Returns401ReplayDetected(t *testing.T) {
	rig := newSubmitTestRig(t)
	header := rig.authHeader("msg-replay-1")

	// First submission succeeds.
	rec1 := doSubmit(t, rig.handler, header, string(validBody(t)))
	if rec1.Code != http.StatusAccepted {
		t.Fatalf("first submit: want 202, got %d body=%s", rec1.Code, rec1.Body.String())
	}

	// Second submission with the exact same nonce must be refused as a replay.
	rec2 := doSubmit(t, rig.handler, header, string(validBody(t)))
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("replay: want 401, got %d body=%s", rec2.Code, rec2.Body.String())
	}
	code, _ := decodeError(t, rec2.Body.Bytes())
	if code != "replay_detected" {
		t.Errorf("code: want replay_detected, got %q", code)
	}
}

// ─── Proof 4: Authentic request → 202 + message enqueued ─────────────────────

func TestSubmit_Authentic_Returns202AndEnqueues(t *testing.T) {
	rig := newSubmitTestRig(t)
	header := rig.authHeader("msg-ok-1")

	rec := doSubmit(t, rig.handler, header, string(validBody(t)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: want 202, got %d body=%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		MessageID     string `json:"message_id"`
		AccountID     string `json:"account_id"`
		QueuePosition int    `json:"queue_position"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode 202 body: %v", err)
	}
	if resp.MessageID != "fixed-test-id" {
		t.Errorf("message_id: want fixed-test-id, got %q", resp.MessageID)
	}
	if resp.AccountID != rig.account {
		t.Errorf("account_id: want %q, got %q", rig.account, resp.AccountID)
	}
	if resp.QueuePosition != 1 {
		t.Errorf("queue_position: want 1, got %d", resp.QueuePosition)
	}

	// Verify the message is actually in the queue.
	leased, err := rig.queue.Lease(context.Background(), 10)
	if err != nil {
		t.Fatalf("Lease after submit: %v", err)
	}
	if len(leased) != 1 {
		t.Fatalf("expected 1 leased message, got %d", len(leased))
	}
	got := leased[0].OutboundMessage
	if got.ID != "fixed-test-id" {
		t.Errorf("queued ID: want fixed-test-id, got %q", got.ID)
	}
	if got.AccountID != rig.account {
		t.Errorf("queued AccountID: want %q, got %q", rig.account, got.AccountID)
	}
	if got.Sender != "sender@example.com" {
		t.Errorf("queued Sender: want sender@example.com, got %q", got.Sender)
	}
	if len(got.Recipients) != 1 || got.Recipients[0] != "rcpt@example.org" {
		t.Errorf("queued Recipients: want [rcpt@example.org], got %v", got.Recipients)
	}
	if !bytes.Contains(got.RawRFC822, []byte("hello")) {
		t.Errorf("queued RawRFC822 missing body: %q", string(got.RawRFC822))
	}
}

// ─── Proof: per-IP rate cap rejects a flood from one source ──────────────────

func TestSubmit_PerIPRateCap_RejectsFlood(t *testing.T) {
	reg := relay.NewMemAccountRegistry()
	reg.Register(relay.AccountRecord{AccountID: "acct", SharedSecret: []byte("x")})
	auth := relay.NewSharedSecretAuth(reg)
	router := relay.NewRouter(relay.RouterConfig{})
	q := queue.NewMemQueue()
	enq, err := newQueueEnqueuerAdapter(q)
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}

	// Cap of 3 requests/min from any single IP, enforced before auth.
	h := relay.NewSubmitHandler(relay.SubmitHandlerConfig{
		Authenticator: auth,
		Router:        router,
		Queue:         enq,
		PerIPLimit:    3,
	})

	do := func() int {
		req := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(string(validBody(t))))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "198.51.100.7:5555" // same source IP for all
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// First 3 (unauthenticated) requests are allowed past the limiter (and then
	// rejected as 401 by the auth gate). The 4th must be 429 from the limiter.
	for i := 0; i < 3; i++ {
		if code := do(); code == http.StatusTooManyRequests {
			t.Fatalf("request %d hit the cap too early (got 429)", i+1)
		}
	}
	if code := do(); code != http.StatusTooManyRequests {
		t.Fatalf("4th request from same IP: want 429, got %d", code)
	}

	// A DIFFERENT IP is unaffected by the first IP's window.
	req := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(string(validBody(t))))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.9:6666"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusTooManyRequests {
		t.Fatalf("a different IP must not be rate-limited by another IP's window, got 429")
	}
}

// ─── Proof 5: RELAY_SUBMIT_DISABLE=1 → no listener bound ─────────────────────

func TestSubmit_DisabledViaEnv_NoListenerBound(t *testing.T) {
	// Pick a free port up-front so we can prove nothing is listening on it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("temp listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close temp listener: %v", err)
	}

	cfg := config{
		SubmitAddr:     addr,
		SubmitDisabled: true,
	}

	// Build the smallest plausible auth/router/queue trio.
	reg := relay.NewMemAccountRegistry()
	auth := relay.NewSharedSecretAuth(reg)
	router := relay.NewRouter(relay.RouterConfig{})
	q := queue.NewMemQueue()

	srv, err := startSubmitListener(cfg, auth, router, q, nil, nil)
	if err != nil {
		t.Fatalf("startSubmitListener: %v", err)
	}
	if srv != nil {
		_ = srv.Shutdown(context.Background())
		t.Fatalf("expected nil http.Server when disabled, got %T", srv)
	}

	// Confirm nothing is listening on the chosen port. A short Dial timeout
	// keeps the test fast on hosts that don't reset connections promptly.
	conn, dialErr := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		t.Fatalf("expected no listener on %s, but Dial succeeded", addr)
	}
}

// ─── Proof 6: Enabled listener actually serves and refuses unauth over TCP ───

func TestSubmit_EnabledViaConfig_TCPListenerRefusesUnauth(t *testing.T) {
	// Bind to an OS-assigned port up-front so the test knows the address.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()

	cfg := config{
		SubmitAddr:     addr,
		SubmitDisabled: false,
	}
	reg := relay.NewMemAccountRegistry()
	reg.Register(relay.AccountRecord{AccountID: "acct", SharedSecret: []byte("x")})
	auth := relay.NewSharedSecretAuth(reg)
	router := relay.NewRouter(relay.RouterConfig{})
	q := queue.NewMemQueue()

	srv, err := startSubmitListener(cfg, auth, router, q, nil, nil)
	if err != nil {
		t.Fatalf("startSubmitListener: %v", err)
	}
	if srv == nil {
		t.Fatalf("expected non-nil http.Server when enabled")
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()

	// Drive the listener over real TCP with no Authorization header.
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/submit",
		strings.NewReader(string(validBody(t))))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: want 401 over TCP, got %d", resp.StatusCode)
	}
}
