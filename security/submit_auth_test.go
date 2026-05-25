// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package security_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/relay"
)

// ─── Attack class 1: open-relay / submission auth ────────────────────────────
//
// The frozen invariant is: the relay NEVER forwards mail for an unauthenticated
// or unknown sender. These tests drive the real relay.SubmitHandler over
// httptest the way a client (or attacker) would, and prove the auth gate cannot
// be bypassed and never enqueues an unauthenticated message.

// countingQueue is an in-memory MessageEnqueuer. enqueued() is the canary: it
// MUST stay 0 across every rejected-submission attack.
type countingQueue struct {
	mu  sync.Mutex
	n   int
	ids []string
}

func (q *countingQueue) Enqueue(_ context.Context, m relay.EnqueuedMessage) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.n++
	q.ids = append(q.ids, m.ID)
	return nil
}

func (q *countingQueue) Depth(context.Context) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.n
}

func (q *countingQueue) enqueued() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.n
}

// submitRig is the production submission surface under attack.
type submitRig struct {
	handler *relay.SubmitHandler
	queue   *countingQueue
	secret  []byte
	account string
	now     time.Time
}

func newSubmitRig(t *testing.T, perIPLimit int) *submitRig {
	t.Helper()
	reg := relay.NewMemAccountRegistry()
	secret := []byte("pentest-account-secret")
	account := "tenant-1"
	reg.Register(relay.AccountRecord{AccountID: account, SharedSecret: secret})

	auth := relay.NewSharedSecretAuth(reg)
	now := time.Unix(1_800_000_000, 0)
	auth.SetClock(func() time.Time { return now })

	q := &countingQueue{}
	h := relay.NewSubmitHandler(relay.SubmitHandlerConfig{
		Authenticator: auth,
		Router:        relay.NewRouter(relay.RouterConfig{MaxMessageBytes: 1 << 20}),
		Queue:         q,
		PerIPLimit:    perIPLimit,
		Now:           func() time.Time { return now },
		IDGen:         func() string { return "id-fixed" },
	})
	return &submitRig{handler: h, queue: q, secret: secret, account: account, now: now}
}

func (r *submitRig) authHeader(messageID string) string {
	tok := relay.ComputeHMACToken(r.secret, r.account, messageID, r.now.Unix())
	return fmt.Sprintf("VulosShared %s:%s:%d:%s", tok.AccountID, tok.MessageID, tok.Timestamp, tok.Signature)
}

func submitBody() string {
	b, _ := json.Marshal(map[string]any{
		"from": "alice@tenant.example",
		"to":   []string{"bob@elsewhere.example"},
		"raw":  []byte("Subject: x\r\n\r\nhi"),
	})
	return string(b)
}

func (r *submitRig) post(t *testing.T, authHeader, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(submitBody()))
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	return rec
}

func errCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var er struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &er)
	return er.Code
}

// ATTACK: submit with NO credentials. EXPECT: 401, nothing enqueued.
func TestSubmit_NoCredentials_Rejected(t *testing.T) {
	r := newSubmitRig(t, -1)
	rec := r.post(t, "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	if r.queue.enqueued() != 0 {
		t.Fatal("VULN: unauthenticated submission was enqueued (open relay)")
	}
}

// ATTACK: forge an HMAC for a known account using a GUESSED/wrong secret.
// EXPECT: 401 invalid_signature, nothing enqueued.
func TestSubmit_ForgedHMAC_Rejected(t *testing.T) {
	r := newSubmitRig(t, -1)
	// Mint with the WRONG secret — the gate must reject it.
	tok := relay.ComputeHMACToken([]byte("attacker-guess"), r.account, "m1", r.now.Unix())
	hdr := fmt.Sprintf("VulosShared %s:%s:%d:%s", tok.AccountID, tok.MessageID, tok.Timestamp, tok.Signature)
	rec := r.post(t, hdr, "")
	if rec.Code != http.StatusUnauthorized || errCode(t, rec) != "invalid_signature" {
		t.Fatalf("want 401/invalid_signature, got %d/%q", rec.Code, errCode(t, rec))
	}
	if r.queue.enqueued() != 0 {
		t.Fatal("VULN: forged-HMAC submission was enqueued")
	}
}

// ATTACK: claim to be an account that does not exist. EXPECT: 401, nothing
// enqueued (no oracle that leaks account existence beyond the generic 401).
func TestSubmit_UnknownAccount_Rejected(t *testing.T) {
	r := newSubmitRig(t, -1)
	tok := relay.ComputeHMACToken([]byte("whatever"), "ghost-account", "m1", r.now.Unix())
	hdr := fmt.Sprintf("VulosShared %s:%s:%d:%s", tok.AccountID, tok.MessageID, tok.Timestamp, tok.Signature)
	rec := r.post(t, hdr, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	if r.queue.enqueued() != 0 {
		t.Fatal("VULN: submission for an unknown account was enqueued")
	}
}

// ATTACK: replay a captured, previously-valid Authorization header. EXPECT: the
// first succeeds (202) but the replay is rejected (401 replay_detected), so a
// captured credential cannot be reused.
func TestSubmit_ReplayedCredential_Rejected(t *testing.T) {
	r := newSubmitRig(t, -1)
	hdr := r.authHeader("m-replay")
	if rec := r.post(t, hdr, ""); rec.Code != http.StatusAccepted {
		t.Fatalf("first submit should be 202, got %d", rec.Code)
	}
	rec := r.post(t, hdr, "")
	if rec.Code != http.StatusUnauthorized || errCode(t, rec) != "replay_detected" {
		t.Fatalf("replay: want 401/replay_detected, got %d/%q", rec.Code, errCode(t, rec))
	}
	if r.queue.enqueued() != 1 {
		t.Fatalf("VULN: credential replay caused %d enqueues, want exactly 1", r.queue.enqueued())
	}
}

// ATTACK: present a credential whose timestamp is far outside the allowed skew
// (a stale captured token). EXPECT: 401 expired, nothing enqueued.
func TestSubmit_ExpiredCredential_Rejected(t *testing.T) {
	r := newSubmitRig(t, -1)
	staleTs := r.now.Add(-1 * time.Hour).Unix()
	tok := relay.ComputeHMACToken(r.secret, r.account, "m-stale", staleTs)
	hdr := fmt.Sprintf("VulosShared %s:%s:%d:%s", tok.AccountID, tok.MessageID, tok.Timestamp, tok.Signature)
	rec := r.post(t, hdr, "")
	if rec.Code != http.StatusUnauthorized || errCode(t, rec) != "expired" {
		t.Fatalf("want 401/expired, got %d/%q", rec.Code, errCode(t, rec))
	}
	if r.queue.enqueued() != 0 {
		t.Fatal("VULN: stale (expired) credential was accepted")
	}
}

// ATTACK: try to slip past the gate with a malformed Authorization scheme
// (e.g. Basic / Bearer) or a malformed VulosShared structure. EXPECT: 401,
// nothing enqueued — the gate accepts ONLY a well-formed VulosShared credential.
func TestSubmit_MalformedAuthScheme_Rejected(t *testing.T) {
	r := newSubmitRig(t, -1)
	for _, hdr := range []string{
		"Basic dXNlcjpwYXNz",
		"Bearer some.jwt.token",
		"VulosShared not-enough-fields",
		"VulosShared a::ts:sig",          // empty field
		"VulosShared a:m:notanint:sig",   // non-integer ts
		"VulosShared " + r.account + ":", // truncated
	} {
		rec := r.post(t, hdr, "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("malformed auth %q: want 401, got %d", hdr, rec.Code)
		}
	}
	if r.queue.enqueued() != 0 {
		t.Fatal("VULN: a malformed Authorization header bypassed the gate")
	}
}

// ATTACK: hit the wrong path / method to see if some other route silently
// enqueues. EXPECT: 404/405, nothing enqueued, the auth gate is never skipped.
func TestSubmit_WrongPathOrMethod_NeverEnqueues(t *testing.T) {
	r := newSubmitRig(t, -1)
	// GET /submit
	getReq := httptest.NewRequest(http.MethodGet, "/submit", nil)
	getRec := httptest.NewRecorder()
	r.handler.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /submit: want 405, got %d", getRec.Code)
	}
	// POST /admin (unknown path)
	pReq := httptest.NewRequest(http.MethodPost, "/admin", strings.NewReader(submitBody()))
	pRec := httptest.NewRecorder()
	r.handler.ServeHTTP(pRec, pReq)
	if pRec.Code != http.StatusNotFound {
		t.Fatalf("POST /admin: want 404, got %d", pRec.Code)
	}
	if r.queue.enqueued() != 0 {
		t.Fatal("VULN: a non-/submit-POST route enqueued a message")
	}
}

// sanity: a correctly-authenticated submission IS accepted, proving the gate is
// not a broken always-reject.
func TestSubmit_ValidCredential_Accepted(t *testing.T) {
	r := newSubmitRig(t, -1)
	rec := r.post(t, r.authHeader("m-ok"), "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("valid submit: want 202, got %d body=%s", rec.Code, rec.Body.String())
	}
	if r.queue.enqueued() != 1 {
		t.Fatalf("valid submit should enqueue exactly once, got %d", r.queue.enqueued())
	}
}
