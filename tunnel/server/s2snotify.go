package server

// s2snotify.go — CROSS-INSTANCE NOTIFICATION FORWARDING (MINST-06 / S2S notify).
//
// A Vulos box fans an OS notification out to the account's OTHER online
// instances (multi-device). Local delivery already happened on the origin box;
// this path is the best-effort CROSS-INSTANCE leg. The origin box cannot reach a
// peer box directly (both sit behind NAT), so it POSTs the notification to the
// relay, which forwards it to the peer box over the peer's EXISTING reverse
// tunnel — the same tunnel the peer already holds open for its public traffic.
//
// Wire shape (HTTPS, JSON) on the relay's public listener:
//
//	POST {relay}/api/s2s/notify   → 202 {ok:true}  (forwarded over the tunnel)
//
// Request envelope (from vulos notifyfanout.sendToRelay):
//
//	{
//	  "target_ulid":  "…",          // informational (logging/correlation)
//	  "target":       "peerbox",    // ROUTABLE tunnel name of the destination box
//	  "sender":       "myself",     // origin box's own tunnel name
//	  "notification": { … }         // the BARE payload to forward verbatim
//	}
//
//	Authorization: Bearer <VULOS_RELAY_TOKEN>   // origin box's relay token
//
// AUTH (fail-closed): the bearer token must be authorized (TokenStore.Authorize)
// for the `sender` name — the SAME grant that authorizes the origin box's own
// tunnel. This proves the caller is a legitimate box and resolves its account.
// An unauthorized/missing token is refused (401). This mirrors authorizeSFUHost.
//
// CROSS-TENANT GUARD (fail-closed): on the SHARED cloud relay a token→account
// mapping alone would let account A POST a notification into account B's box (a
// cross-tenant injection). So after resolving the target tunnel session, we
// require it to belong to the SAME account as the authenticated sender. A
// mismatch is refused (403). Unbilled/self-host (accountID "") is single-tenant
// by construction, so a "" sender may only reach a "" target — never a billed
// one, and vice-versa. This is the same one-account-per-name discipline the
// SFU-host registry enforces (P1-2).
//
// SSRF-SAFE BY CONSTRUCTION: the relay never dials an attacker-supplied URL. It
// only ever forwards over an ALREADY-ESTABLISHED yamux tunnel that the target
// box itself opened and authenticated. `target` selects among live tunnels by
// name; it cannot point the relay at an arbitrary host/IP. The forwarded request
// path is a fixed constant (/api/notify/receive), not caller-controlled.
//
// BEST-EFFORT / NON-FATAL: every failure (no such tunnel, target offline, tunnel
// error) returns a small non-2xx the origin box logs and ignores — local
// delivery already occurred. Nothing here can break an existing tunnel or the
// SFU-host registry.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// s2sNotifyPath is the relay-owned cross-instance notify route.
const s2sNotifyPath = "/api/s2s/notify"

// maxS2SNotifyBody bounds the inbound envelope (a notification is tiny).
const maxS2SNotifyBody = 64 << 10 // 64 KiB

// s2sNotifyForwardPath is the FIXED path on the target box the relay forwards to.
// It is a constant — never caller-controlled — so this path cannot be abused to
// reach arbitrary endpoints inside the target box.
const s2sNotifyForwardPath = "/api/notify/receive"

// s2sNotifyEnvelope is the JSON wire shape POSTed to /api/s2s/notify. Notification
// is kept as raw JSON so the relay forwards the BARE object verbatim without
// needing to know its schema (the target box decodes it).
type s2sNotifyEnvelope struct {
	TargetULID   string          `json:"target_ulid"`
	Target       string          `json:"target"`
	Sender       string          `json:"sender"`
	Notification json.RawMessage `json:"notification"`
}

// handleS2SNotify authenticates the origin box, resolves the target tunnel, and
// forwards the bare notification to the target box over its existing tunnel.
func (s *Server) handleS2SNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var env s2sNotifyEnvelope
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxS2SNotifyBody))
	if err := dec.Decode(&env); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	targetName := normalizeName(env.Target)
	if targetName == "" {
		http.Error(w, "target required", http.StatusBadRequest)
		return
	}
	// A missing field decodes to nil; an explicit JSON null decodes to the literal
	// "null". Both mean "no notification to forward" — reject fail-closed.
	if len(bytes.TrimSpace(env.Notification)) == 0 || bytes.Equal(bytes.TrimSpace(env.Notification), []byte("null")) {
		http.Error(w, "notification required", http.StatusBadRequest)
		return
	}

	// AUTH (fail-closed): the bearer must be authorized for the sender's own name.
	senderAccount, ok := s.authorizeS2SSender(w, r, env.Sender)
	if !ok {
		return
	}

	// Resolve the target tunnel. Best-effort: an unknown/offline target is a clean
	// non-2xx the origin box logs and ignores (local delivery already happened).
	sess, ok := s.registry.lookup(targetName)
	if !ok {
		http.Error(w, "target tunnel offline", http.StatusBadGateway)
		return
	}

	// CROSS-TENANT GUARD (fail-closed): the target must belong to the SAME account
	// as the authenticated sender, so account A can never inject a notification
	// into account B's box on the shared relay. Unbilled "" is its own tenant.
	if sess.accountID != senderAccount {
		s.metrics.authFail(authFailUnauthorized)
		s.logInfo("s2s notify cross-account refused", logFields{Name: targetName, Account: senderAccount})
		http.Error(w, "target not permitted for this account", http.StatusForbidden)
		return
	}

	if err := s.forwardS2SNotify(r, sess, env.Notification); err != nil {
		http.Error(w, "forward failed", http.StatusBadGateway)
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

// authorizeS2SSender validates the bearer token against the sender's own tunnel
// name and returns the resolved account ("" = unbilled/self-host). Mirrors
// authorizeSFUHost: same throttle, same fail-closed posture, same grant.
func (s *Server) authorizeS2SSender(w http.ResponseWriter, r *http.Request, sender string) (string, bool) {
	if !s.ctrlLimiter.allow(s.clientIP(r)) {
		s.metrics.rateLimitReject(limitControl)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return "", false
	}
	token := bearer(r)
	if token == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", false
	}
	sn := normalizeName(sender)
	if sn == "" {
		http.Error(w, "invalid sender", http.StatusBadRequest)
		return "", false
	}
	accountID, err := s.cfg.Tokens.Authorize(token, sn)
	if err != nil {
		s.metrics.authFail(authFailUnauthorized)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", false
	}
	if !s.gate.allowConnect(accountID) {
		s.metrics.authFail(authFailEntitlement)
		http.Error(w, "relay not permitted for this account", http.StatusForbidden)
		return "", false
	}
	return accountID, true
}

// forwardS2SNotify opens one yamux stream into the target box and writes a POST
// to the fixed /api/notify/receive path carrying the bare notification, then
// reads (and discards) the response. It reuses the same per-agent stream cap +
// request-timeout discipline the public proxy uses, so a half-dead target cannot
// pin a stream forever. The stream is short-lived (small request, small reply).
func (s *Server) forwardS2SNotify(r *http.Request, sess *session, notification json.RawMessage) error {
	if !sess.acquireStream() {
		return fmt.Errorf("target tunnel busy")
	}
	defer sess.releaseStream()

	stream, err := sess.mux.OpenStream()
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	// Bound time-to-response-headers (mirrors proxy.go): a half-dead agent that
	// never services this stream must not hold it open forever.
	if s.cfg.RequestTimeout > 0 {
		_ = stream.SetDeadline(time.Now().Add(s.cfg.RequestTimeout))
	}

	outReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "http://"+sess.name+s2sNotifyForwardPath, bytes.NewReader(notification))
	if err != nil {
		return err
	}
	outReq.Header.Set("Content-Type", "application/json")
	outReq.Header.Set("X-Vulos-S2S-Notify", "1")
	outReq.ContentLength = int64(len(notification))

	if err := outReq.Write(stream); err != nil {
		return fmt.Errorf("write request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(stream), outReq)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 300 {
		return fmt.Errorf("target returned status %d", resp.StatusCode)
	}
	return nil
}
