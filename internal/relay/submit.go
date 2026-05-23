// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

// Submission HTTP listener (RELAY-16 enforcement).
//
// This file wires SubmitAuthenticator and Router into a real HTTP endpoint
// that callers POST messages to. Without this listener the daemon would
// silently accept any locally-enqueued message and forward it — violating the
// frozen invariant "The relay NEVER forwards mail for an unauthenticated /
// unknown sender."
package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ─── Queue enqueuer seam ──────────────────────────────────────────────────────

// MessageEnqueuer is the minimal seam the submission listener needs from a
// queue backend. Both MemQueue and FSQueue implement compatible Enqueue
// methods (with slightly different signatures); to keep this package free of
// import cycles we define a tiny shim. The cmd/relay wiring adapts whichever
// concrete queue is in use to this interface.
type MessageEnqueuer interface {
	// Enqueue adds a message for outbound delivery. Implementations should
	// return a non-nil error to signal that the message could not be persisted.
	Enqueue(ctx context.Context, m EnqueuedMessage) error

	// Depth returns the current queue depth (best-effort, advisory). It is
	// reported back to the caller in the 202 response as queue_position.
	Depth(ctx context.Context) int
}

// EnqueuedMessage is the wire shape used between the submission listener and
// the queue. It mirrors queue.OutboundMessage but lives here to keep the
// relay package free of a queue dependency.
type EnqueuedMessage struct {
	ID         string
	AccountID  string
	Sender     string
	Recipients []string
	RawRFC822  []byte
	Metadata   map[string]string
}

// ─── HTTP error response shape ────────────────────────────────────────────────

// errorCode is the stable machine-readable identifier returned in the
// JSON body of a non-2xx submission response.
type errorCode string

const (
	codeUnauthenticated   errorCode = "unauthenticated"
	codeUnknownAccount    errorCode = "unknown_account"
	codeInvalidSignature  errorCode = "invalid_signature"
	codeExpired           errorCode = "expired"
	codeReplayDetected    errorCode = "replay_detected"
	codeInvalidRequest    errorCode = "invalid_request"
	codeRejectedByRouter  errorCode = "rejected_by_router"
	codePayloadTooLarge   errorCode = "payload_too_large"
	codeInternal          errorCode = "internal_error"
	codeMethodNotAllowed  errorCode = "method_not_allowed"
)

type errorBody struct {
	Code    errorCode `json:"code"`
	Message string    `json:"message"`
}

// acceptedBody is the 202 response payload.
type acceptedBody struct {
	MessageID     string `json:"message_id"`
	AccountID     string `json:"account_id"`
	QueuePosition int    `json:"queue_position"`
}

// ─── SubmitHandler ────────────────────────────────────────────────────────────

// SubmitHandlerConfig configures a SubmitHandler.
type SubmitHandlerConfig struct {
	// Authenticator is the open-relay prevention gate. REQUIRED.
	Authenticator SubmitAuthenticator

	// Router validates structural and authorization properties of the message
	// before enqueue. REQUIRED.
	Router *Router

	// Queue is the destination for accepted messages. REQUIRED.
	Queue MessageEnqueuer

	// MaxBodyBytes caps the size of an inbound request body. 0 = use default
	// (16 MiB).
	MaxBodyBytes int64

	// Now is overridable for tests; defaults to time.Now.
	Now func() time.Time

	// IDGen generates a unique message ID when the caller does not provide
	// one. Defaults to a 128-bit hex random value.
	IDGen func() string
}

// SubmitHandler is the http.Handler for POST /submit.
type SubmitHandler struct {
	cfg SubmitHandlerConfig
}

// NewSubmitHandler returns a SubmitHandler. It panics if any of the required
// fields in cfg are nil — wiring this incorrectly is a programmer error and
// must not silently fall through to an open-relay state.
func NewSubmitHandler(cfg SubmitHandlerConfig) *SubmitHandler {
	if cfg.Authenticator == nil {
		panic("relay: SubmitHandler requires a SubmitAuthenticator (open-relay gate must not be nil)")
	}
	if cfg.Router == nil {
		panic("relay: SubmitHandler requires a Router")
	}
	if cfg.Queue == nil {
		panic("relay: SubmitHandler requires a MessageEnqueuer")
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 16 << 20 // 16 MiB default
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.IDGen == nil {
		cfg.IDGen = defaultIDGen
	}
	return &SubmitHandler{cfg: cfg}
}

// ServeHTTP implements http.Handler. Only POST /submit is accepted; every
// other path/method returns 405 or 404 without invoking the authenticator.
func (h *SubmitHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/submit" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, codeMethodNotAllowed, "only POST is accepted")
		return
	}

	// 1. Extract credentials.
	creds, err := extractCredentials(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, codeUnauthenticated, err.Error())
		return
	}

	// 2. Authenticate (open-relay gate).
	ctx := r.Context()
	accountID, authErr := h.cfg.Authenticator.Authenticate(ctx, creds)
	if authErr != nil {
		status, code := classifyAuthError(authErr)
		writeError(w, status, code, authErr.Error())
		return
	}

	// 3. Parse outbound message from request body.
	body, readErr := io.ReadAll(io.LimitReader(r.Body, h.cfg.MaxBodyBytes+1))
	if readErr != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "read body: "+readErr.Error())
		return
	}
	if int64(len(body)) > h.cfg.MaxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, codePayloadTooLarge,
			fmt.Sprintf("body exceeds %d bytes", h.cfg.MaxBodyBytes))
		return
	}

	sub, parseErr := parseSubmission(r.Header.Get("Content-Type"), body)
	if parseErr != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, parseErr.Error())
		return
	}

	// 4. Build OutboundMessage and ask the router.
	out := OutboundMessage{
		AccountID:         accountID,
		From:              sub.From,
		To:                sub.To,
		RawRFC822:         sub.Raw,
		AuthorizedDomains: nil, // operator-injected registries can extend this later
	}
	if routerErr := h.cfg.Router.AcceptOutbound(ctx, out); routerErr != nil {
		writeError(w, http.StatusBadRequest, codeRejectedByRouter, routerErr.Error())
		return
	}

	// 5. Enqueue.
	msgID := sub.MessageID
	if msgID == "" {
		msgID = h.cfg.IDGen()
	}
	enq := EnqueuedMessage{
		ID:         msgID,
		AccountID:  accountID,
		Sender:     sub.From,
		Recipients: sub.To,
		RawRFC822:  sub.Raw,
		Metadata: map[string]string{
			"submitted_at": h.cfg.Now().UTC().Format(time.RFC3339Nano),
		},
	}
	if err := h.cfg.Queue.Enqueue(ctx, enq); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "enqueue: "+err.Error())
		return
	}

	// 6. 202 Accepted.
	resp := acceptedBody{
		MessageID:     msgID,
		AccountID:     accountID,
		QueuePosition: h.cfg.Queue.Depth(ctx),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(resp)
}

// ─── Credential extraction ────────────────────────────────────────────────────

// extractCredentials pulls credentials from either the Authorization header
// (SharedSecretAuth) or the TLS connection state (MutualTLSAuth). An
// Authorization header takes precedence if both are present.
func extractCredentials(r *http.Request) (Credentials, error) {
	if h := r.Header.Get("Authorization"); h != "" {
		tok, err := parseSharedAuth(h)
		if err != nil {
			return Credentials{}, err
		}
		return Credentials{HMACToken: tok}, nil
	}
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
		state := r.TLS // capture
		return Credentials{TLSState: state}, nil
	}
	return Credentials{}, errors.New("no Authorization header and no verified TLS client certificate")
}

// parseSharedAuth parses a header of the form:
//
//	VulosShared <account>:<message_id>:<ts>:<hmac-hex>
//
// The trailing fields after "VulosShared " are joined by ':' to preserve
// account IDs that themselves contain dashes etc., but the message ID,
// timestamp and signature segments must each be non-empty.
func parseSharedAuth(h string) (*HMACToken, error) {
	const prefix = "VulosShared "
	if !strings.HasPrefix(h, prefix) {
		return nil, errors.New("Authorization scheme must be VulosShared")
	}
	rest := strings.TrimSpace(h[len(prefix):])
	parts := strings.Split(rest, ":")
	if len(parts) != 4 {
		return nil, fmt.Errorf("VulosShared expects 4 fields (account:message_id:ts:sig), got %d", len(parts))
	}
	account := strings.TrimSpace(parts[0])
	messageID := strings.TrimSpace(parts[1])
	tsStr := strings.TrimSpace(parts[2])
	sig := strings.TrimSpace(parts[3])
	if account == "" || messageID == "" || tsStr == "" || sig == "" {
		return nil, errors.New("VulosShared credential has an empty field")
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("VulosShared timestamp not an integer: %v", err)
	}
	return &HMACToken{
		AccountID: account,
		MessageID: messageID,
		Timestamp: ts,
		Signature: sig,
	}, nil
}

// ─── Submission body parsing ──────────────────────────────────────────────────

type submission struct {
	MessageID string
	From      string
	To        []string
	Raw       []byte
}

// jsonSubmission is the JSON request shape.
type jsonSubmission struct {
	MessageID string   `json:"message_id,omitempty"`
	From      string   `json:"from"`
	To        []string `json:"to"`
	Raw       []byte   `json:"raw"` // base64 in JSON
}

// parseSubmission accepts either application/json or
// application/octet-stream (with envelope headers in X-Vulos-From /
// X-Vulos-To). Multipart is intentionally not parsed by hand; JSON is the
// canonical and well-tested wire shape.
func parseSubmission(contentType string, body []byte) (submission, error) {
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	switch ct {
	case "application/json", "":
		var js jsonSubmission
		if err := json.Unmarshal(body, &js); err != nil {
			return submission{}, fmt.Errorf("invalid JSON body: %v", err)
		}
		if js.From == "" || len(js.To) == 0 || len(js.Raw) == 0 {
			return submission{}, errors.New("JSON body must include from, to[], and raw")
		}
		return submission{
			MessageID: js.MessageID,
			From:      js.From,
			To:        js.To,
			Raw:       js.Raw,
		}, nil
	default:
		return submission{}, fmt.Errorf("unsupported Content-Type %q (use application/json)", contentType)
	}
}

// ─── Error classification ─────────────────────────────────────────────────────

// classifyAuthError maps an authenticator error to the appropriate HTTP
// status and machine-readable code.
func classifyAuthError(err error) (int, errorCode) {
	switch {
	case errors.Is(err, ErrInvalidSignature):
		return http.StatusUnauthorized, codeInvalidSignature
	case errors.Is(err, ErrCredentialExpired):
		return http.StatusUnauthorized, codeExpired
	case errors.Is(err, ErrReplayDetected):
		return http.StatusUnauthorized, codeReplayDetected
	case errors.Is(err, ErrUnauthenticated):
		// Distinguish "no token" vs "unknown account" by message substring;
		// both still 401 — the code just hints at the failure mode.
		if strings.Contains(err.Error(), "account not found") {
			return http.StatusUnauthorized, codeUnknownAccount
		}
		return http.StatusUnauthorized, codeUnauthenticated
	default:
		return http.StatusUnauthorized, codeUnauthenticated
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func writeError(w http.ResponseWriter, status int, code errorCode, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Code: code, Message: msg})
}

func defaultIDGen() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Fall back to a timestamp-only ID; collisions are extremely unlikely
		// for self-host scale and the queue will surface duplicates if any.
		return fmt.Sprintf("ts-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf[:])
}
