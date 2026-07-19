package rendezvous

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// service.go — the HTTP surface that ties announce / resolve / signal / mailbox /
// ice together into one content-blind http.Handler mountable on any relayd (or run
// standalone). See docs/RENDEZVOUS.md for the full wire protocol.
//
// Endpoint map (PathPrefix defaults to "/rendezvous"):
//
//	POST {p}/announce             signed presence upsert            (fail-closed)
//	POST {p}/withdraw             signed presence removal           (fail-closed)
//	GET  {p}/resolve/{key}        public presence read              (open by default)
//	POST {p}/signal/{to}          deposit opaque WebRTC signal      (sender-signed)
//	POST {p}/signal/{key}/poll    pick up signals (long-poll)       (recipient-signed)
//	POST {p}/signal/{key}/ack     delete consumed signals           (recipient-signed)
//	POST {p}/mailbox/{to}         deposit opaque encrypted blob     (sender-signed)
//	POST {p}/mailbox/{key}/poll   pick up blobs (long-poll)         (recipient-signed)
//	POST {p}/mailbox/{key}/ack    delete consumed blobs             (recipient-signed)
//	GET  {p}/ice                  ICE (STUN + ephemeral-cred TURN)  (open)
//	GET  {p}/healthz              liveness                          (open)
//
// AUTH MODEL (fail-closed): every WRITE carries an Ed25519 signature over a
// domain-separated, length-prefixed canonical message plus a fresh timestamp and a
// replay-protected nonce. A deposit is signed by the SENDER (accountability +
// replay protection, never a social-graph gate — the node has no contact store, so
// it is the recipient's client that discards blobs from unknown senders). A poll/ack
// is signed by the RECIPIENT'S key, which proves possession of the matching private
// key and is what authorizes reading that mailbox. Reads of PUBLIC presence and ICE
// are unauthenticated by default (presence is self-signed public data; ICE is just
// STUN URLs + short-lived TURN creds).
//
// SSRF: the node makes NO outbound connection on behalf of any request. Announced
// endpoints are stored and echoed opaquely, never dialed. So the rendezvous role has
// no SSRF surface of its own (unlike the relay's direct-endpoint probe).

// Config configures a rendezvous Service. The zero value (plus applyDefaults) is a
// working self-host node: STUN-only ICE, open resolve, sane caps and limits.
type Config struct {
	// PathPrefix is the mount prefix for all routes. Default "/rendezvous".
	PathPrefix string

	// DisablePublicResolve requires resolve reads to be... (reserved) — by default
	// resolve is an open, unauthenticated read of self-signed public presence. When
	// true, resolve returns 404 for everyone (the directory becomes write-only /
	// signal-only), for a deployment that does not want to expose a presence lookup.
	DisablePublicResolve bool

	// ICE configures the STUN/TURN surface. See ICEConfig.
	ICE ICEConfig

	// ClockSkew is the ± freshness window for signed writes. 0 => 5m.
	ClockSkew time.Duration

	// Rate limits. For each pair, rate<=0 disables that limiter, 0 => a safe default.
	// Writes are keyed: announce by announcing key, deposit by sender key, poll/ack
	// by recipient key. GlobalRate caps the aggregate write rate across all keys.
	AnnounceRate, AnnounceBurst float64
	DepositRate, DepositBurst   float64
	PollRate, PollBurst         float64
	GlobalRate, GlobalBurst     float64
	RateLimitIdleTTL            time.Duration
	RateLimitMaxKeys            int

	// SignalCaps / MailboxCaps override the queue bounds. Any zero field falls back
	// to the built-in default for that queue.
	SignalCaps  queueCaps
	MailboxCaps queueCaps

	// MaxPresenceKeys / MaxQueueKeys bound distinct-key memory. 0 => 100k.
	MaxPresenceKeys int

	// MaxPollWait caps a long-poll's server-side wait. 0 => 30s.
	MaxPollWait time.Duration

	// Logger is the structured logger. nil => slog default.
	Logger *slog.Logger

	// now overrides the clock (tests). nil => time.Now.
	now func() time.Time
}

func defaultSignalCaps() queueCaps {
	return queueCaps{
		MaxBlobBytes:   64 << 10,        // 64 KiB — an SDP + ICE bundle is a few KiB
		MaxPerKeyBlobs: 64,              // plenty of in-flight offer/answer/ICE frames
		MaxPerKeyBytes: 1 << 20,         // 1 MiB
		DefaultTTL:     2 * time.Minute, // a live negotiation is worthless once stale
		MaxTTL:         10 * time.Minute,
		SweepEvery:     30 * time.Second,
	}
}

func defaultMailboxCaps() queueCaps {
	return queueCaps{
		MaxBlobBytes:   25 << 20,  // 25 MiB per blob
		MaxPerKeyBlobs: 256,       // pending blobs per recipient
		MaxPerKeyBytes: 100 << 20, // 100 MiB per recipient
		DefaultTTL:     48 * time.Hour,
		MaxTTL:         48 * time.Hour, // buffer, not archive (DMTAP §14.3)
		SweepEvery:     15 * time.Minute,
	}
}

func mergeCaps(override, def queueCaps) queueCaps {
	out := def
	if override.MaxBlobBytes > 0 {
		out.MaxBlobBytes = override.MaxBlobBytes
	}
	if override.MaxPerKeyBlobs > 0 {
		out.MaxPerKeyBlobs = override.MaxPerKeyBlobs
	}
	if override.MaxPerKeyBytes > 0 {
		out.MaxPerKeyBytes = override.MaxPerKeyBytes
	}
	if override.DefaultTTL > 0 {
		out.DefaultTTL = override.DefaultTTL
	}
	if override.MaxTTL > 0 {
		out.MaxTTL = override.MaxTTL
	}
	if override.MaxKeys > 0 {
		out.MaxKeys = override.MaxKeys
	}
	if override.SweepEvery > 0 {
		out.SweepEvery = override.SweepEvery
	}
	return out
}

// stats are lightweight internal counters exposed via Stats() (tests/observability).
type stats struct {
	announces       atomic.Uint64
	announceRejects atomic.Uint64
	resolves        atomic.Uint64
	signalDeposits  atomic.Uint64
	signalPickups   atomic.Uint64
	mailboxDeposits atomic.Uint64
	mailboxPickups  atomic.Uint64
	authFailures    atomic.Uint64
	rateLimited     atomic.Uint64
}

// Stats is a snapshot of the service counters.
type Stats struct {
	Announces       uint64 `json:"announces"`
	AnnounceRejects uint64 `json:"announce_rejects"`
	Resolves        uint64 `json:"resolves"`
	SignalDeposits  uint64 `json:"signal_deposits"`
	SignalPickups   uint64 `json:"signal_pickups"`
	MailboxDeposits uint64 `json:"mailbox_deposits"`
	MailboxPickups  uint64 `json:"mailbox_pickups"`
	AuthFailures    uint64 `json:"auth_failures"`
	RateLimited     uint64 `json:"rate_limited"`
	LivePresence    int    `json:"live_presence"`
}

// Service is the rendezvous HTTP handler. Construct with New, mount ServeHTTP (or
// Handler()) on any listener, and call Close when done.
type Service struct {
	cfg      Config
	prefix   string
	presence *presenceStore
	signal   *queue
	mailbox  *queue
	replay   *replayGuard
	ice      *iceProvider
	notify   *notifier
	log      *slog.Logger

	announceLim *limiter
	depositLim  *limiter
	pollLim     *limiter
	globalLim   *limiter

	st  stats
	now func() time.Time
}

func limitOr(v, def float64) float64 {
	switch {
	case v < 0:
		return 0 // disabled
	case v == 0:
		return def
	default:
		return v
	}
}

// New builds a rendezvous Service from cfg, applying defaults. It never fails — the
// zero config is a valid self-host node.
func New(cfg Config) *Service {
	prefix := strings.TrimRight(strings.TrimSpace(cfg.PathPrefix), "/")
	if prefix == "" {
		prefix = "/rendezvous"
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	if cfg.MaxPresenceKeys <= 0 {
		cfg.MaxPresenceKeys = 100_000
	}
	if cfg.MaxPollWait <= 0 {
		cfg.MaxPollWait = 30 * time.Second
	}
	if cfg.RateLimitIdleTTL <= 0 {
		cfg.RateLimitIdleTTL = 10 * time.Minute
	}
	if cfg.RateLimitMaxKeys <= 0 {
		cfg.RateLimitMaxKeys = 100_000
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := cfg.now
	if now == nil {
		now = time.Now
	}

	sigCaps := mergeCaps(cfg.SignalCaps, defaultSignalCaps())
	mboxCaps := mergeCaps(cfg.MailboxCaps, defaultMailboxCaps())

	s := &Service{
		cfg:      cfg,
		prefix:   prefix,
		presence: newPresenceStore(cfg.MaxPresenceKeys),
		signal:   newQueue(sigCaps),
		mailbox:  newQueue(mboxCaps),
		replay:   newReplayGuard(cfg.ClockSkew, cfg.RateLimitMaxKeys),
		ice:      newICEProvider(cfg.ICE),
		notify:   newNotifier(),
		log:      logger.With("component", "rendezvous"),
		now:      now,

		announceLim: newLimiter(limitOr(cfg.AnnounceRate, 10), limitOr(cfg.AnnounceBurst, 20), cfg.RateLimitIdleTTL, cfg.RateLimitMaxKeys),
		depositLim:  newLimiter(limitOr(cfg.DepositRate, 30), limitOr(cfg.DepositBurst, 60), cfg.RateLimitIdleTTL, cfg.RateLimitMaxKeys),
		pollLim:     newLimiter(limitOr(cfg.PollRate, 30), limitOr(cfg.PollBurst, 60), cfg.RateLimitIdleTTL, cfg.RateLimitMaxKeys),
		globalLim:   newLimiter(limitOr(cfg.GlobalRate, 2000), limitOr(cfg.GlobalBurst, 4000), cfg.RateLimitIdleTTL, cfg.RateLimitMaxKeys),
	}
	return s
}

// Prefix returns the mount prefix (e.g. "/rendezvous").
func (s *Service) Prefix() string { return s.prefix }

// Close releases resources. Idempotent. (The stores are GC'd; there is no
// background goroutine — sweeps are lazy on access.)
func (s *Service) Close() {}

// Handler returns an http.Handler for the service, with all routes registered under
// the configured prefix.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	p := s.prefix
	mux.HandleFunc("POST "+p+"/announce", s.handleAnnounce)
	mux.HandleFunc("POST "+p+"/withdraw", s.handleWithdraw)
	mux.HandleFunc("GET "+p+"/resolve/{key}", s.handleResolve)

	mux.HandleFunc("POST "+p+"/signal/{to}", s.depositHandler(s.signal, domainSignalDeposit, &s.st.signalDeposits))
	mux.HandleFunc("POST "+p+"/signal/{key}/poll", s.pollHandler(s.signal, domainSignalPoll, &s.st.signalPickups))
	mux.HandleFunc("POST "+p+"/signal/{key}/ack", s.ackHandler(s.signal, domainSignalAck))

	mux.HandleFunc("POST "+p+"/mailbox/{to}", s.depositHandler(s.mailbox, domainMailboxDeposit, &s.st.mailboxDeposits))
	mux.HandleFunc("POST "+p+"/mailbox/{key}/poll", s.pollHandler(s.mailbox, domainMailboxPoll, &s.st.mailboxPickups))
	mux.HandleFunc("POST "+p+"/mailbox/{key}/ack", s.ackHandler(s.mailbox, domainMailboxAck))

	mux.HandleFunc("GET "+p+"/ice", s.handleICE)
	mux.HandleFunc("GET "+p+"/healthz", s.handleHealth)
	return mux
}

// ServeHTTP lets the Service be used directly as an http.Handler.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.Handler().ServeHTTP(w, r)
}

// Stats returns a snapshot of the service counters.
func (s *Service) Stats() Stats {
	return Stats{
		Announces:       s.st.announces.Load(),
		AnnounceRejects: s.st.announceRejects.Load(),
		Resolves:        s.st.resolves.Load(),
		SignalDeposits:  s.st.signalDeposits.Load(),
		SignalPickups:   s.st.signalPickups.Load(),
		MailboxDeposits: s.st.mailboxDeposits.Load(),
		MailboxPickups:  s.st.mailboxPickups.Load(),
		AuthFailures:    s.st.authFailures.Load(),
		RateLimited:     s.st.rateLimited.Load(),
		LivePresence:    s.presence.count(s.now()),
	}
}

// ── canonical domain tags (must match docs/RENDEZVOUS.md and the JS client) ──

const (
	domainAnnounce       = "vulos-rdv/announce/1"
	domainWithdraw       = "vulos-rdv/withdraw/1"
	domainSignalDeposit  = "vulos-rdv/signal-deposit/1"
	domainSignalPoll     = "vulos-rdv/signal-poll/1"
	domainSignalAck      = "vulos-rdv/signal-ack/1"
	domainMailboxDeposit = "vulos-rdv/mailbox-deposit/1"
	domainMailboxPoll    = "vulos-rdv/mailbox-poll/1"
	domainMailboxAck     = "vulos-rdv/mailbox-ack/1"
)

// maxDepositBody bounds a deposit request body: the largest blob (base64url ~1.34x)
// plus JSON envelope headroom. Applied via http.MaxBytesReader before decode.
func (s *Service) maxDepositBody(q *queue) int64 {
	return int64(q.caps.MaxBlobBytes)*2 + (16 << 10)
}

// maxControlBody bounds announce/poll/ack/withdraw bodies (no large payload).
const maxControlBody = 64 << 10 // 64 KiB (announce meta is ≤2 KiB, ack ids bounded)

// ── ANNOUNCE ────────────────────────────────────────────────────────────────

type announceRequest struct {
	Key       string   `json:"key"`
	Endpoints []string `json:"endpoints,omitempty"`
	Meta      string   `json:"meta,omitempty"`
	TTL       int      `json:"ttl,omitempty"`
	Nonce     string   `json:"nonce"`
	Timestamp int64    `json:"ts"`
	Sig       string   `json:"sig"`
}

type announceResponse struct {
	OK        bool   `json:"ok"`
	Key       string `json:"key"`
	TTL       int    `json:"ttl"`
	ExpiresAt int64  `json:"expires_at"`
}

// announceSigningMessage builds the canonical message an announce signature covers.
// Field order: key, ts, ttl, nonce, meta, endpoints... (all as strings). Documented
// in docs/RENDEZVOUS.md and reproduced byte-for-byte by the JS client.
func announceSigningMessage(req *announceRequest) []byte {
	fields := make([]string, 0, 5+len(req.Endpoints))
	fields = append(fields, req.Key, strconv.FormatInt(req.Timestamp, 10), strconv.Itoa(req.TTL), req.Nonce, req.Meta)
	fields = append(fields, req.Endpoints...)
	return canonicalMessage(domainAnnounce, fields...)
}

func (s *Service) handleAnnounce(w http.ResponseWriter, r *http.Request) {
	if !s.globalLim.allow("global") {
		s.st.rateLimited.Add(1)
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	var req announceRequest
	if !s.decodeJSON(w, r, maxControlBody, &req) {
		return
	}
	pub, err := decodeKey(req.Key)
	if err != nil {
		s.st.announceRejects.Add(1)
		writeErr(w, http.StatusBadRequest, "invalid key")
		return
	}
	key := b64.EncodeToString(pub)
	if !s.announceLim.allow(key) {
		s.st.rateLimited.Add(1)
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	now := s.now()
	if err := verifySig(pub, req.Sig, announceSigningMessage(&req)); err != nil {
		s.st.authFailures.Add(1)
		writeErr(w, http.StatusUnauthorized, "signature verification failed")
		return
	}
	if !s.replay.CheckAndRecord(key, req.Nonce, req.Timestamp, now) {
		s.st.announceRejects.Add(1)
		writeErr(w, http.StatusConflict, "stale or replayed request")
		return
	}
	if len(req.Meta) > maxMetaLen {
		writeErr(w, http.StatusRequestEntityTooLarge, "meta too large")
		return
	}
	eps := sanitizeEndpoints(req.Endpoints)
	ttl := clampPresenceTTL(req.TTL)
	exp, ok := s.presence.upsert(key, eps, req.Meta, ttl, now)
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "presence directory at capacity")
		return
	}
	s.st.announces.Add(1)
	s.log.Debug("announce", "key", shortKey(key), "endpoints", len(eps), "ttl_s", int(ttl.Seconds()))
	writeJSON(w, http.StatusOK, announceResponse{OK: true, Key: key, TTL: int(ttl.Seconds()), ExpiresAt: exp.Unix()})
}

// ── WITHDRAW ─────────────────────────────────────────────────────────────────

type withdrawRequest struct {
	Key       string `json:"key"`
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"ts"`
	Sig       string `json:"sig"`
}

func withdrawSigningMessage(req *withdrawRequest) []byte {
	return canonicalMessage(domainWithdraw, req.Key, strconv.FormatInt(req.Timestamp, 10), req.Nonce)
}

func (s *Service) handleWithdraw(w http.ResponseWriter, r *http.Request) {
	var req withdrawRequest
	if !s.decodeJSON(w, r, maxControlBody, &req) {
		return
	}
	pub, err := decodeKey(req.Key)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid key")
		return
	}
	key := b64.EncodeToString(pub)
	now := s.now()
	if err := verifySig(pub, req.Sig, withdrawSigningMessage(&req)); err != nil {
		s.st.authFailures.Add(1)
		writeErr(w, http.StatusUnauthorized, "signature verification failed")
		return
	}
	if !s.replay.CheckAndRecord(key, req.Nonce, req.Timestamp, now) {
		writeErr(w, http.StatusConflict, "stale or replayed request")
		return
	}
	s.presence.remove(key)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "key": key})
}

// ── RESOLVE ──────────────────────────────────────────────────────────────────

type resolveResponse struct {
	Key       string   `json:"key"`
	Online    bool     `json:"online"`
	Endpoints []string `json:"endpoints,omitempty"`
	Meta      string   `json:"meta,omitempty"`
	ExpiresAt int64    `json:"expires_at,omitempty"`
}

func (s *Service) handleResolve(w http.ResponseWriter, r *http.Request) {
	s.st.resolves.Add(1)
	key := normalizeKey(r.PathValue("key"))
	if key == "" {
		writeErr(w, http.StatusBadRequest, "invalid key")
		return
	}
	if s.cfg.DisablePublicResolve {
		// Directory reads disabled: do not confirm or deny presence.
		writeJSON(w, http.StatusNotFound, resolveResponse{Key: key, Online: false})
		return
	}
	eps, meta, exp, ok := s.presence.resolve(key, s.now())
	if !ok {
		writeJSON(w, http.StatusNotFound, resolveResponse{Key: key, Online: false})
		return
	}
	writeJSON(w, http.StatusOK, resolveResponse{
		Key: key, Online: true, Endpoints: eps, Meta: meta, ExpiresAt: exp.Unix(),
	})
}

// ── DEPOSIT (signal + mailbox share this) ────────────────────────────────────

type depositRequest struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Payload   string `json:"payload"` // base64url opaque ciphertext
	TTL       int    `json:"ttl,omitempty"`
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"ts"`
	Sig       string `json:"sig"`
}

type depositResponse struct {
	OK        bool   `json:"ok"`
	ID        string `json:"id"`
	ExpiresAt int64  `json:"expires_at"`
}

func depositSigningMessage(domain string, req *depositRequest) []byte {
	return canonicalMessage(domain,
		req.From, req.To, strconv.FormatInt(req.Timestamp, 10), strconv.Itoa(req.TTL), req.Nonce, req.Payload)
}

func (s *Service) depositHandler(q *queue, domain string, counter *atomic.Uint64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.globalLim.allow("global") {
			s.st.rateLimited.Add(1)
			writeErr(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		var req depositRequest
		if !s.decodeJSON(w, r, s.maxDepositBody(q), &req) {
			return
		}
		// Recipient comes from the path; the body must agree (it is inside the
		// canonical the sender signed, binding the signature to this recipient).
		toPath := normalizeKey(r.PathValue("to"))
		if toPath == "" {
			writeErr(w, http.StatusBadRequest, "invalid recipient key")
			return
		}
		if normalizeKey(req.To) != toPath {
			writeErr(w, http.StatusBadRequest, "recipient mismatch")
			return
		}
		fromPub, err := decodeKey(req.From)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid sender key")
			return
		}
		fromKey := b64.EncodeToString(fromPub)
		if !s.depositLim.allow(fromKey) {
			s.st.rateLimited.Add(1)
			writeErr(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		payload, err := b64.DecodeString(req.Payload)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid payload encoding")
			return
		}
		now := s.now()
		if err := verifySig(fromPub, req.Sig, depositSigningMessage(domain, &req)); err != nil {
			s.st.authFailures.Add(1)
			writeErr(w, http.StatusUnauthorized, "signature verification failed")
			return
		}
		if !s.replay.CheckAndRecord(fromKey, req.Nonce, req.Timestamp, now) {
			writeErr(w, http.StatusConflict, "stale or replayed request")
			return
		}
		ttl := q.clampTTL(req.TTL)
		id, res := q.deposit(fromKey, toPath, payload, ttl, now)
		switch res {
		case depositOK:
			counter.Add(1)
			s.notify.notify(toPath)
			writeJSON(w, http.StatusCreated, depositResponse{OK: true, ID: id, ExpiresAt: now.Add(ttl).Unix()})
		case depositTooLarge:
			writeErr(w, http.StatusRequestEntityTooLarge, "blob too large")
		case depositQuotaFull:
			writeErr(w, http.StatusInsufficientStorage, "recipient quota exceeded")
		case depositCapacity:
			writeErr(w, http.StatusServiceUnavailable, "at capacity")
		}
	}
}

// ── POLL (signal + mailbox share this) ───────────────────────────────────────

type pollRequest struct {
	Key       string `json:"key"`
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"ts"`
	Sig       string `json:"sig"`
	// Wait requests a long-poll: block up to Wait seconds (capped by MaxPollWait)
	// for a blob to arrive before returning an empty list. 0 => return immediately.
	Wait int `json:"wait,omitempty"`
}

type pollResponse struct {
	Key   string     `json:"key"`
	Blobs []blobView `json:"blobs"`
}

func pollSigningMessage(domain string, req *pollRequest) []byte {
	return canonicalMessage(domain, req.Key, strconv.FormatInt(req.Timestamp, 10), req.Nonce)
}

func (s *Service) pollHandler(q *queue, domain string, counter *atomic.Uint64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req pollRequest
		if !s.decodeJSON(w, r, maxControlBody, &req) {
			return
		}
		keyPath := normalizeKey(r.PathValue("key"))
		if keyPath == "" {
			writeErr(w, http.StatusBadRequest, "invalid key")
			return
		}
		pub, err := decodeKey(req.Key)
		if err != nil || b64.EncodeToString(pub) != keyPath {
			writeErr(w, http.StatusBadRequest, "key mismatch")
			return
		}
		key := keyPath
		if !s.pollLim.allow(key) {
			s.st.rateLimited.Add(1)
			writeErr(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		now := s.now()
		// Ownership proof: only the holder of key's private key can produce this sig.
		if err := verifySig(pub, req.Sig, pollSigningMessage(domain, &req)); err != nil {
			s.st.authFailures.Add(1)
			writeErr(w, http.StatusUnauthorized, "signature verification failed")
			return
		}
		if !s.replay.CheckAndRecord(key, req.Nonce, req.Timestamp, now) {
			writeErr(w, http.StatusConflict, "stale or replayed request")
			return
		}
		blobs := q.pickup(key, now)
		if len(blobs) == 0 && req.Wait > 0 {
			blobs = s.longPoll(r, q, key, req.Wait)
		}
		if len(blobs) > 0 {
			counter.Add(1)
		}
		writeJSON(w, http.StatusOK, pollResponse{Key: key, Blobs: blobs})
	}
}

// longPoll blocks up to min(wait, MaxPollWait) for a deposit to key, then re-checks
// the queue once. It returns as soon as a blob arrives (or on client disconnect).
func (s *Service) longPoll(r *http.Request, q *queue, key string, waitSec int) []blobView {
	wait := time.Duration(waitSec) * time.Second
	if wait > s.cfg.MaxPollWait {
		wait = s.cfg.MaxPollWait
	}
	ch := s.notify.wait(key)
	defer s.notify.cancel(key, ch)

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ch:
		return q.pickup(key, s.now())
	case <-timer.C:
		return nil
	case <-r.Context().Done():
		return nil
	}
}

// ── ACK (signal + mailbox share this) ────────────────────────────────────────

type ackRequest struct {
	Key       string   `json:"key"`
	IDs       []string `json:"ids"`
	Nonce     string   `json:"nonce"`
	Timestamp int64    `json:"ts"`
	Sig       string   `json:"sig"`
}

func ackSigningMessage(domain string, req *ackRequest) []byte {
	fields := make([]string, 0, 3+len(req.IDs))
	fields = append(fields, req.Key, strconv.FormatInt(req.Timestamp, 10), req.Nonce)
	fields = append(fields, req.IDs...)
	return canonicalMessage(domain, fields...)
}

func (s *Service) ackHandler(q *queue, domain string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ackRequest
		if !s.decodeJSON(w, r, maxControlBody, &req) {
			return
		}
		keyPath := normalizeKey(r.PathValue("key"))
		if keyPath == "" {
			writeErr(w, http.StatusBadRequest, "invalid key")
			return
		}
		pub, err := decodeKey(req.Key)
		if err != nil || b64.EncodeToString(pub) != keyPath {
			writeErr(w, http.StatusBadRequest, "key mismatch")
			return
		}
		key := keyPath
		now := s.now()
		if err := verifySig(pub, req.Sig, ackSigningMessage(domain, &req)); err != nil {
			s.st.authFailures.Add(1)
			writeErr(w, http.StatusUnauthorized, "signature verification failed")
			return
		}
		if !s.replay.CheckAndRecord(key, req.Nonce, req.Timestamp, now) {
			writeErr(w, http.StatusConflict, "stale or replayed request")
			return
		}
		deleted := q.ack(key, req.IDs, now)
		writeJSON(w, http.StatusOK, map[string]any{"deleted": deleted})
	}
}

// ── ICE + health ─────────────────────────────────────────────────────────────

func (s *Service) handleICE(w http.ResponseWriter, r *http.Request) {
	// The optional "key" query param is folded into the TURN username as an opaque
	// coturn bookkeeping hint — it is NOT authenticated and grants nothing.
	hint := r.URL.Query().Get("key")
	servers := s.ice.servers(hint, s.now())
	writeJSON(w, http.StatusOK, map[string]any{"ice_servers": servers})
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "role": "rendezvous", "prefix": s.prefix})
}

// ── helpers ──────────────────────────────────────────────────────────────────

// decodeJSON reads a size-capped JSON body into v. On any error it writes a bounded
// 400/413 and returns false. It never echoes body content back to the client.
func (s *Service) decodeJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		// A MaxBytesError means the body exceeded the cap.
		var mbe *http.MaxBytesError
		if strings.Contains(err.Error(), "http: request body too large") || (err != nil && asMaxBytes(err, &mbe)) {
			writeErr(w, http.StatusRequestEntityTooLarge, "request too large")
			return false
		}
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	// Reject trailing garbage after the JSON object.
	if dec.More() {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

func asMaxBytes(err error, target **http.MaxBytesError) bool {
	e, ok := err.(*http.MaxBytesError)
	if ok {
		*target = e
	}
	return ok
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr writes a bounded, non-leaky error object. The reason is always a fixed
// string chosen by the handler — never raw input or a wrapped error.
func writeErr(w http.ResponseWriter, status int, reason string) {
	writeJSON(w, status, map[string]any{"error": reason})
}

// shortKey returns a truncated key for logs (public data, but kept short/tidy).
func shortKey(k string) string {
	if len(k) <= 12 {
		return k
	}
	return k[:12]
}

// ── long-poll notifier ───────────────────────────────────────────────────────

// notifier wakes long-poll waiters when a blob is deposited for their key. A waiter
// registers a channel; a deposit closes and clears all channels for that key.
type notifier struct {
	mu    sync.Mutex
	waits map[string][]chan struct{}
}

func newNotifier() *notifier { return &notifier{waits: make(map[string][]chan struct{})} }

func (n *notifier) wait(key string) chan struct{} {
	ch := make(chan struct{})
	n.mu.Lock()
	n.waits[key] = append(n.waits[key], ch)
	n.mu.Unlock()
	return ch
}

func (n *notifier) cancel(key string, ch chan struct{}) {
	n.mu.Lock()
	defer n.mu.Unlock()
	list := n.waits[key]
	for i, c := range list {
		if c == ch {
			n.waits[key] = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(n.waits[key]) == 0 {
		delete(n.waits, key)
	}
}

func (n *notifier) notify(key string) {
	n.mu.Lock()
	list := n.waits[key]
	delete(n.waits, key)
	n.mu.Unlock()
	for _, ch := range list {
		close(ch)
	}
}
