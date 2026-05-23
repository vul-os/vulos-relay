// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

// Command relay is the Vulos outbound mail relay and Vulos-to-Vulos peering
// transport. It provides a warmed-IP SMTP relay and an encrypted peer
// delivery path, with pluggable queue and reputation-policy seams so the core
// is never hardwired to Vulos's infrastructure.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/vul-os/vulos-relay/internal/peering"
	"github.com/vul-os/vulos-relay/internal/queue"
	"github.com/vul-os/vulos-relay/internal/relay"
	"github.com/vul-os/vulos-relay/internal/reputation"
	"github.com/vul-os/vulos-relay/internal/sending"
)

const version = "0.0.1-dev"

// config holds all runtime configuration parsed from environment variables.
type config struct {
	// Queue backend selection.
	// RELAY_QUEUE_BACKEND: "fs" (default) or "mem"
	QueueBackend string

	// RELAY_QUEUE_DIR: directory for FSQueue (default: "/var/lib/vulos-relay/queue")
	QueueDir string

	// Reputation policy selection.
	// RELAY_POLICY: "permissive" (default) or "capped"
	Policy string

	// CappedPolicy tuning (only used when RELAY_POLICY=capped).
	// RELAY_POLICY_DAILY_CAP: per-account daily send cap (default: 1000)
	PolicyDailyCap int
	// RELAY_POLICY_BOUNCE_THRESHOLD: bounce+complaint rate threshold (default: 0.10)
	PolicyBounceThreshold float64
	// RELAY_POLICY_WINDOW_SIZE: rolling window size (default: 100)
	PolicyWindowSize int

	// SMTP source binding (optional dedicated IP).
	// RELAY_SMTP_LOCAL_IP: source IP for outbound connections (empty = OS default)
	SMTPLocalIP string
	// RELAY_SMTP_HELO: HELO/EHLO hostname (empty = system hostname)
	SMTPHelo string

	// Peering resolver static config path.
	// RELAY_PEER_CONFIG: path to a peering config file (empty = no static peers)
	PeerConfig string

	// Pipeline tuning.
	// RELAY_WORKERS: number of concurrent delivery goroutines (default: 4)
	Workers int

	// Submission listener.
	// RELAY_SUBMIT_ADDR: TCP address for the HTTP submit endpoint (default: ":8025")
	SubmitAddr string

	// RELAY_SUBMIT_DISABLE: when "1"/"true", do not bind the submission
	// listener. The daemon will only drain the existing queue (queue-only
	// mode for self-hosters that fill the queue out-of-band).
	SubmitDisabled bool

	// RELAY_SUBMIT_MAX_BYTES: maximum submission request body size
	// (default: 0 → handler default of 16 MiB).
	SubmitMaxBytes int
}

// envString reads an env var, returning def if it is unset or empty.
func envString(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envInt reads an env var as an integer, returning def if it is unset or invalid.
func envInt(key string, def int) int {
	s := os.Getenv(key)
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		log.Printf("relay: invalid %s=%q (expected int), using default %d", key, s, def)
		return def
	}
	return v
}

// envFloat reads an env var as a float64, returning def if it is unset or invalid.
func envFloat(key string, def float64) float64 {
	s := os.Getenv(key)
	if s == "" {
		return def
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		log.Printf("relay: invalid %s=%q (expected float), using default %f", key, s, def)
		return def
	}
	return v
}

// parseConfig reads all configuration from environment variables.
func parseConfig() config {
	return config{
		QueueBackend:          envString("RELAY_QUEUE_BACKEND", "fs"),
		QueueDir:              envString("RELAY_QUEUE_DIR", "/var/lib/vulos-relay/queue"),
		Policy:                envString("RELAY_POLICY", "permissive"),
		PolicyDailyCap:        envInt("RELAY_POLICY_DAILY_CAP", 1000),
		PolicyBounceThreshold: envFloat("RELAY_POLICY_BOUNCE_THRESHOLD", 0.10),
		PolicyWindowSize:      envInt("RELAY_POLICY_WINDOW_SIZE", 100),
		SMTPLocalIP:           envString("RELAY_SMTP_LOCAL_IP", ""),
		SMTPHelo:              envString("RELAY_SMTP_HELO", ""),
		PeerConfig:            envString("RELAY_PEER_CONFIG", ""),
		Workers:               envInt("RELAY_WORKERS", 4),
		SubmitAddr:            envString("RELAY_SUBMIT_ADDR", ":8025"),
		SubmitDisabled:        envBool("RELAY_SUBMIT_DISABLE", false),
		SubmitMaxBytes:        envInt("RELAY_SUBMIT_MAX_BYTES", 0),
	}
}

// envBool returns true when key is "1", "true", "yes", or "on" (case-insensitive).
func envBool(key string, def bool) bool {
	s := os.Getenv(key)
	if s == "" {
		return def
	}
	switch s {
	case "1", "true", "TRUE", "True", "yes", "YES", "Yes", "on", "ON", "On":
		return true
	case "0", "false", "FALSE", "False", "no", "NO", "No", "off", "OFF", "Off":
		return false
	default:
		log.Printf("relay: invalid %s=%q (expected bool), using default %v", key, s, def)
		return def
	}
}

// buildQueue constructs the queue backend from cfg.
func buildQueue(cfg config) (queue.Queue, error) {
	switch cfg.QueueBackend {
	case "mem":
		log.Println("relay: using in-memory queue (messages will be lost on restart)")
		return queue.NewMemQueue(), nil
	default: // "fs"
		log.Printf("relay: using filesystem queue at %s", cfg.QueueDir)
		return queue.NewFSQueue(cfg.QueueDir)
	}
}

// buildPolicy constructs the reputation policy from cfg.
func buildPolicy(cfg config) reputation.Policy {
	switch cfg.Policy {
	case "capped":
		p := reputation.NewCappedPolicy()
		p.DailyCap = cfg.PolicyDailyCap
		p.BounceThreshold = cfg.PolicyBounceThreshold
		p.WindowSize = cfg.PolicyWindowSize
		log.Printf("relay: using CappedPolicy (daily_cap=%d, bounce_threshold=%.2f, window=%d)",
			p.DailyCap, p.BounceThreshold, p.WindowSize)
		return p
	default: // "permissive"
		log.Println("relay: using Permissive reputation policy")
		return reputation.Permissive{}
	}
}

// buildAuthenticator constructs the open-relay prevention gate (RELAY-16).
//
// The authenticator is MANDATORY and cannot be disabled via configuration.  In
// the default configuration a SharedSecretAuth backed by an empty
// MemAccountRegistry is returned; the operator must populate accounts (e.g. by
// replacing the registry with their own AccountRegistry implementation before
// accepting submissions).
//
// A RELAY_ACCOUNTS_SECRET environment variable, when set, registers a single
// "default" account whose shared secret is the value of that variable.  This is
// intended for simple single-tenant self-hosting only.
func buildAuthenticator(cfg config) relay.SubmitAuthenticator {
	reg := relay.NewMemAccountRegistry()

	// Bootstrap a default account from the environment when provided.
	if secret := envString("RELAY_ACCOUNTS_SECRET", ""); secret != "" {
		reg.Register(relay.AccountRecord{
			AccountID:    "default",
			SharedSecret: []byte(secret),
		})
		log.Printf("relay: open-relay gate: registered default account from RELAY_ACCOUNTS_SECRET")
	} else {
		log.Printf("relay: open-relay gate: no accounts configured — all submissions will be refused; set RELAY_ACCOUNTS_SECRET or inject a custom AccountRegistry")
	}

	auth := relay.NewSharedSecretAuth(reg)
	log.Printf("relay: open-relay prevention gate active (SharedSecretAuth)")
	return auth
}

// buildRouter constructs the submission-side Router (RELAY-15).
func buildRouter(cfg config) *relay.Router {
	rcfg := relay.RouterConfig{}
	if sz := envInt("RELAY_MAX_MESSAGE_BYTES", 0); sz > 0 {
		rcfg.MaxMessageBytes = sz
		log.Printf("relay: message size limit: %d bytes", sz)
	}
	if spool := envString("RELAY_SPOOL_DIR", ""); spool != "" {
		rcfg.SpoolDir = spool
		log.Printf("relay: inbound spool dir: %s", spool)
	}
	return relay.NewRouter(rcfg)
}

// queueEnqueuerAdapter adapts the concrete queue implementations (MemQueue,
// FSQueue) to the relay.MessageEnqueuer interface required by the submission
// listener. We dispatch on the concrete type because the two backends have
// slightly different Enqueue signatures (FSQueue returns error, MemQueue does
// not) and neither exposes a Depth method directly.
type queueEnqueuerAdapter struct {
	mem *queue.MemQueue
	fs  *queue.FSQueue

	mu       sync.Mutex
	approxN  int // best-effort depth counter, advisory only
}

func newQueueEnqueuerAdapter(q queue.Queue) (*queueEnqueuerAdapter, error) {
	switch v := q.(type) {
	case *queue.MemQueue:
		return &queueEnqueuerAdapter{mem: v}, nil
	case *queue.FSQueue:
		return &queueEnqueuerAdapter{fs: v}, nil
	default:
		return nil, fmt.Errorf("relay: queue backend %T does not expose Enqueue; cannot wire submission listener", q)
	}
}

func (a *queueEnqueuerAdapter) Enqueue(_ context.Context, m relay.EnqueuedMessage) error {
	qm := queue.OutboundMessage{
		ID:         m.ID,
		AccountID:  m.AccountID,
		Sender:     m.Sender,
		Recipients: m.Recipients,
		RawRFC822:  m.RawRFC822,
		Metadata:   m.Metadata,
	}
	switch {
	case a.mem != nil:
		a.mem.Enqueue(qm)
	case a.fs != nil:
		if err := a.fs.Enqueue(qm); err != nil {
			return err
		}
	default:
		return errors.New("queueEnqueuerAdapter: no backend wired")
	}
	a.mu.Lock()
	a.approxN++
	a.mu.Unlock()
	return nil
}

func (a *queueEnqueuerAdapter) Depth(_ context.Context) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.approxN
}

// buildSMTPSender constructs an SMTPSender with optional source binding.
func buildSMTPSender(cfg config) *sending.SMTPSender {
	s := &sending.SMTPSender{}
	if cfg.SMTPLocalIP != "" {
		ip := net.ParseIP(cfg.SMTPLocalIP)
		if ip == nil {
			log.Printf("relay: invalid RELAY_SMTP_LOCAL_IP=%q, ignoring", cfg.SMTPLocalIP)
		} else {
			localAddr := &net.TCPAddr{IP: ip}
			s.Dialer = &net.Dialer{LocalAddr: localAddr}
			log.Printf("relay: SMTP source binding: %s", cfg.SMTPLocalIP)
		}
	}
	if cfg.SMTPHelo != "" {
		log.Printf("relay: SMTP HELO name: %s", cfg.SMTPHelo)
	}
	return s
}

// buildResolver constructs a peering resolver.  If PeerConfig is set, it is
// reserved for a future file-based peer loader; for now we always return an
// empty StaticResolver (no static peers configured at startup means all mail
// goes via SMTP).
func buildResolver(cfg config) *peering.StaticResolver {
	r := peering.NewStaticResolver()
	if cfg.PeerConfig != "" {
		log.Printf("relay: peer config path %q (static peer loading not yet implemented, SMTP-only mode)", cfg.PeerConfig)
	}
	return r
}

func main() {
	// CLI flags: --version and --help (flag package provides -help automatically).
	ver := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "vulos-relay %s\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: relay [flags]\n\nFlags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Environment variables:
  RELAY_QUEUE_BACKEND          Queue backend: "fs" (default) or "mem"
  RELAY_QUEUE_DIR              FSQueue directory (default: /var/lib/vulos-relay/queue)
  RELAY_POLICY                 Reputation policy: "permissive" (default) or "capped"
  RELAY_POLICY_DAILY_CAP       CappedPolicy: daily send cap per account (default: 1000)
  RELAY_POLICY_BOUNCE_THRESHOLD CappedPolicy: bounce+complaint rate threshold (default: 0.10)
  RELAY_POLICY_WINDOW_SIZE     CappedPolicy: rolling window size (default: 100)
  RELAY_SMTP_LOCAL_IP          Outbound SMTP source IP (default: OS routing)
  RELAY_SMTP_HELO              SMTP EHLO/HELO hostname (default: system hostname)
  RELAY_PEER_CONFIG            Path to static peer config (default: none)
  RELAY_WORKERS                Concurrent delivery workers (default: 4)
  RELAY_SUBMIT_ADDR            HTTP submission listener address (default: ":8025")
  RELAY_SUBMIT_DISABLE         Set to 1 to skip binding the submission listener
  RELAY_SUBMIT_MAX_BYTES       Max submission body size (default: 16 MiB)
  RELAY_ACCOUNTS_SECRET        Shared secret for a bootstrap "default" account
`)
	}
	flag.Parse()

	if *ver {
		fmt.Printf("vulos-relay %s\n", version)
		return
	}

	cfg := parseConfig()
	log.Printf("vulos-relay %s starting", version)

	// Build open-relay prevention gate (RELAY-16 — mandatory, not bypassable).
	auth := buildAuthenticator(cfg)

	// Build submission-side router (RELAY-15).
	router := buildRouter(cfg)

	// Build queue.
	q, err := buildQueue(cfg)
	if err != nil {
		log.Fatalf("relay: queue init: %v", err)
	}

	// Build reputation policy.
	policy := buildPolicy(cfg)

	// Build SMTP sender.
	smtpSender := buildSMTPSender(cfg)

	// Build peering resolver and peer sender.
	resolver := buildResolver(cfg)
	peerIdentity, err := peering.GenerateIdentity()
	if err != nil {
		log.Fatalf("relay: generate peer identity: %v", err)
	}
	transport := peering.NewLoopbackTransport()
	peerSender := peering.NewPeerSender(peerIdentity, resolver, transport)

	// Wire RoutingSender: peer path wraps SMTP path.
	routingSender := &peering.RoutingSender{
		Peer:     peerSender,
		SMTP:     smtpSender,
		Resolver: resolver,
	}

	// Build and start pipeline.
	pipelineCfg := sending.PipelineConfig{
		Workers: cfg.Workers,
	}
	pipeline := sending.NewPipeline(q, policy, routingSender, pipelineCfg)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// Start the submission listener alongside the outbound pipeline.
	srv, srvErr := startSubmitListener(cfg, auth, router, q)
	if srvErr != nil {
		log.Fatalf("relay: submit listener: %v", srvErr)
	}

	pipelineDone := make(chan struct{})
	go func() {
		log.Printf("relay: pipeline starting with %d workers", cfg.Workers)
		pipeline.Run(ctx) // blocks; graceful drain on context cancel
		close(pipelineDone)
	}()

	<-ctx.Done()
	log.Println("relay: shutdown signal received")

	// Graceful shutdown of the HTTP listener with a bounded timeout.
	if srv != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("relay: submit listener shutdown: %v", err)
		}
		cancel()
	}

	<-pipelineDone
	log.Println("relay: pipeline drained, exiting")
}

// startSubmitListener wires the submission HTTP endpoint and starts it on a
// background goroutine. When SubmitDisabled is true it logs a warning and
// returns (nil, nil) — the caller treats that as "no listener, queue-only
// mode."
func startSubmitListener(cfg config, auth relay.SubmitAuthenticator, router *relay.Router, q queue.Queue) (*http.Server, error) {
	if cfg.SubmitDisabled {
		log.Printf("relay: WARNING — RELAY_SUBMIT_DISABLE is set; submission listener will not bind. " +
			"The relay will only drain the queue. Open-relay prevention is enforced for any submission that " +
			"reaches this binary via the HTTP path; in queue-only mode the operator is responsible for ensuring " +
			"messages reach the queue from a trusted source.")
		return nil, nil
	}

	enq, err := newQueueEnqueuerAdapter(q)
	if err != nil {
		return nil, err
	}

	h := relay.NewSubmitHandler(relay.SubmitHandlerConfig{
		Authenticator: auth,
		Router:        router,
		Queue:         enq,
		MaxBodyBytes:  int64(cfg.SubmitMaxBytes),
	})

	mux := http.NewServeMux()
	mux.Handle("/submit", h)

	srv := &http.Server{
		Addr:              cfg.SubmitAddr,
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ln, err := net.Listen("tcp", cfg.SubmitAddr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", cfg.SubmitAddr, err)
	}
	log.Printf("relay: submission listener bound to %s (POST /submit)", ln.Addr().String())

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("relay: submit listener serve: %v", err)
		}
	}()

	return srv, nil
}
