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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vul-os/vulos-relay/internal/obs"
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

	// DKIM signing.
	// RELAY_DKIM_DOMAIN: signing domain (d= tag). When set, outbound mail is
	// DKIM-signed with the rotator's current key. Empty = no signing.
	DKIMDomain string
	// RELAY_DKIM_KEY_DIR: directory for persisting DKIM keys. Empty = in-memory
	// (a key is generated at startup and lost on restart).
	DKIMKeyDir string

	// TLS enforcement policy for outbound SMTP.
	// RELAY_SMTP_TLS_POLICY: "required" (secure default) or "opportunistic".
	SMTPTLSPolicy string

	// Warm-IP pool / ramp / blocklist wiring (RELAY-11/RELAY-09/RELAY-12).
	// RELAY_POOL_IPS: comma-separated list of source IPs to warm and rotate.
	// Each may be "ip" or "ip@helo" or "ip@helo@segment". Empty = no pool;
	// the single RELAY_SMTP_LOCAL_IP binding (if any) is used instead.
	PoolIPs string
	// RELAY_RAMP_ENABLE: enable the warm-up ramp scheduler over the pool IPs.
	RampEnable bool
	// RELAY_BLOCKLIST_ENABLE: enable DNSBL monitoring + quarantine over pool IPs.
	BlocklistEnable bool
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
		DKIMDomain:            envString("RELAY_DKIM_DOMAIN", ""),
		DKIMKeyDir:            envString("RELAY_DKIM_KEY_DIR", ""),
		SMTPTLSPolicy:         envString("RELAY_SMTP_TLS_POLICY", "required"),
		PoolIPs:               envString("RELAY_POOL_IPS", ""),
		RampEnable:            envBool("RELAY_RAMP_ENABLE", false),
		BlocklistEnable:       envBool("RELAY_BLOCKLIST_ENABLE", false),
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

	mu      sync.Mutex
	approxN int // best-effort depth counter, advisory only
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

// buildSMTPSender constructs an SMTPSender with optional source binding, DKIM
// signing, and a TLS-enforcement policy.
func buildSMTPSender(cfg config, signer sending.MessageSigner) *sending.SMTPSender {
	s := &sending.SMTPSender{Signer: signer}

	// TLS policy: secure by default (required). The operator must explicitly
	// opt out per the documented knob to permit plaintext downgrade.
	switch cfg.SMTPTLSPolicy {
	case "opportunistic":
		s.TLSPolicy = sending.TLSPolicyOpportunistic
		log.Printf("relay: SMTP TLS policy: opportunistic (plaintext downgrade permitted)")
	default: // "required" and anything unrecognized → secure default
		s.TLSPolicy = sending.TLSPolicyRequired
		if cfg.SMTPTLSPolicy != "required" && cfg.SMTPTLSPolicy != "" {
			log.Printf("relay: unrecognized RELAY_SMTP_TLS_POLICY=%q, using secure default 'required'", cfg.SMTPTLSPolicy)
		} else {
			log.Printf("relay: SMTP TLS policy: required (refuse plaintext downgrade)")
		}
	}

	// A single static source binding still applies when no warm-IP pool is
	// configured. When a pool IS configured, PoolSender overrides msg.Binding.
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

// buildDKIMSigner builds a DKIM signer wired to a DKIMRotator when
// RELAY_DKIM_DOMAIN is set. It returns (nil, nil) when DKIM is not configured.
// The rotator is seeded with a key at startup so outbound mail is signed
// immediately, and a background goroutine rotates keys on the configured
// interval.
func buildDKIMSigner(ctx context.Context, cfg config) (sending.MessageSigner, error) {
	if cfg.DKIMDomain == "" {
		log.Printf("relay: DKIM signing DISABLED (set RELAY_DKIM_DOMAIN to enable) — outbound mail will be UNSIGNED")
		return nil, nil
	}

	var store sending.KeyStore
	if cfg.DKIMKeyDir != "" {
		fs, err := sending.NewFSKeyStore(cfg.DKIMKeyDir)
		if err != nil {
			return nil, fmt.Errorf("dkim key store: %w", err)
		}
		store = fs
		log.Printf("relay: DKIM key store: %s", cfg.DKIMKeyDir)
	} else {
		store = sending.NewMemKeyStore()
		log.Printf("relay: DKIM key store: in-memory (keys lost on restart; set RELAY_DKIM_KEY_DIR to persist)")
	}

	rotator, err := sending.NewDKIMRotator(cfg.DKIMDomain, store, sending.DKIMRotatorConfig{})
	if err != nil {
		return nil, fmt.Errorf("dkim rotator: %w", err)
	}

	// Seed a key if the store is empty so signing works from the first message.
	if _, err := rotator.CurrentKey(); err != nil {
		k, rerr := rotator.Rotate()
		if rerr != nil {
			return nil, fmt.Errorf("dkim seed key: %w", rerr)
		}
		log.Printf("relay: DKIM seeded key selector=%s — publish DNS TXT at %s._domainkey.%s",
			k.Selector, k.Selector, cfg.DKIMDomain)
	}

	// Background rotation.
	go func() {
		ticker := time.NewTicker(7 * 24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, rerr := rotator.Rotate(); rerr != nil {
					log.Printf("relay: DKIM rotation failed: %v", rerr)
				}
			}
		}
	}()

	signer, err := sending.NewDKIMSigner(sending.DKIMSignerConfig{
		Domain:   cfg.DKIMDomain,
		Provider: rotator,
	})
	if err != nil {
		return nil, fmt.Errorf("dkim signer: %w", err)
	}
	log.Printf("relay: DKIM signing ENABLED for domain %s", cfg.DKIMDomain)
	return signer, nil
}

// poolEntrySpec parses a RELAY_POOL_IPS element of the form
// "ip[@helo[@segment]]" into a sending.PoolEntry.
func parsePoolEntry(spec string) (sending.PoolEntry, bool) {
	parts := strings.Split(spec, "@")
	ip := net.ParseIP(strings.TrimSpace(parts[0]))
	if ip == nil {
		return sending.PoolEntry{}, false
	}
	e := sending.PoolEntry{IP: ip, Segment: sending.SegmentEstablished}
	if len(parts) >= 2 && parts[1] != "" {
		e.HELOName = strings.TrimSpace(parts[1])
	}
	if len(parts) >= 3 && parts[2] != "" {
		e.Segment = sending.SegmentName(strings.TrimSpace(parts[2]))
	}
	return e, true
}

// buildPoolSender wires the warm-IP Pool, RampScheduler, and BlocklistMonitor
// into the send path when RELAY_POOL_IPS is configured. It returns the inner
// sender unchanged (no pool) when no pool IPs are set.
func buildPoolSender(ctx context.Context, cfg config, inner sending.Sender) sending.Sender {
	if cfg.PoolIPs == "" {
		return inner
	}

	pool := sending.NewPool()
	var ips []net.IP
	for _, spec := range strings.Split(cfg.PoolIPs, ",") {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		entry, ok := parsePoolEntry(spec)
		if !ok {
			log.Printf("relay: invalid RELAY_POOL_IPS entry %q, skipping", spec)
			continue
		}
		pool.AddEntry(entry)
		ips = append(ips, entry.IP)
		log.Printf("relay: warm-IP pool entry: ip=%s helo=%s segment=%s", entry.IP, entry.HELOName, entry.Segment)
	}
	if len(ips) == 0 {
		log.Printf("relay: RELAY_POOL_IPS set but no valid entries — pool disabled")
		return inner
	}

	ps := &sending.PoolSender{
		Pool:  pool,
		Inner: inner,
		// Default selection hint: established. Operators running a static warm
		// pool want their configured IPs used; the low-trust gating in
		// Pool.Select is meaningful only when accounts are classified, which a
		// tenant-aware deployment supplies by overriding SegmentFor.
		SegmentFor: func(string) sending.SegmentName { return sending.SegmentEstablished },
	}

	if cfg.RampEnable {
		ps.Ramp = sending.NewRampScheduler(sending.RampConfig{})
		log.Printf("relay: warm-up ramp scheduler ENABLED over %d pool IPs", len(ips))
	}

	if cfg.BlocklistEnable {
		monitor := reputation.NewBlocklistMonitor(pool, reputation.BlocklistMonitorConfig{})
		monitor.AddSource(&reputation.SpamhausSource{})
		monitor.AddSource(&reputation.SORBSSource{})
		for _, ip := range ips {
			monitor.WatchIP(ip)
		}
		go monitor.Run(ctx)
		log.Printf("relay: blocklist monitor ENABLED (spamhaus, sorbs) over %d pool IPs", len(ips))
	}

	log.Printf("relay: warm-IP pool active — outbound IP rotation in effect")
	return ps
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
  RELAY_DKIM_DOMAIN            DKIM signing domain (d=); enables outbound DKIM signing
  RELAY_DKIM_KEY_DIR           Directory to persist DKIM keys (default: in-memory)
  RELAY_SMTP_TLS_POLICY        "required" (secure default) or "opportunistic"
  RELAY_POOL_IPS               Comma-list of warm-IP pool entries: ip[@helo[@segment]]
  RELAY_RAMP_ENABLE            Enable warm-up ramp caps over pool IPs (1/true)
  RELAY_BLOCKLIST_ENABLE       Enable DNSBL monitoring + quarantine over pool IPs (1/true)
`)
	}
	flag.Parse()

	if *ver {
		fmt.Printf("vulos-relay %s\n", version)
		return
	}

	obs.Init()
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// Build DKIM signer (wired into the SMTP send path so outbound mail is
	// authenticated). Disabled unless RELAY_DKIM_DOMAIN is set.
	dkimSigner, err := buildDKIMSigner(ctx, cfg)
	if err != nil {
		log.Fatalf("relay: dkim init: %v", err)
	}

	// Build SMTP sender (DKIM signing + TLS-enforcement policy).
	smtpSender := buildSMTPSender(cfg, dkimSigner)

	// Wrap the SMTP egress with the warm-IP pool / ramp / blocklist when
	// configured so IP rotation, ramp caps, and blocklist quarantine take
	// effect on public SMTP delivery (the peer path uses its own transport and
	// is not IP-rotated). When no pool is configured this returns smtpSender
	// unchanged.
	smtpEgress := buildPoolSender(ctx, cfg, smtpSender)

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
		SMTP:     smtpEgress,
		Resolver: resolver,
	}

	// Build and start pipeline.
	pipelineCfg := sending.PipelineConfig{
		Workers: cfg.Workers,
	}
	pipeline := sending.NewPipeline(q, policy, routingSender, pipelineCfg)

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
	mux.Handle("/metrics", obs.Handler())

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
