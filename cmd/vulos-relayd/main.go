// Command vulos-relayd runs the sovereign Vulos relay server: the public half of
// the reverse tunnel. It replaces a third-party frp server with a self-hosted one.
//
// Deployment shape:
//   - Provision a wildcard DNS record *.relay.example.com -> this host (primary,
//     subdomain routing). If you cannot get wildcard DNS, run with -path-mode and
//     use https://relay.example.com/t/<name>/.
//   - Terminate TLS at the edge (CDN / load balancer) and run this with -addr on a
//     private port using plain HTTP, OR give it -cert/-key to terminate TLS itself.
//   - Configure agent grants via -tokens-file (JSON) or VULOS_RELAY_TOKENS env.
//
// Tokens file / env JSON format:
//
//	[{"token":"SECRET1","names":["box1"]}, {"token":"SECRET2","names":["a","b"]}]
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/server"
)

func main() {
	var (
		addr       = flag.String("addr", ":8443", "listen address")
		domain     = flag.String("domain", envOr("VULOS_RELAY_DOMAIN", ""), "base relay domain, e.g. relay.example.com")
		certFile   = flag.String("cert", "", "TLS certificate file (omit to run plain HTTP behind a terminating proxy)")
		keyFile    = flag.String("key", "", "TLS key file")
		tokensFile = flag.String("tokens-file", "", "path to JSON grants file (or set VULOS_RELAY_TOKENS)")
		pathMode   = flag.Bool("path-mode", false, "also serve /t/<name>/ fallback (no wildcard DNS)")
		maxAgents  = flag.Int("max-agents", 256, "max concurrent agents")

		// WAVE50-RELAY-OBSERVABILITY: the admin/metrics surface. It is SEPARATE from
		// the public tunnel listener and serves /metrics, /healthz, /readyz. Bind it
		// to a loopback address (default) so it is never internet-reachable; binding
		// to a routable address REQUIRES -metrics-token (refuses to start otherwise).
		adminAddr    = flag.String("admin-addr", envOr("VULOS_RELAY_ADMIN_ADDR", "127.0.0.1:9090"), "admin/metrics listen address (loopback-only unless -metrics-token set; empty disables)")
		metricsToken = flag.String("metrics-token", envOr("VULOS_RELAY_METRICS_TOKEN", ""), "bearer token required for NON-loopback /metrics access")

		// WAVE41-RELAY-REVOCATION: static revoked-list + live-session recheck cadence.
		revokedFile = flag.String("revoked-file", "", "path to JSON revoked-list ({\"tokens\":[],\"names\":[],\"accounts\":[]}); or set VULOS_RELAY_REVOKED")
		revokeSweep = flag.Duration("revoke-sweep", 0, "how often to recheck live sessions for revocation (0=default 20s, <0=disable)")

		// WAVE34-RELAY-HARDEN: rate limits for the internet-facing surfaces. 0 uses
		// the built-in safe default; a negative value DISABLES that limiter.
		ctrlRate   = flag.Float64("ratelimit-control-rate", envFloat("VULOS_RELAY_CTRL_RATE", 0), "control-conn attempts/sec per source IP (0=default 5, <0=off)")
		ctrlBurst  = flag.Float64("ratelimit-control-burst", envFloat("VULOS_RELAY_CTRL_BURST", 0), "control-conn attempt burst per source IP (0=default 20)")
		reqRate    = flag.Float64("ratelimit-req-rate", envFloat("VULOS_RELAY_REQ_RATE", 0), "public requests/sec per tunnel (0=default 50, <0=off)")
		reqBurst   = flag.Float64("ratelimit-req-burst", envFloat("VULOS_RELAY_REQ_BURST", 0), "public request burst per tunnel (0=default 100)")
		globalRate = flag.Float64("ratelimit-global-rate", envFloat("VULOS_RELAY_GLOBAL_RATE", 0), "aggregate public requests/sec across all tunnels (0=default 500, <0=off)")
		globBurst  = flag.Float64("ratelimit-global-burst", envFloat("VULOS_RELAY_GLOBAL_BURST", 0), "aggregate public request burst (0=default 1000)")

		// WAVE24-RELAY-BILLING: link this relay to Vulos Cloud so account-bound
		// tokens are gated + metered. All optional — omit to run UNBILLED (self-host).
		cpURL       = flag.String("cp-url", envOr("VULOS_CP_URL", ""), "Vulos Cloud base URL for entitlement/usage (e.g. https://cloud.vulos.dev)")
		cpSecret    = flag.String("cp-shared-secret", envOr("CP_SHARED_SECRET", ""), "CP_SHARED_SECRET for usage HMAC + entitlement service auth")
		popID       = flag.String("pop-id", envOr("VULOS_RELAY_POP_ID", ""), "this relay's PoP id (usage reports dedup per-PoP)")
		cpTokenMode = flag.Bool("cp-token-store", envOr("VULOS_RELAY_CP_TOKENS", "") == "1", "resolve agent tokens as CP install credentials instead of a static grants file")
	)
	flag.Parse()

	if strings.TrimSpace(*domain) == "" {
		log.Fatal("vulos-relayd: -domain is required (or VULOS_RELAY_DOMAIN)")
	}

	// Build the optional CP client. Metering/gating require both the URL and the
	// shared secret; if either is missing we run unbilled and warn.
	var cp *server.CPClient
	if *cpURL != "" && *cpSecret != "" {
		pid := *popID
		if pid == "" {
			pid = "relay-" + sanitizePoP(*domain)
		}
		cp = &server.CPClient{BaseURL: *cpURL, SharedSecret: *cpSecret, PoPID: pid}
		log.Printf("vulos-relayd: Vulos Cloud billing ENABLED cp=%s pop=%s", *cpURL, pid)
	} else if *cpTokenMode {
		log.Fatal("vulos-relayd: -cp-token-store requires -cp-url and -cp-shared-secret")
	} else {
		log.Printf("vulos-relayd: running UNBILLED (no -cp-url/-cp-shared-secret) — tokens authorized but not metered")
	}

	// WAVE41-RELAY-REVOCATION: load the optional static revoked-list (file/env). A
	// revoked token/name/account is refused at connect and cut mid-session by the
	// sweep. Applies to the static-grants store; the CP-token store's revocation is
	// the CP revoked/404 path.
	revoked, err := loadRevoked(*revokedFile)
	if err != nil {
		log.Fatalf("vulos-relayd: %v", err)
	}
	if n := len(revoked.Tokens) + len(revoked.Names) + len(revoked.Accounts); n > 0 {
		log.Printf("vulos-relayd: static revoked-list loaded (%d tokens, %d names, %d accounts)",
			len(revoked.Tokens), len(revoked.Names), len(revoked.Accounts))
	}

	// Token store: either CP install-credential resolution, or the static grants.
	var store server.TokenStore
	if *cpTokenMode {
		store = server.NewCPTokenStore(cp, 0)
		log.Printf("vulos-relayd: token store = CP install credentials")
	} else {
		grants, err := loadGrants(*tokensFile)
		if err != nil {
			log.Fatalf("vulos-relayd: %v", err)
		}
		st, err := server.NewStaticTokenStoreWithRevoked(grants, revoked)
		if err != nil {
			log.Fatalf("vulos-relayd: token store: %v", err)
		}
		store = st
	}

	srv, err := server.New(server.Config{
		Domain:         *domain,
		Tokens:         store,
		EnablePathMode: *pathMode,
		MaxAgents:      *maxAgents,
		CP:             cp,

		ControlConnRate:  *ctrlRate,
		ControlConnBurst: *ctrlBurst,
		PublicReqRate:    *reqRate,
		PublicReqBurst:   *reqBurst,
		GlobalReqRate:    *globalRate,
		GlobalReqBurst:   *globBurst,

		RevokeSweepPeriod: *revokeSweep,
	})
	if err != nil {
		log.Fatalf("vulos-relayd: %v", err)
	}

	log.Printf("vulos-relayd: listening on %s domain=%s pathMode=%v agents<=%d",
		*addr, *domain, *pathMode, *maxAgents)

	// SIGTERM/SIGINT trigger a graceful drain (Fly + most orchestrators send
	// SIGTERM on deploy/restart): stop accepting new connections, let in-flight
	// requests finish, then flush the final metered usage. Without this the process
	// would be hard-killed and the last usage deltas lost.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// WAVE50-RELAY-OBSERVABILITY: start the admin/metrics surface on its own
	// listener (loopback/token-gated), separate from the public tunnel listener.
	if *adminAddr != "" {
		go func() {
			log.Printf("vulos-relayd: admin/metrics on %s (loopback-only%s)", *adminAddr,
				func() string {
					if *metricsToken != "" {
						return " + metrics-token"
					}
					return ""
				}())
			if err := srv.ServeAdmin(server.AdminConfig{Addr: *adminAddr, MetricsToken: *metricsToken}); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("vulos-relayd: admin surface: %v", err)
			}
		}()
	}

	// Run the public listener in the background so main can wait on either a signal
	// (graceful drain) or a fatal listener error.
	serveErr := make(chan error, 1)
	go func() {
		if *certFile != "" && *keyFile != "" {
			serveErr <- srv.ListenAndServeTLS(*addr, *certFile, *keyFile)
			return
		}
		log.Printf("vulos-relayd: WARNING running plain HTTP — terminate TLS at your edge/CDN")
		serveErr <- srv.ListenAndServe(*addr)
	}()

	select {
	case err := <-serveErr:
		// The listener failed to start or died on its own (not a shutdown). Still
		// flush usage before exiting non-zero.
		srv.Close()
		log.Fatalf("vulos-relayd: %v", err)
	case <-ctx.Done():
		stop() // restore default signal handling: a second signal now kills hard
		log.Printf("vulos-relayd: shutting down (draining in-flight requests)")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("vulos-relayd: graceful shutdown incomplete: %v", err)
		}
		log.Printf("vulos-relayd: stopped")
	}
}

// sanitizePoP derives a DNS-ish PoP id fallback from the relay domain.
func sanitizePoP(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.ReplaceAll(d, ".", "-")
	if d == "" {
		return "local"
	}
	return d
}

// loadGrants reads grants from -tokens-file, else VULOS_RELAY_TOKENS env.
func loadGrants(path string) ([]server.Grant, error) {
	var data []byte
	var err error
	switch {
	case path != "":
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read tokens file: %w", err)
		}
	case os.Getenv("VULOS_RELAY_TOKENS") != "":
		data = []byte(os.Getenv("VULOS_RELAY_TOKENS"))
	default:
		return nil, fmt.Errorf("no grants: set -tokens-file or VULOS_RELAY_TOKENS (refusing to run open)")
	}
	var grants []server.Grant
	if err := json.Unmarshal(data, &grants); err != nil {
		return nil, fmt.Errorf("parse grants JSON: %w", err)
	}
	return grants, nil
}

// loadRevoked reads the static revoked-list from -revoked-file, else the
// VULOS_RELAY_REVOKED env, else returns an empty (revoke-nothing) spec. Unlike
// grants, an absent revoked-list is fine (it just revokes nothing).
func loadRevoked(path string) (server.RevokedSpec, error) {
	var data []byte
	switch {
	case path != "":
		b, err := os.ReadFile(path)
		if err != nil {
			return server.RevokedSpec{}, fmt.Errorf("read revoked file: %w", err)
		}
		data = b
	case os.Getenv("VULOS_RELAY_REVOKED") != "":
		data = []byte(os.Getenv("VULOS_RELAY_REVOKED"))
	default:
		return server.RevokedSpec{}, nil
	}
	var spec server.RevokedSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return server.RevokedSpec{}, fmt.Errorf("parse revoked JSON: %w", err)
	}
	return spec, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// envFloat reads a float from env k, falling back to def when unset/unparseable.
func envFloat(k string, def float64) float64 {
	if v := os.Getenv(k); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}
