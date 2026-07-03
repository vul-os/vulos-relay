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
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

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
		st, err := server.NewStaticTokenStore(grants)
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
	})
	if err != nil {
		log.Fatalf("vulos-relayd: %v", err)
	}
	defer srv.Close() // stop the meter + final usage flush on exit

	log.Printf("vulos-relayd: listening on %s domain=%s pathMode=%v agents<=%d",
		*addr, *domain, *pathMode, *maxAgents)

	if *certFile != "" && *keyFile != "" {
		log.Fatal(srv.ListenAndServeTLS(*addr, *certFile, *keyFile))
	}
	log.Printf("vulos-relayd: WARNING running plain HTTP — terminate TLS at your edge/CDN")
	log.Fatal(srv.ListenAndServe(*addr))
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

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
