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
//
// RELAY-TOKEN-TTL: a grant MAY additionally carry an expiry and a rotation
// predecessor so agent tokens are not long-lived-forever:
//
//		[{"token":"NEW","previous_token":"OLD","names":["box1"],
//		  "expires_at":"2026-12-31T00:00:00Z"}]
//
//	  - expires_at (RFC3339): after this the grant's tokens STOP authorizing
//	    (fail-closed) — a leaked token self-revokes. Omit for no expiry (default).
//	  - previous_token: the OLD token accepted alongside token DURING A ROTATION
//	    window (mirror of CP_SHARED_SECRET_PREVIOUS). Set the new secret on token,
//	    keep the old on previous_token until the agent has rolled, then clear it.
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

	"github.com/vul-os/vulos-relay/tunnel/autoscale"
	"github.com/vul-os/vulos-relay/tunnel/pubcache"
	"github.com/vul-os/vulos-relay/tunnel/rendezvous"
	"github.com/vul-os/vulos-relay/tunnel/server"
)

func main() {
	var (
		addr       = flag.String("addr", envOr("VULOS_RELAY_ADDR", ":8443"), "listen address (or VULOS_RELAY_ADDR)")
		domain     = flag.String("domain", envOr("VULOS_RELAY_DOMAIN", ""), "base relay domain, e.g. relay.example.com")
		certFile   = flag.String("cert", "", "TLS certificate file (omit to run plain HTTP behind a terminating proxy)")
		keyFile    = flag.String("key", "", "TLS key file")
		tokensFile = flag.String("tokens-file", "", "path to JSON grants file (or set VULOS_RELAY_TOKENS)")
		pathMode   = flag.Bool("path-mode", envOr("VULOS_RELAY_PATH_MODE", "") == "1", "also serve /t/<name>/ fallback (no wildcard DNS) (or VULOS_RELAY_PATH_MODE=1)")
		maxAgents  = flag.Int("max-agents", 256, "max concurrent agents")

		// SECURITY: how X-Forwarded-For/-Proto shown to the box's app are built. OFF
		// by default (the relay is the internet-facing trust boundary) => a public
		// client's forwarding headers are DISCARDED and overwritten with the observed
		// peer, so a client cannot spoof its source IP. Turn ON only when a trusted
		// TLS-terminating edge/CDN fronts the relay (the fly.toml deployment: Fly's
		// proxy sets XFF), so the real client chain is preserved. Enabling it while
		// directly exposed re-opens the spoof.
		trustProxy = flag.Bool("trust-proxy-headers", envOr("VULOS_RELAY_TRUST_PROXY_HEADERS", "") == "1", "trust X-Forwarded-* from a fronting proxy (enable ONLY behind a trusted TLS-terminating edge; off=overwrite to prevent client IP spoofing)")

		// CONSOLIDATION A-1: single-request upload cap. The relay streams the body
		// (no buffering) so this bounds per-stream duration/abuse, not RAM. 0 keeps
		// the server-side default (256 MiB); a negative value is refused (never run
		// unbounded). Overflow yields a clean 413 to the public client.
		maxReqBytes = flag.Int64("max-request-bytes", envInt64("VULOS_RELAY_MAX_REQUEST_BYTES", 0), "max upload request body in bytes (0=default 256MiB); overflow returns 413")

		// MEDIUM-2 slow-body DoS guard: overall deadline on ingesting a public client's
		// request body (non-streaming path). Bounds a dribbling body that would otherwise
		// pin a goroutine + a per-agent stream slot. Cleared before the response streams,
		// so SSE/downloads are unaffected. 0=default 30s, <0=disable.
		reqBodyTimeout = flag.Duration("request-body-timeout", envDuration("VULOS_RELAY_REQUEST_BODY_TIMEOUT", 0), "overall deadline to ingest a client request body, slow-body DoS guard (0=default 30s, <0=disable)")

		// WAVE50-RELAY-OBSERVABILITY: the admin/metrics surface. It is SEPARATE from
		// the public tunnel listener and serves /metrics, /healthz, /readyz. Bind it
		// to a loopback address (default) so it is never internet-reachable; binding
		// to a routable address REQUIRES -metrics-token (refuses to start otherwise).
		adminAddr    = flag.String("admin-addr", envOr("VULOS_RELAY_ADMIN_ADDR", "127.0.0.1:9090"), "admin/metrics listen address (loopback-only unless -metrics-token set; empty disables)")
		metricsToken = flag.String("metrics-token", envOr("VULOS_RELAY_METRICS_TOKEN", ""), "bearer token required for NON-loopback /metrics access")

		// WAVE41-RELAY-REVOCATION: static revoked-list + live-session recheck cadence.
		revokedFile = flag.String("revoked-file", "", "path to JSON revoked-list ({\"tokens\":[],\"names\":[],\"accounts\":[]}); or set VULOS_RELAY_REVOKED")
		revokeSweep = flag.Duration("revoke-sweep", envDuration("VULOS_RELAY_REVOKE_SWEEP", 0), "how often to recheck live sessions for revocation (0=default 20s, <0=disable) (or VULOS_RELAY_REVOKE_SWEEP)")

		// WAVE34-RELAY-HARDEN: rate limits for the internet-facing surfaces. 0 uses
		// the built-in safe default; a negative value DISABLES that limiter.
		ctrlRate   = flag.Float64("ratelimit-control-rate", envFloat("VULOS_RELAY_CTRL_RATE", 0), "control-conn attempts/sec per source IP (0=default 5, <0=off)")
		ctrlBurst  = flag.Float64("ratelimit-control-burst", envFloat("VULOS_RELAY_CTRL_BURST", 0), "control-conn attempt burst per source IP (0=default 20)")
		reqRate    = flag.Float64("ratelimit-req-rate", envFloat("VULOS_RELAY_REQ_RATE", 0), "public requests/sec per tunnel (0=default 50, <0=off)")
		reqBurst   = flag.Float64("ratelimit-req-burst", envFloat("VULOS_RELAY_REQ_BURST", 0), "public request burst per tunnel (0=default 100)")
		globalRate = flag.Float64("ratelimit-global-rate", envFloat("VULOS_RELAY_GLOBAL_RATE", 0), "aggregate public requests/sec across all tunnels (0=default 500, <0=off)")
		globBurst  = flag.Float64("ratelimit-global-burst", envFloat("VULOS_RELAY_GLOBAL_BURST", 0), "aggregate public request burst (0=default 1000)")

		// DIRECT-PROBE BUDGET (probe-reflection guard): bound how often the relay emits
		// an outbound direct-endpoint verification GET per account/name, so a box cannot
		// re-register in a loop to reflect GETs off the relay at arbitrary public targets.
		probeRate  = flag.Float64("ratelimit-direct-probe-rate", envFloat("VULOS_RELAY_DIRECT_PROBE_RATE", 0), "direct-endpoint probes/sec per account/name (0=default 1, <0=off)")
		probeBurst = flag.Float64("ratelimit-direct-probe-burst", envFloat("VULOS_RELAY_DIRECT_PROBE_BURST", 0), "direct-endpoint probe burst per account/name (0=default 5)")

		// AUTOSCALE-ON-SATURATION + MULTI-NODE POOL. This relay is one node of a
		// geo-distributed pool (Hetzner primary, Vultr edge). node-id/region/provider
		// make it self-aware (surfaced on /healthz and used by a pool). The soft caps
		// are the per-node "full" thresholds used to compute the
		// vulos_relay_saturation_ratio metric an orchestrator scrapes to decide when to
		// provision/drain a node. They are SOFT (scaling) limits, distinct from the
		// hard -max-agents / rate caps that bound abuse. All optional: leave the soft
		// caps at 0 and the saturation sampler stays off (single-node behavior).
		nodeID   = flag.String("node-id", envOr("VULOS_RELAY_NODE_ID", ""), "this node's stable pool id (e.g. hel1-a); surfaced on /healthz")
		region   = flag.String("region", envOr("VULOS_RELAY_REGION", ""), "coarse geo tag for nearest-node routing (e.g. eu-central, af-south)")
		provider = flag.String("provider", envOr("VULOS_RELAY_PROVIDER", ""), "informational host tag (e.g. hetzner, vultr)")

		softMaxAgents  = flag.Int("soft-max-agents", int(envInt64("VULOS_RELAY_SOFT_MAX_AGENTS", 0)), "soft agent cap for saturation (0=ignore this dimension)")
		softMaxStreams = flag.Int("soft-max-streams", int(envInt64("VULOS_RELAY_SOFT_MAX_STREAMS", 0)), "soft in-flight-stream cap for saturation (0=ignore)")
		softMaxBPS     = flag.Int64("soft-max-bytes-per-sec", envInt64("VULOS_RELAY_SOFT_MAX_BPS", 0), "soft throughput cap (bytes/sec) for saturation (0=ignore)")
		satPeriod      = flag.Duration("saturation-sample-period", envDuration("VULOS_RELAY_SAT_PERIOD", 0), "how often to recompute the saturation gauge (0=default 15s, <0=disable)")

		// SMART-AUTOSCALE: PoP registration + load heartbeat to the CP. public-endpoint
		// is this PoP's agent-facing URL announced to the CP (so it can assign this PoP
		// to agents). Requires the CP link (-cp-url/-cp-shared-secret); with no CP or no
		// public endpoint the relay runs unregistered (self-host / CP-optional).
		publicEndpoint = flag.String("public-endpoint", envOr("VULOS_RELAY_PUBLIC_ENDPOINT", ""), "this PoP's agent-facing base URL announced to the CP (e.g. wss://hel1.relay.example.com); empty=not CP-registered")
		heartbeat      = flag.Duration("heartbeat-period", envDuration("VULOS_RELAY_HEARTBEAT", 0), "PoP load-heartbeat cadence to the CP (0=default 12s, <0=disable)")
		hostMemLimit   = flag.Int64("host-mem-limit-bytes", envInt64("VULOS_RELAY_HOST_MEM_LIMIT", 0), "host/cgroup memory limit for the heartbeat mem_pct gauge (0=report 0)")

		// WAVE24-RELAY-BILLING: link this relay to Vulos Cloud so account-bound
		// tokens are gated + metered. All optional — omit to run UNBILLED (self-host).
		cpURL       = flag.String("cp-url", envOr("VULOS_CP_URL", ""), "Vulos Cloud base URL for entitlement/usage (e.g. https://cloud.vulos.dev)")
		cpSecret    = flag.String("cp-shared-secret", envOr("CP_SHARED_SECRET", ""), "CP_SHARED_SECRET for usage HMAC + entitlement service auth")
		popID       = flag.String("pop-id", envOr("VULOS_RELAY_POP_ID", ""), "this relay's PoP id (usage reports dedup per-PoP)")
		cpTokenMode = flag.Bool("cp-token-store", envOr("VULOS_RELAY_CP_TOKENS", "") == "1", "resolve agent tokens as CP install credentials instead of a static grants file")

		// RENDEZVOUS ROLE: the open key-addressed reachability substrate
		// (announce/resolve/signal/mailbox + ICE). CP-OPTIONAL and self-hostable — it
		// holds only soft-state and needs no Vulos Cloud. Served on the relay's apex
		// host under -rendezvous-prefix. OFF by default (a plain reverse-tunnel relay).
		enableRDV     = flag.Bool("rendezvous", envOr("VULOS_RELAY_RENDEZVOUS", "") == "1", "enable the open announce/resolve/signal/mailbox + ICE rendezvous role (or VULOS_RELAY_RENDEZVOUS=1)")
		rdvPrefix     = flag.String("rendezvous-prefix", envOr("VULOS_RELAY_RENDEZVOUS_PREFIX", "/rendezvous"), "mount prefix for the rendezvous role")
		rdvNoResolve  = flag.Bool("rendezvous-no-public-resolve", envOr("VULOS_RELAY_RENDEZVOUS_NO_RESOLVE", "") == "1", "disable unauthenticated presence resolve reads")
		rdvStun       = flag.String("rendezvous-stun", envOr("VULOS_RELAY_STUN", ""), "comma-separated STUN URLs advertised via /rendezvous/ice (empty=public default)")
		rdvNoPubStun  = flag.Bool("rendezvous-disable-public-stun", envOr("VULOS_RELAY_DISABLE_PUBLIC_STUN", "") == "1", "drop the built-in public STUN fallback (sovereign deployments)")
		rdvTurn       = flag.String("rendezvous-turn", envOr("VULOS_RELAY_TURN", ""), "comma-separated TURN URLs (requires -rendezvous-turn-secret to emit ephemeral creds)")
		rdvTurnSecret = flag.String("rendezvous-turn-secret", envOr("VULOS_RELAY_TURN_SECRET", ""), "coturn static-auth-secret used to mint short-lived TURN credentials (never sent to clients)")
		rdvTurnTTL    = flag.Duration("rendezvous-turn-ttl", envDuration("VULOS_RELAY_TURN_TTL", 0), "lifetime of a minted TURN credential (0=default 12h)")

		// CACHE/PIN ROLE: the DMTAP-PUB public-object read cache (dmtap § 22.5.1,
		// substrate/ROLES.md § 6). Served on the relay's apex host under
		// -pubcache-prefix. OFF by default, and deliberately so: unlike the tunnel,
		// mailbox, and rendezvous roles, this one serves PLAINTEXT THE OPERATOR CAN
		// READ, which shifts the operator's moderation and liability posture
		// (§ 22.6.1). Nothing is ever stored unverified, so the cache can only fail
		// to serve, never forge.
		enablePubCache = flag.Bool("pubcache", envOr("VULOS_RELAY_PUBCACHE", "") == "1", "enable the DMTAP-PUB public-object cache/pin role (or VULOS_RELAY_PUBCACHE=1) — serves PLAINTEXT, explicit operator opt-in")
		pcPrefix       = flag.String("pubcache-prefix", envOr("VULOS_RELAY_PUBCACHE_PREFIX", "/.well-known/dmtap-pub"), "mount prefix for the cache/pin role")
		pcUpstreams    = flag.String("pubcache-upstreams", envOr("VULOS_RELAY_PUBCACHE_UPSTREAMS", ""), "comma-separated § 22.5.1 gateway base URLs to read through, tried in order (the ONLY hosts this role will contact)")
		pcMaxObject    = flag.Int64("pubcache-max-object-bytes", envInt64("VULOS_RELAY_PUBCACHE_MAX_OBJECT", 0), "per-object size cap (0=default 16 MiB)")
		pcMaxCache     = flag.Int64("pubcache-max-bytes", envInt64("VULOS_RELAY_PUBCACHE_MAX_BYTES", 0), "total cache size cap, LRU-evicted (0=default 256 MiB)")
		pcTTL          = flag.Duration("pubcache-ttl", envDuration("VULOS_RELAY_PUBCACHE_TTL", 0), "per-object cache lifetime (0=default 1h)")
		pcUpstreamTO   = flag.Duration("pubcache-upstream-timeout", envDuration("VULOS_RELAY_PUBCACHE_UPSTREAM_TIMEOUT", 0), "timeout for one upstream read (0=default 15s)")
		pcInflight     = flag.Int("pubcache-max-inflight", int(envInt64("VULOS_RELAY_PUBCACHE_MAX_INFLIGHT", 0)), "max concurrent upstream fetches across the role (0=default 16)")
		pcServeFeeds   = flag.Bool("pubcache-serve-feeds", envOr("VULOS_RELAY_PUBCACHE_SERVE_FEEDS", "") == "1", "also proxy the MUTABLE feed head/range reads (never cached; a feed head is signature-authenticated, which this node cannot verify)")
		// DURABLE PINNING (substrate/ROLES.md § 6). The cache holds soft state;
		// a PIN is a durability promise kept on disk across restarts, never
		// evicted under cache pressure, and bounded by its own hard byte budget.
		// It is off until an operator names a directory, and even then accepts
		// no writes until the operator names the keys allowed to spend that disk.
		pcPinDir      = flag.String("pubcache-pin-dir", envOr("VULOS_RELAY_PUBCACHE_PIN_DIR", ""), "enable DURABLE PINNING rooted at this directory (empty=cache only, soft state). Pinned objects survive restart and are never evicted by cache pressure")
		pcPinKeys     = flag.String("pubcache-pin-keys", envOr("VULOS_RELAY_PUBCACHE_PIN_KEYS", ""), "comma-separated base64url Ed25519 public keys allowed to pin/unpin here (empty=serve existing pins but accept no new ones)")
		pcPinMaxBytes = flag.Int64("pubcache-pin-max-bytes", envInt64("VULOS_RELAY_PUBCACHE_PIN_MAX_BYTES", 0), "HARD durable-pin byte budget over unique stored bytes; a pin over it is REFUSED, never admitted by evicting another pin (0=default 1 GiB)")
		pcPinMaxPin   = flag.Int64("pubcache-pin-max-pin-bytes", envInt64("VULOS_RELAY_PUBCACHE_PIN_MAX_PIN_BYTES", 0), "per-pin size cap, so one blob cannot consume the whole budget (0=default 256 MiB)")
		pcPinMaxPins  = flag.Int("pubcache-pin-max-pins", int(envInt64("VULOS_RELAY_PUBCACHE_PIN_MAX_PINS", 0)), "maximum number of distinct pins (0=default 10000)")
		pcServeProofs = flag.Bool("pubcache-serve-proofs", envOr("VULOS_RELAY_PUBCACHE_SERVE_PROOFS", "") == "1", "also serve the OPTIONAL chunk-tree range proofs (FEEDS.md § 5.3: manifest/{id}/proof?chunk=i) for O(log n) verified partial fetch")
	)
	flag.Parse()

	if strings.TrimSpace(*domain) == "" {
		log.Fatal("vulos-relayd: -domain is required (or VULOS_RELAY_DOMAIN)")
	}

	// CONSOLIDATION A-1: a negative cap would be an operator error meaning
	// "unbounded" — refuse it. 0 falls through to the server-side default (256
	// MiB); any positive value is honored verbatim.
	if *maxReqBytes < 0 {
		log.Fatal("vulos-relayd: -max-request-bytes (VULOS_RELAY_MAX_REQUEST_BYTES) must be >= 0 (0=default, never unbounded)")
	}

	// Build the optional CP client. Metering/gating require both the URL and the
	// shared secret; if either is missing we run unbilled and warn.
	var cp *server.CPClient
	if *cpURL != "" && *cpSecret != "" {
		pid := *popID
		if pid == "" {
			pid = "relay-" + sanitizePoP(*domain)
		}
		cp = &server.CPClient{BaseURL: *cpURL, SharedSecret: *cpSecret, PoPID: pid, Region: *region}
		log.Printf("vulos-relayd: Vulos Cloud billing ENABLED cp=%s pop=%s region=%q", *cpURL, pid, *region)
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
		switch {
		case err == nil:
		case errors.Is(err, errNoGrants) && rolesWithoutTunnel(*enableRDV, *enablePubCache):
			// ROLE-ONLY MODE. A node serving ONLY the rendezvous (and/or pubcache)
			// role has no reverse tunnels to authorize, so demanding agent grants
			// was a startup gate with nothing behind it — operators worked around
			// it by inventing a dummy token that authorized a box that did not
			// exist, which is strictly worse than no grant at all.
			//
			// Fail-closed is preserved, not relaxed: we proceed with an EMPTY grant
			// set, so the tunnel surface authorizes NOBODY. Any agent that connects
			// is rejected. This is "no tunnels", never "open tunnels".
			log.Printf("vulos-relayd: no agent grants — running ROLE-ONLY (%s); the reverse-tunnel surface authorizes nobody",
				enabledRoleNames(*enableRDV, *enablePubCache))
			store = server.NewDenyAllTokenStore()
		default:
			log.Fatalf("vulos-relayd: %v", err)
		}
		if store == nil {
			st, err := server.NewStaticTokenStoreWithRevoked(grants, revoked)
			if err != nil {
				log.Fatalf("vulos-relayd: token store: %v", err)
			}
			store = st
		}
	}

	srv, err := server.New(server.Config{
		Domain:             *domain,
		Tokens:             store,
		EnablePathMode:     *pathMode,
		TrustProxyHeaders:  *trustProxy,
		MaxAgents:          *maxAgents,
		MaxRequestBytes:    *maxReqBytes,
		RequestBodyTimeout: *reqBodyTimeout,
		CP:                 cp,

		NodeID:   *nodeID,
		Region:   *region,
		Provider: *provider,
		SoftCapacity: autoscale.Capacity{
			MaxAgents:      *softMaxAgents,
			MaxStreams:     *softMaxStreams,
			MaxBytesPerSec: *softMaxBPS,
		},
		SaturationSamplePeriod: *satPeriod,

		PublicEndpoint:    *publicEndpoint,
		HeartbeatPeriod:   *heartbeat,
		HostMemLimitBytes: *hostMemLimit,

		ControlConnRate:  *ctrlRate,
		ControlConnBurst: *ctrlBurst,
		PublicReqRate:    *reqRate,
		PublicReqBurst:   *reqBurst,
		GlobalReqRate:    *globalRate,
		GlobalReqBurst:   *globBurst,

		DirectProbeRate:  *probeRate,
		DirectProbeBurst: *probeBurst,

		RevokeSweepPeriod: *revokeSweep,

		EnablePubCache: *enablePubCache,
		PubCache: pubcache.Config{
			PathPrefix:          *pcPrefix,
			Upstreams:           splitCSV(*pcUpstreams),
			MaxObjectBytes:      *pcMaxObject,
			MaxCacheBytes:       *pcMaxCache,
			TTL:                 *pcTTL,
			UpstreamTimeout:     *pcUpstreamTO,
			MaxUpstreamInflight: *pcInflight,
			ServeFeeds:          *pcServeFeeds,
			ServeProofs:         *pcServeProofs,

			PinDir:         *pcPinDir,
			PinKeys:        splitCSV(*pcPinKeys),
			PinMaxBytes:    *pcPinMaxBytes,
			PinMaxPinBytes: *pcPinMaxPin,
			PinMaxPins:     *pcPinMaxPins,
		},

		EnableRendezvous: *enableRDV,
		Rendezvous: rendezvous.Config{
			PathPrefix:           *rdvPrefix,
			DisablePublicResolve: *rdvNoResolve,
			ICE: rendezvous.ICEConfig{
				STUNURLs:          splitCSV(*rdvStun),
				DisablePublicSTUN: *rdvNoPubStun,
				TURNURLs:          splitCSV(*rdvTurn),
				TURNSecret:        *rdvTurnSecret,
				TURNCredentialTTL: *rdvTurnTTL,
			},
		},
	})
	if err != nil {
		log.Fatalf("vulos-relayd: %v", err)
	}

	log.Printf("vulos-relayd: listening on %s domain=%s pathMode=%v agents<=%d",
		*addr, *domain, *pathMode, *maxAgents)
	if *nodeID != "" || *region != "" {
		log.Printf("vulos-relayd: pool node id=%q region=%q provider=%q", *nodeID, *region, *provider)
	}
	if cp != nil && *publicEndpoint != "" {
		log.Printf("vulos-relayd: CP PoP heartbeat ENABLED endpoint=%s (registers + heartbeats load; CP drain control on the admin surface)", *publicEndpoint)
	}
	if *softMaxAgents > 0 || *softMaxStreams > 0 || *softMaxBPS > 0 {
		log.Printf("vulos-relayd: saturation sampler ON (soft caps agents=%d streams=%d bps=%d) — vulos_relay_saturation_ratio on /metrics",
			*softMaxAgents, *softMaxStreams, *softMaxBPS)
	}
	if *enableRDV {
		turn := "STUN-only"
		if *rdvTurn != "" && *rdvTurnSecret != "" {
			turn = "STUN+TURN(ephemeral creds)"
		}
		log.Printf("vulos-relayd: RENDEZVOUS role ENABLED prefix=%s ice=%s (announce/resolve/signal/mailbox on the apex host; content-blind, CP-optional)", *rdvPrefix, turn)
	}
	if *enablePubCache {
		feeds := "content-addressed reads only"
		if *pcServeFeeds {
			feeds = "content-addressed reads + mutable feed passthrough (never cached)"
		}
		log.Printf("vulos-relayd: PUBCACHE (DMTAP-PUB cache/pin) role ENABLED prefix=%s upstreams=%d %s", *pcPrefix, len(splitCSV(*pcUpstreams)), feeds)
		if *pcServeProofs {
			log.Printf("vulos-relayd: pubcache CHUNK-TREE RANGE PROOFS ENABLED (FEEDS.md § 5.3, optional) — manifest/{id}/proof?chunk=i serves an O(log n) audit path for verified seek/resume; clients still verify locally")
		}
		if *pcPinDir != "" {
			keys := len(splitCSV(*pcPinKeys))
			log.Printf("vulos-relayd: pubcache DURABLE PINNING ENABLED dir=%s authorized-keys=%d (pins survive restart, are never evicted by cache pressure, and are verified on first serve)", *pcPinDir, keys)
			if keys == 0 {
				log.Printf("vulos-relayd: pubcache pin store accepts NO new pins — set -pubcache-pin-keys to authorize who may spend this disk (it still serves pins it already holds)")
			}
			log.Printf("vulos-relayd: pubcache pin budget is HARD — a pin over it is refused with 507, never admitted by dropping another pin; usage counters at %s/pins/status", *pcPrefix)
		}
		log.Printf("vulos-relayd: NOTE this role serves PUBLIC PLAINTEXT you can read (dmtap § 22.6.1) — unlike the tunnel/mailbox/rendezvous roles it is NOT content-blind; every object is verified against its content address before it is cached or served")
	}
	if *trustProxy {
		log.Printf("vulos-relayd: TRUSTING X-Forwarded-* from a fronting proxy (ensure a trusted TLS-terminating edge fronts this relay)")
	} else {
		log.Printf("vulos-relayd: OVERWRITING X-Forwarded-* with observed peer (directly internet-facing; client IP spoofing prevented)")
	}

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

// splitCSV splits a comma-separated flag value into trimmed, non-empty items.
func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
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

// errNoGrants is returned by loadGrants when no grant source is configured at
// all. It is a hard failure for a reverse-tunnel relay (refusing to run open) but
// a legitimate configuration for a node that serves only the rendezvous and/or
// pubcache roles — see the ROLE-ONLY branch at the token-store setup.
var errNoGrants = errors.New("no grants: set -tokens-file or VULOS_RELAY_TOKENS (refusing to run open)")

// rolesWithoutTunnel reports whether at least one non-tunnel role is enabled, i.e.
// whether this process still has a job to do with an empty grant set.
func rolesWithoutTunnel(rendezvous, pubcache bool) bool { return rendezvous || pubcache }

// enabledRoleNames renders the enabled non-tunnel roles for the startup log.
func enabledRoleNames(rendezvous, pubcache bool) string {
	var roles []string
	if rendezvous {
		roles = append(roles, "rendezvous")
	}
	if pubcache {
		roles = append(roles, "pubcache")
	}
	if len(roles) == 0 {
		return "none"
	}
	return strings.Join(roles, "+")
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
		return nil, errNoGrants
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

// envInt64 reads an int64 from env k, falling back to def when unset/unparseable.
func envInt64(k string, def int64) int64 {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

// envDuration reads a time.Duration from env k, falling back to def when
// unset/unparseable.
func envDuration(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
