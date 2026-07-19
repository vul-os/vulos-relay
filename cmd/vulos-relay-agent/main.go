// Command vulos-relay-agent is a thin CLI around tunnel/agent. It dials a Vulos
// relay server over wss, registers a token-authorized name, and reverse-proxies a
// single local port to the public internet — no inbound ports, no static IP.
//
// Example:
//
//	vulos-relay-agent -server wss://relay.example.com -token SECRET1 \
//	    -name box1 -local 127.0.0.1:8080
//
// The agent binds NOTHING inbound and only ever forwards to -local.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/agent"
)

func main() {
	var (
		serverURL = flag.String("server", os.Getenv("VULOS_RELAY_SERVER"), "relay server URL, e.g. wss://relay.example.com")
		token     = flag.String("token", os.Getenv("VULOS_RELAY_TOKEN"), "agent bearer token")
		name      = flag.String("name", os.Getenv("VULOS_RELAY_NAME"), "public name to claim (must be token-authorized)")
		local     = flag.String("local", "127.0.0.1:8080", "local target host:port (must be loopback)")
		insecure  = flag.Bool("insecure", false, "skip TLS verification (testing only)")
		direct    = flag.String("direct", os.Getenv("VULOS_RELAY_DIRECT_ENDPOINT"), "optional public https:// base URL this box is ALSO directly reachable at (DIRECT-IP fast path); relay verifies reachability+ownership before advertising it")

		// SMART-AUTOSCALE routing hook: when -directory is set, the agent asks the CP
		// for its assigned PoP (nearest + least-loaded) on connect AND reconnect, and
		// migrates to a fresh PoP when its current one drains. Empty => dial -server
		// statically (self-host / single relay).
		directory = flag.String("directory", os.Getenv("VULOS_RELAY_DIRECTORY"), "CP/directory base URL for assigned-PoP resolution (empty=use -server statically)")
		region    = flag.String("region", os.Getenv("VULOS_RELAY_REGION"), "preferred region hint sent to the directory")
	)
	flag.Parse()

	// SECURITY (LOW): -insecure disables TLS verification of the control connection —
	// the SAME connection that carries the agent's bearer TOKEN. With it on, a
	// network attacker can MITM the relay, present any certificate, harvest the token,
	// and impersonate the box. It exists ONLY for local testing against a self-signed
	// relay on loopback. Warn LOUDLY at runtime so it can never be shipped silently;
	// against a NON-loopback target it is especially dangerous, so shout even louder.
	if *insecure {
		loud := func(msg string) {
			log.Printf("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n%s\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", msg)
		}
		if serverIsLoopback(*serverURL) {
			loud("WARNING: -insecure is set — TLS verification of the relay control\n" +
				"connection (which bears your token) is DISABLED. This is for LOCAL\n" +
				"TESTING ONLY. Never use -insecure against a real relay.")
		} else {
			loud("DANGER: -insecure is set AGAINST A NON-LOOPBACK relay (" + *serverURL + ").\n" +
				"TLS verification of the token-bearing control connection is DISABLED —\n" +
				"any network attacker can MITM the relay, STEAL YOUR TOKEN, and\n" +
				"impersonate your box. -insecure is for LOCAL TESTING ONLY. Remove it\n" +
				"and use a properly-issued certificate (or a pinned CA via TLSConfig).")
		}
	}

	a := agent.New(agent.Options{
		ServerURL:          *serverURL,
		Token:              *token,
		Name:               *name,
		LocalAddr:          *local,
		InsecureSkipVerify: *insecure,
		DirectEndpoint:     *direct,
		DirectoryURL:       *directory,
		Region:             *region,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := a.Start(ctx); err != nil {
		log.Fatalf("vulos-relay-agent: %v", err)
	}

	// Poll the snapshot for status transitions and log them.
	go func() {
		last := agent.StatusStopped
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				snap := a.Snapshot()
				if snap.Status != last {
					last = snap.Status
					switch snap.Status {
					case agent.StatusConnected:
						log.Printf("connected: %s", snap.PublicURL)
					case agent.StatusError:
						log.Printf("error: %s", snap.LastError)
					default:
						log.Printf("status: %s", snap.Status)
					}
				}
			}
		}
	}()

	<-ctx.Done()
	a.Stop()
	log.Print("vulos-relay-agent: stopped")
}

// serverIsLoopback reports whether the relay server URL points at a loopback host
// (localhost / 127.0.0.0/8 / ::1). Used only to decide how loud the -insecure
// warning should be. A parse failure or unknown host is treated as NON-loopback
// (the more dangerous case), so we never under-warn.
func serverIsLoopback(serverURL string) bool {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
