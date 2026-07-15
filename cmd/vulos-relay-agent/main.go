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
	"os"
	"os/signal"
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
