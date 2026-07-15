package agent

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/vul-os/vulos-relay/tunnel/internal/wire"
)

// fakeRelayPeer plays the server half of ONE control connection over serverConn:
// it reads the Register frame, acks OK, becomes the yamux client, then ends the
// session after a beat — simulating a normal server-side session drop that makes
// connectOnce return so the maintain loop would reconnect.
func fakeRelayPeer(serverConn net.Conn) {
	dec := json.NewDecoder(io.LimitReader(serverConn, wire.MaxControlMessage))
	var reg wire.Register
	if err := dec.Decode(&reg); err != nil {
		serverConn.Close()
		return
	}
	_ = json.NewEncoder(serverConn).Encode(wire.RegisterAck{
		Type: "register_ack", OK: true, PublicURL: "https://box.relay.test",
	})
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	sess, err := yamux.Client(serverConn, cfg)
	if err != nil {
		serverConn.Close()
		return
	}
	// Hold the session very briefly so connectOnce reaches Accept, then drop it.
	time.Sleep(10 * time.Millisecond)
	_ = sess.Close()
	_ = serverConn.Close()
}

// TestConnectOnce_NoGoroutineLeakPerSession is the regression guard for the
// per-reconnect goroutine leak: connectOnce spawned a `<-ctx.Done()` watcher on
// the LONG-LIVED maintain-loop context, so every session that ended (a reconnect)
// left one goroutine blocked until the whole agent stopped. Under reconnect churn
// this grows without bound. The watcher is now bound to a per-connection context
// that is cancelled when connectOnce returns, so goroutine count stays flat across
// many sessions sharing one live parent context.
func TestConnectOnce_NoGoroutineLeakPerSession(t *testing.T) {
	a := New(Options{
		ServerURL: "ws://relay.test", Token: "t", Name: "box",
		LocalAddr:        "127.0.0.1:1",
		HandshakeTimeout: 2 * time.Second,
	})

	// One long-lived context shared across every connectOnce, exactly like the real
	// maintain loop's loopCtx that outlives each individual session.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runOne := func() {
		clientConn, serverConn := net.Pipe()
		a.dialHook = func(context.Context, string) (net.Conn, error) { return clientConn, nil }
		go fakeRelayPeer(serverConn)
		if _, err := a.connectOnce(ctx, a.opts.ServerURL, nil); err != nil {
			t.Fatalf("connectOnce: %v", err)
		}
	}

	// Warm up (first run allocates lazily-created runtime goroutines).
	for i := 0; i < 3; i++ {
		runOne()
	}
	settle(t)
	base := runtime.NumGoroutine()

	const cycles = 40
	for i := 0; i < cycles; i++ {
		runOne()
	}
	settle(t)
	after := runtime.NumGoroutine()

	// Allow a small slack for scheduler/runtime noise; the pre-fix leak grew by ~1
	// goroutine per cycle (i.e. ~40), so a tolerance well under `cycles` catches it.
	if after-base > 10 {
		t.Fatalf("goroutine leak across reconnects: base=%d after=%d (grew %d over %d cycles)",
			base, after, after-base, cycles)
	}
}

// settle lets transient goroutines from a just-ended session wind down before we
// sample runtime.NumGoroutine(), so the assertion measures the steady state.
func settle(t *testing.T) {
	t.Helper()
	prev := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		runtime.GC()
		n := runtime.NumGoroutine()
		if n <= prev {
			prev = n
			// two consecutive non-increasing samples ⇒ settled
			if i > 0 {
				return
			}
		} else {
			prev = n
		}
	}
}
