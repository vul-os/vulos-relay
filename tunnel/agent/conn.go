package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"github.com/vul-os/vulos-relay/tunnel/internal/keepalive"
	"github.com/vul-os/vulos-relay/tunnel/internal/wire"
)

const controlPath = wire.ControlPath

// connectOutcome tells the supervise loop how a session ended.
type connectOutcome int

const (
	// outcomeEnded: the session dropped (error or clean close) — the loop should
	// re-resolve + re-dial after a backoff.
	outcomeEnded connectOutcome = iota
	// outcomeHandedOff: a graceful reconnect launched a make-before-break SUCCESSOR
	// goroutine that now owns the tunnel — this loop must exit WITHOUT re-dialing.
	outcomeHandedOff
)

// handoffTimeout bounds how long a graceful reconnect keeps the OLD session alive
// while waiting for the successor to connect. Within it the migration is zero-drop
// (both sides briefly up); if the new PoP is slow to accept, the old session is
// still wound down and the successor keeps retrying (a brief gap only in that
// degraded case).
const handoffTimeout = 20 * time.Second

// maintain runs the tunnel supervisor: resolve the assigned PoP (routing hook),
// dial -> register -> serve, then back off and retry until ctx is cancelled. A
// graceful drain reconnect hands the tunnel to a successor goroutine and this loop
// exits.
func (a *Agent) maintain(ctx context.Context) {
	a.superviseFrom(ctx, "", nil)
}

// superviseFrom is the supervise loop. firstEndpoint, when non-empty, is dialed on
// the FIRST iteration (a graceful handoff passes the successor's already-resolved
// PoP); otherwise the endpoint is resolved each iteration via the routing hook.
// ready, when non-nil, is closed once the FIRST session of this loop reaches
// connected — a predecessor waits on it to know the successor is live before winding
// down (make-before-break).
func (a *Agent) superviseFrom(ctx context.Context, firstEndpoint string, ready chan struct{}) {
	backoff := 500 * time.Millisecond
	endpoint := firstEndpoint
	for {
		if ctx.Err() != nil {
			return
		}
		if endpoint == "" {
			endpoint = a.resolveEndpoint(ctx) // routing hook: nearest/least-loaded PoP
		}
		outcome, err := a.connectOnce(ctx, endpoint, ready)
		ready = nil   // only the first successful connect signals the predecessor
		endpoint = "" // re-resolve on the next iteration (drain → new PoP)
		if outcome == outcomeHandedOff {
			return // a successor goroutine owns the tunnel now
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			a.setStatus(StatusError, "", err.Error())
			a.appendLog("connection error: %v", err)
		} else {
			// Clean session end (server closed / stream loop ended); treat as retryable.
			a.setStatus(StatusStarting, "", "")
			a.appendLog("session ended; reconnecting")
		}

		// Exponential backoff with full jitter, capped.
		sleep := time.Duration(rand.Int63n(int64(backoff) + 1))
		select {
		case <-ctx.Done():
			return
		case <-time.After(sleep):
		}
		backoff *= 2
		if backoff > a.opts.MaxBackoff {
			backoff = a.opts.MaxBackoff
		}
	}
}

// connectOnce establishes one control connection to endpoint, registers, and serves
// yamux streams until the session drops, ctx is cancelled, or a graceful-reconnect
// signal triggers a make-before-break handoff.
func (a *Agent) connectOnce(ctx context.Context, endpoint string, ready chan struct{}) (connectOutcome, error) {
	dialCtx, cancel := context.WithTimeout(ctx, a.opts.HandshakeTimeout)
	defer cancel()

	conn, err := a.dial(dialCtx, endpoint)
	if err != nil {
		return outcomeEnded, fmt.Errorf("dial: %w", err)
	}
	// Ensure the raw conn is closed when we leave (yamux also owns it, but this is
	// belt-and-suspenders for the error paths before yamux takes over).
	defer conn.Close()

	ack, err := a.register(conn)
	if err != nil {
		return outcomeEnded, fmt.Errorf("register: %w", err)
	}

	a.setStatus(StatusConnected, ack.PublicURL, "")
	// DIRECT-IP: record the relay's verdict on our advertised direct endpoint.
	a.setDirectResult(ack.DirectEndpoint, ack.DirectVerified, ack.DirectError)
	a.appendLog("connected: public URL %s", ack.PublicURL)
	if a.opts.DirectEndpoint != "" {
		if ack.DirectVerified {
			a.appendLog("direct fast-path verified: %s", ack.DirectEndpoint)
		} else {
			a.appendLog("direct endpoint not used (relay only): %s", ack.DirectError)
		}
	}
	// Signal a waiting predecessor that this (successor) session is live, so it can
	// wind down its old session — the make-before-break overlap that makes a drain
	// zero-drop.
	if ready != nil {
		close(ready)
	}

	// The agent is the yamux SERVER (accepts streams the relay opens).
	session, err := yamux.Server(conn, yamuxConfig())
	if err != nil {
		return outcomeEnded, fmt.Errorf("yamux: %w", err)
	}
	defer session.Close()

	// Close the session if ctx is cancelled so Accept unblocks. Use a
	// per-connection context that is cancelled when connectOnce returns (defer
	// below) so this watcher goroutine does NOT outlive the session: the maintain
	// loop's ctx lives for the whole agent lifetime, so watching it directly would
	// leak one goroutine (and pin one dead session) per reconnect under churn.
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()
	go func() {
		<-connCtx.Done()
		session.Close()
	}()

	// Adaptive keepalive (replaces yamux's built-in, disabled in yamuxConfig): ping
	// the relay on an interval that lengthens while this box's tunnel is idle and
	// restores on activity. A ping failure means the relay is gone ⇒ close the
	// session so the Accept loop below unwinds and the maintain loop reconnects.
	// connCtx bounds the goroutine to this connection's lifetime (no leak on churn).
	go func() {
		if err := keepalive.Run(connCtx, session, agentKeepalive(), time.Now); err != nil {
			session.Close()
		}
	}()

	// Accept streams in a goroutine so the main select can ALSO watch for a graceful
	// reconnect request without blocking on Accept.
	sessErr := make(chan error, 1)
	go func() {
		for {
			stream, err := session.Accept()
			if err != nil {
				sessErr <- err
				return
			}
			go a.serveStream(stream)
		}
	}()

	select {
	case <-ctx.Done():
		return outcomeEnded, nil
	case err := <-sessErr:
		if ctx.Err() != nil {
			return outcomeEnded, nil
		}
		if errors.Is(err, io.EOF) || errors.Is(err, yamux.ErrSessionShutdown) {
			return outcomeEnded, nil // retryable clean end
		}
		return outcomeEnded, fmt.Errorf("accept: %w", err)
	case reason := <-a.reconnectReq:
		return a.gracefulHandoff(ctx, session, reason), nil
	}
}

// gracefulHandoff performs a PROACTIVE, make-before-break migration to the agent's
// re-resolved PoP: it launches a SUCCESSOR supervise goroutine (which resolves a
// fresh PoP — a draining source PoP is no longer handed out — and dials it), waits
// (bounded) for the successor to connect, THEN winds down the OLD session. Because
// the old tunnel stays up until the new one is live, a drain migrates with no
// dropped connectivity. Returns outcomeHandedOff so the caller's loop exits (the
// successor now owns the tunnel).
func (a *Agent) gracefulHandoff(ctx context.Context, old *yamux.Session, reason string) connectOutcome {
	a.appendLog("graceful reconnect (reason=%q): migrating to a fresh PoP", reason)
	ready := make(chan struct{})
	a.handoffWG.Add(1)
	go func() {
		defer a.handoffWG.Done()
		// Successor resolves its OWN endpoint (re-query the directory → new PoP).
		a.superviseFrom(ctx, "", ready)
	}()

	// Wait for the successor to connect (zero-drop overlap), bounded so a slow new
	// PoP cannot pin the old session forever.
	select {
	case <-ready:
		a.appendLog("successor PoP connected; winding down old tunnel")
	case <-ctx.Done():
		return outcomeHandedOff
	case <-time.After(handoffTimeout):
		a.appendLog("successor did not connect within handoff window; winding down old tunnel anyway")
	}

	// GoAway tells the relay to stop opening NEW streams on the old session; in-flight
	// streams are given a brief grace period to finish before the session closes.
	_ = old.GoAway()
	a.drainOldSession(old)
	_ = old.Close()
	return outcomeHandedOff
}

// drainOldSession waits briefly for in-flight streams on a superseded session to
// finish before it is closed, so a graceful reconnect does not sever requests that
// were already mid-flight. Bounded so a stuck stream cannot delay the handoff.
func (a *Agent) drainOldSession(sess *yamux.Session) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sess.NumStreams() == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// dial opens the control websocket to endpoint (or the test hook) and returns a
// net.Conn.
func (a *Agent) dial(ctx context.Context, endpoint string) (net.Conn, error) {
	if a.dialHook != nil {
		return a.dialHook(ctx, endpoint)
	}
	target, err := controlURL(endpoint)
	if err != nil {
		return nil, err
	}

	tlsCfg := a.opts.TLSConfig
	if a.opts.InsecureSkipVerify {
		if tlsCfg == nil {
			tlsCfg = &tls.Config{}
		} else {
			tlsCfg = tlsCfg.Clone()
		}
		tlsCfg.InsecureSkipVerify = true
	}
	httpClient := &http.Client{}
	if tlsCfg != nil {
		httpClient.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	}

	c, _, err := websocket.Dial(ctx, target, &websocket.DialOptions{
		Subprotocols: []string{wire.Subprotocol},
		HTTPHeader: http.Header{
			"Authorization": {"Bearer " + a.opts.Token},
		},
		HTTPClient: httpClient,
	})
	if err != nil {
		return nil, err
	}
	// Unlimited read: yamux frames + tunneled bodies can be large; the server caps
	// request/response sizes, and we cap the local dial. websocket.NetConn gives us
	// a net.Conn we can hand to yamux.
	c.SetReadLimit(-1)
	return websocket.NetConn(context.Background(), c, websocket.MessageBinary), nil
}

// register performs the JSON handshake over the control conn and returns the
// server's ack (public URL + DIRECT-IP verdict).
func (a *Agent) register(conn net.Conn) (wire.RegisterAck, error) {
	_ = conn.SetDeadline(a.opts.now().Add(a.opts.HandshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	req := wire.Register{
		Type:         "register",
		Name:         a.opts.Name,
		Token:        a.opts.Token,
		AgentVersion: "vulos-relay-agent/0.2",
		// DIRECT-IP: advertise our optional direct endpoint (untrusted until the
		// relay verifies it).
		DirectEndpoint: a.opts.DirectEndpoint,
	}
	if err := json.NewEncoder(conn).Encode(&req); err != nil {
		return wire.RegisterAck{}, fmt.Errorf("write register: %w", err)
	}

	// Bounded read of the ack.
	dec := json.NewDecoder(io.LimitReader(conn, wire.MaxControlMessage))
	var ack wire.RegisterAck
	if err := dec.Decode(&ack); err != nil {
		return wire.RegisterAck{}, fmt.Errorf("read ack: %w", err)
	}
	if !ack.OK {
		msg := ack.Error
		if msg == "" {
			msg = "registration rejected"
		}
		return wire.RegisterAck{}, errors.New(msg)
	}
	return ack, nil
}

func yamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.LogOutput = io.Discard
	// Adaptive keepalive: yamux's built-in keepalive is disabled and replaced by
	// keepalive.Run (see connectOnce), which pings at agentKeepalive Base while
	// active and backs off to Idle when the tunnel is idle — reducing standing
	// heartbeat cost without dropping the tunnel. ConnectionWriteTimeout still bounds
	// each ping's dead-peer detection.
	c.EnableKeepAlive = false
	c.ConnectionWriteTimeout = 15 * time.Second
	return c
}

// agentKeepalive is the box side's adaptive keepalive policy. Base (20s) matches the
// previous fixed interval; Idle (60s) applies once no streams have been served for
// IdleAfter. Worst-case dead-idle-peer detection is Idle + ConnectionWriteTimeout
// (~75s), bounded.
func agentKeepalive() keepalive.Params {
	return keepalive.Params{
		Base:      20 * time.Second,
		Idle:      60 * time.Second,
		IdleAfter: 2 * time.Minute,
	}
}

// bufferedConn pairs a net.Conn with a Reader that may already hold buffered
// bytes (from bufio peeking), so downstream reads see the full stream.
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func newBufferedConn(c net.Conn, br *bufio.Reader) net.Conn {
	return &bufferedConn{Conn: c, r: io.MultiReader(br, c)}
}
