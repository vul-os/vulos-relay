package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"github.com/vul-os/vulos-relay/tunnel/internal/wire"
)

const wireControlPath = wire.ControlPath

// handleControl accepts an agent's wss control connection, authenticates it,
// registers its name, and becomes the yamux client for the session lifetime.
func (s *Server) handleControl(w http.ResponseWriter, r *http.Request) {
	// Pre-auth: the bearer token must be present in the Authorization header. We
	// validate token+name after reading the Register frame (the name comes from it),
	// but reject obviously-unauthenticated connections before the WS upgrade to
	// avoid spending an upgrade on anonymous clients.
	if bearer(r) == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{wire.Subprotocol},
		// The relay is same-origin-agnostic (agents are not browsers); but reject
		// browser cross-origin attempts by requiring our subprotocol.
	})
	if err != nil {
		return // Accept already wrote the error
	}
	c.SetReadLimit(-1)
	conn := websocket.NetConn(context.Background(), c, websocket.MessageBinary)

	// Read + validate the Register frame under a deadline.
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	name, token, ok := readRegister(conn)
	if !ok {
		writeAck(conn, wire.RegisterAck{Type: "register_ack", OK: false, Error: "bad registration"})
		c.Close(websocket.StatusPolicyViolation, "bad registration")
		return
	}

	// Prefer the Authorization header token, but accept the in-frame token too;
	// they must agree if both present. The frame token lets non-header transports
	// work; the header is what edge/CDN auth sees.
	authToken := bearer(r)
	if authToken != "" && token != "" && authToken != token {
		writeAck(conn, wire.RegisterAck{Type: "register_ack", OK: false, Error: "token mismatch"})
		c.Close(websocket.StatusPolicyViolation, "token mismatch")
		return
	}
	if authToken != "" {
		token = authToken
	}

	nn := normalizeName(name)
	if nn == "" {
		writeAck(conn, wire.RegisterAck{Type: "register_ack", OK: false, Error: "invalid name"})
		c.Close(websocket.StatusPolicyViolation, "invalid name")
		return
	}

	accountID, err := s.cfg.Tokens.Authorize(token, nn)
	if err != nil {
		// Never leak which check failed.
		writeAck(conn, wire.RegisterAck{Type: "register_ack", OK: false, Error: "unauthorized"})
		c.Close(websocket.StatusPolicyViolation, "unauthorized")
		return
	}

	// WAVE24-RELAY-BILLING: entitlement gate at CONNECT (fail closed). An account
	// whose relay entitlement is definitively denied — or that cannot be vetted
	// against the CP — is refused before we serve any tunnel. An empty accountID
	// (unbilled/self-host token) is always allowed. Mid-session fail-open is
	// handled per-request in the proxy path.
	if !s.gate.allowConnect(accountID) {
		writeAck(conn, wire.RegisterAck{Type: "register_ack", OK: false, Error: "relay not permitted for this account"})
		c.Close(websocket.StatusPolicyViolation, "entitlement denied")
		log.Printf("relay: entitlement denied account=%q name=%q", accountID, nn)
		return
	}

	// The server is the yamux CLIENT (it opens streams into the agent).
	mux, err := yamux.Client(conn, serverYamuxConfig())
	if err != nil {
		writeAck(conn, wire.RegisterAck{Type: "register_ack", OK: false, Error: "session error"})
		c.Close(websocket.StatusInternalError, "session error")
		return
	}

	sess := &session{
		name:      nn,
		accountID: accountID,
		mux:       mux,
		createdAt: time.Now(),
		limit:     s.cfg.MaxStreamsPerAgent,
	}
	release, err := s.registry.add(sess)
	if err != nil {
		// Name collision or capacity: fail closed, don't hijack.
		writeAck(conn, wire.RegisterAck{Type: "register_ack", OK: false, Error: "name unavailable"})
		mux.Close()
		c.Close(websocket.StatusPolicyViolation, "name unavailable")
		return
	}
	defer release()
	defer mux.Close()

	// Clear the handshake deadline; yamux keepalive governs liveness now.
	_ = conn.SetDeadline(time.Time{})

	if err := writeAck(conn, wire.RegisterAck{Type: "register_ack", OK: true, PublicURL: s.publicURL(nn)}); err != nil {
		return
	}
	log.Printf("relay: agent registered name=%q remote=%s", nn, clientIP(r))

	// Block until the session dies; yamux keepalive detects dead peers.
	<-mux.CloseChan()
	log.Printf("relay: agent unregistered name=%q", nn)
}

// readRegister decodes the bounded Register frame.
func readRegister(conn net.Conn) (name, token string, ok bool) {
	dec := json.NewDecoder(io.LimitReader(conn, wire.MaxControlMessage))
	var reg wire.Register
	if err := dec.Decode(&reg); err != nil {
		return "", "", false
	}
	if reg.Type != "register" {
		return "", "", false
	}
	return reg.Name, reg.Token, true
}

func writeAck(conn net.Conn, ack wire.RegisterAck) error {
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetWriteDeadline(time.Time{})
	return json.NewEncoder(conn).Encode(&ack)
}

// bearer extracts the token from an "Authorization: Bearer <t>" header.
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

func serverYamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.LogOutput = io.Discard
	c.EnableKeepAlive = true
	c.KeepAliveInterval = 10 * time.Second
	c.ConnectionWriteTimeout = 10 * time.Second
	return c
}
