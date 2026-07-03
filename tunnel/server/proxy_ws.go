package server

import (
	"bufio"
	"net"
	"net/http"
	"time"
)

// proxyWebSocket handles a public-side WebSocket upgrade. It hijacks the client
// connection, forwards the upgrade request to the agent over the yamux stream,
// relays the agent's 101 response, then splices bytes in both directions.
//
// Unlike the plain-HTTP path, hop-by-hop stripping must PRESERVE the Upgrade and
// Connection headers so the tunneled app performs the handshake; we still strip
// other hop-by-hop headers and set X-Forwarded-*.
func (s *Server) proxyWebSocket(w http.ResponseWriter, outReq *http.Request, stream net.Conn, accountID string) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket unsupported", http.StatusInternalServerError)
		return
	}

	// Re-add the upgrade headers that sanitizeRequestHeaders stripped, so the agent
	// and local app see a valid upgrade request. r.Clone copied the originals into
	// outReq before stripping; restore from the still-intact original values.
	// (outReq shares the header map semantics of a clone, so set explicitly.)
	restoreUpgradeHeaders(outReq)

	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	// Forward the upgrade request to the agent.
	if err := outReq.Write(stream); err != nil {
		return
	}

	// Read the agent's response head (expected 101) and write it verbatim to client.
	agentBr := bufio.NewReader(stream)
	resp, err := http.ReadResponse(agentBr, outReq)
	if err != nil {
		writeRawError(clientConn, http.StatusBadGateway)
		return
	}
	if err := resp.Write(clientConn); err != nil {
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return // handshake refused by app; response already relayed
	}

	// Splice: client <-> agent stream, honoring any buffered bytes on each side.
	clientSide := wrapBuffered(clientConn, clientBuf.Reader)
	agentSide := wrapBuffered(stream, agentBr)
	// Meter spliced bytes (both directions) for the account. A nil meter or empty
	// account makes meterCopy a plain io.Copy.
	if s.meter.enabled() && accountID != "" {
		duplexCopyMetered(clientSide, agentSide, s.meter, accountID)
	} else {
		duplexCopy(clientSide, agentSide)
	}
}

// restoreUpgradeHeaders ensures the WS-critical headers survive to the agent.
func restoreUpgradeHeaders(req *http.Request) {
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
}

func writeRawError(c net.Conn, code int) {
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte("HTTP/1.1 " + http.StatusText(code) + "\r\nConnection: close\r\n\r\n"))
}
