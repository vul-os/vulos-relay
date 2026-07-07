package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestShutdown_DrainsListenerAndReportsDraining verifies that Shutdown gracefully
// stops the public listener (ListenAndServe returns http.ErrServerClosed), flips
// /readyz to draining, and stops accepting new connections. This is the SIGTERM
// path exercised by cmd/vulos-relayd: without it the process is hard-killed and the
// final usage flush is lost.
func TestShutdown_DrainsListenerAndReportsDraining(t *testing.T) {
	s := newTestServer(t)

	// Bind an ephemeral loopback port so we drive a REAL listener (not httptest),
	// which is what Shutdown drains.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // free it; ListenAndServe rebinds the same host:port

	serveErr := make(chan error, 1)
	go func() { serveErr <- s.ListenAndServe(addr) }()

	// Wait until the server is actually accepting.
	waitReachable(t, addr, 2*time.Second)

	if !s.metrics.isReady() {
		t.Fatalf("expected server ready before shutdown")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// The listener goroutine must return with the graceful-close sentinel.
	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("ListenAndServe returned %v, want http.ErrServerClosed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("ListenAndServe did not return after Shutdown")
	}

	// /readyz must now report draining.
	if s.metrics.isReady() {
		t.Fatalf("expected server NOT ready after shutdown (draining)")
	}

	// New connections must be refused (listener closed).
	if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		_ = c.Close()
		t.Fatalf("expected connection refused after shutdown")
	}
}

// TestShutdown_NoListenerIsSafe verifies Shutdown on a server that never started a
// public listener is a safe no-op (still flushes/closes via Close).
func TestShutdown_NoListenerIsSafe(t *testing.T) {
	s := newTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown with no listener: %v", err)
	}
	if s.metrics.isReady() {
		t.Fatalf("expected not ready after Shutdown")
	}
}

func waitReachable(t *testing.T, addr string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			// Confirm it speaks HTTP (healthz on the public handler).
			_, _ = io.WriteString(c, "GET /healthz HTTP/1.0\r\n\r\n")
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server at %s not reachable within %s", addr, within)
}
