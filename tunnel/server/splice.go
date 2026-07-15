package server

import (
	"bufio"
	"io"
	"net"
	"time"
)

// bufferedConn pairs a net.Conn with a reader that may hold bytes already buffered
// past a header boundary (from bufio peeking), so raw splicing sees the full stream.
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func wrapBuffered(c net.Conn, br *bufio.Reader) net.Conn {
	if br == nil {
		return c
	}
	return &bufferedConn{Conn: c, r: io.MultiReader(br, c)}
}

// duplexCopyObserved (WAVE24-RELAY-BILLING) meters the bytes spliced in BOTH
// directions to the account when account != "", and (WAVE50-RELAY-OBSERVABILITY)
// always records them in the duplex-direction proxied-bytes metric.
//
// Metering is INCREMENTAL, per read chunk (see meterReader) — NOT deferred to the
// end of each direction's io.Copy. A WebSocket can stay open for hours moving many
// GB; counting only at close meant a periodic flush saw nothing until the socket
// died and a drain/redeploy/crash before close lost ALL those bytes (a revenue
// hole). Per-chunk accounting makes every flush — including the final shutdown
// drain — capture the bytes moved so far. It never blocks the data path (each add
// is a cheap in-memory counter bump). The two directions bump the SAME account
// concurrently; addBytes is mutex-guarded, so this is race-clean.
func duplexCopyObserved(a, b net.Conn, m *meter, account string, mx *metrics) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, &meterReader{r: src, meter: m, account: account, metrics: mx, dir: dirDuplex})
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.SetReadDeadline(time.Now())
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}
