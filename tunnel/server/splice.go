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

// duplexCopy copies bytes in both directions until either side closes.
func duplexCopy(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
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

// duplexCopyObserved is duplexCopy that (WAVE24-RELAY-BILLING) meters the total
// bytes spliced in BOTH directions to the account when account != "", and
// (WAVE50-RELAY-OBSERVABILITY) always records them in the duplex-direction
// proxied-bytes metric. It never blocks the data path — both updates are cheap
// in-memory adds per io.Copy chunk.
func duplexCopyObserved(a, b net.Conn, m *meter, account string, mx *metrics) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		n, _ := io.Copy(dst, src)
		if n > 0 {
			if account != "" {
				m.addBytes(account, n)
			}
			mx.proxiedBytes(dirDuplex, n)
		}
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
