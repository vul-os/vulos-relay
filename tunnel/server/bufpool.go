package server

import (
	"io"
	"sync"
)

// bufpool.go — EFFICIENCY: the relay is bandwidth-bound (bytes are direct COGS)
// and carries ALL box/app traffic, so the per-byte forwarding path must not
// allocate. io.Copy allocates a fresh 32 KiB scratch buffer on every call when the
// source/destination expose no ReaderFrom/WriterTo fast-path (a yamux stream does
// not), which on a busy relay is one 32 KiB allocation PER request body and PER
// WebSocket direction. We instead reuse a pool of fixed buffers via io.CopyBuffer,
// so steady-state forwarding does zero per-request buffer allocation.
//
// The buffer size (64 KiB) matches the agent's bufio reader and is a good tradeoff
// between syscall count and memory: larger buffers cut read/write syscalls on big
// transfers without bloating per-stream memory. Buffers are returned to the pool
// after each copy, so concurrent streams reuse a small working set rather than
// each holding its own.
const copyBufSize = 64 << 10 // 64 KiB

var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, copyBufSize)
		return &b
	},
}

// pooledCopy is io.Copy with a pooled scratch buffer — no per-call allocation. It
// still honors any ReaderFrom/WriterTo fast-path io.CopyBuffer detects (e.g. a
// splice-capable *net.TCPConn), falling back to the pooled buffer otherwise.
func pooledCopy(dst io.Writer, src io.Reader) (int64, error) {
	bp := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bp)
	return io.CopyBuffer(dst, src, *bp)
}
