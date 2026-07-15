// metering_stream_test.go — byte-accounting correctness for the relay's EGRESS
// paths. These pin the fix for a real revenue hole: before it, the HTTP response
// body and the WebSocket duplex splice added their bytes to the meter ONLY when
// io.Copy finally returned (i.e. at connection close), so a long-lived stream open
// across a flush — or killed by a drain/redeploy/crash before it closed — was
// silently unmetered. meterReader now counts per read chunk, so every flush
// (including the shutdown drain) captures the bytes moved so far.
//
// The tests here prove: (1) in-flight bytes reach the CP via a flush WHILE the
// stream is still open; (2) both directions of the duplex splice are attributed
// to the account; (3) the accounting is exact under concurrency (run with -race);
// and (4) the usage envelope carries the per-region tag the billing meter prices on.
package server

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// meterPending reads (without draining) the pending byte delta for an account, so a
// test can observe metering as it accrues mid-stream.
func meterPending(m *meter, acct string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d := m.pending[acct]; d != nil {
		return d.bytes
	}
	return 0
}

// waitForPending blocks (briefly) until the account's pending delta reaches want,
// failing the test on timeout. Used because meterReader.addBytes runs just AFTER
// the underlying Read returns, so a producer's write may return a hair before the
// counter is bumped.
func waitForPending(t *testing.T, m *meter, acct string, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if meterPending(m, acct) >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for pending bytes >= %d (have %d)", want, meterPending(m, acct))
}

// TestMeterReader_InFlightBytesReachCPBeforeClose is the headline regression: a
// stream that is STILL OPEN must already be metered, and a flush during it must
// deliver those bytes to the CP. Previously the bytes only landed at io.Copy
// completion, so an interrupted long-lived stream lost everything.
func TestMeterReader_InFlightBytesReachCPBeforeClose(t *testing.T) {
	fake := newFakeCP("shh")
	srv := fake.server(t)
	cp := &CPClient{BaseURL: srv.URL, SharedSecret: "shh", PoPID: "pop-1", Region: "eu-central"}
	m := newMeter(cp, time.Hour) // manual flush only — nothing but our flushOnce delivers

	pr, pw := io.Pipe()
	mr := &meterReader{r: pr, meter: m, account: "acct-1", metrics: newMetrics(), dir: dirOutbound}

	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, mr) // the "client" draining the response body
		close(copyDone)
	}()

	// Stream a first chunk; the stream stays OPEN (pw not closed).
	first := bytes.Repeat([]byte("x"), 1000)
	go func() { _, _ = pw.Write(first) }()
	waitForPending(t, m, "acct-1", 1000)

	// Flush WHILE the stream is open: the in-flight bytes must reach the CP.
	m.flushOnce()
	if b, _ := fake.totals("acct-1"); b != 1000 {
		t.Fatalf("in-flight flush should have delivered 1000 bytes to the CP, got %d", b)
	}

	// Stream more, close, drain, and confirm the running total.
	second := bytes.Repeat([]byte("y"), 500)
	go func() { _, _ = pw.Write(second); _ = pw.Close() }()
	<-copyDone
	m.flushOnce()
	if b, _ := fake.totals("acct-1"); b != 1500 {
		t.Fatalf("total after close should be 1500, got %d", b)
	}
}

// TestDuplexCopyObserved_BothDirectionsMetered proves the WebSocket splice path
// attributes BOTH directions' bytes to the account and records them in the duplex
// metric. Uses net.Pipe pairs to drive real bytes through the actual splice code.
func TestDuplexCopyObserved_BothDirectionsMetered(t *testing.T) {
	m := newMeter(nil, time.Hour) // pure in-memory accounting (addBytes needs no CP)
	mx := newMetrics()

	a, aTest := net.Pipe() // 'a' is spliced; aTest is our handle to a's peer
	b, bTest := net.Pipe() // 'b' is spliced; bTest is our handle to b's peer

	payloadX := bytes.Repeat([]byte("X"), 4096) // travels b -> a (read from b)
	payloadY := bytes.Repeat([]byte("Y"), 2048) // travels a -> b (read from a)

	got1 := make([]byte, len(payloadX))
	got2 := make([]byte, len(payloadY))

	var dwg sync.WaitGroup
	dwg.Add(1)
	go func() { defer dwg.Done(); duplexCopyObserved(a, b, m, "acct-dup", mx) }()

	var rwg sync.WaitGroup
	rwg.Add(2)
	go func() { defer rwg.Done(); _, _ = io.ReadFull(aTest, got1) }() // receives payloadX
	go func() { defer rwg.Done(); _, _ = io.ReadFull(bTest, got2) }() // receives payloadY

	var wwg sync.WaitGroup
	wwg.Add(2)
	go func() { defer wwg.Done(); _, _ = bTest.Write(payloadX) }() // -> b -> a -> aTest
	go func() { defer wwg.Done(); _, _ = aTest.Write(payloadY) }() // -> a -> b -> bTest

	wwg.Wait()
	rwg.Wait() // both payloads fully received => both meterReader.Read/addBytes have run

	// Tear down so the splice unwinds, then assert the exact accounting.
	_ = a.Close()
	_ = b.Close()
	dwg.Wait()

	if !bytes.Equal(got1, payloadX) {
		t.Fatalf("b->a direction corrupted: %d bytes", len(got1))
	}
	if !bytes.Equal(got2, payloadY) {
		t.Fatalf("a->b direction corrupted: %d bytes", len(got2))
	}
	want := int64(len(payloadX) + len(payloadY))
	items := m.drain()
	var total int64
	for _, it := range items {
		if it.AccountID == "acct-dup" {
			total = it.Bytes
		}
	}
	if total != want {
		t.Fatalf("duplex metered %d bytes for the account, want %d (both directions)", total, want)
	}
	if mx.bytes[dirDuplex].get() != uint64(want) {
		t.Fatalf("duplex metric = %d, want %d", mx.bytes[dirDuplex].get(), want)
	}
}

// TestMeterReader_ConcurrentAccountingExact drives many concurrent metered copies
// into the SAME account and asserts the total is exact — no lost or double-counted
// bytes under concurrency. Run with -race to prove the addBytes path is race-clean
// now that it is hit per-chunk from multiple splice goroutines at once.
func TestMeterReader_ConcurrentAccountingExact(t *testing.T) {
	m := newMeter(nil, time.Hour)
	mx := newMetrics()

	const goroutines = 64
	const chunk = 4096
	payload := bytes.Repeat([]byte("z"), chunk)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			mr := &meterReader{r: bytes.NewReader(payload), meter: m, account: "hot", metrics: mx, dir: dirOutbound}
			// A tiny copy buffer forces MANY Read calls => many concurrent addBytes.
			_, _ = io.CopyBuffer(io.Discard, mr, make([]byte, 64))
		}()
	}
	wg.Wait()

	want := int64(goroutines * chunk)
	items := m.drain()
	var total int64
	for _, it := range items {
		if it.AccountID == "hot" {
			total = it.Bytes
		}
	}
	if total != want {
		t.Fatalf("concurrent metering total = %d, want %d (lost/double-counted bytes)", total, want)
	}
	if mx.bytes[dirOutbound].get() != uint64(want) {
		t.Fatalf("outbound metric = %d, want %d", mx.bytes[dirOutbound].get(), want)
	}
}

// TestMeterReader_UnbilledNotMetered confirms an empty account (unbilled / self-host
// token) accrues NO per-account usage while STILL being counted in the direction
// metric — so self-host traffic is observable but never billed.
func TestMeterReader_UnbilledNotMetered(t *testing.T) {
	m := newMeter(nil, time.Hour)
	mx := newMetrics()
	mr := &meterReader{r: bytes.NewReader(bytes.Repeat([]byte("q"), 2048)), meter: m, account: "", metrics: mx, dir: dirInbound}
	_, _ = io.Copy(io.Discard, mr)

	if items := m.drain(); len(items) != 0 {
		t.Fatalf("unbilled traffic must not accrue account usage, got %d items", len(items))
	}
	if mx.bytes[dirInbound].get() != 2048 {
		t.Fatalf("unbilled traffic must still be counted in the direction metric, got %d", mx.bytes[dirInbound].get())
	}
}

// TestCPClient_UsageStampsRegion proves per-region attribution: the usage envelope
// carries this PoP's region tag (so the CP prices GB per-region), and an empty
// region is omitted from the wire. HMAC is validated by the fake, so this also
// confirms adding the region field did not break the signature contract.
func TestCPClient_UsageStampsRegion(t *testing.T) {
	fake := newFakeCP("shh")
	srv := fake.server(t)

	cpEU := &CPClient{BaseURL: srv.URL, SharedSecret: "shh", PoPID: "pop-eu-1", Region: "eu-central"}
	if _, err := cpEU.ReportUsage(context.Background(), "rid-eu", []usageItem{{AccountID: "a", Bytes: 10}}); err != nil {
		t.Fatalf("report eu: %v", err)
	}
	if region, pop := fake.lastEnvelopeMeta(); region != "eu-central" || pop != "pop-eu-1" {
		t.Fatalf("region attribution: region=%q pop=%q, want eu-central / pop-eu-1", region, pop)
	}

	// A different region (Fly Africa) on the same CP resolves independently — this is
	// what lets the billing meter price the SAME account's GB differently by PoP.
	cpAF := &CPClient{BaseURL: srv.URL, SharedSecret: "shh", PoPID: "pop-af-1", Region: "af-south"}
	if _, err := cpAF.ReportUsage(context.Background(), "rid-af", []usageItem{{AccountID: "a", Bytes: 20}}); err != nil {
		t.Fatalf("report af: %v", err)
	}
	if region, pop := fake.lastEnvelopeMeta(); region != "af-south" || pop != "pop-af-1" {
		t.Fatalf("region attribution: region=%q pop=%q, want af-south / pop-af-1", region, pop)
	}

	// An unset region is OMITTED from the wire (omitempty) so the CP can apply its
	// own default/flat rate rather than mis-reading "" as a real region.
	var gotRaw string
	rawSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		gotRaw = string(body)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(rawSrv.Close)
	cpNone := &CPClient{BaseURL: rawSrv.URL, SharedSecret: "shh", PoPID: "pop-x", Region: ""}
	if _, err := cpNone.ReportUsage(context.Background(), "rid-x", []usageItem{{AccountID: "a", Bytes: 1}}); err != nil {
		t.Fatalf("report none: %v", err)
	}
	if bytes.Contains([]byte(gotRaw), []byte(`"region"`)) {
		t.Fatalf("empty region must be omitted from the usage envelope, body=%s", gotRaw)
	}
}
