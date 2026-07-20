package rendezvous

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"
)

// queue.go — the content-blind keyed blob queue that backs BOTH the short-TTL
// SIGNAL exchange and the longer-TTL MAILBOX.
//
// It is a store-and-forward buffer of OPAQUE blobs addressed to a recipient's
// public key: a sender DEPOSITs a blob for a recipient key, the holder of that
// key's private key PICKUPs pending blobs, then ACKs the ones it has consumed to
// delete them. The node never decrypts or interprets a blob — it moves bytes keyed
// by public key. The two instantiations differ only in caps:
//
//   - SIGNAL: tiny blobs, short TTL (WebRTC offer/answer/ICE that expire in seconds
//     to minutes; a live negotiation is worthless once stale).
//   - MAILBOX: larger blobs, TTL up to 48h (DMTAP §14.3-shaped: a buffer, not an
//     archive — a recipient offline past the TTL loses undelivered blobs; durability
//     lands at the recipient's edge once picked up).
//
// Both are bounded three ways so they cannot be used to exhaust the node: per-blob
// size, per-recipient quota (max blobs AND max total bytes), and TTL. A background
// sweep reaps expired blobs.

// queueCaps configures a queue's bounds.
type queueCaps struct {
	MaxBlobBytes   int           // per-blob ciphertext cap (bytes)
	MaxPerKeyBlobs int           // max pending blobs per recipient key
	MaxPerKeyBytes int64         // max total pending bytes per recipient key
	DefaultTTL     time.Duration // TTL applied when a deposit requests 0
	MaxTTL         time.Duration // hard TTL ceiling (a longer request is clamped)
	MaxKeys        int           // max distinct recipient keys (bounds memory)
	SweepEvery     time.Duration // reaper cadence
}

// blob is one stored, opaque, addressed item.
type blob struct {
	ID          string
	From        string // sender key (base64url); accountability, never a gate
	To          string // recipient key (base64url)
	Payload     []byte // opaque ciphertext — never inspected
	DepositedAt time.Time
	ExpiresAt   time.Time
}

// blobView is the pickup projection returned to the recipient (payload base64url).
type blobView struct {
	ID          string `json:"id"`
	From        string `json:"from"`
	Payload     string `json:"payload"` // base64url opaque bytes
	DepositedAt int64  `json:"ts"`
	ExpiresAt   int64  `json:"exp"`
}

// queue is a per-recipient-key set of pending blobs. Safe for concurrent use.
type queue struct {
	caps queueCaps

	mu    sync.Mutex
	byKey map[string][]*blob
	bytes map[string]int64 // per-key total pending bytes
	swep  time.Time
}

func newQueue(caps queueCaps) *queue {
	if caps.MaxKeys <= 0 {
		caps.MaxKeys = 100_000
	}
	if caps.SweepEvery <= 0 {
		caps.SweepEvery = time.Minute
	}
	return &queue{caps: caps, byKey: make(map[string][]*blob), bytes: make(map[string]int64)}
}

// deposit outcomes.
type depositResult int

const (
	depositOK        depositResult = iota
	depositTooLarge                // blob exceeds per-blob cap
	depositQuotaFull               // recipient at max blobs or max bytes
	depositCapacity                // node at max distinct keys (new recipient)
)

// clampTTL resolves a requested per-blob TTL (seconds) to the queue's range.
func (q *queue) clampTTL(seconds int) time.Duration {
	if seconds <= 0 {
		return q.caps.DefaultTTL
	}
	d := time.Duration(seconds) * time.Second
	if d > q.caps.MaxTTL {
		return q.caps.MaxTTL
	}
	return d
}

// deposit stores an opaque blob for recipient key `to`. The caller has already
// verified the sender signature, freshness, and recipient-key validity. It returns
// the assigned blob id on success, or a non-OK result when a cap is hit.
func (q *queue) deposit(from, to string, payload []byte, ttl time.Duration, now time.Time) (id string, res depositResult) {
	if len(payload) > q.caps.MaxBlobBytes {
		return "", depositTooLarge
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.sweepLocked(now)

	pending := q.byKey[to]
	if pending == nil {
		if len(q.byKey) >= q.caps.MaxKeys {
			return "", depositCapacity
		}
	}
	if len(pending) >= q.caps.MaxPerKeyBlobs {
		return "", depositQuotaFull
	}
	if q.bytes[to]+int64(len(payload)) > q.caps.MaxPerKeyBytes {
		return "", depositQuotaFull
	}

	id = newBlobID(now)
	b := &blob{
		ID:          id,
		From:        from,
		To:          to,
		Payload:     append([]byte(nil), payload...),
		DepositedAt: now,
		ExpiresAt:   now.Add(ttl),
	}
	q.byKey[to] = append(pending, b)
	q.bytes[to] += int64(len(payload))
	return id, depositOK
}

// pickup returns a snapshot of all non-expired pending blobs for recipient key
// `key`, WITHOUT deleting them (deletion is deferred to ack, so a crash between
// pickup and processing does not lose a blob — at-least-once delivery). Newest-last
// (deposit order). The caller has verified the recipient owns the key.
func (q *queue) pickup(key string, now time.Time) []blobView {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.sweepLocked(now)

	pending := q.byKey[key]
	out := make([]blobView, 0, len(pending))
	for _, b := range pending {
		if !now.Before(b.ExpiresAt) {
			continue
		}
		out = append(out, blobView{
			ID:          b.ID,
			From:        b.From,
			Payload:     b64.EncodeToString(b.Payload),
			DepositedAt: b.DepositedAt.Unix(),
			ExpiresAt:   b.ExpiresAt.Unix(),
		})
	}
	return out
}

// ack deletes the named blobs from recipient key `key`'s queue and returns how many
// were removed. Unknown ids are skipped (idempotent). The caller has verified the
// recipient owns the key.
func (q *queue) ack(key string, ids []string, now time.Time) int {
	if len(ids) == 0 {
		return 0
	}
	del := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		del[id] = struct{}{}
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	pending := q.byKey[key]
	if len(pending) == 0 {
		return 0
	}
	kept := pending[:0]
	removed := 0
	var freed int64
	for _, b := range pending {
		if _, drop := del[b.ID]; drop {
			removed++
			freed += int64(len(b.Payload))
			continue
		}
		kept = append(kept, b)
	}
	if len(kept) == 0 {
		delete(q.byKey, key)
		delete(q.bytes, key)
	} else {
		q.byKey[key] = kept
		q.bytes[key] -= freed
		if q.bytes[key] < 0 {
			q.bytes[key] = 0
		}
	}
	return removed
}

// sweepLocked reaps expired blobs at most ~once per SweepEvery. Caller holds q.mu.
func (q *queue) sweepLocked(now time.Time) {
	if now.Sub(q.swep) < q.caps.SweepEvery {
		return
	}
	q.swep = now
	for key, pending := range q.byKey {
		kept := pending[:0]
		var live int64
		for _, b := range pending {
			if now.Before(b.ExpiresAt) {
				kept = append(kept, b)
				live += int64(len(b.Payload))
			}
		}
		if len(kept) == 0 {
			delete(q.byKey, key)
			delete(q.bytes, key)
		} else {
			q.byKey[key] = kept
			q.bytes[key] = live
		}
	}
}

// newBlobID mints a sortable, collision-resistant opaque id: 6 bytes of the deposit
// time (ms) for rough time-ordering + 10 random bytes, base64url. It carries no
// recipient/sender identity.
func newBlobID(now time.Time) string {
	var raw [16]byte
	ms := uint64(now.UnixMilli())
	// low 48 bits of the ms timestamp, big-endian, in the first 6 bytes.
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], ms)
	copy(raw[0:6], t[2:8])
	_, _ = rand.Read(raw[6:])
	return b64.EncodeToString(raw[:])
}
