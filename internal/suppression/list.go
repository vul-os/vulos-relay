// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package suppression

import (
	"strings"
	"sync"
	"time"
)

// Reason classifies why a recipient was suppressed.
type Reason string

const (
	// ReasonHardBounce is a permanent (5.x.x) delivery failure (RFC 3464 DSN).
	ReasonHardBounce Reason = "hard_bounce"

	// ReasonComplaint is an FBL/ARF abuse complaint (RFC 5965).
	ReasonComplaint Reason = "complaint"

	// ReasonManual is an operator-added suppression.
	ReasonManual Reason = "manual"
)

// Entry is a single suppression-list record.
type Entry struct {
	// Address is the normalised (lowercased) recipient address.
	Address string
	// Reason is why the address was suppressed.
	Reason Reason
	// Detail is an optional human-readable detail (e.g. the DSN status/diag).
	Detail string
	// At is when the suppression was recorded.
	At time.Time
}

// Observer is notified whenever an address is suppressed (for metrics). It must
// be non-blocking and safe for concurrent use. Nil disables observation.
type Observer interface {
	// Suppressed reports that a recipient was added to the list (or refreshed)
	// for the given reason.
	Suppressed(reason Reason)
	// Hit reports that a send was blocked because the recipient is suppressed.
	Hit(reason Reason)
}

// List is the recipient suppression list. It is safe for concurrent use.
//
// The zero value is not usable; call NewList.
type List struct {
	mu       sync.RWMutex
	entries  map[string]Entry
	observer Observer
}

// NewList returns an empty in-memory suppression list.
func NewList() *List {
	return &List{entries: make(map[string]Entry)}
}

// SetObserver installs an Observer for metrics. Safe to call before use begins.
func (l *List) SetObserver(o Observer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.observer = o
}

// normalize lowercases and trims an address for stable matching. It strips a
// surrounding pair of angle brackets ("<a@b>") commonly seen in DSN reports.
func normalize(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimPrefix(addr, "<")
	addr = strings.TrimSuffix(addr, ">")
	return strings.ToLower(strings.TrimSpace(addr))
}

// Suppress adds (or refreshes) addr on the list with the given reason. An empty
// or malformed address is ignored. It returns true if the address was newly
// added (false if it already existed).
func (l *List) Suppress(addr string, reason Reason, detail string) bool {
	n := normalize(addr)
	if n == "" || !strings.Contains(n, "@") {
		return false
	}
	l.mu.Lock()
	_, existed := l.entries[n]
	l.entries[n] = Entry{Address: n, Reason: reason, Detail: detail, At: time.Now()}
	obs := l.observer
	l.mu.Unlock()
	if obs != nil {
		obs.Suppressed(reason)
	}
	return !existed
}

// IsSuppressed reports whether addr is on the suppression list, and the matching
// entry if so. It records a metrics "hit" when a match is found.
func (l *List) IsSuppressed(addr string) (Entry, bool) {
	n := normalize(addr)
	l.mu.RLock()
	e, ok := l.entries[n]
	obs := l.observer
	l.mu.RUnlock()
	if ok && obs != nil {
		obs.Hit(e.Reason)
	}
	return e, ok
}

// Remove deletes addr from the suppression list (e.g. operator re-enables a
// recipient after they confirm the address is valid again). Returns true if an
// entry was removed.
func (l *List) Remove(addr string) bool {
	n := normalize(addr)
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.entries[n]
	delete(l.entries, n)
	return ok
}

// Len returns the number of suppressed addresses.
func (l *List) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}

// FilterRecipients partitions rcpts into those allowed to receive (not
// suppressed) and those dropped (suppressed). The returned slices preserve
// input order. A metrics "hit" is recorded for each dropped recipient.
func (l *List) FilterRecipients(rcpts []string) (allowed, dropped []string) {
	for _, r := range rcpts {
		if _, ok := l.IsSuppressed(r); ok {
			dropped = append(dropped, r)
		} else {
			allowed = append(allowed, r)
		}
	}
	return allowed, dropped
}
