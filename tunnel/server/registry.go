package server

import (
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// session is one live agent connection: a yamux client session (the server opens
// streams into the agent) keyed by the name it serves.
type session struct {
	name      string
	accountID string // Vulos account this agent's token is linked to ("" = unbilled)
	// token is the raw bearer secret this session authenticated with, retained so
	// the WAVE41-RELAY-REVOCATION sweep can recheck it against the static
	// revoked-list mid-session. It lives only in memory for the session lifetime
	// (the token was already in memory to authenticate); it is never logged or sent
	// anywhere. Empty for sessions created before revocation was wired (e.g. tests).
	token     string
	mux       *yamux.Session
	createdAt time.Time

	mu      sync.Mutex
	streams int // concurrent in-flight streams (for per-agent stream cap)
	limit   int
}

// acquireStream reserves a stream slot; returns false if the per-agent cap is hit.
func (s *session) acquireStream() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.limit > 0 && s.streams >= s.limit {
		return false
	}
	s.streams++
	return true
}

func (s *session) releaseStream() {
	s.mu.Lock()
	if s.streams > 0 {
		s.streams--
	}
	s.mu.Unlock()
}

// reconnectWindow bounds how soon after a name departs a new registration for the
// same name is counted as a "reconnect" (for the observability metric). It also
// bounds the size of the recentlyLeft map (entries older than this are pruned).
const reconnectWindow = 2 * time.Minute

// registry maps names -> live sessions and enforces collision + agent-count caps.
type registry struct {
	mu        sync.RWMutex
	byName    map[string]*session
	maxAgents int

	// recentlyLeft records when each name last departed, so a fresh registration
	// for the same name within reconnectWindow can be reported as a reconnect. It is
	// pruned on each add so it stays bounded by the churn within one window.
	recentlyLeft map[string]time.Time
}

func newRegistry(maxAgents int) *registry {
	return &registry{
		byName:       make(map[string]*session),
		maxAgents:    maxAgents,
		recentlyLeft: make(map[string]time.Time),
	}
}

// add registers a session for name. It fails if the name is already held (no
// hijacking) or the global agent cap is reached. On success it returns a release
// func the caller must defer to remove the session when the connection ends, plus
// reconnect=true when this name departed within the reconnect window (observability).
func (r *registry) add(s *session) (release func(), reconnect bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byName[s.name]; exists {
		return nil, false, fmt.Errorf("name %q already in use", s.name)
	}
	if r.maxAgents > 0 && len(r.byName) >= r.maxAgents {
		return nil, false, fmt.Errorf("relay at capacity")
	}
	// Reconnect detection + prune of the recentlyLeft map (bounded cleanup).
	now := time.Now()
	if left, ok := r.recentlyLeft[s.name]; ok {
		if now.Sub(left) <= reconnectWindow {
			reconnect = true
		}
		delete(r.recentlyLeft, s.name)
	}
	for n, t := range r.recentlyLeft {
		if now.Sub(t) > reconnectWindow {
			delete(r.recentlyLeft, n)
		}
	}
	r.byName[s.name] = s
	return func() {
		r.mu.Lock()
		// Only remove if it's still THIS session (guards a fast reconnect race).
		if cur, ok := r.byName[s.name]; ok && cur == s {
			delete(r.byName, s.name)
			r.recentlyLeft[s.name] = time.Now()
		}
		r.mu.Unlock()
	}, reconnect, nil
}

// lookup returns the live session for name, if any.
func (r *registry) lookup(name string) (*session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.byName[name]
	return s, ok
}

func (r *registry) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byName)
}

// snapshot returns the current live sessions as a slice. The revocation sweep
// uses it so it can recheck + close sessions WITHOUT holding the registry lock
// (mux.Close can block; closing under the lock would stall connects/routes).
func (r *registry) snapshot() []*session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*session, 0, len(r.byName))
	for _, s := range r.byName {
		out = append(out, s)
	}
	return out
}
