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

// registry maps names -> live sessions and enforces collision + agent-count caps.
type registry struct {
	mu        sync.RWMutex
	byName    map[string]*session
	maxAgents int
}

func newRegistry(maxAgents int) *registry {
	return &registry{byName: make(map[string]*session), maxAgents: maxAgents}
}

// add registers a session for name. It fails if the name is already held (no
// hijacking) or the global agent cap is reached. On success it returns a release
// func the caller must defer to remove the session when the connection ends.
func (r *registry) add(s *session) (func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byName[s.name]; exists {
		return nil, fmt.Errorf("name %q already in use", s.name)
	}
	if r.maxAgents > 0 && len(r.byName) >= r.maxAgents {
		return nil, fmt.Errorf("relay at capacity")
	}
	r.byName[s.name] = s
	return func() {
		r.mu.Lock()
		// Only remove if it's still THIS session (guards a fast reconnect race).
		if cur, ok := r.byName[s.name]; ok && cur == s {
			delete(r.byName, s.name)
		}
		r.mu.Unlock()
	}, nil
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
