package server

// sfuhost.go — SFU-HOST REGISTRY (Vulos Meet SFU Phase 2, BYO / self-host).
//
// A self-hoster who wants to run BIG calls on their OWN infra installs the SFU
// worker next to their box (the in-process Pion SFU, or a co-located vulos-meet
// LiveKit server) and REGISTERS it here as an available SFU host. When a call
// escalates past the mesh cap, the box asks this registry to RESOLVE a reachable
// SFU endpoint and hands it back to the client as the join serverUrl.
//
// This mirrors the GPU streaming-host pattern (STREAM-BYO-01) almost verbatim,
// and REUSES — unchanged — the same direct-endpoint verifier the relay already
// runs for a box's tunnel fast-path (directprobe.go): a nonce-echo,
// SSRF-guarded, DNS-rebind-defended proof that the advertised endpoint is (a)
// reachable over the public internet and (b) actually controlled by the
// registrant. The verifier is protocol-agnostic — it proves endpoint ownership,
// not "is a streamer" — so an SFU endpoint is verified with the SAME code.
//
// Wire shape (HTTPS, JSON) on the relay's public listener:
//
//	POST {relay}/api/meet/host/register      → 200 {host}  (verifies endpoint)
//	POST {relay}/api/meet/host/heartbeat     → 200         (refreshes TTL)
//	POST {relay}/api/meet/host/deregister    → 200
//	GET  {relay}/api/meet/host/resolve       → 200 {allocation}
//
// Auth: register/heartbeat/deregister require the SAME bearer token + name grant
// the box uses for its tunnel (TokenStore.Authorize) AND pass the account
// relay-entitlement gate (fail-closed for billed accounts; an unbilled "" token
// is always allowed — self-host). The resolve lookup is read-only routing info
// (a public serverUrl); it carries no user data and mutates nothing, so it needs
// no auth — the SFU's own token gate (VULOS-MEET/1) still admits every joiner.
//
// INERT BY DEFAULT: the registry is empty until a box registers, so resolve
// returns available=false and the caller falls back to whatever static serverUrl
// it already had (unchanged Phase-1 behavior). Registration is additionally
// opt-in behind Config.EnableSFUHostRegistry so a relay that does not want to run
// the placement layer rejects registers outright.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SFU-host registry routes on the relay's public listener.
const (
	sfuHostRegisterPath   = "/api/meet/host/register"
	sfuHostHeartbeatPath  = "/api/meet/host/heartbeat"
	sfuHostDeregisterPath = "/api/meet/host/deregister"
	sfuHostResolvePath    = "/api/meet/host/resolve"
)

// sfuHostTTL is how long a registered SFU host lives without a heartbeat before it
// is pruned. It must be comfortably longer than the box's heartbeat cadence so a
// single missed beat does not evict a live host. The box heartbeats every ~30s.
const sfuHostTTL = 90 * time.Second

// maxSFUHostBody bounds a registration/heartbeat request body.
const maxSFUHostBody = 8 << 10 // 8 KiB

// sfuHostCapabilities describes what a registered SFU host can serve. It is
// advisory matchmaking metadata surfaced to the allocation step; the SFU's own
// token gate is the security boundary, not these fields.
type sfuHostCapabilities struct {
	// MaxParticipants is the host's per-room participant cap (the Pion SFU is 50).
	MaxParticipants int `json:"max_participants"`
	// HasE2EE reports whether the host supports client-side E2EE (insertable
	// streams / SFrame). For a self-host / BYO host this is typically false — the
	// operator owns the media node, so no E2EE is needed (§4, LOCKED stance).
	HasE2EE bool `json:"has_e2ee"`
	// Region is an optional locality hint (e.g. "eu"). Informational for Phase 2.
	Region string `json:"region,omitempty"`
	// Codec is the negotiated video codec (informational).
	Codec string `json:"codec,omitempty"`
}

// sfuHostRegistration is the JSON wire shape POSTed to register/heartbeat. It
// deliberately mirrors gpuhost.HostRegistration so the box side is a near-copy.
type sfuHostRegistration struct {
	// HostID is the stable fabric identifier (the box's VulaID). Required.
	HostID string `json:"host_id"`
	// PublicKeyB64 is the box's Ed25519 public key (informational at Phase 2; the
	// endpoint ownership proof is the nonce echo, not a signature over this).
	PublicKeyB64 string `json:"public_key_b64,omitempty"`
	// Domain is the box's fabric authority domain (informational).
	Domain string `json:"domain,omitempty"`
	// Name is the token-authorized tunnel name this box serves. It is the name the
	// bearer token grants; register is refused if the token does not authorize it.
	Name string `json:"name"`
	// Endpoint is the advertised SFU serverUrl the client should connect to: a
	// public https:// (or wss://-equivalent https origin) base URL. It is verified
	// (reachable + owned) via the SAME directprobe verifier before it is stored.
	Endpoint string `json:"endpoint"`
	// Capabilities is advisory matchmaking metadata.
	Capabilities sfuHostCapabilities `json:"capabilities"`
}

// sfuHostRecord is a stored, VERIFIED SFU host. It is only ever created from a
// registration whose Endpoint fully passed verifyDirectEndpoint.
type sfuHostRecord struct {
	hostID           string
	name             string
	verifiedEndpoint string // normalized, verified endpoint (never the raw claim)
	caps             sfuHostCapabilities
	accountID        string
	expires          time.Time
}

// sfuHostRegistry holds VERIFIED SFU hosts keyed by hostID, with TTL pruning.
// Safe for concurrent use. Empty until a box registers ⇒ resolve is inert.
type sfuHostRegistry struct {
	mu    sync.Mutex
	hosts map[string]*sfuHostRecord
}

func newSFUHostRegistry() *sfuHostRegistry {
	return &sfuHostRegistry{hosts: make(map[string]*sfuHostRecord)}
}

// put stores/refreshes a verified host with a fresh TTL, enforcing the
// ONE-OWNER-PER-NAME invariant that pick() relies on. On the SHARED cloud relay
// (VULOS_RELAY_CP_TOKENS=1) the CP validates a token → account but allows ANY
// normalized name for that account, and record identity is the hostID — so two
// DIFFERENT accounts (each a valid endpoint owner) could otherwise both register
// under the SAME tunnel name, and pick(name) — which selects by name only — would
// route account A's big-call media to account B's SFU (cross-tenant leak, P1-2).
//
// put therefore REFUSES when a LIVE record already exists under the same name
// owned by a DIFFERENT accountID. Same-account re-register/update stays allowed
// (a box replacing its own hostID under its own name); an expired collider is
// pruned and the slot is free again. Fail-closed: the name's first live owner
// keeps it until it lapses.
func (r *sfuHostRegistry) put(rec *sfuHostRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for id, existing := range r.hosts {
		if now.After(existing.expires) {
			delete(r.hosts, id) // prune expired as we scan — frees any lapsed name
			continue
		}
		if existing.name == rec.name && existing.accountID != rec.accountID {
			// A different account already owns this live tunnel name. Refuse rather
			// than overwrite, so account A can never be hijacked onto account B's SFU.
			return errNameOwnedByOtherAccount
		}
	}
	rec.expires = now.Add(sfuHostTTL)
	r.hosts[rec.hostID] = rec
	return nil
}

// errNameOwnedByOtherAccount is returned by put when a live record under the same
// tunnel name is owned by a different account (the cross-tenant collision).
var errNameOwnedByOtherAccount = errors.New("sfu host name already owned by another account")

// refresh extends the TTL of an existing host (heartbeat). Returns false if the
// host is unknown/expired — the caller then re-registers (re-verifies).
func (r *sfuHostRegistry) refresh(hostID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.hosts[hostID]
	if !ok || time.Now().After(rec.expires) {
		if ok {
			delete(r.hosts, hostID) // prune the expired entry we just observed
		}
		return false
	}
	rec.expires = time.Now().Add(sfuHostTTL)
	return true
}

// remove deregisters a host.
func (r *sfuHostRegistry) remove(hostID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.hosts, hostID)
}

// pick returns a live (unexpired) host registered under name to allocate a big
// call to, pruning any expired entries it walks past. Selection is SCOPED BY
// name (the box's token-authorized tunnel name): the relay is SHARED across many
// accounts, so an unscoped "first live host" would hand box B's clients box A's
// SFU endpoint — a cross-tenant routing leak. A box therefore only ever resolves
// a host it itself registered under its own name. An empty name matches nothing
// (fail-closed). A name has at most ONE live owning account — put() refuses a
// cross-account collision at register time (P1-2) — so selecting by name here
// cannot straddle tenants even on the shared CP-token relay. Phase 2 selection
// among a single name's own hosts is "first live"; PEER-25's richer election
// refines it later. Returns nil when none is live.
func (r *sfuHostRegistry) pick(name string) *sfuHostRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	if name == "" {
		return nil
	}
	now := time.Now()
	var chosen *sfuHostRecord
	for id, rec := range r.hosts {
		if now.After(rec.expires) {
			delete(r.hosts, id)
			continue
		}
		if chosen == nil && rec.name == name {
			chosen = rec
		}
	}
	return chosen
}

// sfuHostResolveResponse is the allocation lookup reply.
type sfuHostResolveResponse struct {
	// Available reports whether a reachable SFU host is registered. When false the
	// caller falls back to its static serverUrl (Phase-1 behavior) — inert default.
	Available bool `json:"available"`
	// ServerURL is the verified endpoint the client should join (direct-first).
	// Empty when Available is false.
	ServerURL string `json:"server_url,omitempty"`
	// HostID/Region/MaxParticipants/HasE2EE echo the chosen host's metadata.
	HostID          string `json:"host_id,omitempty"`
	Region          string `json:"region,omitempty"`
	MaxParticipants int    `json:"max_participants,omitempty"`
	HasE2EE         bool   `json:"has_e2ee,omitempty"`
}

// handleSFUHostRegister verifies the advertised endpoint (reusing directprobe)
// and stores the host. It authenticates the bearer token + name grant and passes
// the entitlement gate before verifying, so an unauthorized box can never make
// the relay probe an arbitrary target (defense-in-depth on top of the SSRF guard
// already inside the verifier).
func (s *Server) handleSFUHostRegister(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.EnableSFUHostRegistry {
		http.Error(w, "sfu host registry disabled", http.StatusNotFound)
		return
	}
	reg, ok := decodeSFUHostBody(w, r)
	if !ok {
		return
	}
	accountID, ok := s.authorizeSFUHost(w, r, reg.Name)
	if !ok {
		return
	}
	// Verify the advertised endpoint NOW (reachable + ownership-proven) with the
	// SAME verifier the tunnel fast-path uses — unchanged. A verification failure
	// is fatal for registration (unlike a tunnel, an SFU host with no reachable
	// endpoint is useless): the host is simply not registered and the caller falls
	// back to its static serverUrl.
	if s.directVerifier == nil {
		http.Error(w, "direct verification disabled", http.StatusServiceUnavailable)
		return
	}
	if strings.TrimSpace(reg.Endpoint) == "" {
		http.Error(w, "endpoint required", http.StatusBadRequest)
		return
	}
	probeCtx, cancel := context.WithTimeout(r.Context(), directProbeTimeout+2*time.Second)
	norm, verr := s.directVerifier.verify(probeCtx, reg.Endpoint)
	cancel()
	if verr != nil {
		s.metrics.directRejected()
		s.logInfo("sfu host endpoint rejected", logFields{Name: reg.Name, Account: accountID, Reason: verr.Error()})
		http.Error(w, "endpoint verification failed", http.StatusBadGateway)
		return
	}
	s.metrics.directVerified()
	if err := s.sfuHosts.put(&sfuHostRecord{
		hostID: reg.HostID,
		// Store the NORMALIZED name (the same form authorizeSFUHost validated the
		// token grant against) so a name-scoped resolve matches deterministically —
		// register authorized "box1" but reg.Name may be "Box1".
		name:             normalizeName(reg.Name),
		verifiedEndpoint: norm,
		caps:             reg.Capabilities,
		accountID:        accountID,
	}); err != nil {
		// A different account already owns this live tunnel name. Refuse fail-closed
		// so the shared relay never routes the name's owner onto this registrant's
		// SFU (cross-tenant media leak, P1-2). The rightful owner keeps the name.
		s.metrics.authFail(authFailUnauthorized)
		s.logInfo("sfu host name collision refused", logFields{Name: reg.Name, Account: accountID, Reason: err.Error()})
		http.Error(w, "sfu host name already in use", http.StatusConflict)
		return
	}
	s.logInfo("sfu host registered", logFields{Name: reg.Name, Account: accountID})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "host_id": reg.HostID, "endpoint": norm})
}

// handleSFUHostHeartbeat refreshes a registered host's TTL. If the host is
// unknown/expired it returns 404 so the box re-registers (which re-verifies).
func (s *Server) handleSFUHostHeartbeat(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.EnableSFUHostRegistry {
		http.Error(w, "sfu host registry disabled", http.StatusNotFound)
		return
	}
	reg, ok := decodeSFUHostBody(w, r)
	if !ok {
		return
	}
	if _, ok := s.authorizeSFUHost(w, r, reg.Name); !ok {
		return
	}
	if !s.sfuHosts.refresh(reg.HostID) {
		http.Error(w, "not registered", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleSFUHostDeregister removes a registered host.
func (s *Server) handleSFUHostDeregister(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.EnableSFUHostRegistry {
		http.Error(w, "sfu host registry disabled", http.StatusNotFound)
		return
	}
	reg, ok := decodeSFUHostBody(w, r)
	if !ok {
		return
	}
	if _, ok := s.authorizeSFUHost(w, r, reg.Name); !ok {
		return
	}
	s.sfuHosts.remove(reg.HostID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleSFUHostResolve is the allocation lookup: it returns the reachable SFU
// endpoint the CALLER'S OWN box registered (direct-first via the verified
// endpoint), or available=false when none is. Read-only, unauthenticated (public
// routing info only; the SFU's own token gate admits joiners) — but SCOPED BY the
// required ?name= param so the shared relay never hands one tenant's SFU endpoint
// to another tenant's clients. A missing/empty/unmatched name is available=false.
func (s *Server) handleSFUHostResolve(w http.ResponseWriter, r *http.Request) {
	// name scopes the lookup to the caller's own registration on this shared relay.
	// It is the box's tunnel name (VULOS_RELAY_NAME); normalized to match storage.
	name := normalizeName(r.URL.Query().Get("name"))
	if name == "" {
		writeJSON(w, http.StatusOK, sfuHostResolveResponse{Available: false})
		return
	}
	// When registration is disabled the registry is always empty, so this
	// naturally returns available=false — the caller keeps its static serverUrl.
	rec := s.sfuHosts.pick(name)
	if rec == nil {
		writeJSON(w, http.StatusOK, sfuHostResolveResponse{Available: false})
		return
	}
	writeJSON(w, http.StatusOK, sfuHostResolveResponse{
		Available:       true,
		ServerURL:       rec.verifiedEndpoint,
		HostID:          rec.hostID,
		Region:          rec.caps.Region,
		MaxParticipants: rec.caps.MaxParticipants,
		HasE2EE:         rec.caps.HasE2EE,
	})
}

// authorizeSFUHost validates the bearer token against the claimed name and passes
// the account entitlement gate. Mirrors the control-path auth so the SAME grant
// that authorizes a box's tunnel authorizes its SFU-host registration. Returns
// the resolved account ("" = unbilled/self-host, always allowed) on success.
func (s *Server) authorizeSFUHost(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	// Per-source throttle to match the control path's abuse posture.
	if !s.ctrlLimiter.allow(s.clientIP(r)) {
		s.metrics.rateLimitReject(limitControl)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return "", false
	}
	token := bearer(r)
	if token == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", false
	}
	nn := normalizeName(name)
	if nn == "" {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return "", false
	}
	accountID, err := s.cfg.Tokens.Authorize(token, nn)
	if err != nil {
		s.metrics.authFail(authFailUnauthorized)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", false
	}
	if !s.gate.allowConnect(accountID) {
		s.metrics.authFail(authFailEntitlement)
		http.Error(w, "relay not permitted for this account", http.StatusForbidden)
		return "", false
	}
	return accountID, true
}

// decodeSFUHostBody reads + bounds the registration JSON. It requires host_id and
// name (the two fields every op keys on); endpoint is required only for register
// (checked by the register handler).
func decodeSFUHostBody(w http.ResponseWriter, r *http.Request) (sfuHostRegistration, bool) {
	var reg sfuHostRegistration
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSFUHostBody))
	if err := dec.Decode(&reg); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return sfuHostRegistration{}, false
	}
	if strings.TrimSpace(reg.HostID) == "" || strings.TrimSpace(reg.Name) == "" {
		http.Error(w, "host_id and name required", http.StatusBadRequest)
		return sfuHostRegistration{}, false
	}
	return reg, true
}

// writeJSON writes a JSON body with a status code.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
