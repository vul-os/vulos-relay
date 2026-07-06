package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// cpclient.go — WAVE24-RELAY-BILLING: the relay's client to Vulos Cloud (CP).
//
// The relay talks to the CP for two things, reusing the CP's existing seams:
//
//  1. Entitlement gate: GET /api/relay/entitlement — is this account allowed to
//     relay, and is it over quota? Presented as a SERVICE caller
//     (X-Relay-Auth: CP_SHARED_SECRET + ?account_id=) since the relay already
//     holds that shared secret for usage reporting.
//
//  2. Usage report: POST /api/relay/usage — per-account byte/session DELTAS with
//     an HMAC X-Pop-Sig over the body and a monotonic report_id (idempotent).
//
// It also backs the CPTokenStore, which resolves an agent's install credential
// to its account by asking the CP for that credential's entitlement (the CP
// resolves the Bearer install credential → account and echoes account_id).

// CPClient calls the Vulos control plane. It is safe for concurrent use.
type CPClient struct {
	// BaseURL is the CP origin, e.g. https://cloud.vulos.dev (no trailing slash).
	BaseURL string
	// SharedSecret is CP_SHARED_SECRET — used for the X-Pop-Sig HMAC on usage
	// reports and as the X-Relay-Auth service credential on entitlement reads.
	SharedSecret string
	// PoPID identifies this relay instance in usage reports (dedup is per-PoP).
	PoPID string
	// HTTP is the client used for CP calls; defaults to a bounded-timeout client.
	HTTP *http.Client
}

func (c *CPClient) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (c *CPClient) base() string { return strings.TrimRight(c.BaseURL, "/") }

// Entitlement is the relay-relevant subset of GET /api/relay/entitlement.
type Entitlement struct {
	AccountID    string `json:"account_id"`
	Tier         string `json:"tier"`
	RelayAllowed bool   `json:"relay_allowed"`
	OverQuota    bool   `json:"over_quota"`
	ByteCap      int64  `json:"byte_cap"`
	TurnCap      int    `json:"turn_cap"`
	// Revoked (WAVE41-RELAY-REVOCATION) is set by the CP when the credential or
	// account has been revoked. A revoked=true response is a DEFINITIVE revoke: the
	// connect is refused and any live tunnel is dropped on the next recheck. A CP
	// 404 for a previously-valid credential is treated the same way (see
	// ErrCredentialRevoked below).
	Revoked bool `json:"revoked"`
}

// ErrCredentialRevoked is returned by the entitlement reads when the CP
// DEFINITIVELY revokes a credential/account: either it answers 404 (Not Found —
// the credential no longer exists) or it returns revoked:true. It is distinct
// from a transient/unknown CP error so callers can fail CLOSED on a revoke while
// still failing OPEN mid-session on a mere blip.
var ErrCredentialRevoked = errors.New("cpclient: credential revoked")

// EntitlementForAccount reads an account's relay entitlement as a SERVICE caller
// (shared secret + account_id). Used by the entitlement gate.
func (c *CPClient) EntitlementForAccount(ctx context.Context, accountID string) (Entitlement, error) {
	if c.SharedSecret == "" {
		return Entitlement{}, fmt.Errorf("cpclient: no shared secret")
	}
	u := c.base() + "/api/relay/entitlement?account_id=" + accountID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Entitlement{}, err
	}
	req.Header.Set("X-Relay-Auth", c.SharedSecret)
	return c.doEntitlement(req)
}

// EntitlementForCredential reads the entitlement for an INSTALL credential
// (Bearer). The CP resolves the credential → account and returns account_id. This
// is how the CPTokenStore both validates a token AND resolves its account in one
// round trip.
func (c *CPClient) EntitlementForCredential(ctx context.Context, credential string) (Entitlement, error) {
	u := c.base() + "/api/relay/entitlement"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Entitlement{}, err
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	return c.doEntitlement(req)
}

func (c *CPClient) doEntitlement(req *http.Request) (Entitlement, error) {
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return Entitlement{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	// WAVE41-RELAY-REVOCATION: a 404 is a DEFINITIVE revoke (the credential/account
	// no longer exists at the CP), distinct from a transient 5xx/timeout. Surface it
	// as ErrCredentialRevoked so the connect path fails closed and the live-session
	// sweep drops the tunnel — but a blip (5xx / network) stays a generic error so
	// mid-session stays fail-open.
	if resp.StatusCode == http.StatusNotFound {
		return Entitlement{}, ErrCredentialRevoked
	}
	if resp.StatusCode != http.StatusOK {
		return Entitlement{}, fmt.Errorf("cpclient: entitlement status %d", resp.StatusCode)
	}
	var ent Entitlement
	if err := json.Unmarshal(body, &ent); err != nil {
		return Entitlement{}, fmt.Errorf("cpclient: decode entitlement: %w", err)
	}
	// An explicit revoked:true flag is also a definitive revoke.
	if ent.Revoked {
		return ent, ErrCredentialRevoked
	}
	return ent, nil
}

// usageItem mirrors the CP's relayUsageItem.
type usageItem struct {
	AccountID string `json:"account_id"`
	Bytes     int64  `json:"bytes"`
	Sessions  int    `json:"sessions"`
}

// usageEnvelope mirrors the CP's relayUsageEnvelope.
type usageEnvelope struct {
	PoPID    string      `json:"pop_id"`
	ReportID string      `json:"report_id"`
	Period   string      `json:"period,omitempty"`
	Items    []usageItem `json:"items"`
}

// ReportUsage flushes per-account DELTAS to POST /api/relay/usage with a valid
// X-Pop-Sig HMAC over the exact body and the supplied monotonic report_id
// (idempotent: a replay is a no-op on the CP). Returns the CP's over-quota
// account list, if any.
func (c *CPClient) ReportUsage(ctx context.Context, reportID string, items []usageItem) (overQuota []string, err error) {
	if c.SharedSecret == "" {
		return nil, fmt.Errorf("cpclient: no shared secret")
	}
	env := usageEnvelope{PoPID: c.PoPID, ReportID: reportID, Items: items}
	body, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base()+"/api/relay/usage", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Pop-Sig", signBody(c.SharedSecret, body))
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cpclient: usage status %d", resp.StatusCode)
	}
	var out struct {
		OverQuota []string `json:"over_quota"`
	}
	_ = json.Unmarshal(rb, &out)
	return out.OverQuota, nil
}

// signBody returns hex(HMAC-SHA256(secret, body)) — the X-Pop-Sig scheme the CP
// verifies with validPopSigEither.
func signBody(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// ──────────────────────────────────────────────────────────────────────────
// CPTokenStore — validates an agent token as an INSTALL credential against the
// CP and resolves it to an account. Fails closed on a CP error at connect time.
//
// The presented "token" IS the account-bound install credential the install
// obtained from the device-link flow. The CP resolves it → account and confirms
// relay is allowed; the store caches the (token → account) mapping briefly to
// avoid a CP round trip on every reconnect. Name authorization is delegated to a
// fallback static store (self-host name grants) if provided, otherwise ANY
// normalized name is allowed for a validated account (the CP is the authority on
// billing; name uniqueness is still enforced by the registry).
// ──────────────────────────────────────────────────────────────────────────

// CPTokenStore resolves tokens via the CP. It optionally wraps a static store to
// also honour a local name allow-list.
type CPTokenStore struct {
	CP  *CPClient
	TTL time.Duration // cache TTL for a validated token → account (default 60s)

	mu    sync.Mutex
	cache map[[32]byte]cpTokenCacheEntry
}

type cpTokenCacheEntry struct {
	account string
	expires time.Time
}

// NewCPTokenStore constructs a CP-backed token store.
func NewCPTokenStore(cp *CPClient, ttl time.Duration) *CPTokenStore {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &CPTokenStore{CP: cp, TTL: ttl, cache: make(map[[32]byte]cpTokenCacheEntry)}
}

// Authorize validates the token as an install credential against the CP and
// returns its account. name is accepted for any validated account (name
// collision is still guarded by the registry). Fails closed on a CP error.
func (s *CPTokenStore) Authorize(token, name string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", fmt.Errorf("empty token")
	}
	if normalizeName(name) == "" {
		return "", fmt.Errorf("invalid name")
	}
	h := sha256.Sum256([]byte(token))

	s.mu.Lock()
	if e, ok := s.cache[h]; ok && time.Now().Before(e.expires) {
		acct := e.account
		s.mu.Unlock()
		return acct, nil
	}
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ent, err := s.CP.EntitlementForCredential(ctx, token)
	if err != nil {
		// WAVE41-RELAY-REVOCATION: a DEFINITIVE revoke (revoked:true / 404) purges
		// any cached good mapping so a leaked token cannot ride a stale cache entry,
		// and fails closed. A transient error also fails closed at connect (we cannot
		// vet an unknown token) but leaves any cache untouched.
		if errors.Is(err, ErrCredentialRevoked) {
			s.mu.Lock()
			delete(s.cache, h)
			s.mu.Unlock()
			return "", fmt.Errorf("credential revoked")
		}
		// Fail CLOSED at connect: an install credential we cannot validate is
		// rejected (the connect-time gate must not pass an unknown token).
		return "", fmt.Errorf("credential validation failed")
	}
	if ent.AccountID == "" {
		return "", fmt.Errorf("unknown credential")
	}

	s.mu.Lock()
	s.cache[h] = cpTokenCacheEntry{account: ent.AccountID, expires: time.Now().Add(s.TTL)}
	// Opportunistic cleanup so the cache cannot grow without bound.
	if len(s.cache) > 4096 {
		now := time.Now()
		for k, v := range s.cache {
			if now.After(v.expires) {
				delete(s.cache, k)
			}
		}
	}
	s.mu.Unlock()
	return ent.AccountID, nil
}

var _ TokenStore = (*CPTokenStore)(nil)
