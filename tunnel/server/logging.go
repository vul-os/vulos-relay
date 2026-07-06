package server

import (
	"context"
	"log/slog"
	"os"
)

// logging.go — WAVE50-RELAY-OBSERVABILITY: structured logging for the relay's key
// lifecycle events.
//
// The relay previously used the stdlib `log` package with free-form Printf lines,
// which are unqueryable and, worse, easy to accidentally leak a token/account into.
// This wave routes the security-relevant lifecycle events (agent connect /
// auth-fail / disconnect, tunnel open/close, rate-limit reject, revocation cut,
// over-quota cut) through slog with a CONSISTENT, BOUNDED field set and explicit
// levels.
//
// FIELD DISCIPLINE (must hold for every call site):
//
//   - name    — the normalized tunnel name (public, non-secret; it is literally the
//               subdomain the world hits).
//   - account — the resolved Vulos account id ("" for unbilled/self-host). An
//               account id is an opaque identifier, not PII; it is safe to log and
//               is the join key operators need.
//   - remote  — the source IP (already exposed in access logs).
//   - reason  — a BOUNDED enum string (never a raw error containing input).
//
//   NEVER logged: the bearer token / secret, the CP shared secret, request
//   bodies/paths/query strings, or any header value. There is no field for a
//   token; the helpers below do not accept one.
//
// LEVELS: info = normal lifecycle (connect/disconnect, a cut). debug = the noisy,
// per-attempt detail (every auth-fail, every rate-limit reject) so a busy relay
// stays quiet at info but an operator can turn the firehose on. warn/error are
// reserved for genuine server-side faults (usage-flush failure).

// newLogger builds the relay's structured logger. Level comes from the
// VULOS_RELAY_LOG_LEVEL env (debug|info|warn|error), defaulting to info. Format is
// JSON unless VULOS_RELAY_LOG_FORMAT=text.
func newLogger() *slog.Logger {
	lvl := slog.LevelInfo
	switch os.Getenv("VULOS_RELAY_LOG_LEVEL") {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if os.Getenv("VULOS_RELAY_LOG_FORMAT") == "text" {
		h = slog.NewTextHandler(os.Stderr, opts)
	} else {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	return slog.New(h).With("component", "relay")
}

// logFields is the bounded set of fields a lifecycle event may carry. It exists so
// call sites cannot accidentally attach a token: there is simply no field for one.
type logFields struct {
	Name    string // normalized tunnel name (public)
	Account string // resolved account id ("" = unbilled)
	Remote  string // source IP
	Reason  string // bounded enum reason (auth-fail / cut reason)
}

func (f logFields) attrs() []any {
	a := make([]any, 0, 8)
	if f.Name != "" {
		a = append(a, "name", f.Name)
	}
	if f.Account != "" {
		a = append(a, "account", f.Account)
	}
	if f.Remote != "" {
		a = append(a, "remote", f.Remote)
	}
	if f.Reason != "" {
		a = append(a, "reason", f.Reason)
	}
	return a
}

// logger returns the server's logger, falling back to the slog default if unset
// (e.g. a zero-value Server in a test that didn't go through New).
func (s *Server) logger() *slog.Logger {
	if s.log != nil {
		return s.log
	}
	return slog.Default()
}

func (s *Server) logInfo(msg string, f logFields) {
	s.logger().LogAttrs(context.Background(), slog.LevelInfo, msg, toAttrs(f)...)
}

func (s *Server) logDebug(msg string, f logFields) {
	s.logger().LogAttrs(context.Background(), slog.LevelDebug, msg, toAttrs(f)...)
}

func toAttrs(f logFields) []slog.Attr {
	kv := f.attrs()
	out := make([]slog.Attr, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, slog.String(kv[i].(string), kv[i+1].(string)))
	}
	return out
}
