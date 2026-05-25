// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package suppression

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
)

// IngressPath is the HTTP path the report-intake handler is mounted at.
const IngressPath = "/reports"

// IngressConfig configures the report-intake HTTP handler.
type IngressConfig struct {
	// List is the suppression list reports feed into. REQUIRED.
	List *List

	// MaxBodyBytes caps the inbound report body size. 0 → 1 MiB default.
	MaxBodyBytes int64

	// Logger is used for operational messages. If nil, the standard logger.
	Logger *log.Logger
}

// IngressHandler is the http.Handler that accepts inbound DSN/ARF reports and
// feeds the suppression list. It accepts a raw RFC-822 report POSTed as
// message/rfc822 (or any body — the parser sniffs the content).
//
// This is the "ingress endpoint" path. Operators who instead pull reports from
// a postmaster@/abuse@ mailbox can call ProcessReport directly per message.
type IngressHandler struct {
	cfg IngressConfig
}

// NewIngressHandler builds an IngressHandler. It panics if List is nil — wiring
// an intake with no destination is a programmer error.
func NewIngressHandler(cfg IngressConfig) *IngressHandler {
	if cfg.List == nil {
		panic("suppression: IngressHandler requires a non-nil List")
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20 // 1 MiB
	}
	return &IngressHandler{cfg: cfg}
}

func (h *IngressHandler) logger() *log.Logger {
	if h.cfg.Logger != nil {
		return h.cfg.Logger
	}
	return log.Default()
}

// ingressResponse is the JSON response shape.
type ingressResponse struct {
	Kind         ReportKind `json:"kind"`
	Suppressed   int        `json:"suppressed"`
	HardBounces  []string   `json:"hard_bounces,omitempty"`
	Complaints   []string   `json:"complaints,omitempty"`
	SoftFailures []string   `json:"soft_failures,omitempty"`
}

// ServeHTTP implements http.Handler. Only POST is accepted.
func (h *IngressHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST is accepted", http.StatusMethodNotAllowed)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, h.cfg.MaxBodyBytes+1))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if int64(len(raw)) > h.cfg.MaxBodyBytes {
		http.Error(w, "report body too large", http.StatusRequestEntityTooLarge)
		return
	}

	report, n, perr := h.ProcessReport(raw)
	if perr != nil {
		// A parse failure is a client problem (malformed report) — 400.
		h.logger().Printf("suppression: report parse failed: %v", perr)
		http.Error(w, "report parse failed: "+perr.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(ingressResponse{
		Kind:         report.Kind,
		Suppressed:   n,
		HardBounces:  report.HardBounces,
		Complaints:   report.Complaints,
		SoftFailures: report.SoftFailures,
	})
}

// ProcessReport parses a single raw report and applies it to the suppression
// list, returning the parsed report and the number of addresses newly
// suppressed. It is the mailbox-processor entry point (call it per message
// fetched from a postmaster@/abuse@ mailbox).
func (h *IngressHandler) ProcessReport(raw []byte) (ParsedReport, int, error) {
	report, err := ParseReport(raw)
	if err != nil {
		return report, 0, err
	}
	n := report.ApplyTo(h.cfg.List)
	if n > 0 {
		h.logger().Printf("suppression: %s report suppressed %d recipient(s) (hard_bounces=%d complaints=%d)",
			report.Kind, n, len(report.HardBounces), len(report.Complaints))
	}
	return report, n, nil
}
