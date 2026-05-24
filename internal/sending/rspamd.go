// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
)

// VerdictAction classifies Rspamd's recommended action for a message.
type VerdictAction string

const (
	// VerdictPass means the message scored cleanly and can be sent.
	VerdictPass VerdictAction = "pass"

	// VerdictAddHeader means the message has a moderate score; it will be sent
	// but a soft negative signal is recorded.
	VerdictAddHeader VerdictAction = "add header"

	// VerdictGreylist means the message should be temporarily deferred.
	VerdictGreylist VerdictAction = "greylist"

	// VerdictReject means the message should be rejected outright.
	VerdictReject VerdictAction = "reject"

	// VerdictSoftReject is treated the same as VerdictReject for outbound.
	VerdictSoftReject VerdictAction = "soft reject"

	// VerdictNoAction is returned when Rspamd responds with "no action".
	VerdictNoAction VerdictAction = "no action"
)

// Verdict is the result of scanning a message through Rspamd.
type Verdict struct {
	// Action is the recommended action.
	Action VerdictAction

	// Score is the Rspamd total score for the message.
	Score float64

	// Symbols is the set of symbols Rspamd matched (for logging/debugging).
	Symbols []string
}

// IsReject returns true when the verdict indicates the message should be
// rejected (reject or soft reject).
func (v Verdict) IsReject() bool {
	return v.Action == VerdictReject || v.Action == VerdictSoftReject
}

// IsSoft returns true for verdicts where the message is sent but a soft signal
// is recorded (add_header or greylist).
func (v Verdict) IsSoft() bool {
	return v.Action == VerdictAddHeader || v.Action == VerdictGreylist
}

// RspamdConfig holds configuration for the Rspamd scanner.
type RspamdConfig struct {
	// Endpoint is the Rspamd HTTP base URL (e.g. "http://localhost:11333").
	// If empty, the scanner is a pass-through (one startup warning is logged).
	Endpoint string

	// Password is the Rspamd controller password, sent as the
	// "Password" HTTP header.  Optional.
	Password string

	// HTTPClient is used for scanner requests.  If nil, http.DefaultClient.
	HTTPClient interface {
		Do(req *http.Request) (*http.Response, error)
	}

	// Logger is used for operational messages.  If nil, log.Default().
	Logger *log.Logger
}

func (c *RspamdConfig) endpoint() string { return c.Endpoint }

func (c *RspamdConfig) httpClient() interface {
	Do(req *http.Request) (*http.Response, error)
} {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *RspamdConfig) logger() *log.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return log.Default()
}

// RspamdScanner scans outbound messages through Rspamd's /checkv2 endpoint.
//
// If Endpoint is empty, Scan is a pass-through that returns VerdictPass (one
// warning is logged at startup so operators know the scanner is not active).
//
// RspamdScanner is safe for concurrent use.
type RspamdScanner struct {
	cfg        RspamdConfig
	warnedOnce sync.Once
}

// NewRspamdScanner creates an RspamdScanner with the given configuration.
func NewRspamdScanner(cfg RspamdConfig) *RspamdScanner {
	return &RspamdScanner{cfg: cfg}
}

// Scan submits rawMessage to Rspamd /checkv2 and returns the Verdict.
//
// On a rejection verdict the pipeline should Fail the message and record a
// strong negative reputation signal.  On a soft verdict the pipeline should
// proceed with sending but record a soft signal.
func (s *RspamdScanner) Scan(ctx context.Context, rawMessage []byte) (Verdict, error) {
	if s.cfg.endpoint() == "" {
		s.warnedOnce.Do(func() {
			s.cfg.logger().Print("rspamd: no endpoint configured — outbound content scanning disabled (pass-through)")
		})
		return Verdict{Action: VerdictPass}, nil
	}

	url := s.cfg.endpoint() + "/checkv2"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(rawMessage))
	if err != nil {
		return Verdict{}, fmt.Errorf("rspamd: build request: %w", err)
	}
	req.Header.Set("Content-Type", "message/rfc822")
	if s.cfg.Password != "" {
		req.Header.Set("Password", s.cfg.Password)
	}

	resp, err := s.cfg.httpClient().Do(req)
	if err != nil {
		return Verdict{}, fmt.Errorf("rspamd: POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Verdict{}, fmt.Errorf("rspamd: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Verdict{}, fmt.Errorf("rspamd: non-200 status %d: %s", resp.StatusCode, string(body))
	}

	return parseRspamdResponse(body)
}

// rspamdResponse mirrors the relevant fields of the Rspamd /checkv2 JSON response.
type rspamdResponse struct {
	Action  string                 `json:"action"`
	Score   float64                `json:"score"`
	Symbols map[string]interface{} `json:"symbols"`
}

func parseRspamdResponse(body []byte) (Verdict, error) {
	var r rspamdResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return Verdict{}, fmt.Errorf("rspamd: unmarshal response: %w", err)
	}

	action := mapAction(r.Action)

	symbols := make([]string, 0, len(r.Symbols))
	for name := range r.Symbols {
		symbols = append(symbols, name)
	}

	return Verdict{
		Action:  action,
		Score:   r.Score,
		Symbols: symbols,
	}, nil
}

func mapAction(a string) VerdictAction {
	switch a {
	case "no action", "":
		return VerdictNoAction
	case "add header":
		return VerdictAddHeader
	case "greylist":
		return VerdictGreylist
	case "reject":
		return VerdictReject
	case "soft reject":
		return VerdictSoftReject
	default:
		return VerdictPass
	}
}
