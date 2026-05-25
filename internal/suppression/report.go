// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package suppression

import (
	"bufio"
	"bytes"
	"fmt"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
)

// ReportKind classifies a parsed inbound report.
type ReportKind string

const (
	// KindDSN is an RFC 3464 delivery-status notification (bounce).
	KindDSN ReportKind = "dsn"
	// KindARF is an RFC 5965 abuse/feedback report (complaint).
	KindARF ReportKind = "arf"
	// KindUnknown is a message that is neither a DSN nor an ARF report.
	KindUnknown ReportKind = "unknown"
)

// ParsedReport is the outcome of parsing an inbound report message.
type ParsedReport struct {
	// Kind classifies the report.
	Kind ReportKind
	// HardBounces are recipient addresses that permanently (5.x.x) failed.
	HardBounces []string
	// SoftFailures are recipients with a transient (4.x.x) status (NOT
	// suppressed; surfaced for visibility/metrics only).
	SoftFailures []string
	// Complaints are recipient addresses that filed an FBL/ARF complaint.
	Complaints []string
}

// ApplyTo records this report's hard bounces and complaints into the
// suppression list. It returns the number of addresses newly suppressed.
func (r ParsedReport) ApplyTo(list *List) int {
	n := 0
	for _, a := range r.HardBounces {
		if list.Suppress(a, ReasonHardBounce, "DSN 5.x.x permanent failure") {
			n++
		}
	}
	for _, a := range r.Complaints {
		if list.Suppress(a, ReasonComplaint, "ARF/FBL complaint") {
			n++
		}
	}
	return n
}

// ParseReport parses a raw RFC-822 report message. It auto-detects DSN
// (multipart/report; report-type=delivery-status) vs ARF (report-type=feedback-report).
// A message that is neither yields a ParsedReport with Kind=KindUnknown and no
// addresses.
func ParseReport(raw []byte) (ParsedReport, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return ParsedReport{Kind: KindUnknown}, fmt.Errorf("parse report message: %w", err)
	}

	ct := msg.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return ParsedReport{Kind: KindUnknown}, fmt.Errorf("parse content-type %q: %w", ct, err)
	}

	if !strings.EqualFold(mediaType, "multipart/report") {
		return ParsedReport{Kind: KindUnknown}, nil
	}

	boundary := params["boundary"]
	if boundary == "" {
		return ParsedReport{Kind: KindUnknown}, fmt.Errorf("multipart/report missing boundary")
	}

	reportType := strings.ToLower(params["report-type"])
	mr := multipart.NewReader(msg.Body, boundary)

	switch reportType {
	case "delivery-status":
		return parseDSNParts(mr)
	case "feedback-report":
		return parseARFParts(mr)
	default:
		// Some senders omit report-type; sniff the parts.
		return sniffParts(mr)
	}
}

// parseDSNParts extracts per-recipient status from the message/delivery-status
// part(s) of a multipart/report (RFC 3464 §2).
func parseDSNParts(mr *multipart.Reader) (ParsedReport, error) {
	out := ParsedReport{Kind: KindDSN}
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		pct, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if !strings.EqualFold(pct, "message/delivery-status") {
			continue
		}
		body := readPart(part)
		hard, soft := parseDeliveryStatus(body)
		out.HardBounces = append(out.HardBounces, hard...)
		out.SoftFailures = append(out.SoftFailures, soft...)
	}
	return out, nil
}

// parseDeliveryStatus parses a message/delivery-status body, which is a series
// of header-style "field: value" groups (one per-message group, then one group
// per recipient). We extract Final-Recipient/Original-Recipient + Status +
// Action and classify 5.x.x as hard, 4.x.x as soft.
func parseDeliveryStatus(body string) (hard, soft []string) {
	groups := splitBlankLine(body)
	for _, g := range groups {
		fields := parseFields(g)
		rcpt := recipientAddr(fields["final-recipient"])
		if rcpt == "" {
			rcpt = recipientAddr(fields["original-recipient"])
		}
		if rcpt == "" {
			continue
		}
		status := strings.TrimSpace(fields["status"])
		action := strings.ToLower(strings.TrimSpace(fields["action"]))
		switch {
		case strings.HasPrefix(status, "5.") || action == "failed" && strings.HasPrefix(status, "5"):
			hard = append(hard, rcpt)
		case strings.HasPrefix(status, "4."):
			soft = append(soft, rcpt)
		case action == "failed":
			// No parseable status but explicitly failed → treat as hard bounce.
			hard = append(hard, rcpt)
		}
	}
	return hard, soft
}

// parseARFParts extracts the complained-about recipient from a feedback-report
// part (RFC 5965 §3). The "Original-Rcpt-To" / "Original-Mail-From" header in
// the message/feedback-report part carries the address.
func parseARFParts(mr *multipart.Reader) (ParsedReport, error) {
	out := ParsedReport{Kind: KindARF}
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		pct, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if !strings.EqualFold(pct, "message/feedback-report") {
			continue
		}
		body := readPart(part)
		fields := parseFields(body)
		fbType := strings.ToLower(strings.TrimSpace(fields["feedback-type"]))
		// Only "abuse" complaints suppress; "not-spam"/"auth-failure" do not.
		if fbType != "" && fbType != "abuse" && fbType != "fraud" && fbType != "virus" {
			continue
		}
		if rcpt := recipientAddr(fields["original-rcpt-to"]); rcpt != "" {
			out.Complaints = append(out.Complaints, rcpt)
		}
	}
	return out, nil
}

// sniffParts handles a multipart/report with no report-type param by looking
// for either a delivery-status or feedback-report part.
func sniffParts(mr *multipart.Reader) (ParsedReport, error) {
	out := ParsedReport{Kind: KindUnknown}
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		pct, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
		body := readPart(part)
		switch {
		case strings.EqualFold(pct, "message/delivery-status"):
			out.Kind = KindDSN
			hard, soft := parseDeliveryStatus(body)
			out.HardBounces = append(out.HardBounces, hard...)
			out.SoftFailures = append(out.SoftFailures, soft...)
		case strings.EqualFold(pct, "message/feedback-report"):
			out.Kind = KindARF
			fields := parseFields(body)
			if rcpt := recipientAddr(fields["original-rcpt-to"]); rcpt != "" {
				out.Complaints = append(out.Complaints, rcpt)
			}
		}
	}
	return out, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func readPart(part *multipart.Part) string {
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := part.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return sb.String()
}

// splitBlankLine splits a body into groups separated by blank lines.
func splitBlankLine(body string) []string {
	var groups []string
	var cur strings.Builder
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			if cur.Len() > 0 {
				groups = append(groups, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteString(line)
		cur.WriteString("\n")
	}
	if cur.Len() > 0 {
		groups = append(groups, cur.String())
	}
	return groups
}

// parseFields parses a block of "Key: value" lines into a lowercased-key map.
// Later duplicate keys overwrite earlier ones.
func parseFields(block string) map[string]string {
	out := make(map[string]string)
	sc := bufio.NewScanner(strings.NewReader(block))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(val)
	}
	return out
}

// recipientAddr extracts the address from a DSN recipient field of the form
// "rfc822; user@example.com" (or a bare address).
func recipientAddr(field string) string {
	field = strings.TrimSpace(field)
	if field == "" {
		return ""
	}
	if _, addr, ok := strings.Cut(field, ";"); ok {
		field = strings.TrimSpace(addr)
	}
	field = strings.TrimPrefix(field, "<")
	field = strings.TrimSuffix(field, ">")
	return strings.TrimSpace(field)
}
