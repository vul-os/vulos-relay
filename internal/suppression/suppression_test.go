// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package suppression_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vul-os/vulos-relay/internal/suppression"
)

// A realistic RFC 3464 DSN with a permanent (5.1.1) failure.
const dsnHardBounce = "From: MAILER-DAEMON@mx.example.net\r\n" +
	"To: bounces@sender.test\r\n" +
	"Subject: Delivery Status Notification (Failure)\r\n" +
	"Content-Type: multipart/report; report-type=delivery-status; boundary=\"BOUND\"\r\n" +
	"\r\n" +
	"--BOUND\r\n" +
	"Content-Type: text/plain\r\n" +
	"\r\n" +
	"Your message could not be delivered.\r\n" +
	"--BOUND\r\n" +
	"Content-Type: message/delivery-status\r\n" +
	"\r\n" +
	"Reporting-MTA: dns; mx.example.net\r\n" +
	"\r\n" +
	"Final-Recipient: rfc822; deadbox@example.com\r\n" +
	"Action: failed\r\n" +
	"Status: 5.1.1\r\n" +
	"Diagnostic-Code: smtp; 550 5.1.1 user unknown\r\n" +
	"--BOUND--\r\n"

// A transient (4.x.x) DSN — must NOT suppress.
const dsnSoftBounce = "From: MAILER-DAEMON@mx.example.net\r\n" +
	"Content-Type: multipart/report; report-type=delivery-status; boundary=\"B\"\r\n" +
	"\r\n" +
	"--B\r\n" +
	"Content-Type: message/delivery-status\r\n" +
	"\r\n" +
	"Final-Recipient: rfc822; slowbox@example.com\r\n" +
	"Action: delayed\r\n" +
	"Status: 4.2.1\r\n" +
	"--B--\r\n"

// An RFC 5965 ARF abuse complaint.
const arfComplaint = "From: fbl@isp.example\r\n" +
	"Content-Type: multipart/report; report-type=feedback-report; boundary=\"F\"\r\n" +
	"\r\n" +
	"--F\r\n" +
	"Content-Type: text/plain\r\n" +
	"\r\n" +
	"This is an email abuse report.\r\n" +
	"--F\r\n" +
	"Content-Type: message/feedback-report\r\n" +
	"\r\n" +
	"Feedback-Type: abuse\r\n" +
	"User-Agent: SomeISP/1.0\r\n" +
	"Version: 1\r\n" +
	"Original-Rcpt-To: complainer@isp.example\r\n" +
	"--F--\r\n"

func TestParseDSNHardBounceSuppresses(t *testing.T) {
	r, err := suppression.ParseReport([]byte(dsnHardBounce))
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if r.Kind != suppression.KindDSN {
		t.Fatalf("kind: want dsn, got %s", r.Kind)
	}
	if len(r.HardBounces) != 1 || r.HardBounces[0] != "deadbox@example.com" {
		t.Fatalf("hard bounces: want [deadbox@example.com], got %v", r.HardBounces)
	}

	list := suppression.NewList()
	if n := r.ApplyTo(list); n != 1 {
		t.Fatalf("ApplyTo: want 1 newly suppressed, got %d", n)
	}
	if _, ok := list.IsSuppressed("DeadBox@Example.com"); !ok {
		t.Error("address should be suppressed (case-insensitive)")
	}
}

func TestParseDSNSoftBounceDoesNotSuppress(t *testing.T) {
	r, err := suppression.ParseReport([]byte(dsnSoftBounce))
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if len(r.HardBounces) != 0 {
		t.Errorf("transient failure must not be a hard bounce, got %v", r.HardBounces)
	}
	if len(r.SoftFailures) != 1 {
		t.Errorf("want 1 soft failure recorded, got %v", r.SoftFailures)
	}
	list := suppression.NewList()
	if n := r.ApplyTo(list); n != 0 {
		t.Errorf("transient failure must not suppress; suppressed %d", n)
	}
}

func TestParseARFComplaintSuppresses(t *testing.T) {
	r, err := suppression.ParseReport([]byte(arfComplaint))
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if r.Kind != suppression.KindARF {
		t.Fatalf("kind: want arf, got %s", r.Kind)
	}
	if len(r.Complaints) != 1 || r.Complaints[0] != "complainer@isp.example" {
		t.Fatalf("complaints: want [complainer@isp.example], got %v", r.Complaints)
	}
	list := suppression.NewList()
	r.ApplyTo(list)
	e, ok := list.IsSuppressed("complainer@isp.example")
	if !ok || e.Reason != suppression.ReasonComplaint {
		t.Fatalf("complaint address should be suppressed with complaint reason, got %+v ok=%v", e, ok)
	}
}

func TestFilterRecipientsDropsSuppressed(t *testing.T) {
	list := suppression.NewList()
	list.Suppress("bad@example.com", suppression.ReasonHardBounce, "")
	allowed, dropped := list.FilterRecipients([]string{"good@example.com", "bad@example.com"})
	if len(allowed) != 1 || allowed[0] != "good@example.com" {
		t.Errorf("allowed: want [good@example.com], got %v", allowed)
	}
	if len(dropped) != 1 || dropped[0] != "bad@example.com" {
		t.Errorf("dropped: want [bad@example.com], got %v", dropped)
	}
}

func TestIngressHandlerFeedsList(t *testing.T) {
	list := suppression.NewList()
	h := suppression.NewIngressHandler(suppression.IngressConfig{List: list})

	req := httptest.NewRequest(http.MethodPost, suppression.IngressPath, bytes.NewReader([]byte(dsnHardBounce)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Kind        string `json:"kind"`
		Suppressed  int    `json:"suppressed"`
		HardBounces []string
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Suppressed != 1 {
		t.Errorf("suppressed: want 1, got %d", resp.Suppressed)
	}
	if _, ok := list.IsSuppressed("deadbox@example.com"); !ok {
		t.Error("ingress POST should have suppressed the hard-bounced address")
	}

	// GET must be rejected.
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, httptest.NewRequest(http.MethodGet, suppression.IngressPath, strings.NewReader("")))
	if getRec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: want 405, got %d", getRec.Code)
	}
}
