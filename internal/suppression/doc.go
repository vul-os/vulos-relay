// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

// Package suppression maintains the relay's recipient suppression list and the
// inbound report intake that feeds it.
//
// Two classes of report are parsed:
//
//   - DSN / bounce reports (RFC 3464, message/delivery-status): a permanent
//     (5.x.x) failure for a recipient is a HARD BOUNCE → the recipient is
//     suppressed. Transient (4.x.x) failures are NOT suppressed (they are
//     retried by the queue).
//   - ARF / FBL complaint reports (RFC 5965, message/feedback-report): a
//     feedback-type "abuse" complaint → the complaining recipient is
//     suppressed.
//
// A suppressed recipient is dropped at the send gate so the relay never
// re-sends to an address that hard-bounced or filed a complaint — the single
// most important deliverability control for protecting sender reputation.
//
// The List is an in-memory reference store with a pluggable persistence seam;
// Vulos's durable (bucket-backed) suppression store is an external
// implementation and is NOT part of this repository.
package suppression
