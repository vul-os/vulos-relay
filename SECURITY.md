# Security Policy — Vulos Relay

## Scope

### In scope
- Submission listener (SMTP ingress from Vulos Mail instances)
- Sending pipeline and retry queue
- Peering / federation between relay nodes
- Reputation and denylist logic
- Relay configuration and secret handling

### Out of scope
- Third-party Go module vulnerabilities — report to upstream maintainers
- Social engineering or phishing
- Denial-of-service via high-volume SMTP floods (operational concern, not a code vulnerability)
- Infrastructure outside this repository (DNS, hosting)

## How to Report

**Email:** security@vulos.org  
PGP key: _placeholder — key will be published at https://vulos.org/.well-known/security.txt_

**GitHub Security Advisories:** Use the "Report a vulnerability" button in the Security tab of this repository. Preferred channel.

Please include:
- Affected component (submission, sending, peering, reputation)
- Steps to reproduce
- Potential impact
- Any suggested mitigations

## Response SLA

| Stage | Target |
|-------|--------|
| Acknowledgement | ≤ 72 hours |
| Initial triage | ≤ 7 days |
| Fix or tracked mitigation | ≤ 90 days for critical/high |

## Safe Harbor

Vulos commits to not pursuing legal action against researchers who:
- Act in good faith to identify and report vulnerabilities
- Do not exploit beyond demonstrating the issue
- Do not intercept or inject real mail
- Do not disrupt the relay's sending pipeline
- Disclose to us before public disclosure

## Bug Bounty

No paid bug-bounty program at this time. Confirmed reporters are credited in release notes.

## Credit Policy

Every confirmed finding is credited in the release that ships the fix:

> Thanks to [Name / Handle] for responsibly disclosing [CVE-XXXX-XXXXX / summary].
