# Security Policy — @vulos/relay-client

## Scope

### In scope
- Endpoint failover and probe logic (cloud / LAN selection, cache poisoning)
- Signaling session isolation (cross-session message leakage)
- Auth token handling (storage, transmission, expiry)
- Offline queue integrity (replay attacks, queue tampering)
- BroadcastChannel stub (same-origin message injection)

### Out of scope
- Third-party npm package vulnerabilities — report to upstream maintainers
- Social engineering or phishing
- Infrastructure outside this repository (DNS, hosting, relay servers)
- Infrastructure outside this repository (DNS, hosting, relay servers) beyond what is listed above

## How to Report

**Email:** security@vulos.org  
PGP key: _placeholder — key will be published at https://vulos.org/.well-known/security.txt_

**GitHub Security Advisories:** Use the "Report a vulnerability" button in the Security tab of this repository. Preferred channel.

Please include:
- Affected component (endpoint selection, signaling, auth tokens, offline queue)
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
- Do not intercept or inject real user sessions
- Do not disrupt live relay or signaling infrastructure
- Disclose to us before public disclosure

## Bug Bounty

No paid bug-bounty program at this time. Confirmed reporters are credited in release notes.

## Credit Policy

Every confirmed finding is credited in the release that ships the fix:

> Thanks to [Name / Handle] for responsibly disclosing [CVE-XXXX-XXXXX / summary].
