# Contributing to @vulos/relay-client

## Code of Conduct

We follow the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## Dev Environment Setup

Requirements: Node.js 20+ and npm 10+.

```bash
cd client
npm ci
npm run build
npm test
```

The SDK targets browser environments (WebSocket, BroadcastChannel, WebRTC). Tests run under Vitest with jsdom.

## Branch and PR Conventions

- Branch off `main`. Name: `feat/description`, `fix/description`, `chore/description`.
- One logical change per PR.
- PRs require at least one approving review.
- Squash-merge to keep history linear.

## Commit Message Style

Conventional Commits welcome, not required:

```
feat(signaling): retry WebSocket connection with exponential backoff
fix(endpoints): fall back to same-origin when both cloud and LAN are down
chore: upgrade vitest
```

## Testing Expectations

Before opening a PR:

```bash
cd client
npm test
```

Changes to endpoint failover, signaling, or the offline queue require tests.
Security-relevant paths (auth token handling, session isolation) require
explicit test coverage.

## Scope: What We Say Yes and No To

### Yes
- Bug fixes and security improvements
- Endpoint failover and probe logic
- Signaling reliability and reconnect strategies
- Offline queue and service-worker bootstrap improvements
- Tests and documentation

### No — frozen invariants
- **No .tsx** files. JSX only, or plain JS.
- **No Go code** — the Go mail daemon is retired. This repo is a pure JS SDK.
- **No Google SSO / OAuth**.
- **No Stripe billing**.
- **No Rust rewrites**.
- Features that require vulos-cloud coordination belong in vulos-cloud, not here.
- New external dependencies without prior issue discussion.

## Licensing

@vulos/relay-client is MIT-licensed. Contributions inherit MIT. No CLA required.
