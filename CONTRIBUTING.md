# Contributing to Vulos Relay

## Code of Conduct

We follow the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## Dev Environment Setup

Requirements: Go 1.22+

```bash
go build ./...
go test ./...
```

To run relay locally against a local Vulos Mail instance, copy `config.yaml.example` to `config.yaml` and adjust the SMTP upstream address.

## Branch and PR Conventions

- Branch off `main`. Name: `feat/description`, `fix/description`, `chore/description`.
- One logical change per PR.
- PRs require at least one approving review.
- Squash-merge to keep history linear.

## Commit Message Style

Conventional Commits welcome, not required:

```
feat(peering): implement TLS mutual auth for relay-to-relay
fix(queue): retry backoff capped at 4h
chore: upgrade golang.org/x/net
```

## Testing Expectations

Before opening a PR:

```bash
go test ./...
go vet ./...
```

Changes to the sending pipeline or peering logic require tests. Security-relevant paths (TLS, auth) require explicit test coverage.

## Finding a Good First Issue

Look for `good first issue` or `help wanted` labels on GitHub.

## Scope: What We Say Yes and No To

### Yes
- Bug fixes and security improvements
- Improved retry / backoff strategies
- TLS and mTLS improvements for peering
- Reputation / denylist logic improvements
- Tests and documentation

### No — frozen invariants
- **No CGO** in any Go code. Pure Go only.
- **No .tsx** files in any frontend helpers.
- **No Google SSO / OAuth**.
- **No Stripe billing**.
- **No Rust rewrites** — Go throughout.
- Features that require vulos-cloud coordination belong in vulos-cloud, not here.
- New external dependencies without prior issue discussion.

## Licensing

Vulos Relay is MIT-licensed. Contributions inherit MIT. No CLA required.
