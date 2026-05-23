# Vulos Relay – Versioning & Release Policy

## Versioning

Semver (`vX.Y.Z`). Currently **v0.x**.

v1.0 when: the submit API, queue format, and peering wire protocol are stable.

## Tag Format

`vX.Y.Z` on `main`. Release branches: `release/X.Y`.

## Commit Convention

Conventional Commits. Breaking wire-protocol changes require a `BREAKING CHANGE:` footer and a major version bump.

## Signed Artifacts

```sh
cosign sign-blob --key release.key vulos-relay-linux-amd64 > vulos-relay-linux-amd64.sig
git tag -s v0.3.1 -m "Release v0.3.1"
```

## CHANGELOG

`CHANGELOG.md` at repo root. Conventional Commits format.
