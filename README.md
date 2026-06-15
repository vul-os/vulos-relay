<div align="center">

# Vulos Relay

**`@vulos/relay-client` — the peer-fabric client SDK for Vulos web surfaces**

[![npm](https://img.shields.io/npm/v/%40vulos%2Frelay-client?label=%40vulos%2Frelay-client)](https://www.npmjs.com/package/@vulos/relay-client)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/vul-os/vulos-relay/pulls)

*Vulos — rooted in **vula**, the Zulu and Xhosa word for **open**.*

</div>

---

## What is this?

This repository provides **`@vulos/relay-client`**, the shared JavaScript SDK
used by every Vulos web surface (the OS shell, [vulos-office](https://github.com/vul-os/vulos-office),
[vulos-mail](https://github.com/vul-os/vulos-mail)) for peer-fabric and
connectivity concerns:

- **Endpoint failover** — cloud ↔ LAN backend selection with health probing.
- **Offline bootstrap** — offline-first boot + write-queue.
- **WebRTC signaling** — offer/answer/ICE over the host's peering WebSocket.
- **Fabric sessions** — per-document P2P data channels with a relay-circuit fallback.
- **Presence & live cursors** — multi-peer awareness on the fabric channel.

It talks to the **host application's own peering backend** (e.g. the Vulos OS
`/api/peering/*` endpoints) over HTTP/WebSocket — it does not bundle a server.

> **History.** This repo previously also shipped a standalone Go *mail-delivery
> daemon* (outbound SMTP/DKIM/MTA-STS + Vulos↔Vulos mail peering). That daemon
> was **retired** — mail delivery is now owned entirely by
> [vulos-mail](https://github.com/vul-os/vulos-mail) (a [Mox](https://github.com/mjl-/mox)
> fork, which does its own outbound delivery), and the live peer-fabric/relay
> functionality the SDK uses is served by the host's peering backend.

## Usage

```bash
npm install @vulos/relay-client   # or file:../vulos-relay/client in the monorepo
```

See [`client/`](client/) for the full API, subpath exports, and migration notes.

## Versioning and releases

This package follows [Semantic Versioning](https://semver.org/).

Releases are cut by pushing a `v*` tag:

```bash
# bump version in client/package.json first, then:
git tag v1.2.3
git push origin v1.2.3
```

The [release workflow](.github/workflows/release.yml) will:

1. Install, build, and run tests.
2. Verify the tag matches the version in `client/package.json`.
3. Publish to npm (`--access public --provenance`) if `NPM_TOKEN` is set as a
   repository secret. The gate uses a job-level output (`check-npm-token`) to
   work around the GitHub Actions limitation where secrets cannot be evaluated
   directly in `if:` expressions.
4. Create a GitHub Release with the `dist-lib/` tarball attached.

npm publish is gated on `NPM_TOKEN` — if it is absent the GitHub Release is
still created and the workflow succeeds.

See [CHANGELOG.md](CHANGELOG.md) for the history and [ROADMAP.md](ROADMAP.md)
for planned directions.

## License

MIT — see [LICENSE](LICENSE).
