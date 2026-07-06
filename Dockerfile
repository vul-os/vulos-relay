# Dockerfile — Vulos sovereign relay server (vulos-relayd) + agent.
#
# vulos-relayd is the PUBLIC half of the Vulos reverse tunnel — the self-hosted
# replacement for a third-party frp server. This image is what makes the
# sovereign relay actually DEPLOYABLE (the release workflow previously shipped
# only the npm SDK, never the Go server).
#
# Both Go commands are pure-Go (coder/websocket + hashicorp/yamux; no cgo), so
# this is a straightforward self-contained multi-stage build — the whole repo is
# the build context, no sibling repos required:
#
#   docker build -t ghcr.io/vul-os/vulos-relayd:latest .
#
# The image bundles BOTH binaries; ENTRYPOINT is vulos-relayd. To run the agent
# instead, override: `docker run ... --entrypoint /usr/local/bin/vulos-relay-agent`.
#
# Run the server (plain HTTP behind a TLS-terminating edge/CDN — the Fly shape):
#   docker run -d -p 8443:8443 \
#     -e VULOS_RELAY_DOMAIN=relay.example.com \
#     -e VULOS_RELAY_TOKENS='[{"token":"SECRET","names":["box1"]}]' \
#     ghcr.io/vul-os/vulos-relayd:latest
# Or terminate TLS in-process by mounting certs and passing -cert/-key.

# ── Stage 1: build both static binaries ───────────────────────────────────────
FROM golang:1.25-alpine AS build
ARG VERSION=docker
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Pure-Go, CGO off → fully static binaries for the scratch-like alpine runtime.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
      -o /out/vulos-relayd ./cmd/vulos-relayd \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
      -o /out/vulos-relay-agent ./cmd/vulos-relay-agent

# ── Stage 2: minimal non-root runtime ─────────────────────────────────────────
FROM alpine:3.20
# ca-certificates for the optional Vulos Cloud billing/entitlement calls + agent
# TLS dial; wget for the container healthcheck.
RUN apk add --no-cache ca-certificates wget \
 && adduser -D -u 10001 vulos
COPY --from=build /out/vulos-relayd       /usr/local/bin/vulos-relayd
COPY --from=build /out/vulos-relay-agent  /usr/local/bin/vulos-relay-agent
USER vulos
# Public control/data port (see cmd/vulos-relayd -addr default :8443). Terminate
# TLS at the edge and run plain HTTP here, or mount certs + pass -cert/-key.
EXPOSE 8443
# Liveness: handlePublic serves GET /healthz on the listen addr regardless of Host.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8443/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/vulos-relayd"]
