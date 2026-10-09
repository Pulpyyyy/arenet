# Arenet - Homelab-friendly reverse proxy with integrated security
# Copyright (C) 2026  The Arenet Authors
# Licensed under the GNU AGPL v3 or later. See LICENSE.

# Step S.1 — Multi-arch Docker image (linux/amd64 + linux/arm64).
#
# Three stages:
#   1. frontend — Node 24 Alpine builds the SvelteKit SPA into
#      web/frontend/build/. The build is consumed by stage 2 via
#      COPY --from=frontend.
#   2. backend — Go 1.26 Alpine compiles the static binary with
#      CGO_ENABLED=0 (distroless requires it). The frontend build
#      is copied INTO the source tree before `go build` so the
#      //go:embed directive at web/embed.go picks it up.
#   Both build stages run on $BUILDPLATFORM: the SPA output is
#   arch-independent and Go cross-compiles to $TARGETARCH, so a
#   multi-arch buildx run never builds under QEMU emulation.
#   3. runtime — distroless static-debian12:nonroot. No shell, no
#      package manager, no debug tooling. Operators rely on
#      `docker logs`, `docker inspect`, `docker stats`, and the
#      built-in `arenet --healthcheck=...` subcommand.
#
# Build (multi-arch via buildx, push to a registry):
#
#   docker buildx build \
#     --platform linux/amd64,linux/arm64 \
#     --tag ghcr.io/barto95100/arenet:v1.0.0 \
#     --build-arg VERSION=v1.0.0 \
#     --push .
#
# Build (single-arch, local-only):
#
#   docker build --build-arg VERSION=v1.0.0-dev -t arenet:dev .
#
# The VERSION build arg lands at -X main.version=...; defaults to
# "dev" when omitted so a local `docker build` still produces a
# binary that reports a non-DEV version string.

# -----------------------------------------------------------------
# Stage 1 — frontend build (SvelteKit → static HTML+CSS+JS)
# -----------------------------------------------------------------
FROM --platform=$BUILDPLATFORM node:24-alpine AS frontend
WORKDIR /src/web/frontend

# Layer-cached deps install: copy lockfiles first. The npm cache
# mount only speeds up local rebuilds (the GHA cache backend does
# not export cache mounts); node_modules still lands in the layer.
COPY web/frontend/package.json web/frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --no-audit --no-fund

# Now copy the actual source + build.
COPY web/frontend ./
RUN npm run build

# -----------------------------------------------------------------
# Stage 2 — Go backend build (static, stripped)
# -----------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS backend
WORKDIR /src

# go.mod / go.sum first for layer caching.
COPY go.mod go.sum ./
RUN go mod download

# Whole repo for the embed directive (web/embed.go reads
# all:frontend/build); the frontend build comes from stage 1.
COPY . .
COPY --from=frontend /src/web/frontend/build /src/web/frontend/build

# Cross-compile target derived from buildx TARGETOS/TARGETARCH.
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

# Static binary. CGO_ENABLED=0 is mandatory for distroless/static
# (no libc). -ldflags "-s -w" strips debug symbols; -trimpath
# removes local paths from stack traces. The version string is
# injected at -X main.version. The go-build cache mount only
# speeds up local rebuilds; modules stay in the `go mod download`
# layer above so CI layer-cache hits still skip the download.
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -trimpath \
      -o /out/arenet \
      ./cmd/arenet

# Pre-create the runtime data dir so stage 3 can COPY it into the
# image with nonroot ownership (named-volume case fix).
RUN mkdir -p /out/data

# -----------------------------------------------------------------
# Stage 3 — distroless runtime
# -----------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

# OCI metadata. REVISION is the git commit SHA, passed by the
# release workflow (.git is excluded from the build context, so
# the image cannot derive it itself).
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="Arenet" \
      org.opencontainers.image.description="Homelab-friendly reverse proxy with integrated security" \
      org.opencontainers.image.source="https://github.com/barto95100/arenet" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

# The distroless `nonroot` user is uid:gid 65532:65532. The Go
# binary lives at /usr/local/bin/arenet; the data directory at
# /var/lib/arenet matches the spec D4 default.
COPY --from=backend /out/arenet /usr/local/bin/arenet

# Pre-create /var/lib/arenet with nonroot ownership so named
# volumes inherit the correct ownership on first mount. Without
# this, Docker creates the dir implicitly via WORKDIR with root
# ownership, and the named volume becomes root-owned → nonroot
# (UID 65532) can't write → restart loop with permission denied.
# Bind mounts require the operator to chown the host dir
# separately (see docs/install/docker-quickstart.md).
#
# --chmod=700 bakes owner-only perms into the image dir. The Go
# boot path also chmods 0o700 at runtime, but a named volume's
# perms are seeded from THIS image dir on first mount, so setting
# it here keeps a fresh named-volume install owner-only from the
# very first boot rather than relying on the runtime chmod. Needs
# BuildKit (the release pipeline builds via docker buildx).
COPY --from=backend --chown=nonroot:nonroot --chmod=700 /out/data /var/lib/arenet

# Data plane ports + admin port. The container EXPOSE is purely
# informational — Docker doesn't open ports without an explicit
# `-p` / compose `ports:` directive. 443/udp carries HTTP/3
# (QUIC), which Caddy serves by default next to 443/tcp.
EXPOSE 80 443 443/udp 8001

# TLS cert storage path fix. certmagic stores certs under
# caddy.AppDataDir() = $HOME/.local/share/caddy on Linux. The
# distroless base sets NO $HOME (unlike systemd, which derives it
# from the arenet user's passwd entry), so without this the binary
# falls back to a relative "./caddy" dir resolved against WORKDIR —
# a different, cwd-dependent path that breaks reverse-proxy TLS in
# Docker while working fine on the binary. Pinning HOME here makes
# the container store certs at /var/lib/arenet/.local/share/caddy,
# identical to the systemd install and to what the docs describe.
# This ENV is the LOAD-BEARING fix: it is set before the process
# starts, so it is visible at program init when caddy.DefaultStorage
# freezes AppDataDir() (caddy/v2 storage.go:160). The Go-side
# resolveCertStorageHome() runs after init and only aligns certinfo's
# live-derived paths — it canNOT move Caddy's already-frozen storage,
# so setting HOME in the image is what actually repairs the handshake.
ENV HOME=/var/lib/arenet

# Run as nonroot (uid 65532). The systemd unit ships the same
# pattern via User=arenet + CAP_NET_BIND_SERVICE; Docker handles
# privileged-port bind via the runtime's CAP_NET_BIND_SERVICE
# (compose `cap_add: [NET_BIND_SERVICE]` makes it explicit).
USER nonroot:nonroot
WORKDIR /var/lib/arenet

# Runtime defaults as ENV, NOT as CMD flags. Flags sit at the
# top of the precedence stack (flag > env > file > default, see
# internal/config/config.go), so a CMD carrying --admin-port /
# --data-dir would silently shadow every ARENET_ADMIN_BIND /
# ARENET_DATA_DIR an operator sets in compose or `docker run -e`.
#
# The admin listens on all container interfaces on purpose:
# Docker forwards a published port to the container's eth0, never
# to its loopback, so a 127.0.0.1 bind here would make the admin
# unreachable. Loopback-only exposure is done on the HOST side by
# publishing "127.0.0.1:8001:8001" (see docker-compose.yml).
ENV ARENET_ADMIN_BIND=:8001 \
    ARENET_DATA_DIR=/var/lib/arenet

# In-binary probe (distroless has no curl/wget). Baked into the
# image so `docker run` / Portainer installs get a health status
# too, not only the reference compose. If ARENET_ADMIN_BIND moves
# the admin off :8001, override the healthcheck to match.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/arenet", "--healthcheck=http://127.0.0.1:8001/healthz"]

# Distroless has no shell, so the entrypoint is the binary
# directly (no `sh -c` wrapping). Operators pass flags via
# compose `command:` or env vars.
ENTRYPOINT ["/usr/local/bin/arenet"]
