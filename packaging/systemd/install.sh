#!/usr/bin/env bash
# Arenet - Homelab-friendly reverse proxy with integrated security
# Copyright (C) 2026  The Arenet Authors
# Licensed under the GNU AGPL v3 or later. See LICENSE.
#
# Native Linux install script for the systemd unit.
#
# Works in TWO modes:
#
#   A. curl-pipe (one-liner, no clone needed):
#        curl -fsSL https://raw.githubusercontent.com/barto95100/arenet/main/packaging/systemd/install.sh | sudo bash
#      In this mode the binary + unit file are downloaded from the
#      GitHub release (the script is reading itself from stdin, so
#      there are no sibling files to copy).
#
#   B. local checkout:
#        cd arenet/packaging/systemd && sudo ./install.sh
#      In this mode the sibling arenet.service is used as-is, and a
#      binary already present at /usr/local/bin/arenet is kept.
#
# What it does (idempotent — safe to re-run):
#   1. Installs the arenet binary to /usr/local/bin/arenet
#      (downloads the release asset for the host arch if the binary
#      is missing; skip the download with ARENET_SKIP_BINARY=1).
#   2. Installs the systemd unit to /etc/systemd/system/.
#   3. Creates the system user `arenet` (no shell, no home content).
#   4. Creates /var/lib/arenet owned by arenet:arenet.
#   5. Creates /etc/arenet + a commented sample env file.
#   6. Reloads systemd and enables + starts the service.
#
# Environment overrides:
#   ARENET_VERSION=v1.2.3   Pin a release tag (default: latest).
#   ARENET_SKIP_BINARY=1    Don't touch /usr/local/bin/arenet
#                           (build/copy it yourself).
#   ARENET_NO_START=1       Install everything but don't
#                           enable/start the service.
#
# Uninstall (not scripted — deleting state is irreversible):
#   sudo systemctl disable --now arenet
#   sudo rm /etc/systemd/system/arenet.service
#   sudo systemctl daemon-reload
#   # /var/lib/arenet is preserved — delete manually to wipe state.

set -euo pipefail

REPO="barto95100/arenet"
BINARY_PATH="/usr/local/bin/arenet"
UNIT_DEST="/etc/systemd/system/arenet.service"
DATA_DIR="/var/lib/arenet"
ENV_DIR="/etc/arenet"
ENV_FILE="${ENV_DIR}/arenet.env"

VERSION="${ARENET_VERSION:-latest}"
SKIP_BINARY="${ARENET_SKIP_BINARY:-0}"
NO_START="${ARENET_NO_START:-0}"

log()  { printf '  %s\n' "$*"; }
err()  { printf 'error: %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
	die "install.sh must be run as root (try: sudo)"
fi

for cmd in curl install systemctl; do
	command -v "$cmd" >/dev/null 2>&1 || die "required command not found: $cmd"
done

# Map uname -m to the release asset arch suffix.
case "$(uname -m)" in
	x86_64 | amd64)          ASSET_ARCH="amd64" ;;
	aarch64 | arm64)         ASSET_ARCH="arm64" ;;
	*) die "unsupported architecture '$(uname -m)' — only amd64/arm64 have release binaries. Build from source (see docs/install/systemd-native.md) and re-run with ARENET_SKIP_BINARY=1." ;;
esac

# Is there a sibling arenet.service (local checkout, mode B)? When
# curl-piped, BASH_SOURCE[0] is not a real path, so guard the lookup.
SCRIPT_SRC="${BASH_SOURCE[0]:-}"
LOCAL_UNIT=""
if [[ -n "$SCRIPT_SRC" && -f "$SCRIPT_SRC" ]]; then
	SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_SRC")" && pwd)"
	if [[ -f "${SCRIPT_DIR}/arenet.service" ]]; then
		LOCAL_UNIT="${SCRIPT_DIR}/arenet.service"
	fi
fi

# Resolve a release download URL for a given asset name. Uses the
# "latest" redirect when no version is pinned.
release_url() {
	local asset="$1"
	if [[ "$VERSION" == "latest" ]]; then
		printf 'https://github.com/%s/releases/latest/download/%s' "$REPO" "$asset"
	else
		printf 'https://github.com/%s/releases/download/%s/%s' "$REPO" "$VERSION" "$asset"
	fi
}

echo "Arenet native install — version=${VERSION}, arch=${ASSET_ARCH}"

# ---------------------------------------------------------------------------
# 1. Binary
# ---------------------------------------------------------------------------

if [[ "$SKIP_BINARY" == "1" ]]; then
	log "ARENET_SKIP_BINARY=1 — not touching ${BINARY_PATH}"
	[[ -x "$BINARY_PATH" ]] || err "note: ${BINARY_PATH} is missing/not executable; the service won't start until you install it."
elif [[ -x "$BINARY_PATH" ]]; then
	log "binary already present at ${BINARY_PATH} — keeping it (set ARENET_VERSION + remove it to force re-download)"
else
	asset="arenet-linux-${ASSET_ARCH}"
	url="$(release_url "$asset")"
	tmp_bin="$(mktemp)"
	log "downloading ${asset} from ${url}"
	if ! curl -fsSL -o "$tmp_bin" "$url"; then
		rm -f "$tmp_bin"
		die "download failed: ${url}
       Check the version tag, or build from source and re-run with ARENET_SKIP_BINARY=1 (see docs/install/systemd-native.md)."
	fi

	# Best-effort checksum verification against the release manifest.
	sums_url="$(release_url "checksums.txt")"
	tmp_sums="$(mktemp)"
	if curl -fsSL -o "$tmp_sums" "$sums_url" 2>/dev/null && grep -q " ${asset}\$" "$tmp_sums"; then
		expected="$(grep " ${asset}\$" "$tmp_sums" | awk '{print $1}')"
		if command -v sha256sum >/dev/null 2>&1; then
			actual="$(sha256sum "$tmp_bin" | awk '{print $1}')"
		elif command -v shasum >/dev/null 2>&1; then
			actual="$(shasum -a 256 "$tmp_bin" | awk '{print $1}')"
		else
			actual=""
		fi
		if [[ -n "$actual" && "$actual" != "$expected" ]]; then
			rm -f "$tmp_bin" "$tmp_sums"
			die "checksum mismatch for ${asset} (expected ${expected}, got ${actual}) — refusing to install."
		fi
		[[ -n "$actual" ]] && log "checksum OK (${expected})"
	else
		log "checksum manifest unavailable — skipping integrity check"
	fi
	rm -f "$tmp_sums"

	install -o root -g root -m 0755 "$tmp_bin" "$BINARY_PATH"
	rm -f "$tmp_bin"
	log "installed binary to ${BINARY_PATH}"
fi

# ---------------------------------------------------------------------------
# 2. systemd unit
# ---------------------------------------------------------------------------

if [[ -n "$LOCAL_UNIT" ]]; then
	log "installing unit from local checkout (${LOCAL_UNIT})"
	install -o root -g root -m 0644 "$LOCAL_UNIT" "$UNIT_DEST"
else
	unit_url="https://raw.githubusercontent.com/${REPO}/main/packaging/systemd/arenet.service"
	tmp_unit="$(mktemp)"
	log "downloading systemd unit from ${unit_url}"
	if ! curl -fsSL -o "$tmp_unit" "$unit_url"; then
		rm -f "$tmp_unit"
		die "unit download failed: ${unit_url}"
	fi
	install -o root -g root -m 0644 "$tmp_unit" "$UNIT_DEST"
	rm -f "$tmp_unit"
fi
log "installed unit to ${UNIT_DEST}"

# ---------------------------------------------------------------------------
# 3. System user
# ---------------------------------------------------------------------------

if id arenet >/dev/null 2>&1; then
	log "user 'arenet' already exists — skipping useradd"
else
	log "creating system user 'arenet'"
	useradd \
		--system \
		--no-create-home \
		--home-dir "$DATA_DIR" \
		--shell /usr/sbin/nologin \
		--user-group \
		arenet
fi

# ---------------------------------------------------------------------------
# 4. Data directory
# ---------------------------------------------------------------------------

log "ensuring ${DATA_DIR} exists"
install -d -o arenet -g arenet -m 0750 "$DATA_DIR"

# ---------------------------------------------------------------------------
# 5. Config directory + sample env file
# ---------------------------------------------------------------------------

log "ensuring ${ENV_DIR} exists"
install -d -o root -g root -m 0755 "$ENV_DIR"

if [[ ! -f "$ENV_FILE" ]]; then
	cat > "$ENV_FILE" <<'EOF'
# Arenet env file — sourced by the systemd unit via
# EnvironmentFile=-/etc/arenet/arenet.env.
#
# Uncomment + edit the values below to override the binary's
# defaults. All keys are optional.

# ARENET_ADMIN_BIND=127.0.0.1:8001
# ARENET_DATA_DIR=/var/lib/arenet
# ARENET_LOG_LEVEL=info

# Where the HTTP access log goes when enabled in Settings. The unit
# already sets /var/log/arenet/access.log; uncomment to move it.
# ARENET_ACCESS_LOG_PATH=/var/log/arenet/access.log
EOF
	chmod 0644 "$ENV_FILE"
	log "wrote ${ENV_FILE} (sample, commented out)"
else
	log "${ENV_FILE} already exists — preserving operator config"
fi

# ---------------------------------------------------------------------------
# 6. Reload + enable + start
# ---------------------------------------------------------------------------

log "reloading systemd unit registry"
systemctl daemon-reload

if [[ "$NO_START" == "1" ]]; then
	echo
	echo "Install done (service NOT started — ARENET_NO_START=1)."
	echo "Start it when ready:  sudo systemctl enable --now arenet"
	exit 0
fi

if [[ ! -x "$BINARY_PATH" ]]; then
	echo
	echo "Install done, but ${BINARY_PATH} is missing — NOT starting the service."
	echo "Install the binary there, then:  sudo systemctl enable --now arenet"
	exit 0
fi

log "enabling + starting arenet.service"
systemctl enable --now arenet

echo
echo "Install done. Service status:"
systemctl --no-pager --lines=0 status arenet || true

echo
echo "Next steps:"
echo "  1. Grab the one-shot setup token from the journal:"
echo "       sudo journalctl -u arenet | grep 'Setup token'"
echo "  2. Open http://localhost:8001 (admin binds to 127.0.0.1 by"
echo "     default — use an SSH tunnel from a remote workstation:"
echo "       ssh -L 8001:localhost:8001 <this-host>"
echo "  3. Paste the token, create your first admin user, done."
echo
echo "Logs:    sudo journalctl -u arenet -f"
echo "Restart: sudo systemctl restart arenet"
