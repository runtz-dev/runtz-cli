#!/usr/bin/env bash
#
# runtz CLI installer for Linux and macOS.
#
#   curl -fsSL https://runtz.dev/install.sh | bash
#
# This script:
#   - Detects your OS and architecture.
#   - Downloads the matching release binary from GitHub Releases.
#   - Verifies its SHA-256 against the release's checksums.txt.
#   - Installs it to /usr/local/bin (or RUNTZ_INSTALL_DIR), using sudo only
#     if the target directory isn't already writable.
#
# It does not install any other dependencies or touch system package
# managers: the runtz CLI is a single static Go binary.
#
# Environment overrides:
#   RUNTZ_VERSION      Release tag to install (default: latest)
#   RUNTZ_INSTALL_DIR  Install directory (default: /usr/local/bin)
#   RUNTZ_REPO         GitHub repository (default: runtz-dev/runtz-cli)
#
# Source code: https://github.com/runtz-dev/runtz-cli/blob/main/install.sh

set -euo pipefail

REPO="${RUNTZ_REPO:-runtz-dev/runtz-cli}"
VERSION="${RUNTZ_VERSION:-latest}"
INSTALL_DIR="${RUNTZ_INSTALL_DIR:-/usr/local/bin}"
BINARY="runtz"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

command_exists() { command -v "$1" >/dev/null 2>&1; }

command_exists curl || fail "curl is required to install runtz"

# sha256sum (GNU/most Linux) or shasum -a 256 (macOS/BSD) — pick whichever
# exists rather than assuming one.
sha256() {
  if command_exists sha256sum; then
    sha256sum "$1" | awk '{print $1}'
  elif command_exists shasum; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required to verify the download"
  fi
}

case "$(uname -s)" in
  Linux) OS="linux" ;;
  Darwin) OS="darwin" ;;
  *) fail "unsupported operating system: $(uname -s) (runtz supports Linux and macOS)" ;;
esac

case "$(uname -m)" in
  x86_64 | amd64) ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *) fail "unsupported architecture: $(uname -m) (runtz supports amd64 and arm64)" ;;
esac

ASSET="runtz_${OS}_${ARCH}"
if [ "$VERSION" = "latest" ]; then
  RELEASE_URL="https://github.com/${REPO}/releases/latest/download"
else
  RELEASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
fi

# GitHub's "latest" only covers stable releases. While runtz ships release
# candidates (1.0.0-rcN), fall back to the newest release, prereleases included.
resolve_newest_tag() {
  curl -fsSL --proto '=https' "https://api.github.com/repos/${REPO}/releases?per_page=1" 2>/dev/null |
    grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
}

# fetch retries once on a transient network failure before giving up.
fetch() {
  local url="$1" out="$2"
  if curl -fsSL --proto '=https' "$url" -o "$out" 2>/dev/null; then
    return 0
  fi
  sleep 1
  curl -fsSL --proto '=https' "$url" -o "$out"
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

info "Downloading runtz (${OS}/${ARCH}, ${VERSION})..."
if ! fetch "${RELEASE_URL}/${ASSET}" "${TMP_DIR}/${BINARY}"; then
  if [ "$VERSION" = "latest" ]; then
    TAG="$(resolve_newest_tag)"
    [ -n "$TAG" ] || fail "download failed: ${RELEASE_URL}/${ASSET}"
    info "No stable release yet; using newest release ${TAG}..."
    RELEASE_URL="https://github.com/${REPO}/releases/download/${TAG}"
    fetch "${RELEASE_URL}/${ASSET}" "${TMP_DIR}/${BINARY}" ||
      fail "download failed: ${RELEASE_URL}/${ASSET}"
  else
    fail "download failed: ${RELEASE_URL}/${ASSET}"
  fi
fi

info "Verifying checksum..."
if fetch "${RELEASE_URL}/checksums.txt" "${TMP_DIR}/checksums.txt"; then
  WANT="$(grep " ${ASSET}\$" "${TMP_DIR}/checksums.txt" | awk '{print $1}')"
  if [ -z "$WANT" ]; then
    fail "checksum for ${ASSET} not found in checksums.txt"
  fi
  GOT="$(sha256 "${TMP_DIR}/${BINARY}")"
  [ "$GOT" = "$WANT" ] || fail "checksum mismatch for ${ASSET}: got ${GOT}, want ${WANT}"
else
  fail "download failed: ${RELEASE_URL}/checksums.txt"
fi

chmod +x "${TMP_DIR}/${BINARY}"

info "Installing to ${INSTALL_DIR}/${BINARY}..."
if [ -w "$INSTALL_DIR" ] || [ "$(id -u)" = "0" ]; then
  mkdir -p "$INSTALL_DIR"
  mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
  command_exists sudo || fail "no write access to ${INSTALL_DIR} and sudo is not available; set RUNTZ_INSTALL_DIR to a writable directory"
  info "Elevated permissions required for ${INSTALL_DIR}"
  sudo mkdir -p "$INSTALL_DIR"
  sudo mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi

info "Installed $("${INSTALL_DIR}/${BINARY}" version)"
info "Run 'runtz --help' to get started."
