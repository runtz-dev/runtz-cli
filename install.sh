#!/usr/bin/env bash
#
# runtz CLI installer
#
#   curl -fsSL https://get.runtz.dev | bash
#
# Environment overrides:
#   RUNTZ_VERSION      Release tag to install (default: latest)
#   RUNTZ_INSTALL_DIR  Install directory (default: /usr/local/bin)
#   RUNTZ_REPO         GitHub repository (default: runtz-dev/runtz-cli)

set -euo pipefail

REPO="${RUNTZ_REPO:-runtz-dev/runtz-cli}"
VERSION="${RUNTZ_VERSION:-latest}"
INSTALL_DIR="${RUNTZ_INSTALL_DIR:-/usr/local/bin}"
BINARY="runtz"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

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
  URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
else
  URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
fi

# GitHub's "latest" only covers stable releases. While runtz ships release
# candidates (1.0.0-rcN), fall back to the newest release, prereleases included.
resolve_newest_tag() {
  curl -fsSL --proto '=https' "https://api.github.com/repos/${REPO}/releases?per_page=1" 2>/dev/null |
    grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

info "Downloading runtz (${OS}/${ARCH}, ${VERSION})..."
if ! curl -fsSL --proto '=https' "$URL" -o "${TMP_DIR}/${BINARY}"; then
  if [ "$VERSION" = "latest" ]; then
    TAG="$(resolve_newest_tag)"
    [ -n "$TAG" ] || fail "download failed: ${URL}"
    info "No stable release yet; using newest release ${TAG}..."
    URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
    curl -fsSL --proto '=https' "$URL" -o "${TMP_DIR}/${BINARY}" ||
      fail "download failed: ${URL}"
  else
    fail "download failed: ${URL}"
  fi
fi

chmod +x "${TMP_DIR}/${BINARY}"

info "Installing to ${INSTALL_DIR}/${BINARY}..."
if [ -w "$INSTALL_DIR" ]; then
  mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
  info "Elevated permissions required for ${INSTALL_DIR}"
  sudo mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi

info "Installed $("${INSTALL_DIR}/${BINARY}" version)"
info "Run 'runtz --help' to get started."
