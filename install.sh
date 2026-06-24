#!/usr/bin/env bash
# Copyright 2026 Defense Unicorns
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

set -euo pipefail

REPO="defenseunicorns/uds-pk"
BIN="uds-pk"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${VERSION:-latest}"

# GoReleaser publishes assets as uds-pk_<tag>_<Os>_<Arch> with title-cased OS
# and GOARCH-style arch. uname -s already returns Darwin/Linux to match.
os="$(uname -s)"
arch="$(uname -m)"
case "$arch" in
  x86_64 | amd64) arch="amd64" ;;
  arm64 | aarch64) arch="arm64" ;;
  *)
    echo "unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

case "$os" in
  Darwin | Linux) ;;
  *)
    echo "unsupported OS: $os" >&2
    exit 1
    ;;
esac

if [ "$VERSION" = "latest" ]; then
  # Resolve into a variable first; piping curl into `grep -m1` makes grep close
  # the pipe early, leaving curl with a broken pipe (exit 23) that pipefail
  # would surface as a silent failure.
  release_json="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest")"
  VERSION="$(grep -m1 '"tag_name"' <<<"$release_json" | cut -d'"' -f4)"
fi

if [ -z "$VERSION" ]; then
  echo "could not resolve release version" >&2
  exit 1
fi

asset="${BIN}_${VERSION}_${os}_${arch}"
base="https://github.com/${REPO}/releases/download/${VERSION}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "downloading ${asset} ..."
curl -fsSL "${base}/${asset}" -o "${tmp}/${BIN}"
curl -fsSL "${base}/checksums.txt" -o "${tmp}/checksums.txt"

# Verify only this asset's checksum line, rewritten to the local filename.
(cd "$tmp" && grep " ${asset}\$" checksums.txt | sed "s/${asset}/${BIN}/" | shasum -a 256 -c -)

chmod +x "${tmp}/${BIN}"
if ! install -m 0755 "${tmp}/${BIN}" "${INSTALL_DIR}/${BIN}" 2>/dev/null; then
  echo "elevated permissions required to write to ${INSTALL_DIR}"
  sudo install -m 0755 "${tmp}/${BIN}" "${INSTALL_DIR}/${BIN}"
fi

echo "installed ${BIN} ${VERSION} -> ${INSTALL_DIR}/${BIN}"
