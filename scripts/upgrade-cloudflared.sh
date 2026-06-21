#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-2026.6.1}"
REMOTE="${REMOTE:-}"
KEY="${KEY:-}"
REMOTE_DIR="${REMOTE_DIR:-/opt/macftpd}"
INSTALL_PATH="${INSTALL_PATH:-${REMOTE_DIR}/bin/cloudflared}"
EXPECTED_BINARY_SHA256_DARWIN_ARM64="${EXPECTED_BINARY_SHA256_DARWIN_ARM64:-ae6ee90188ae5833c687ce937c3693e28403677607c06c65a2ff2b6a022f50e4}"
ASSET="cloudflared-darwin-arm64.tgz"
URL="https://github.com/cloudflare/cloudflared/releases/download/${VERSION}/${ASSET}"
SSH_OPTS=()
if [[ -n "${KEY}" ]]; then
  SSH_OPTS=(-i "${KEY}")
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

archive="${tmpdir}/${ASSET}"
curl -fL --retry 3 --connect-timeout 15 -o "${archive}" "${URL}"
tar -xzf "${archive}" -C "${tmpdir}"
binary="$(find "${tmpdir}" -type f -name cloudflared | head -1)"
if [[ -z "${binary}" ]]; then
  echo "cloudflared binary not found in ${ASSET}" >&2
  exit 1
fi
actual="$(shasum -a 256 "${binary}" | awk '{print $1}')"
if [[ "${actual}" != "${EXPECTED_BINARY_SHA256_DARWIN_ARM64}" ]]; then
  echo "checksum mismatch for extracted cloudflared: got ${actual}, expected ${EXPECTED_BINARY_SHA256_DARWIN_ARM64}" >&2
  exit 1
fi
chmod 755 "${binary}"
"${binary}" --version

if [[ -n "${REMOTE}" ]]; then
  ssh "${SSH_OPTS[@]}" "${REMOTE}" "mkdir -p '${REMOTE_DIR}/bin'"
  scp "${SSH_OPTS[@]}" "${binary}" "${REMOTE}:${REMOTE_DIR}/bin/cloudflared.new"
  ssh "${SSH_OPTS[@]}" "${REMOTE}" "REMOTE_DIR='${REMOTE_DIR}' bash -s" <<'SH'
set -euo pipefail
chmod 755 "${REMOTE_DIR}/bin/cloudflared.new"
if [[ -f "${REMOTE_DIR}/bin/cloudflared" ]]; then
  cp "${REMOTE_DIR}/bin/cloudflared" "${REMOTE_DIR}/bin/cloudflared.prev.$(date -u +%Y%m%dT%H%M%SZ)"
fi
mv "${REMOTE_DIR}/bin/cloudflared.new" "${REMOTE_DIR}/bin/cloudflared"
"${REMOTE_DIR}/bin/cloudflared" --version
if launchctl print "gui/$(id -u)/com.example.macftpd-cloudflared" >/dev/null 2>&1; then
  launchctl kickstart -k "gui/$(id -u)/com.example.macftpd-cloudflared"
fi
SH
else
  mkdir -p "$(dirname "${INSTALL_PATH}")"
  cp "${binary}" "${INSTALL_PATH}.new"
  chmod 755 "${INSTALL_PATH}.new"
  mv "${INSTALL_PATH}.new" "${INSTALL_PATH}"
fi
