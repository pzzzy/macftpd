#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${MACFTPD_APP_DIR:-/opt/macftpd}"
CONFIG="${MACFTPD_CONFIG:-${APP_DIR}/config.json}"
LINEAGE="${RENEWED_LINEAGE:-${MACFTPD_RENEWED_LINEAGE:-}}"
if [[ -z "${LINEAGE}" ]]; then
  echo "RENEWED_LINEAGE or MACFTPD_RENEWED_LINEAGE is required" >&2
  exit 2
fi

read -r cert_path key_path < <(python3 - "$CONFIG" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    cfg = json.load(f)
print(cfg["ftp"]["tls_cert_file"], cfg["ftp"]["tls_key_file"])
PY
)

if [[ -z "${cert_path}" || -z "${key_path}" ]]; then
  echo "ftp.tls_cert_file and ftp.tls_key_file must be configured" >&2
  exit 2
fi

install -d -m 750 "$(dirname "${cert_path}")" "$(dirname "${key_path}")"
if [[ -f "${cert_path}" || -f "${key_path}" ]]; then
  backup_dir="${APP_DIR}/var/tls/backup"
  install -d -m 700 "${backup_dir}"
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  [[ -f "${cert_path}" ]] && cp "${cert_path}" "${backup_dir}/$(basename "${cert_path}").${stamp}"
  [[ -f "${key_path}" ]] && cp "${key_path}" "${backup_dir}/$(basename "${key_path}").${stamp}"
fi

cp "${LINEAGE}/fullchain.pem" "${cert_path}"
cp "${LINEAGE}/privkey.pem" "${key_path}"
chmod 644 "${cert_path}"
chmod 600 "${key_path}"

if pgrep -f "^${APP_DIR}/bin/macftpd -config " >/dev/null 2>&1; then
  pgrep -f "^${APP_DIR}/bin/macftpd -config " | while read -r pid; do
    kill "${pid}" >/dev/null 2>&1 || true
  done
elif launchctl print "gui/$(id -u)/com.example.macftpd" >/dev/null 2>&1; then
  launchctl kickstart -k "gui/$(id -u)/com.example.macftpd"
elif launchctl print "gui/$(id -u)/com.luke.macftpd" >/dev/null 2>&1; then
  launchctl kickstart -k "gui/$(id -u)/com.luke.macftpd"
fi
