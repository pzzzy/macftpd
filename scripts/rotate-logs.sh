#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/macftpd}"
VAR_DIR="${VAR_DIR:-${APP_DIR}/var}"
MAX_BYTES="${MAX_BYTES:-5242880}"
RETENTION_DAYS="${RETENTION_DAYS:-45}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

rotate_file() {
  local path="$1"
  [[ -f "${path}" ]] || return 0
  local size
  size="$(wc -c <"${path}" | tr -d '[:space:]')"
  [[ "${size}" =~ ^[0-9]+$ ]] || return 0
  if (( size < MAX_BYTES )); then
    return 0
  fi
  local archive="${path}.${STAMP}"
  cp -p "${path}" "${archive}"
  : >"${path}"
  gzip -f "${archive}"
  printf 'rotated %s bytes=%s archive=%s.gz\n' "${path}" "${size}" "${archive}"
}

mkdir -p "${VAR_DIR}"

logs=(
  "${VAR_DIR}/activity.jsonl"
  "${VAR_DIR}/macftpd.launchd.log"
  "${VAR_DIR}/macftpd.launchd.err.log"
  "${VAR_DIR}/macftpd.manual.log"
  "${VAR_DIR}/macftpd.manual.err.log"
  "${VAR_DIR}/macftpd.screen.log"
  "${VAR_DIR}/monitor.log"
  "${VAR_DIR}/monitor.launchd.log"
  "${VAR_DIR}/monitor.launchd.err.log"
  "${VAR_DIR}/cloudflared.launchd.log"
  "${VAR_DIR}/cloudflared.launchd.err.log"
  "${VAR_DIR}/cloudflared.screen.log"
  "${VAR_DIR}/cert-renew.log"
  "${VAR_DIR}/cert-renew.err.log"
)

for path in "${logs[@]}"; do
  rotate_file "${path}"
done

find "${VAR_DIR}" -type f \
  \( -name '*.log.*.gz' -o -name '*.jsonl.*.gz' \) \
  -mtime "+${RETENTION_DAYS}" -print -delete 2>/dev/null || true
