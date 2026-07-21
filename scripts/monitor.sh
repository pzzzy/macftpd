#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/macftpd}"
HOST="${HOST:-127.0.0.1}"
HTTP_PORT="${HTTP_PORT:-8080}"
FTP_PORT="${FTP_PORT:-2121}"
ADMIN_USER="${ADMIN_USER:-admin}"
INTERVAL="${INTERVAL:-60}"
LOG_PATH="${LOG_PATH:-${APP_DIR}/var/monitor.log}"
ENV_PATH="${ENV_PATH:-${APP_DIR}/var/monitor.env}"
SUMMARY_INTERVAL="${SUMMARY_INTERVAL:-3600}"

if [[ -f "${ENV_PATH}" ]]; then
  # shellcheck source=/dev/null
  source "${ENV_PATH}"
fi

if [[ -z "${ADMIN_PASS:-}" ]]; then
  echo "ADMIN_PASS is required in the environment or ${ENV_PATH}" >&2
  exit 2
fi

mkdir -p "$(dirname "${LOG_PATH}")"
STATE_DIR="${APP_DIR}/var/monitor-state"
mkdir -p "${STATE_DIR}"
LAST_STATUS_PATH="${STATE_DIR}/last-status"
LAST_SUMMARY_PATH="${STATE_DIR}/last-summary"

while true; do
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  now="$(date -u +%s)"
  status="ok"
  output_path="$(mktemp "${STATE_DIR}/probe.XXXXXX")"
  {
    if ! curl -fsS --max-time 10 "http://${HOST}:${HTTP_PORT}/healthz"; then
      status="fail"
      echo "http health failed"
    fi
    echo
    if ! python3 - "${HOST}" "${FTP_PORT}" "${ADMIN_USER}" "${ADMIN_PASS}" <<'PY'
import ftplib
import io
import sys
import time

host, port, user, password = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
payload = f"macftpd monitor {stamp}\n".encode()
remote_dir = "_monitor"
remote_file = f"{remote_dir}/{stamp}.txt"

ftp = ftplib.FTP()
ftp.connect(host, port, timeout=20)
ftp.sendcmd("CLNT macftpd-monitor")
ftp.login(user, password)
try:
    ftp.mkd(remote_dir)
except ftplib.error_perm:
    pass
ftp.storbinary(f"STOR {remote_file}", io.BytesIO(payload))
chunks = []
ftp.retrbinary(f"RETR {remote_file}", chunks.append)
if b"".join(chunks) != payload:
    raise SystemExit("payload mismatch")
ftp.delete(remote_file)
ftp.quit()
print(f"ftp ok {remote_file} {len(payload)} bytes")
PY
    then
      status="fail"
      echo "ftp probe failed"
    fi
    echo "status=${status}"
  } >"${output_path}" 2>&1

  last_status="$(cat "${LAST_STATUS_PATH}" 2>/dev/null || true)"
  last_summary="$(cat "${LAST_SUMMARY_PATH}" 2>/dev/null || echo 0)"
  should_log=0
  if [[ "${status}" != "ok" ]]; then
    should_log=1
  elif [[ "${last_status}" == "fail" ]]; then
    should_log=1
  elif (( now - last_summary >= SUMMARY_INTERVAL )); then
    should_log=1
  fi

  if (( should_log )); then
    {
      echo "=== ${ts} ==="
      if [[ "${status}" == "ok" && "${last_status}" == "fail" ]]; then
        echo "recovered"
      fi
      if [[ "${status}" == "ok" ]]; then
        echo "status=ok"
        echo "${now}" >"${LAST_SUMMARY_PATH}"
      else
        cat "${output_path}"
      fi
    } >>"${LOG_PATH}" 2>&1
  fi
  rm -f "${output_path}"
  printf '%s\n' "${status}" >"${LAST_STATUS_PATH}"
  sleep "${INTERVAL}"
done
