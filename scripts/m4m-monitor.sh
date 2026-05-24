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

if [[ -f "${ENV_PATH}" ]]; then
  # shellcheck source=/dev/null
  source "${ENV_PATH}"
fi

if [[ -z "${ADMIN_PASS:-}" ]]; then
  echo "ADMIN_PASS is required in the environment or ${ENV_PATH}" >&2
  exit 2
fi

mkdir -p "$(dirname "${LOG_PATH}")"

while true; do
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  status="ok"
  {
    echo "=== ${ts} ==="
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
  } >>"${LOG_PATH}" 2>&1
  sleep "${INTERVAL}"
done
