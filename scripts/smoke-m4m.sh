#!/usr/bin/env bash
set -euo pipefail

REMOTE="${REMOTE:-deployer@example-host}"
KEY="${KEY:-~/.ssh/id_ed25519}"
HOST="${HOST:-}"
HTTP_PORT="${HTTP_PORT:-8080}"
FTP_PORT="${FTP_PORT:-2121}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:?set ADMIN_PASS to the deployed admin password}"

if [[ -z "${HOST}" ]]; then
  HOST="$(ssh -i "${KEY}" -o BatchMode=yes -o ConnectTimeout=5 "${REMOTE}" "ipconfig getifaddr en0 || ipconfig getifaddr en1 || ifconfig | awk '/inet / && !/127.0.0.1/ {print \\\$2; exit}'" 2>/dev/null || true)"
fi
if [[ -z "${HOST}" ]]; then
  HOST="example-host.local"
fi

echo "Checking HTTP health..."
curl -fsS "http://${HOST}:${HTTP_PORT}/healthz"
echo

tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT
printf 'macftpd smoke %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"${tmp}"

echo "Checking FTP upload/download/delete..."
python3 - "$HOST" "$FTP_PORT" "$ADMIN_USER" "$ADMIN_PASS" "$tmp" <<'PY'
import ftplib
import pathlib
import sys

host, port, user, password, path = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], pathlib.Path(sys.argv[5])
remote_dir = "smoke"
remote_file = f"{remote_dir}/{path.name}"
ftp = ftplib.FTP()
ftp.connect(host, port, timeout=15)
ftp.login(user, password)
try:
    ftp.mkd(remote_dir)
except ftplib.error_perm:
    pass
with path.open("rb") as f:
    ftp.storbinary(f"STOR {remote_file}", f)
chunks = []
ftp.retrbinary(f"RETR {remote_file}", chunks.append)
payload = b"".join(chunks)
if payload != path.read_bytes():
    raise SystemExit("downloaded payload did not match upload")
ftp.delete(remote_file)
ftp.quit()
print("ftp transfer ok")
PY

echo "Smoke test passed."
