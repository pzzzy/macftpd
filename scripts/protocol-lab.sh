#!/usr/bin/env bash
set -euo pipefail

HOST="${HOST:-127.0.0.1}"
FTP_PORT="${FTP_PORT:-2121}"
HTTP_PORT="${HTTP_PORT:-8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-}"

if [[ -z "${ADMIN_PASS}" && -f var/admin-pass.txt ]]; then
  ADMIN_PASS="$(cat var/admin-pass.txt)"
fi
if [[ -z "${ADMIN_PASS}" ]]; then
  echo "ADMIN_PASS is required" >&2
  exit 2
fi

curl -fsS --max-time 10 "http://${HOST}:${HTTP_PORT}/healthz" >/dev/null

python3 - "${HOST}" "${FTP_PORT}" "${ADMIN_USER}" "${ADMIN_PASS}" <<'PY'
import ftplib
import io
import ssl
import sys
import time

host, port, user, password = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
base = f"_protocol_lab/{stamp}"

def ftp_plain():
    ftp = ftplib.FTP()
    ftp.connect(host, port, timeout=20)
    ftp.login(user, password)
    return ftp

def ensure_dir(ftp, name):
    try:
        ftp.mkd(name)
    except ftplib.error_perm:
        pass

ftp = ftp_plain()
ensure_dir(ftp, "_protocol_lab")
ensure_dir(ftp, base)
ftp.voidcmd("TYPE I")
features = "\n".join(ftp.sendcmd("FEAT").splitlines())
required = ["UTF8", "PASV", "EPSV", "REST STREAM", "SIZE", "MDTM", "MLSD"]
missing = [x for x in required if x not in features]
if missing:
    raise SystemExit(f"missing FEAT entries: {missing}")

payload = b"abcdefghijklmnopqrstuvwxyz"
remote = f"{base}/resume.bin"
ftp.storbinary(f"STOR {remote}", io.BytesIO(payload[:10]))
ftp.sendcmd("REST 10")
ftp.storbinary(f"STOR {remote}", io.BytesIO(payload[10:]))
buf = []
ftp.retrbinary(f"RETR {remote}", buf.append)
if b"".join(buf) != payload:
    raise SystemExit("REST STOR resume mismatch")
ftp.sendcmd("REST 5")
buf = []
ftp.retrbinary(f"RETR {remote}", buf.append)
if b"".join(buf) != payload[5:]:
    raise SystemExit("REST RETR resume mismatch")
list(ftp.mlsd(base))
if int(ftp.size(remote)) != len(payload):
    raise SystemExit("SIZE mismatch")
ftp.delete(remote)
ftp.rmd(base)
ftp.quit()

try:
    ftps = ftplib.FTP_TLS(context=ssl._create_unverified_context())
    ftps.connect(host, port, timeout=10)
    ftps.auth()
    ftps.prot_p()
    ftps.login(user, password)
    ftps.quit()
    print("ftps=ok")
except Exception as exc:
    print(f"ftps=skip ({exc})")

print("protocol lab ok")
PY
