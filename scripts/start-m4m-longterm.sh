#!/usr/bin/env bash
set -euo pipefail

REMOTE="${REMOTE:-deployer@example-host}"
KEY="${KEY:-~/.ssh/id_ed25519}"
REMOTE_DIR="${REMOTE_DIR:-/opt/macftpd}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-}"
INTERVAL="${INTERVAL:-60}"
HOST="${HOST:-}"
SERVER_SESSION="${SERVER_SESSION:-macftpd-server}"
MONITOR_SESSION="${MONITOR_SESSION:-macftpd-monitor}"

if [[ -z "${ADMIN_PASS}" && -f var/example-admin-pass.txt ]]; then
  ADMIN_PASS="$(cat var/example-admin-pass.txt)"
fi
if [[ -z "${ADMIN_PASS}" ]]; then
  echo "ADMIN_PASS is required or var/example-admin-pass.txt must exist" >&2
  exit 2
fi

scp -i "${KEY}" scripts/example-monitor.sh "${REMOTE}:${REMOTE_DIR}/bin/example-monitor.sh"

if [[ -z "${HOST}" ]]; then
  HOST="$(ssh -i "${KEY}" -o BatchMode=yes -o ConnectTimeout=5 "${REMOTE}" "ipconfig getifaddr en0 || ipconfig getifaddr en1 || ifconfig | awk '/inet / && !/127.0.0.1/ {print \\\$2; exit}'" 2>/dev/null || true)"
fi
if [[ -z "${HOST}" ]]; then
  HOST="example-host.local"
fi

ssh -i "${KEY}" "${REMOTE}" \
  "REMOTE_DIR='${REMOTE_DIR}' ADMIN_USER='${ADMIN_USER}' ADMIN_PASS='${ADMIN_PASS}' INTERVAL='${INTERVAL}' HOST='${HOST}' SERVER_SESSION='${SERVER_SESSION}' MONITOR_SESSION='${MONITOR_SESSION}' bash -s" <<'SH'
set -euo pipefail

mkdir -p "${REMOTE_DIR}/var"
chmod 700 "${REMOTE_DIR}/var"
chmod 755 "${REMOTE_DIR}/bin/example-monitor.sh"

cat >"${REMOTE_DIR}/var/monitor.env" <<ENV
ADMIN_PASS='${ADMIN_PASS}'
ENV
chmod 600 "${REMOTE_DIR}/var/monitor.env"

(screen -ls || true) | awk -v name=".${SERVER_SESSION}" '$1 ~ name {print $1}' | while read -r session; do
  screen -S "${session}" -X quit >/dev/null 2>&1 || true
done
(screen -ls || true) | awk -v name=".${MONITOR_SESSION}" '$1 ~ name {print $1}' | while read -r session; do
  screen -S "${session}" -X quit >/dev/null 2>&1 || true
done
launchctl bootout "gui/$(id -u)/com.luke.macftpd" >/dev/null 2>&1 || true
pkill -x macftpd >/dev/null 2>&1 || true
pkill -f "${REMOTE_DIR}/bin/example-monitor.sh" >/dev/null 2>&1 || true
pgrep -f "macftpd.screen.log" | while read -r pid; do
  [[ "${pid}" == "$$" ]] && continue
  kill "${pid}" >/dev/null 2>&1 || true
done
sleep 1

screen -dmS "${SERVER_SESSION}" bash -lc "
  cd '${REMOTE_DIR}'
  while true; do
    printf '\n=== %s starting macftpd ===\n' \"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
    ./bin/macftpd -config ./config.json
    code=\$?
    printf '=== %s macftpd exited code=%s; restarting in 5s ===\n' \"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\" \"\$code\"
    sleep 5
  done >>'${REMOTE_DIR}/var/macftpd.screen.log' 2>&1
"

sleep 1

screen -dmS "${MONITOR_SESSION}" bash -lc "
  APP_DIR='${REMOTE_DIR}' ADMIN_USER='${ADMIN_USER}' INTERVAL='${INTERVAL}' HOST='${HOST}' '${REMOTE_DIR}/bin/example-monitor.sh'
"

sleep 2
screen -ls || true
pgrep -lf macftpd || true
tail -20 "${REMOTE_DIR}/var/macftpd.screen.log" || true
tail -40 "${REMOTE_DIR}/var/monitor.log" || true
SH
