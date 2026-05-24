#!/usr/bin/env bash
set -euo pipefail

REMOTE="${REMOTE:-deployer@example-host}"
KEY="${KEY:-~/.ssh/id_ed25519}"
REMOTE_DIR="${REMOTE_DIR:-/opt/macftpd}"
SESSION="${SESSION:-macftpd-cloudflared}"
TUNNEL_TOKEN="${TUNNEL_TOKEN:-}"
TUNNEL_TOKEN_FILE="${TUNNEL_TOKEN_FILE:-}"
CLOUDFLARED="${CLOUDFLARED:-/opt/homebrew/bin/cloudflared}"

if [[ -z "${TUNNEL_TOKEN}" && -n "${TUNNEL_TOKEN_FILE}" ]]; then
  TUNNEL_TOKEN="$(cat "${TUNNEL_TOKEN_FILE}")"
fi
if [[ -z "${TUNNEL_TOKEN}" ]]; then
  echo "set TUNNEL_TOKEN or TUNNEL_TOKEN_FILE to the Cloudflare Tunnel token" >&2
  exit 2
fi

scp -i "${KEY}" "${CLOUDFLARED}" "${REMOTE}:${REMOTE_DIR}/bin/cloudflared"

ssh -i "${KEY}" "${REMOTE}" "REMOTE_DIR='${REMOTE_DIR}' SESSION='${SESSION}' TUNNEL_TOKEN='${TUNNEL_TOKEN}' bash -s" <<'SH'
set -euo pipefail
mkdir -p "${REMOTE_DIR}/var"
chmod 755 "${REMOTE_DIR}/bin/cloudflared"
cat >"${REMOTE_DIR}/var/cloudflared.env" <<ENV
TUNNEL_TOKEN='${TUNNEL_TOKEN}'
ENV
chmod 600 "${REMOTE_DIR}/var/cloudflared.env"
printf '%s' "${TUNNEL_TOKEN}" >"${REMOTE_DIR}/var/cloudflared.env.token"
chmod 600 "${REMOTE_DIR}/var/cloudflared.env.token"

(screen -ls || true) | awk -v name=".${SESSION}" '$1 ~ name {print $1}' | while read -r session; do
  screen -S "${session}" -X quit >/dev/null 2>&1 || true
done
pkill -f "${REMOTE_DIR}/bin/cloudflared tunnel run" >/dev/null 2>&1 || true
sleep 1

screen -dmS "${SESSION}" bash -lc "
  source '${REMOTE_DIR}/var/cloudflared.env'
  while true; do
    printf '\n=== %s starting cloudflared ===\n' \"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
    '${REMOTE_DIR}/bin/cloudflared' tunnel --no-autoupdate run --token-file '${REMOTE_DIR}/var/cloudflared.env.token'
    code=\$?
    printf '=== %s cloudflared exited code=%s; restarting in 5s ===\n' \"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\" \"\$code\"
    sleep 5
  done >>'${REMOTE_DIR}/var/cloudflared.screen.log' 2>&1
"

sleep 3
screen -ls || true
pgrep -lf "${REMOTE_DIR}/bin/cloudflared" || true
tail -40 "${REMOTE_DIR}/var/cloudflared.screen.log" || true
SH
