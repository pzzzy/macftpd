#!/usr/bin/env bash
set -euo pipefail

REMOTE="${REMOTE:-macftpd@example-host.local}"
KEY="${KEY:-}"
REMOTE_DIR="${REMOTE_DIR:-/opt/macftpd}"
SESSION="${SESSION:-macftpd-cloudflared}"
START_MODE="${START_MODE:-launchd}"
TUNNEL_TOKEN="${TUNNEL_TOKEN:-}"
TUNNEL_TOKEN_FILE="${TUNNEL_TOKEN_FILE:-}"
CLOUDFLARED="${CLOUDFLARED:-/opt/homebrew/bin/cloudflared}"
SSH_OPTS=()
if [[ -n "${KEY}" ]]; then
  SSH_OPTS=(-i "${KEY}")
fi

if [[ -z "${TUNNEL_TOKEN}" && -n "${TUNNEL_TOKEN_FILE}" ]]; then
  TUNNEL_TOKEN="$(cat "${TUNNEL_TOKEN_FILE}")"
fi
if [[ -z "${TUNNEL_TOKEN}" ]]; then
  echo "set TUNNEL_TOKEN or TUNNEL_TOKEN_FILE to the Cloudflare Tunnel token" >&2
  exit 2
fi

scp "${SSH_OPTS[@]}" "${CLOUDFLARED}" "${REMOTE}:${REMOTE_DIR}/bin/cloudflared"

ssh "${SSH_OPTS[@]}" "${REMOTE}" "REMOTE_DIR='${REMOTE_DIR}' SESSION='${SESSION}' START_MODE='${START_MODE}' TUNNEL_TOKEN='${TUNNEL_TOKEN}' bash -s" <<'SH'
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
launchctl bootout "gui/$(id -u)/com.example.macftpd-cloudflared" >/dev/null 2>&1 || true
sleep 1

if [[ "${START_MODE}" == "launchd" ]]; then
  mkdir -p "${HOME}/Library/LaunchAgents"
  cat >"${HOME}/Library/LaunchAgents/com.example.macftpd-cloudflared.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.macftpd-cloudflared</string>
  <key>ProgramArguments</key>
  <array>
    <string>${REMOTE_DIR}/bin/cloudflared</string>
    <string>tunnel</string>
    <string>--no-autoupdate</string>
    <string>run</string>
    <string>--token-file</string>
    <string>${REMOTE_DIR}/var/cloudflared.env.token</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${REMOTE_DIR}</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${REMOTE_DIR}/var/cloudflared.launchd.log</string>
  <key>StandardErrorPath</key>
  <string>${REMOTE_DIR}/var/cloudflared.launchd.err.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
</dict>
</plist>
EOF
  plutil -lint "${HOME}/Library/LaunchAgents/com.example.macftpd-cloudflared.plist"
  launchctl bootstrap "gui/$(id -u)" "${HOME}/Library/LaunchAgents/com.example.macftpd-cloudflared.plist"
  launchctl kickstart -k "gui/$(id -u)/com.example.macftpd-cloudflared"
else
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
fi

sleep 3
screen -ls || true
launchctl print "gui/$(id -u)/com.example.macftpd-cloudflared" 2>/dev/null | sed -n '1,80p' || true
pgrep -lf "${REMOTE_DIR}/bin/cloudflared" || true
tail -40 "${REMOTE_DIR}/var/cloudflared.launchd.err.log" 2>/dev/null || tail -40 "${REMOTE_DIR}/var/cloudflared.screen.log" || true
SH
