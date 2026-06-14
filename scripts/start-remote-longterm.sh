#!/usr/bin/env bash
set -euo pipefail

REMOTE="${REMOTE:-macftpd@example-host.local}"
KEY="${KEY:-}"
REMOTE_DIR="${REMOTE_DIR:-/opt/macftpd}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-}"
INTERVAL="${INTERVAL:-60}"
HOST="${HOST:-}"
START_MODE="${START_MODE:-launchd}"
SERVER_SESSION="${SERVER_SESSION:-macftpd-server}"
MONITOR_SESSION="${MONITOR_SESSION:-macftpd-monitor}"
SSH_OPTS=()
if [[ -n "${KEY}" ]]; then
  SSH_OPTS=(-i "${KEY}")
fi

if [[ -z "${ADMIN_PASS}" && -f var/admin-pass.txt ]]; then
  ADMIN_PASS="$(cat var/admin-pass.txt)"
fi
if [[ -z "${ADMIN_PASS}" ]]; then
  echo "ADMIN_PASS is required or var/admin-pass.txt must exist" >&2
  exit 2
fi

scp "${SSH_OPTS[@]}" scripts/monitor.sh scripts/rotate-logs.sh scripts/weekly-report.sh "${REMOTE}:${REMOTE_DIR}/bin/"

if [[ -z "${HOST}" ]]; then
  HOST="$(ssh "${SSH_OPTS[@]}" -o BatchMode=yes -o ConnectTimeout=5 "${REMOTE}" "ipconfig getifaddr en0 || ipconfig getifaddr en1 || ifconfig | awk '/inet / && !/127.0.0.1/ {print \\\$2; exit}'" 2>/dev/null || true)"
fi
if [[ -z "${HOST}" ]]; then
  HOST="example-host.local"
fi

ssh "${SSH_OPTS[@]}" "${REMOTE}" \
  "REMOTE_DIR='${REMOTE_DIR}' ADMIN_USER='${ADMIN_USER}' ADMIN_PASS='${ADMIN_PASS}' INTERVAL='${INTERVAL}' HOST='${HOST}' START_MODE='${START_MODE}' SERVER_SESSION='${SERVER_SESSION}' MONITOR_SESSION='${MONITOR_SESSION}' bash -s" <<'SH'
set -euo pipefail

mkdir -p "${REMOTE_DIR}/var"
chmod 700 "${REMOTE_DIR}/var"
chmod 755 "${REMOTE_DIR}/bin/monitor.sh" "${REMOTE_DIR}/bin/rotate-logs.sh" "${REMOTE_DIR}/bin/weekly-report.sh"

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
launchctl bootout "gui/$(id -u)/com.example.macftpd" >/dev/null 2>&1 || true
pkill -x macftpd >/dev/null 2>&1 || true
pkill -f "${REMOTE_DIR}/bin/monitor.sh" >/dev/null 2>&1 || true
(pgrep -f "macftpd.screen.log" || true) | while read -r pid; do
  [[ "${pid}" == "$$" ]] && continue
  kill "${pid}" >/dev/null 2>&1 || true
done
launchctl bootout "gui/$(id -u)/com.example.macftpd-monitor" >/dev/null 2>&1 || true
launchctl bootout "gui/$(id -u)/com.example.macftpd-logrotate" >/dev/null 2>&1 || true
launchctl bootout "gui/$(id -u)/com.example.macftpd-weekly-report" >/dev/null 2>&1 || true
sleep 1

if [[ "${START_MODE}" == "launchd" ]]; then
  mkdir -p "${HOME}/Library/LaunchAgents"
  cat >"${HOME}/Library/LaunchAgents/com.example.macftpd.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.macftpd</string>
  <key>ProgramArguments</key>
  <array>
    <string>${REMOTE_DIR}/bin/macftpd</string>
    <string>-config</string>
    <string>${REMOTE_DIR}/config.json</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${REMOTE_DIR}</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${REMOTE_DIR}/var/macftpd.launchd.log</string>
  <key>StandardErrorPath</key>
  <string>${REMOTE_DIR}/var/macftpd.launchd.err.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
</dict>
</plist>
EOF
  cat >"${HOME}/Library/LaunchAgents/com.example.macftpd-monitor.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.macftpd-monitor</string>
  <key>ProgramArguments</key>
  <array>
    <string>${REMOTE_DIR}/bin/monitor.sh</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${REMOTE_DIR}</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${REMOTE_DIR}/var/monitor.launchd.log</string>
  <key>StandardErrorPath</key>
  <string>${REMOTE_DIR}/var/monitor.launchd.err.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>APP_DIR</key>
    <string>${REMOTE_DIR}</string>
    <key>HOST</key>
    <string>${HOST}</string>
    <key>ADMIN_USER</key>
    <string>${ADMIN_USER}</string>
    <key>INTERVAL</key>
    <string>${INTERVAL}</string>
    <key>SUMMARY_INTERVAL</key>
    <string>3600</string>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
</dict>
</plist>
EOF
  cat >"${HOME}/Library/LaunchAgents/com.example.macftpd-logrotate.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.macftpd-logrotate</string>
  <key>ProgramArguments</key>
  <array>
    <string>${REMOTE_DIR}/bin/rotate-logs.sh</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${REMOTE_DIR}</string>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key>
    <integer>2</integer>
    <key>Minute</key>
    <integer>37</integer>
  </dict>
  <key>StandardOutPath</key>
  <string>${REMOTE_DIR}/var/logrotate.launchd.log</string>
  <key>StandardErrorPath</key>
  <string>${REMOTE_DIR}/var/logrotate.launchd.err.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>APP_DIR</key>
    <string>${REMOTE_DIR}</string>
    <key>MAX_BYTES</key>
    <string>5242880</string>
    <key>RETENTION_DAYS</key>
    <string>45</string>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
</dict>
</plist>
EOF
  cat >"${HOME}/Library/LaunchAgents/com.example.macftpd-weekly-report.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.macftpd-weekly-report</string>
  <key>ProgramArguments</key>
  <array>
    <string>${REMOTE_DIR}/bin/weekly-report.sh</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${REMOTE_DIR}</string>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Weekday</key>
    <integer>0</integer>
    <key>Hour</key>
    <integer>3</integer>
    <key>Minute</key>
    <integer>12</integer>
  </dict>
  <key>StandardOutPath</key>
  <string>${REMOTE_DIR}/var/weekly-report.launchd.log</string>
  <key>StandardErrorPath</key>
  <string>${REMOTE_DIR}/var/weekly-report.launchd.err.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>APP_DIR</key>
    <string>${REMOTE_DIR}</string>
    <key>HOST</key>
    <string>${HOST}</string>
    <key>WINDOW_DAYS</key>
    <string>7</string>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
</dict>
</plist>
EOF
  for plist in "${HOME}/Library/LaunchAgents/com.example.macftpd.plist" "${HOME}/Library/LaunchAgents/com.example.macftpd-monitor.plist" "${HOME}/Library/LaunchAgents/com.example.macftpd-logrotate.plist" "${HOME}/Library/LaunchAgents/com.example.macftpd-weekly-report.plist"; do
    plutil -lint "${plist}"
    launchctl bootstrap "gui/$(id -u)" "${plist}"
  done
  launchctl kickstart -k "gui/$(id -u)/com.example.macftpd"
  launchctl kickstart -k "gui/$(id -u)/com.example.macftpd-monitor"
  launchctl kickstart -k "gui/$(id -u)/com.example.macftpd-logrotate" || true
  launchctl kickstart -k "gui/$(id -u)/com.example.macftpd-weekly-report" || true
else
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
    APP_DIR='${REMOTE_DIR}' ADMIN_USER='${ADMIN_USER}' INTERVAL='${INTERVAL}' HOST='${HOST}' '${REMOTE_DIR}/bin/monitor.sh'
  "
fi

sleep 2
screen -ls || true
launchctl print "gui/$(id -u)/com.example.macftpd" 2>/dev/null | sed -n '1,60p' || true
launchctl print "gui/$(id -u)/com.example.macftpd-monitor" 2>/dev/null | sed -n '1,60p' || true
launchctl print "gui/$(id -u)/com.example.macftpd-logrotate" 2>/dev/null | sed -n '1,45p' || true
launchctl print "gui/$(id -u)/com.example.macftpd-weekly-report" 2>/dev/null | sed -n '1,45p' || true
pgrep -lf macftpd || true
tail -20 "${REMOTE_DIR}/var/macftpd.launchd.err.log" 2>/dev/null || tail -20 "${REMOTE_DIR}/var/macftpd.screen.log" || true
tail -40 "${REMOTE_DIR}/var/monitor.log" || true
SH
