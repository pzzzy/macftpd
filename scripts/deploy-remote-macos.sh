#!/usr/bin/env bash
set -euo pipefail

REMOTE="${REMOTE:-macftpd@example-host.local}"
KEY="${KEY:-}"
REMOTE_DIR="${REMOTE_DIR:-/opt/macftpd}"
STORAGE_ROOT="${STORAGE_ROOT:-/srv/macftpd/files}"
START_MODE="${START_MODE:-manual}"
FTP_LISTEN="${FTP_LISTEN:-0.0.0.0:2121}"
HTTP_LISTEN="${HTTP_LISTEN:-0.0.0.0:8080}"
PASSIVE_PORTS="${PASSIVE_PORTS:-50000-50100}"
FTP_EXTERNAL_IP="${FTP_EXTERNAL_IP:-auto}"
FTP_AUTO_MAP="${FTP_AUTO_MAP:-true}"
FTP_NAT_GATEWAY="${FTP_NAT_GATEWAY:-}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-}"
SESSION_KEY="${SESSION_KEY:-}"
SSH_OPTS=()
if [[ -n "${KEY}" ]]; then
  SSH_OPTS=(-i "${KEY}")
fi

if [[ -z "${ADMIN_PASS}" ]]; then
  ADMIN_PASS="$(openssl rand -base64 24 | tr '+/' '-_')"
  echo "Generated admin password: ${ADMIN_PASS}"
fi
if [[ -z "${SESSION_KEY}" ]]; then
  SESSION_KEY="$(openssl rand -base64 36 | tr '+/' '-_')"
fi

mkdir -p dist
GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/macftpd ./cmd/macftpd

tmp_config="$(mktemp)"
python3 - "$tmp_config" <<PY
import json, sys
auto_map = "${FTP_AUTO_MAP}".strip().lower() in ("1", "true", "yes", "on")
cfg = {
  "ftp": {
    "listen": "${FTP_LISTEN}",
    "passive_ports": "${PASSIVE_PORTS}",
    "external_ip": "${FTP_EXTERNAL_IP}",
    "auto_map": auto_map,
    "nat_gateway": "${FTP_NAT_GATEWAY}",
    "mapping_lifetime": "1h",
    "tls_cert_file": "",
    "tls_key_file": "",
    "require_tls": False,
    "allow_active": True,
    "allow_fxp": False,
    "idle_timeout": "10m",
    "welcome": "macftpd ready"
  },
  "http": {
    "listen": "${HTTP_LISTEN}",
    "public_base_url": "",
    "session_key": "${SESSION_KEY}",
    "public_cache_control": "public, max-age=300, stale-while-revalidate=60",
    "read_timeout": "10s",
    "write_timeout": "60s"
  },
  "storage": {
    "root": "${STORAGE_ROOT}",
    "public_dir": "public",
    "dropbox_dir": "dropboxes",
    "ignore": [".DS_Store", "._*", ".AppleDouble", ".Spotlight-V100", ".Trashes", ".fseventsd", ".TemporaryItems", ".apdisk", ".git", ".svn", ".hg", ".env", ".ssh", "._macftpd_trash", "._macftpd_versions"]
  },
  "auth": {
    "users_path": "${REMOTE_DIR}/var/users.json",
    "bootstrap_admin_user": "${ADMIN_USER}",
    "bootstrap_admin_pass": "${ADMIN_PASS}"
  },
  "cloudflare": {
    "enabled": False,
    "zone_id": "",
    "api_token": "",
    "cache_tag": "macftpd-public",
    "http_proxy": True
  }
}
with open(sys.argv[1], "w") as f:
    json.dump(cfg, f, indent=2)
PY

ssh "${SSH_OPTS[@]}" "${REMOTE}" "mkdir -p '${REMOTE_DIR}/bin' '${REMOTE_DIR}/var' '${STORAGE_ROOT}/public' '${STORAGE_ROOT}/dropboxes'"
scp "${SSH_OPTS[@]}" dist/macftpd "${REMOTE}:${REMOTE_DIR}/bin/macftpd.new"
scp "${SSH_OPTS[@]}" "${tmp_config}" "${REMOTE}:${REMOTE_DIR}/config.json.new"
rm -f "${tmp_config}"

ssh "${SSH_OPTS[@]}" "${REMOTE}" "REMOTE_DIR='${REMOTE_DIR}' START_MODE='${START_MODE}' bash -s" <<'SH'
set -euo pipefail
REMOTE_DIR="${REMOTE_DIR:-/opt/macftpd}"
chmod 755 "${REMOTE_DIR}/bin/macftpd.new"
if [[ -f "${REMOTE_DIR}/bin/macftpd" ]]; then
  cp "${REMOTE_DIR}/bin/macftpd" "${REMOTE_DIR}/bin/macftpd.prev.$(date -u +%Y%m%dT%H%M%SZ)"
fi
mv "${REMOTE_DIR}/bin/macftpd.new" "${REMOTE_DIR}/bin/macftpd"
if command -v codesign >/dev/null 2>&1; then
  codesign --force --sign - --identifier org.rememe.macftpd "${REMOTE_DIR}/bin/macftpd"
fi
if [[ ! -f "${REMOTE_DIR}/config.json" ]]; then
  mv "${REMOTE_DIR}/config.json.new" "${REMOTE_DIR}/config.json"
else
  backup="${REMOTE_DIR}/config.json.backup.$(date -u +%Y%m%dT%H%M%SZ)"
  cp "${REMOTE_DIR}/config.json" "${backup}"
  chmod 600 "${backup}"
  python3 - "${REMOTE_DIR}/config.json" "${REMOTE_DIR}/config.json.new" "${REMOTE_DIR}/config.json.merged" <<'PY'
import json, sys
old_path, new_path, out_path = sys.argv[1:]
with open(old_path) as f:
    old = json.load(f)
with open(new_path) as f:
    new = json.load(f)
for section, keys in {
    "auth": ["bootstrap_admin_pass"],
    "http": ["session_key", "turnstile_site_key", "turnstile_secret"],
    "ftp": ["tls_cert_file", "tls_key_file", "require_tls"],
    "cloudflare": ["zone_id", "api_token", "enabled"],
}.items():
    if section in old and section in new:
        for key in keys:
            if old[section].get(key) not in ("", None):
                new[section][key] = old[section][key]
with open(out_path, "w") as f:
    json.dump(new, f, indent=2)
    f.write("\n")
PY
  mv "${REMOTE_DIR}/config.json.new" "${REMOTE_DIR}/config.json.last_deployed"
mv "${REMOTE_DIR}/config.json.merged" "${REMOTE_DIR}/config.json"
fi
chmod 600 "${REMOTE_DIR}/config.json" "${REMOTE_DIR}/config.json.last_deployed" 2>/dev/null || true
cat >"${REMOTE_DIR}/com.example.macftpd.plist" <<EOF
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
plutil -lint "${REMOTE_DIR}/com.example.macftpd.plist"
cp "${REMOTE_DIR}/com.example.macftpd.plist" "${HOME}/Library/LaunchAgents/com.example.macftpd.plist"
launchctl bootout "gui/$(id -u)/com.example.macftpd" 2>/dev/null || true
pkill -x macftpd 2>/dev/null || true
if [[ "${START_MODE}" == "launchd" ]]; then
  launchctl bootstrap "gui/$(id -u)" "${HOME}/Library/LaunchAgents/com.example.macftpd.plist"
  launchctl kickstart -k "gui/$(id -u)/com.example.macftpd"
  sleep 1
  launchctl print "gui/$(id -u)/com.example.macftpd" | sed -n '1,80p'
else
  nohup "${REMOTE_DIR}/bin/macftpd" -config "${REMOTE_DIR}/config.json" >"${REMOTE_DIR}/var/macftpd.manual.log" 2>"${REMOTE_DIR}/var/macftpd.manual.err.log" </dev/null &
  sleep 1
  pgrep -lf macftpd
  tail -20 "${REMOTE_DIR}/var/macftpd.manual.err.log" || true
fi
SH

echo "Deployment complete."
echo "HTTP health: http://${REMOTE#*@}:8080/healthz"
echo "FTP: ${REMOTE#*@}:2121 user=${ADMIN_USER}"
