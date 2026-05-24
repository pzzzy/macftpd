#!/usr/bin/env bash
set -euo pipefail

REMOTE="${REMOTE:-deployer@example-host}"
KEY="${KEY:-~/.ssh/id_ed25519}"
REMOTE_DIR="${REMOTE_DIR:-/opt/macftpd}"
STORAGE_ROOT="${STORAGE_ROOT:-/srv/macftpd/ftpd}"
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
    "allow_active": True,
    "allow_fxp": False,
    "idle_timeout": "10m",
    "welcome": "macftpd on example host ready"
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
    "ignore": [".DS_Store", "._*", ".AppleDouble", ".Spotlight-V100", ".Trashes", ".fseventsd", ".TemporaryItems", ".apdisk", ".git", ".svn", ".hg", ".env", ".ssh"]
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

ssh -i "${KEY}" "${REMOTE}" "mkdir -p '${REMOTE_DIR}/bin' '${REMOTE_DIR}/var' '${STORAGE_ROOT}/public' '${STORAGE_ROOT}/dropboxes'"
scp -i "${KEY}" dist/macftpd "${REMOTE}:${REMOTE_DIR}/bin/macftpd.new"
scp -i "${KEY}" "${tmp_config}" "${REMOTE}:${REMOTE_DIR}/config.json.new"
scp -i "${KEY}" launchd/com.luke.macftpd.plist "${REMOTE}:${REMOTE_DIR}/com.luke.macftpd.plist.new"
rm -f "${tmp_config}"

ssh -i "${KEY}" "${REMOTE}" "REMOTE_DIR='${REMOTE_DIR}' START_MODE='${START_MODE}' bash -s" <<'SH'
set -euo pipefail
REMOTE_DIR="${REMOTE_DIR:-/opt/macftpd}"
chmod 755 "${REMOTE_DIR}/bin/macftpd.new"
mv "${REMOTE_DIR}/bin/macftpd.new" "${REMOTE_DIR}/bin/macftpd"
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
    "http": ["session_key"],
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
mv "${REMOTE_DIR}/com.luke.macftpd.plist.new" "${REMOTE_DIR}/com.luke.macftpd.plist"
cp "${REMOTE_DIR}/com.luke.macftpd.plist" "${HOME}/Library/LaunchAgents/com.luke.macftpd.plist"
launchctl bootout "gui/$(id -u)/com.luke.macftpd" 2>/dev/null || true
pkill -x macftpd 2>/dev/null || true
if [[ "${START_MODE}" == "launchd" ]]; then
  launchctl bootstrap "gui/$(id -u)" "${HOME}/Library/LaunchAgents/com.luke.macftpd.plist"
  launchctl kickstart -k "gui/$(id -u)/com.luke.macftpd"
  sleep 1
  launchctl print "gui/$(id -u)/com.luke.macftpd" | sed -n '1,80p'
else
  nohup "${REMOTE_DIR}/bin/macftpd" -config "${REMOTE_DIR}/config.json" >"${REMOTE_DIR}/var/macftpd.manual.log" 2>"${REMOTE_DIR}/var/macftpd.manual.err.log" </dev/null &
  sleep 1
  pgrep -lf macftpd
  tail -20 "${REMOTE_DIR}/var/macftpd.manual.err.log" || true
fi
SH

echo "Deployment complete."
echo "HTTP health: http://example-host.local:8080/healthz"
echo "FTP: example-host.local:2121 user=${ADMIN_USER}"
