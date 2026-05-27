#!/usr/bin/env bash
set -euo pipefail

HOSTNAME="${HOSTNAME:-ftp.example.com}"
ZONE_ID="${CF_ZONE_ID:-${CLOUDFLARE_ZONE_ID:-}}"
API_TOKEN="${CF_API_TOKEN:-${CLOUDFLARE_API_TOKEN:-}}"

if [[ -f ".env" ]]; then
  # shellcheck source=/dev/null
  source ".env"
  ZONE_ID="${ZONE_ID:-${CF_ZONE_ID:-${CLOUDFLARE_ZONE_ID:-}}}"
  API_TOKEN="${API_TOKEN:-${CF_API_TOKEN:-${CLOUDFLARE_API_TOKEN:-}}}"
fi

if [[ -z "${ZONE_ID}" || -z "${API_TOKEN}" ]]; then
  echo "Set CF_ZONE_ID and CF_API_TOKEN, or provide them in .env" >&2
  exit 2
fi

python3 - "$ZONE_ID" "$API_TOKEN" "$HOSTNAME" <<'PY'
import json
import sys
import urllib.error
import urllib.request

zone, token, hostname = sys.argv[1:]
base = f"https://api.cloudflare.com/client/v4/zones/{zone}"
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

def request(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            out = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise SystemExit(f"Cloudflare API {method} {path} failed: {e.code} {e.read().decode()}")
    if not out.get("success"):
        raise SystemExit(f"Cloudflare API {method} {path} failed: {out}")
    return out["result"]

rules = [
    {
        "ref": "macftpd-deny-unexpected-methods",
        "description": "macftpd: deny unexpected HTTP methods",
        "expression": f'(http.host eq "{hostname}" and not http.request.method in {{"GET" "HEAD" "POST" "PUT" "PATCH" "DELETE" "OPTIONS"}})',
        "action": "block",
        "enabled": True,
    },
    {
        "ref": "macftpd-admin-api-challenge-suspicious",
        "description": "macftpd: challenge suspicious admin/API traffic",
        "expression": f'(http.host eq "{hostname}" and (starts_with(http.request.uri.path, "/admin") or starts_with(http.request.uri.path, "/api/")) and cf.threat_score ge 10)',
        "action": "managed_challenge",
        "enabled": True,
    },
    {
        "ref": "macftpd-public-download-challenge-high-threat",
        "description": "macftpd: challenge high-threat public download traffic",
        "expression": f'(http.host eq "{hostname}" and starts_with(http.request.uri.path, "/public/") and cf.threat_score ge 25)',
        "action": "managed_challenge",
        "enabled": True,
    },
]

existing = request("GET", "/rulesets?phase=http_request_firewall_custom")
target = None
for ruleset in existing:
    if ruleset.get("name") == "macftpd hardening":
        target = ruleset
        break

body = {
    "name": "macftpd hardening",
    "description": "Managed by macftpd scripts/cloudflare-hardening.sh",
    "kind": "zone",
    "phase": "http_request_firewall_custom",
    "rules": rules,
}
if target:
    result = request("PUT", f"/rulesets/{target['id']}", body)
    print(f"updated {result['id']}")
else:
    result = request("POST", "/rulesets", body)
    print(f"created {result['id']}")
PY
