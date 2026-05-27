#!/usr/bin/env bash
set -euo pipefail

ACCOUNT_ID="${CF_ACCOUNT_ID:-${CLOUDFLARE_ACCOUNT_ID:-}}"
API_TOKEN="${CF_API_TOKEN:-${CLOUDFLARE_API_TOKEN:-}}"
HOSTNAME="${HOSTNAME:-ftp.example.com}"
APP_DOMAIN="${APP_DOMAIN:-${HOSTNAME}/admin*}"
APP_NAME="${APP_NAME:-macftpd admin}"
ALLOW_EMAILS="${ALLOW_EMAILS:-}"

if [[ -f ".env" ]]; then
  # shellcheck source=/dev/null
  source ".env"
  ACCOUNT_ID="${ACCOUNT_ID:-${CF_ACCOUNT_ID:-${CLOUDFLARE_ACCOUNT_ID:-}}}"
  API_TOKEN="${API_TOKEN:-${CF_API_TOKEN:-${CLOUDFLARE_API_TOKEN:-}}}"
fi

if [[ -z "${ACCOUNT_ID}" || -z "${API_TOKEN}" || -z "${ALLOW_EMAILS}" ]]; then
  echo "Set CF_ACCOUNT_ID, CF_API_TOKEN, and ALLOW_EMAILS='you@example.com,other@example.com'" >&2
  exit 2
fi

python3 - "$ACCOUNT_ID" "$API_TOKEN" "$APP_NAME" "$APP_DOMAIN" "$ALLOW_EMAILS" <<'PY'
import json
import sys
import urllib.error
import urllib.request

account, token, app_name, domain, emails = sys.argv[1:]
base = f"https://api.cloudflare.com/client/v4/accounts/{account}/access"
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

def request(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            out = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise SystemExit(f"Cloudflare Access API {method} {path} failed: {e.code} {e.read().decode()}")
    if not out.get("success"):
        raise SystemExit(f"Cloudflare Access API {method} {path} failed: {out}")
    return out["result"]

apps = request("GET", "/apps")
app = next((a for a in apps if a.get("name") == app_name), None)
body = {
    "name": app_name,
    "domain": domain,
    "type": "self_hosted",
    "session_duration": "12h",
    "auto_redirect_to_identity": True,
}
if app:
    app = request("PUT", f"/apps/{app['id']}", body)
    print(f"updated app {app['id']}")
else:
    app = request("POST", "/apps", body)
    print(f"created app {app['id']}")

include = [{"email": {"email": e.strip()}} for e in emails.split(",") if e.strip()]
policy_body = {
    "name": "macftpd admins",
    "decision": "allow",
    "include": include,
}
policies = request("GET", f"/apps/{app['id']}/policies")
policy = next((p for p in policies if p.get("name") == "macftpd admins"), None)
if policy:
    policy = request("PUT", f"/apps/{app['id']}/policies/{policy['id']}", policy_body)
    print(f"updated policy {policy['id']}")
else:
    policy = request("POST", f"/apps/{app['id']}/policies", policy_body)
    print(f"created policy {policy['id']}")
PY
