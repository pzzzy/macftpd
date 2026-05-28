#!/usr/bin/env bash
set -euo pipefail

CONFIG="${MACFTPD_CONFIG:-${MACFTPD_APP_DIR:-/opt/macftpd}/config.json}"
STORAGE_ROOT="${MACFTPD_STORAGE_ROOT:-}"
if [[ -z "${STORAGE_ROOT}" ]]; then
  STORAGE_ROOT="$(python3 - "$CONFIG" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    print(json.load(f)["storage"]["root"])
PY
)"
fi

: "${CERTBOT_TOKEN:?CERTBOT_TOKEN is required}"
: "${CERTBOT_VALIDATION:?CERTBOT_VALIDATION is required}"

challenge_dir="${STORAGE_ROOT}/public/.well-known/acme-challenge"
mkdir -p "${challenge_dir}"
printf '%s' "${CERTBOT_VALIDATION}" >"${challenge_dir}/${CERTBOT_TOKEN}"
chmod 644 "${challenge_dir}/${CERTBOT_TOKEN}"
