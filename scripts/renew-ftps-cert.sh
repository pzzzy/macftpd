#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${MACFTPD_APP_DIR:-/opt/macftpd}"
DOMAIN="${MACFTPD_ACME_DOMAIN:-ftp.example.com}"
EMAIL="${MACFTPD_ACME_EMAIL:-}"
JITTER_SECONDS="${MACFTPD_RENEW_JITTER_SECONDS:-3600}"
CERTBOT_CONFIG="${MACFTPD_CERTBOT_CONFIG:-${APP_DIR}/var/letsencrypt}"
CERTBOT_WORK="${MACFTPD_CERTBOT_WORK:-${APP_DIR}/var/certbot-work}"
CERTBOT_LOGS="${MACFTPD_CERTBOT_LOGS:-${APP_DIR}/var/certbot-logs}"
CERTBOT_BIN="${MACFTPD_CERTBOT_BIN:-}"
AUTH_HOOK="${MACFTPD_ACME_AUTH_HOOK:-${APP_DIR}/bin/acme-http-auth.sh}"
CLEANUP_HOOK="${MACFTPD_ACME_CLEANUP_HOOK:-${APP_DIR}/bin/acme-http-cleanup.sh}"
DEPLOY_HOOK="${MACFTPD_ACME_DEPLOY_HOOK:-${APP_DIR}/bin/install-ftps-cert.sh}"

export MACFTPD_APP_DIR="${APP_DIR}"
export MACFTPD_CONFIG="${MACFTPD_CONFIG:-${APP_DIR}/config.json}"
export MACFTPD_STORAGE_ROOT="${MACFTPD_STORAGE_ROOT:-}"

if [[ "${JITTER_SECONDS}" =~ ^[0-9]+$ && "${JITTER_SECONDS}" -gt 0 ]]; then
  sleep "$((RANDOM % (JITTER_SECONDS + 1)))"
fi

if [[ -z "${CERTBOT_BIN}" ]]; then
  if command -v certbot >/dev/null 2>&1; then
    CERTBOT_BIN="$(command -v certbot)"
  elif command -v uvx >/dev/null 2>&1; then
    CERTBOT_BIN="uvx --from certbot certbot"
  else
    echo "certbot or uvx is required" >&2
    exit 2
  fi
fi

mkdir -p "${CERTBOT_CONFIG}" "${CERTBOT_WORK}" "${CERTBOT_LOGS}"

common_args=(
  --config-dir "${CERTBOT_CONFIG}"
  --work-dir "${CERTBOT_WORK}"
  --logs-dir "${CERTBOT_LOGS}"
  --manual
  --preferred-challenges http
  --manual-auth-hook "${AUTH_HOOK}"
  --manual-cleanup-hook "${CLEANUP_HOOK}"
  --deploy-hook "${DEPLOY_HOOK}"
)

if [[ -f "${CERTBOT_CONFIG}/renewal/${DOMAIN}.conf" ]]; then
  # shellcheck disable=SC2086
  ${CERTBOT_BIN} renew --cert-name "${DOMAIN}" --quiet --no-random-sleep-on-renew "${common_args[@]}"
else
  email_args=(--register-unsafely-without-email)
  if [[ -n "${EMAIL}" ]]; then
    email_args=(--email "${EMAIL}")
  fi
  # shellcheck disable=SC2086
  ${CERTBOT_BIN} certonly --non-interactive --agree-tos "${email_args[@]}" \
    --domain "${DOMAIN}" --keep-until-expiring "${common_args[@]}"
fi
