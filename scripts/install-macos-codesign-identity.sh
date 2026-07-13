#!/usr/bin/env bash
set -euo pipefail

REMOTE_DIR="${REMOTE_DIR:-/opt/macftpd}"
SIGN_NAME="${MACFTPD_CODESIGN_IDENTITY:-macftpd local code signing}"
KEYCHAIN="${MACFTPD_CODESIGN_KEYCHAIN:-${REMOTE_DIR}/var/macftpd-codesign.keychain-db}"
PASS_FILE="${MACFTPD_CODESIGN_KEYCHAIN_PASS_FILE:-${REMOTE_DIR}/var/macftpd-codesign.keychain.pass}"
CERT="${REMOTE_DIR}/var/macftpd-codesign.crt"
KEY="${REMOTE_DIR}/var/macftpd-codesign.key"
P12="${REMOTE_DIR}/var/macftpd-codesign.p12"
OPENSSL_CONFIG="${REMOTE_DIR}/var/macftpd-codesign.openssl.cnf"

mkdir -p "${REMOTE_DIR}/var"
umask 077
if [[ ! -f "${PASS_FILE}" ]]; then
  openssl rand -hex 24 >"${PASS_FILE}"
fi
PASS="$(cat "${PASS_FILE}")"

if [[ ! -f "${KEYCHAIN}" ]]; then
  security create-keychain -p "${PASS}" "${KEYCHAIN}"
  security set-keychain-settings -lut 21600 "${KEYCHAIN}"
fi
security unlock-keychain -p "${PASS}" "${KEYCHAIN}"

cat >"${OPENSSL_CONFIG}" <<EOF
[ req ]
distinguished_name = dn
x509_extensions = codesign_ext
prompt = no

[ dn ]
CN = ${SIGN_NAME}

[ codesign_ext ]
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
basicConstraints = critical,CA:true
EOF

if ! security find-identity -v -p codesigning "${KEYCHAIN}" | grep -F "\"${SIGN_NAME}\"" >/dev/null 2>&1; then
  rm -f "${CERT}" "${KEY}" "${P12}"
  openssl req -new -newkey rsa:2048 -nodes -x509 -days 3650 \
    -config "${OPENSSL_CONFIG}" \
    -keyout "${KEY}" \
    -out "${CERT}" >/dev/null 2>&1
  openssl pkcs12 -export \
    -inkey "${KEY}" \
    -in "${CERT}" \
    -out "${P12}" \
    -password "pass:${PASS}" \
    -name "${SIGN_NAME}" >/dev/null 2>&1
  security import "${P12}" -k "${KEYCHAIN}" -P "${PASS}" -T /usr/bin/codesign >/dev/null
  security set-key-partition-list -S apple-tool:,apple: -s -k "${PASS}" "${KEYCHAIN}" >/dev/null 2>&1 || true
fi

if ! security find-identity -v -p codesigning "${KEYCHAIN}" | grep -F "\"${SIGN_NAME}\"" >/dev/null 2>&1; then
  cat >&2 <<EOF
The identity was imported, but macOS does not trust it for code signing yet.
Run this once on the Mac, then rerun this script:

  sudo security add-trusted-cert -d -r trustRoot -p codeSign -k /Library/Keychains/System.keychain "${CERT}"

EOF
  exit 2
fi

cat <<EOF
Installed code-signing identity:
  MACFTPD_CODESIGN_IDENTITY='${SIGN_NAME}'
  MACFTPD_CODESIGN_KEYCHAIN='${KEYCHAIN}'
  MACFTPD_CODESIGN_KEYCHAIN_PASS_FILE='${PASS_FILE}'
EOF
