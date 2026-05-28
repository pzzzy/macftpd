#!/usr/bin/env bash
set -euo pipefail

patterns=(
  '(?i)m4m'
  '[[:alnum:]_.-]+@(?!example-host\.local)[[:alnum:]_.-]+\.local'
  '/Users/[[:alnum:]_.-]+'
  '/Volumes/[^[:space:]`"'"'"']+'
  'ftp\.(?!example\.)[[:alnum:]_.-]+\.(org|com|net)'
  '192\.168\.'
  '10\.[0-9]+\.'
  '172\.(1[6-9]|2[0-9]|3[0-1])\.'
)

paths=("$@")
if [[ ${#paths[@]} -eq 0 ]]; then
  paths=(README.md TEST_PLAN.md SECURITY.md configs scripts cloudflare internal cmd launchd)
fi

failed=0
for pattern in "${patterns[@]}"; do
  if rg -n -P --glob '!scripts/check-private-identifiers.sh' --glob '!internal/upnpigd/upnpigd_test.go' --glob '!*.sum' --glob '!go.mod' -- "${pattern}" "${paths[@]}"; then
    failed=1
  fi
done

if [[ ${failed} -ne 0 ]]; then
  echo "private identifier scan failed; replace real hostnames, usernames, paths, domains, or IPs with examples" >&2
  exit 1
fi
