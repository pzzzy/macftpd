#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

go_files=()
while IFS= read -r file; do
  go_files+=("${file}")
done < <(rg --files -g '*.go')
if [[ ${#go_files[@]} -eq 0 ]]; then
  echo "no Go files found" >&2
  exit 1
fi
unformatted="$(gofmt -l "${go_files[@]}")"
if [[ -n "${unformatted}" ]]; then
  echo "gofmt required:" >&2
  echo "${unformatted}" >&2
  exit 1
fi

go mod verify
go test -shuffle=on -count=3 ./...
go test -race ./...
go vet ./...

build_dir="$(mktemp -d)"
asset_snapshot="$(mktemp -d)"
trap 'rm -rf "${asset_snapshot}" "${build_dir}"' EXIT
go build -o "${build_dir}/macftpd" ./cmd/macftpd
GOOS=darwin GOARCH=arm64 go build -o "${build_dir}/macftpd-darwin-arm64" ./cmd/macftpd

npm ci
npm audit --audit-level=high
cp internal/httpapi/static/macftpd.css internal/httpapi/static/htmx.min.js "${asset_snapshot}/"
npm run build
diff -u "${asset_snapshot}/macftpd.css" internal/httpapi/static/macftpd.css
diff -u "${asset_snapshot}/htmx.min.js" internal/httpapi/static/htmx.min.js

for script in scripts/*.sh; do
  bash -n "${script}"
done
shellcheck --severity=warning scripts/*.sh
node --check cloudflare/worker.js
./scripts/check-private-identifiers.sh

go run github.com/securego/gosec/v2/cmd/gosec@v2.27.1 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
npx wrangler deploy --config cloudflare/wrangler.jsonc --dry-run
