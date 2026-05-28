# macftpd

`macftpd` is a Go-powered FTP server with a companion HTTP admin/public interface for a modern macOS file host.

Current capabilities:

- FTP control/data server with USER/PASS, passive EPSV/PASV, active PORT/EPRT, LIST/NLST, upload, download, delete, mkdir, rename, SIZE, and MDTM.
- Explicit FTPS with `AUTH TLS`, `PBSZ`, `PROT`, plus modern `MLSD`/`MLST` listings.
- User and group permissions for list, download, upload, delete, mkdir, rename, admin, public, and dropbox workflows.
- Storage-root containment, default macOS/security ignore rules, and virtual `public`/`dropbox` mounts for permitted users.
- HTTP admin UI and JSON API for user management, file listing/detail/download/upload/rename/delete, public share links, upload drop links, live session status, trash/version restore, Cloudflare purge, and remote FTP pull into local storage.
- Public HTTP file serving from the configured `public` folder with cache headers and optional Cloudflare cache tags.
- NAT-PMP automatic TCP port mapping for FTP control and passive data ports when the router supports it.
- Remote macOS deployment through launchd with a repairable `/opt/macftpd` app folder and `/srv/macftpd/files` storage root.

## Local Development

```bash
go test ./...
go run ./cmd/macftpd -config configs/macftpd.example.json
```

For local-only testing, override paths and ports:

```bash
MACFTPD_STORAGE_ROOT="$PWD/var/ftpd" \
MACFTPD_USERS_PATH="$PWD/var/users.json" \
MACFTPD_ADMIN_PASS="secret" \
MACFTPD_FTP_LISTEN="127.0.0.1:2121" \
MACFTPD_HTTP_LISTEN="127.0.0.1:8080" \
go run ./cmd/macftpd
```

Admin UI:

```text
http://127.0.0.1:8080/admin
```

Use HTTP Basic auth or `POST /api/login` with the admin credentials.

## Remote macOS Deploy

The deploy script builds a Darwin/arm64 binary locally, copies it to a remote Mac, installs a LaunchAgent, and starts/restarts the service. Set `REMOTE` to your SSH host. If you do not use an SSH agent, also set `KEY` to your private key path.

```bash
REMOTE='macftpd@example-host.local' KEY='/path/to/ssh-key' \
ADMIN_PASS='choose-a-strong-password' ./scripts/deploy-remote-macos.sh
```

The first deploy writes `/opt/macftpd/config.json`. Later deploys merge generated operational settings into the active config while preserving secrets such as the admin password and session key. The previous active config is backed up as `config.json.backup.<timestamp>`, and the generated config is also kept as `config.json.last_deployed`.

By default the deploy starts the service in `START_MODE=manual`, launched over SSH. This is useful while validating macOS privacy permissions for external or removable storage. After granting the binary external volume or Full Disk Access, use:

```bash
START_MODE=launchd ADMIN_PASS='choose-a-strong-password' ./scripts/deploy-remote-macos.sh
```

Smoke test against remote Mac:

```bash
ADMIN_PASS='same-password' ./scripts/smoke-remote.sh
ADMIN_PASS='same-password' HOST=192.0.2.10 ./scripts/protocol-lab.sh
```

## Cloudflare HTTP Front Door

`https://ftp.example.com` is served through Cloudflare Tunnel and a Worker:

- `macftpd-tunnel` tunnel forwards `ftp.example.com` and `macftpd-origin.example.com` to `http://127.0.0.1:8080` from the remote Mac connector, so LAN IP changes do not break the HTTP front door.
- `macftpd-public-cache` Worker runs on `ftp.example.com/*`.
- `/public/*` responses are cached with Cloudflare Cache API and include `X-Macftpd-Cache: MISS` or `HIT`.
- `/admin/`, `/api/*`, and health checks are proxied with `Cache-Control: no-store`.

Start or repair the remote Mac tunnel connector:

```bash
TUNNEL_TOKEN_FILE=/path/to/token ./scripts/start-cloudflare-tunnel.sh
```

The token is stored on the remote Mac at `/opt/macftpd/var/cloudflared.env.token` with mode `0600`, and the screen session is `macftpd-cloudflared`.

Deploy or repair the Worker route:

```bash
wrangler deploy --config cloudflare/wrangler.jsonc
```

The Worker forwards the public host to the origin with `X-Forwarded-Host` and `X-Macftpd-Public-Host` so admin CSRF checks see browser requests from `ftp.example.com`, while `/public/*` remains cached at the edge and admin/API traffic remains `no-store`.

Optional hardening helpers:

```bash
CF_ZONE_ID=... CF_API_TOKEN=... ./scripts/cloudflare-hardening.sh
CF_ACCOUNT_ID=... CF_API_TOKEN=... ALLOW_EMAILS='admin@example.com' ./scripts/cloudflare-access-admin.sh
```

`cloudflare-hardening.sh` maintains a zone WAF ruleset for the public hostname. `cloudflare-access-admin.sh` creates or updates a Cloudflare Access self-hosted application for `/admin*`; keep the built-in macftpd admin login enabled as a second layer.

## Release Gate

Before a release candidate, run:

```bash
go test ./...
go test -race ./...
go vet ./...
go run github.com/securego/gosec/v2/cmd/gosec@latest ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
wrangler deploy --config cloudflare/wrangler.jsonc --dry-run
ADMIN_PASS="$(cat var/admin-pass.txt)" ./scripts/smoke-remote.sh
```

Then verify through `https://ftp.example.com`: admin login, create/edit/delete a test user, public cache `MISS` then `HIT`, and the remote Mac monitor screen showing `status=ok`.

## Network Notes

For internet exposure, macftpd can automatically map these with NAT-PMP and UPnP IGD:

- TCP `2121` to the remote Mac for FTP control.
- TCP `50000-50100` to the remote Mac for passive FTP data.
- TCP `8080` or a reverse-proxied HTTPS endpoint for HTTP/admin/public.

Use `"external_ip": "auto"` with `"auto_map": true` to advertise the discovered public address in classic PASV replies. Passive FTP data ports are mapped on demand and released after the data connection is closed or the passive setup is abandoned. Set `ftp.external_ip` to a fixed public IP or DNS target if the router does not support automatic mapping. EPSV-capable clients usually work better through NAT.

Default storage ignore rules hide and deny downloads for macOS metadata and sensitive dot-directories such as `.DS_Store`, `._*`, `.AppleDouble`, `.Spotlight-V100`, `.Trashes`, `.git`, `.env`, and `.ssh`. Adjust `storage.ignore` in `config.json` if you need a different policy.

Deletes move files into `._macftpd_trash`, and overwrites create retained versions under `._macftpd_versions`; both locations are hidden by default ignore rules. Restore from the admin UI or `/api/retention/restore`.

Keep `ftp.allow_fxp` disabled unless you explicitly trust server-to-server active FTP targets. The HTTP `/api/fxp` endpoint performs authenticated remote FTP pulls into local storage and is admin-only.

## FTPS Certificates

macftpd supports optional explicit FTPS when `ftp.tls_cert_file` and `ftp.tls_key_file` are configured. A free Let's Encrypt certificate can be renewed with:

```bash
MACFTPD_APP_DIR=/opt/macftpd \
MACFTPD_ACME_DOMAIN=ftp.example.com \
/opt/macftpd/bin/renew-ftps-cert.sh
```

The renewal helper uses Certbot's `renew` flow when a lineage already exists, serves HTTP-01 challenge files from `/public/.well-known/acme-challenge/`, installs renewed certs through a deploy hook, and restarts the running macftpd process so the new certificate is presented. The example LaunchAgent `launchd/com.example.macftpd.cert-renew.plist` runs renewal checks twice daily with jitter.

## macOS File Access

The launchd service runs as the target login user, so macOS privacy and external-volume permissions apply to that user. If the service cannot see `/srv/macftpd/files`, grant the hosting terminal/app Full Disk Access or run the first launch interactively once from Terminal:

```bash
/opt/macftpd/bin/macftpd -config /opt/macftpd/config.json
```

## Repair

```bash
ssh macftpd@example-host.local 'launchctl kickstart -k gui/$(id -u)/com.example.macftpd'
ssh macftpd@example-host.local 'tail -100 /opt/macftpd/var/macftpd.err.log'
```

Re-run `./scripts/deploy-remote-macos.sh` to replace the binary and reinstall launchd without deleting user data or FTP storage.
