# macftpd

`macftpd` is a Go-powered FTP server with a companion HTTP admin/public interface for a modern macOS file host.

Current capabilities:

- FTP control/data server with USER/PASS, passive EPSV/PASV, active PORT/EPRT, LIST/NLST, upload, download, delete, mkdir, rename, SIZE, and MDTM.
- Explicit FTPS with `AUTH TLS`, `PBSZ`, `PROT`, plus modern `MLSD`/`MLST` listings.
- User and group permissions for list, download, upload, delete, mkdir, rename, admin, public, and dropbox workflows.
- Storage-root containment, default macOS/security ignore rules, and virtual `public`/`dropbox` mounts for permitted users.
- HTMX + Tailwind CSS + daisyUI HTTP admin UI and JSON API for user management, file listing/detail/download/chunked-upload/rename/delete, copy/move, public share links, upload drop links, link revocation, live session status, trash/version restore, Cloudflare purge, and remote FTP pull into local storage.
- Public HTTP file serving from the configured `public` folder with sortable directory listings, cache headers, optional Cloudflare cache tags, and download/referrer analytics.
- Short direct share URLs (`/s/<id>/<token>/<filename>`) that serve bare files with correct MIME and `Content-Disposition` behavior; image/video/PDF/text content opens inline, archive-style content downloads.
- Password-protected share/drop links with secure share-scoped cookies, one-download links, timed expiry, never-expiring links, and admin-visible persistent link URLs.
- Public upload drops (`/d/<id>/<token>`) with the same chunked upload path as the admin UI; uploads into `public` return the public download URL.
- NAT-PMP and UPnP IGD automatic TCP port mapping for FTP control and passive data ports when the router supports it.
- Remote macOS deployment through launchd with a repairable `/opt/macftpd` app folder and `/srv/macftpd/files` storage root.
- Transactional FTP, HTTP, drop-link, chunked, and remote-pull uploads: data is staged under a permanently hidden internal directory and only swapped into place after the transfer and retained-version copy succeed.

## Local Development

```bash
npm install
npm run build
go test ./...
go run ./cmd/macftpd -config configs/macftpd.example.json
```

The generated admin/public CSS and local HTMX asset are embedded into the Go binary from `internal/httpapi/static`. Run `npm run build` after changing templates or CSS.

HTTP body read/write deadlines are disabled by default so large uploads and downloads can stream for as long as they are making progress. Header parsing still has a 10-second deadline and idle keep-alive connections expire after 60 seconds. Set `http.read_timeout` or `http.write_timeout` only when you intentionally want a whole-request or whole-response deadline.

The overnight 10,824,083,788-byte MKV validation completed successfully. macftpd streamed the object unchanged; it does not transcode, remux, or otherwise process media. See [Large Transfer Operations](docs/large-transfers.md) for the range-request interpretation, validation commands, and timeout guidance derived from that run.

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

For a stable macOS code identity across upgrades, install a local signing identity once on the destination Mac, then pass it to deploys:

```bash
REMOTE_DIR=/opt/macftpd ./scripts/install-macos-codesign-identity.sh

MACFTPD_CODESIGN_IDENTITY='macftpd local code signing' \
MACFTPD_CODESIGN_KEYCHAIN='/opt/macftpd/var/macftpd-codesign.keychain-db' \
MACFTPD_CODESIGN_KEYCHAIN_PASS_FILE='/opt/macftpd/var/macftpd-codesign.keychain.pass' \
./scripts/deploy-remote-macos.sh
```

Run the installer on the remote Mac itself. It prints the three values needed by the deploy script. The installer registers its custom keychain in the user search list and grants `codesign` access to the private key. If macOS asks for an interactive trust approval, use the exact case-sensitive `trustRoot` and `codeSign` values printed by the installer. When any stable-signing option is configured, deployment signs and verifies the staged binary before replacing the active one and fails closed if the identity cannot be used. Ad-hoc signing is retained only for deploys with no stable identity configured and may cause macOS to ask for removable-volume access again after a binary replacement.

Override `REMOTE_DIR` and `STORAGE_ROOT` for site-specific installs, for example a home-directory app folder with an external-volume FTP root:

```bash
REMOTE='macftpd@example-host.local' KEY='/path/to/ssh-key' \
REMOTE_DIR='~/macftpd' STORAGE_ROOT='/path/to/ftpd-storage' \
ADMIN_PASS='choose-a-strong-password' ./scripts/deploy-remote-macos.sh
```

By default the deploy starts the service in `START_MODE=manual`, launched over SSH. This is useful while validating macOS privacy permissions for external or removable storage. After granting the binary external volume or Full Disk Access, use:

```bash
START_MODE=launchd ADMIN_PASS='choose-a-strong-password' ./scripts/deploy-remote-macos.sh
```

Smoke test against remote Mac:

```bash
ADMIN_PASS='same-password' ./scripts/smoke-remote.sh
ADMIN_PASS='same-password' HOST=192.0.2.10 ./scripts/protocol-lab.sh
```

Prefer a numeric LAN IPv4 address for the protocol lab when `.local` resolution exposes both link-local IPv6 and IPv4 routes. The lab intentionally exercises a long-lived FTP control connection, so a lossy link-local route can fail even while loopback monitoring and the IPv4 service are healthy.

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

Upgrade the bundled connector with the release-pinned, checksum-verified helper. A remote upgrade keeps a timestamped previous binary and restarts only the connector LaunchAgent:

```bash
REMOTE='macftpd@example-host.local' KEY='/path/to/ssh-key' \
REMOTE_DIR='/opt/macftpd' ./scripts/upgrade-cloudflared.sh
```

Deploy or repair the Worker route:

```bash
wrangler deploy --config cloudflare/wrangler.jsonc
```

The Worker forwards the public host to the origin with `X-Forwarded-Host` and `X-Macftpd-Public-Host` so admin CSRF checks see browser requests from `ftp.example.com`, while `/public/*` remains cached at the edge and admin/API traffic remains `no-store`.

Set `http.public_base_url` (or `MACFTPD_PUBLIC_BASE_URL`) to the externally visible HTTPS origin when admin traffic can reach macftpd through another hostname. Successful HTTP public mutations purge the configured cache tag, with exact file and parent-listing purges as a fallback. Successful FTP mutations under the public root also purge the tag. Cache invalidation requires `cloudflare.enabled`, `zone_id`, `api_token`, and `cache_tag`.

Optional hardening helpers:

```bash
CF_ZONE_ID=... CF_API_TOKEN=... ./scripts/cloudflare-hardening.sh
CF_ACCOUNT_ID=... CF_API_TOKEN=... ALLOW_EMAILS='admin@example.com' ./scripts/cloudflare-access-admin.sh
```

`cloudflare-hardening.sh` maintains a zone WAF ruleset for the public hostname. `cloudflare-access-admin.sh` creates or updates a Cloudflare Access self-hosted application for `/admin*`; keep the built-in macftpd admin login enabled as a second layer.

## Shares, Drops, And Public Analytics

Admins can create and revoke links from the `/admin` Links panel or the `/api/shares` endpoint. New links persist their token-bearing URL path in `var/shares.json` so the admin list can continue showing useful URLs after refresh. Existing legacy links that were created before URL persistence may need to be revoked and recreated if their full token URL is no longer known.

Download shares use short `/s/<id>/<token>` URLs. For file shares, macftpd appends the original filename to the returned URL for readability without leaking the storage path. The share handler still authorizes by id/token, not by the display filename. Shared files are served directly: images, videos, audio, PDFs, and text are inline by default, while other file types use attachment disposition. Add `?download=1` to force attachment behavior.

Upload drops use `/d/<id>/<token>` URLs. Protected drops first accept a password form, then set a secure, HttpOnly, share-scoped cookie before showing the compact chunked upload UI. Drops created against the public folder return a `public_url` after upload, such as `/public/example.mp4`.

Public and shared downloads are recorded in the activity log with count, last download time, remote address, byte count, and HTTP referrer. Admin file detail cards summarize these stats through `/api/stats?path=<storage-path>`.

Expiry presets in the admin UI are `1 download`, `1h`, `12h`, `24h`, `1w`, `1m`, and `never`.

## HTTP API Highlights

All `/api/*` endpoints require an admin session or HTTP Basic auth unless noted. Unsafe methods enforce same-origin checks using `Origin`, Fetch Metadata, and Cloudflare forwarded-host headers.

```bash
auth=(-u "$MACFTPD_ADMIN_USER:$MACFTPD_ADMIN_PASS")

# Create a direct download share.
curl "${auth[@]}" -H 'content-type: application/json' \
  -d '{"kind":"download","path":"/public/example.mp4","expires_in":"24h"}' \
  https://ftp.example.com/api/shares

# Create a password-protected public upload drop.
curl "${auth[@]}" -H 'content-type: application/json' \
  -d '{"kind":"upload","path":"/public","expires_in":"1h","password":"optional"}' \
  https://ftp.example.com/api/shares

# List and revoke links.
curl "${auth[@]}" https://ftp.example.com/api/shares
curl "${auth[@]}" -X DELETE https://ftp.example.com/api/shares/<id>

# Inspect public/share download stats for a storage path.
curl "${auth[@]}" 'https://ftp.example.com/api/stats?path=/public/example.mp4'
```

Other admin endpoints include `/api/users`, `/api/groups`, `/api/files`, `/api/files/action`, `/api/upload/chunk`, `/api/download`, `/api/fxp`, `/api/activity`, `/api/status`, `/api/doctor`, `/api/retention`, `/api/retention/restore`, and `/api/cloudflare/purge`.

The authenticated `/api/doctor` response includes build provenance and uptime, effective HTTP timeouts, activity-buffer capacity and age, and individual storage/integration checks. Optional integrations that are disabled are reported as informational rather than failed. The activity dashboard scans the full in-memory history before filtering monitor traffic, so a busy probe loop cannot hide human or security events.

## Release Gate

Before a release candidate, run:

```bash
./scripts/check.sh
ADMIN_PASS="$(cat var/admin-pass.txt)" ./scripts/smoke-remote.sh
```

`scripts/check.sh` is the same release gate used by GitHub Actions. It verifies formatting and modules; runs shuffled tests, race tests, vet, native and Darwin/arm64 builds; rebuilds embedded assets reproducibly; checks shell and Worker syntax; scans for private identifiers; runs pinned gosec and govulncheck versions; and performs a Wrangler dry run.

Then verify through `https://ftp.example.com`: admin login, create/edit/delete a test user, chunked admin upload of a large file, direct `/s/` share of that file with correct MIME/disposition, protected `/d/` drop upload, public cache `MISS` then `HIT`, and the remote Mac monitor screen showing `status=ok`.

## Network Notes

For internet exposure, macftpd can automatically map these with NAT-PMP and UPnP IGD:

- TCP `2121` to the remote Mac for FTP control.
- TCP `50000-50100` to the remote Mac for passive FTP data.
- TCP `8080` or a reverse-proxied HTTPS endpoint for HTTP/admin/public.

Use `"external_ip": "auto"` with `"auto_map": true` to advertise the discovered public address in classic PASV replies. Passive FTP data ports are mapped on demand and released after the data connection is closed or the passive setup is abandoned. macftpd tries NAT-PMP and UPnP IGD when available. Set `ftp.external_ip` to a fixed public IP or DNS target if the router does not support automatic mapping. EPSV-capable clients usually work better through NAT.

Default storage ignore rules hide and deny downloads for macOS metadata and sensitive dot-directories such as `.DS_Store`, `._*`, `.AppleDouble`, `.Spotlight-V100`, `.Trashes`, `.git`, `.env`, and `.ssh`. Adjust `storage.ignore` in `config.json` if you need a different policy.

Deletes move files into `._macftpd_trash`, overwrites create retained versions under `._macftpd_versions`, and in-progress uploads use `._macftpd_uploads`. These internal locations are denied and hidden even if an operator removes them from `storage.ignore`. Restore retained data from the admin UI or `/api/retention/restore`.

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
