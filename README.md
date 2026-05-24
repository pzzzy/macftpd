# macftpd

`macftpd` is a Go-powered FTP server with a companion HTTP admin/public interface for a modern macOS file host.

It is designed as a practical operations tool: local storage containment, user/group permissions, FTP compatibility, public HTTP file serving, a browser admin UI, Cloudflare front-door support, NAT-PMP port mapping, and macOS launchd deployment examples.

## Features

- FTP control/data server with USER/PASS, passive EPSV/PASV, active PORT/EPRT, LIST/NLST, upload, download, delete, mkdir, rename, SIZE, and MDTM.
- User and group permissions for list, download, upload, delete, mkdir, rename, admin, public, and dropbox workflows.
- Storage-root containment and default ignore rules for macOS metadata and sensitive dot-directories.
- HTTP admin UI and JSON API for user management, file listing/detail/download/upload/rename/delete, Cloudflare purge, and authenticated remote FTP pull into local storage.
- Public HTTP file serving from the configured `public` folder with cache headers and optional Cloudflare cache tags.
- NAT-PMP automatic TCP port mapping for FTP control and passive data ports when the router supports it.
- launchd and script examples for running as a macOS service.

## Why this exists

FTP is old, but it still appears in real operational workflows: scanners, printers, cameras, embedded devices, media appliances, and legacy transfer clients. This project explores how to make an FTP-compatible service safer and easier to operate on a modern Mac while also providing a web admin/public-file layer.

## Local Development

```bash
go test ./...
go run ./cmd/macftpd -config configs/macftpd.example.json
```

For local-only testing, override paths and ports:

```bash
MACFTPD_STORAGE_ROOT="$PWD/var/ftpd" MACFTPD_USERS_PATH="$PWD/var/users.json" MACFTPD_ADMIN_PASS="change-this-password" MACFTPD_FTP_LISTEN="127.0.0.1:2121" MACFTPD_HTTP_LISTEN="127.0.0.1:8080" go run ./cmd/macftpd
```

Admin UI:

```text
http://127.0.0.1:8080/admin
```

Use HTTP Basic auth or `POST /api/login` with the admin credentials.

## Configuration

Start from `configs/macftpd.example.json` and change:

- `storage.root`
- `auth.users_path`
- `auth.bootstrap_admin_pass`
- `http.session_key`
- Cloudflare settings, if using edge cache purge or a Worker front door

Do not commit real config files, passwords, session keys, tunnel tokens, logs, user databases, or private storage paths.

## Cloudflare Front Door

The `cloudflare/` folder contains a Worker example that can proxy a public hostname to a private origin and cache `/public/*` responses while keeping `/admin/`, `/api/*`, and health checks uncached.

Use placeholder domains such as `ftp.example.com` and `macftpd-origin.example.com` until you configure your own Cloudflare zone/tunnel.

## Release Gate

Before publishing or deploying a release candidate, run:

```bash
go test ./...
go test -race ./...
go vet ./...
go run github.com/securego/gosec/v2/cmd/gosec@latest ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
wrangler deploy --config cloudflare/wrangler.jsonc --dry-run
```

## Network Notes

For internet exposure, macftpd can automatically map these with NAT-PMP:

- TCP `2121` for FTP control.
- TCP `50000-50100` for passive FTP data.
- TCP `8080` or a reverse-proxied HTTPS endpoint for HTTP/admin/public.

Use `"external_ip": "auto"` with `"auto_map": true` to advertise the NAT-PMP discovered public address in classic PASV replies. Set `ftp.external_ip` to a fixed public IP or DNS target if the router does not support NAT-PMP. EPSV-capable clients usually work better through NAT.

Keep `ftp.allow_fxp` disabled unless you explicitly trust server-to-server active FTP targets. The HTTP `/api/fxp` endpoint performs authenticated remote FTP pulls into local storage and is admin-only.

## Security / Privacy

- Never expose the admin UI without TLS and strong credentials.
- Keep `http.session_key`, admin passwords, Cloudflare API tokens, tunnel tokens, and user databases out of git.
- Default storage ignore rules deny common metadata and sensitive dot-directories such as `.git`, `.env`, and `.ssh`.
- Treat FTP as compatibility infrastructure. Prefer HTTPS or SSH/SFTP where you control both ends and do not need legacy FTP semantics.

## Portfolio Notes

This project demonstrates practical backend and operations engineering: network protocols, HTTP APIs, macOS service management, Cloudflare edge integration, credential handling, storage containment, smoke testing, and release gates.

## License

MIT. See `LICENSE`.
