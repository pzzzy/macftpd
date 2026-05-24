# macftpd Feature Test Plan

Use this checklist against a local or lab test instance. Replace all hostnames, paths, and credentials with your own non-production values.

## Endpoints

- FTP control: `localhost:2121`
- FTP passive data: `50000-50100`
- HTTP health: `http://localhost:8080/healthz`
- HTTP admin: `http://localhost:8080/admin`
- Public files: `http://localhost:8080/public/<path>`
- Example storage root: `/tmp/macftpd/ftpd`

## Operations And Monitoring

- Run locally: `go run ./cmd/macftpd -config configs/macftpd.example.json`
- Manual smoke test: `ADMIN_PASS="change-this-password" ./scripts/smoke-example.sh`
- Inspect logs from your configured service manager or terminal session.

## FTP Protocol

- Login succeeds with valid admin credentials.
- Login fails with wrong password.
- `SYST`, `FEAT`, `PWD`, `CWD`, `CDUP`, `NOOP`, and `QUIT` behave normally.
- ASCII and binary `TYPE` commands are accepted.
- Passive mode works with `PASV`.
- Extended passive mode works with `EPSV`.
- Active mode works with `PORT` on trusted same-client target.
- Extended active mode works with `EPRT` on trusted same-client target.
- FXP-style active third-party target is rejected while `allow_fxp` is false.
- `LIST` returns Unix-style directory listings.
- `NLST` returns names only.
- `SIZE` returns file byte count.
- `MDTM` returns UTC modification timestamp.

## FTP File Actions

- Upload a small text file.
- Upload a large file.
- Upload nested paths after `MKD`.
- Download and byte-compare uploaded files.
- Append with `APPE`.
- Delete files with `DELE`.
- Create directories with `MKD`.
- Remove empty directories with `RMD`.
- Rename files with `RNFR` then `RNTO`.
- Rename directories with `RNFR` then `RNTO`.
- Attempt path traversal such as `RETR ../../etc/passwd`; it should fail.
- Attempt to access outside a non-admin user home; it should fail.

## Users, Groups, And Permissions

- Create a read-only user in the admin UI.
- Confirm read-only user can list/download but cannot upload/delete.
- Create an upload-only/dropbox-style user.
- Confirm dropbox user can upload but cannot list/download if those bits are disabled.
- Create a public-folder publisher user.
- Confirm public publisher can upload into `/public`.
- Disable a user and confirm FTP and admin API login fail.
- Change a user password and confirm old password fails.
- Add a group with permissions.
- Assign a user to the group and confirm merged permissions apply.

## HTTP Admin And API

- Access `/admin` with HTTP Basic auth.
- `POST /api/login` creates an admin session cookie.
- `POST /api/logout` clears the session.
- `GET /api/me` returns the current user.
- `GET /api/users` lists sanitized users without password hashes.
- `POST /api/users` creates a user.
- `PUT /api/users/<name>` updates a user.
- `DELETE /api/users/<name>` deletes a user.
- `GET /api/groups` lists groups.
- `POST /api/groups` creates or updates a group.
- `GET /api/files?path=/` lists storage entries.
- `POST /api/upload` uploads a multipart file.
- Unauthenticated `/api/*` calls return `401`.

## Public HTTP Files

- Place a file under the configured `public` directory.
- Fetch it from `/public/<file>`.
- Confirm `Cache-Control` is present.
- Confirm `Cache-Tag` is present when Cloudflare cache tag is configured.
- Confirm missing files return `404`.
- Confirm traversal attempts under `/public/` cannot escape the public folder.

## Cloudflare

- Configure a test hostname such as `ftp.example.com` and an origin such as `macftpd-origin.example.com`.
- Confirm `/healthz` returns `200` and `X-Macftpd-Cache: BYPASS`.
- Confirm `/admin/`, `/api/*`, and `/healthz` include `Cache-Control: no-store` through the Worker.
- Confirm a write with `Origin: https://evil.example` returns `403`.
- Confirm `/public/<file>` can be cached and purged without exposing the API token.

## Durability

- Restart the service and confirm config/users persist.
- Re-run deploy and confirm existing config is preserved.
- Fill passive port range with multiple simultaneous downloads.
- Leave monitoring running overnight and inspect failed health checks.
