# macftpd Feature Test Plan

Use this checklist against the remote Mac long-term test instance.

## Endpoints

- FTP control: `example-host.local:2121`
- FTP passive data: `50000-50100`
- HTTP health: `http://example-host.local:8080/healthz`
- Cloudflare HTTP: `https://ftp.example.com`
- HTTP admin: `http://example-host.local:8080/admin`
- Public files: `http://example-host.local:8080/public/<path>`
- Direct share links: `https://ftp.example.com/s/<id>/<token>/<filename>`
- Upload drop links: `https://ftp.example.com/d/<id>/<token>`
- Storage root on remote Mac: `/srv/macftpd/files`

## Operations And Monitoring

- Attach to server screen: `ssh macftpd@example-host.local 'screen -r macftpd-server'`
- Attach to monitor screen: `ssh macftpd@example-host.local 'screen -r macftpd-monitor'`
- Detach from screen: `Ctrl-A`, then `D`
- Server log: `/opt/macftpd/var/macftpd.screen.log`
- Monitor log: `/opt/macftpd/var/monitor.log`
- Cloudflare tunnel log: `/opt/macftpd/var/cloudflared.screen.log`
- Manual smoke test: `ADMIN_PASS="$(cat var/admin-pass.txt)" ./scripts/smoke-remote.sh`
- Restart long-term screens: `./scripts/start-remote-longterm.sh`

## FTP Protocol

- Login succeeds with valid admin credentials.
- Login fails with wrong password.
- `SYST`, `FEAT`, `PWD`, `CWD`, `CDUP`, `NOOP`, and `QUIT` behave normally.
- `FEAT` advertises `REST STREAM`, `MLSD`, `MLST`, and, when configured, `AUTH TLS`/`PBSZ`/`PROT`.
- `AUTH TLS`, `PBSZ 0`, and `PROT P` allow protected login and data transfers.
- `MLSD` and `MLST` return machine-readable facts.
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
- `POST /api/upload/chunk` uploads large admin files in chunks and assembles them atomically.
- `POST /api/files/action` copies or moves files and folders, including copy/move into `/public`.
- `GET /api/shares` lists active links with persisted URL paths for newly-created links.
- `DELETE /api/shares/<id>` revokes a link before expiry.
- `GET /api/stats?path=/public/<file>` summarizes public/share download count, last download time, recent downloads, and referrers.
- Unauthenticated `/api/*` calls return `401`.

## Public HTTP Files

- Place a file under `/srv/macftpd/files/public`.
- Fetch it from `/public/<file>`.
- Confirm `Cache-Control` is present.
- Confirm `Cache-Tag` is present when Cloudflare cache tag is configured.
- Confirm `/public/` renders a sortable directory listing and hides ignored files such as `.DS_Store`.
- Create a download share with `POST /api/shares`, open the returned `/s/<id>/<token>/<filename>` URL, and confirm the file is served directly.
- Confirm images/videos/PDF/text shares open inline and archive-style shares download as attachments.
- Confirm filenames with spaces, brackets, or non-ASCII characters are preserved in `Content-Disposition`.
- Create a one-download share and confirm the second request returns unavailable/gone.
- Create a never-expiring share and confirm the admin list does not show a year-1 expiry date.
- Create a password-protected share, submit the password form, and confirm the direct file URL works after the secure cookie is set.
- Create an upload drop link with `POST /api/shares {"kind":"upload"}`, upload a file to `/d/<id>/<token>`, and confirm it appears in the destination folder.
- Create a password-protected drop and confirm wrong passwords re-render the password form without `bad upload`.
- Upload a large file through the drop UI and confirm chunked upload progress completes.
- Create a drop into `/public`, upload a file, and confirm the UI/API exposes the returned `public_url`.
- Confirm `GET /api/shares` continues to show newly-created token URLs after page refresh.
- Revoke a share/drop link from the admin UI and confirm the URL stops working before its original expiry.
- Download public and shared files, then confirm `/api/stats?path=<path>` increments counts and records recent downloads/referrers.
- Delete a file and confirm it appears in `GET /api/retention?kind=trash`; restore it with `POST /api/retention/restore`.
- Overwrite a file and confirm a version appears in `GET /api/retention?kind=versions`.
- Confirm `/api/status` shows active FTP sessions during a held FTP control connection.
- Confirm `/api/doctor` reports storage roots, share store, activity store, Cloudflare config, and Turnstile config.
- Confirm missing files return `404`.
- Confirm traversal attempts under `/public/` cannot escape the public folder.

## Cloudflare

- Confirm `https://ftp.example.com/healthz` returns `200` and `X-Macftpd-Cache: BYPASS`.
- Confirm `https://ftp.example.com/admin/` works with admin Basic auth.
- From `https://ftp.example.com/admin/`, create, edit, list, and delete a test user; saves must not fail with `cross-origin admin request denied`.
- Confirm `https://ftp.example.com/public/` renders the sortable public directory listing.
- Fetch the same `https://ftp.example.com/public/<file>` twice and confirm `X-Macftpd-Cache: HIT` on a repeated request.
- Create and open a `https://ftp.example.com/s/...` direct share; confirm it bypasses admin auth and uses the correct MIME/disposition.
- Create and use a `https://ftp.example.com/d/...` protected drop; confirm password form, cookie, chunked upload, and public URL behavior.
- Confirm public responses include CDN cache headers.
- Confirm `/admin/`, `/api/*`, and `/healthz` include `Cache-Control: no-store` through the Worker.
- Confirm a write with `Origin: https://evil.example` still returns `403`.
- Confirm `macftpd-cloudflared` screen remains attached to the `macftpd-tunnel` tunnel.
- Configure `cloudflare.enabled`, `zone_id`, and `api_token` for in-app purge once a zone cache-purge token is available.
- `POST /api/cloudflare/purge` purges cache without exposing the token after that token is configured.
- `POST /api/cloudflare/purge` with `paths` purges specific public-file URLs.
- Run `scripts/cloudflare-hardening.sh` with a Cloudflare zone token to install/update the macftpd WAF ruleset.
- Run `scripts/cloudflare-access-admin.sh` with `ALLOW_EMAILS` to install/update the Cloudflare Access app for `/admin*`.

## HTTP FTP Pull

- Use `/api/fxp` to pull a file from another FTP server into local storage.
- Confirm pulled file appears in `GET /api/files`.
- Confirm pulled file can be downloaded over FTP.
- Confirm invalid remote credentials fail without creating a partial file.

## macOS And Durability

- Restart the screen server and confirm config/users persist.
- Re-run deploy and confirm existing `/opt/macftpd/config.json` is preserved.
- Confirm `/srv/macftpd/files` remains the storage root.
- Reboot remote Mac and decide whether to use manual screen restart or launchd after Full Disk Access is granted.
- Fill passive port range with multiple simultaneous downloads.
- Confirm passive UPnP/NAT-PMP mappings are created on demand and released after data connections close.
- Leave monitor running overnight and inspect `status=fail` lines.
- Run `ADMIN_PASS=... HOST=192.0.2.10 ./scripts/protocol-lab.sh` for the recursive FTP compatibility suite.
