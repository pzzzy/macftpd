# Security Policy

macftpd is a network-facing service. Before deploying it outside a local lab:

- Use TLS for browser/API access.
- Use strong unique admin credentials.
- Keep config files, user databases, session keys, tunnel tokens, API tokens, logs, and storage roots out of git.
- Keep `http.session_key` stable and secret; it signs admin sessions and password-protected share/drop cookies.
- Treat share and drop URLs as bearer secrets. Prefer expiry, one-download links, optional passwords, and revocation for sensitive files.
- Review `/api/shares` regularly and revoke links that are no longer needed.
- Use Cloudflare Access or equivalent in front of `/admin*` when exposing the admin UI on the internet; keep macftpd admin auth enabled as a second layer.
- Leave FXP disabled unless you understand and accept the server-to-server transfer risk.
- Keep active FTP and FXP restrictions enabled: passive data peers must match the control peer, and third-party active targets require explicit `ftp.allow_fxp` authorization.
- Keep `cloudflare.cache_tag` scoped to macftpd public responses; public writes invalidate that tag so stale protected content is not served after replacement or deletion.
- Leave default storage ignore rules enabled for macOS metadata and sensitive dot-directories such as `.DS_Store`, `.env`, `.ssh`, and `.git`.
- Internal upload, trash, and version directories are always denied by the storage resolver. Do not expose the storage root through a second, less restrictive file server.
- Keep FTPS optional but use it for FTP over untrusted networks; prefer HTTPS share links or SSH/SFTP for sensitive transfers when FTP compatibility is not required.
- Password-protected public links are rate-limited, and protected multipart drops require an authorized share cookie before macftpd parses the upload body.

Please report security issues through GitHub security advisories.
