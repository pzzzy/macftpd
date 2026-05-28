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
- Leave default storage ignore rules enabled for macOS metadata and sensitive dot-directories such as `.DS_Store`, `.env`, `.ssh`, and `.git`.
- Keep FTPS optional but use it for FTP over untrusted networks; prefer HTTPS share links or SSH/SFTP for sensitive transfers when FTP compatibility is not required.
- Prefer HTTPS or SSH/SFTP when FTP compatibility is not required.

Please report security issues through GitHub security advisories.
