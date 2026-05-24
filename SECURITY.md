# Security Policy

macftpd is a network-facing service. Before deploying it outside a local lab:

- Use TLS for browser/API access.
- Use strong unique admin credentials.
- Keep config files, user databases, session keys, tunnel tokens, API tokens, logs, and storage roots out of git.
- Leave FXP disabled unless you understand and accept the server-to-server transfer risk.
- Prefer HTTPS or SSH/SFTP when FTP compatibility is not required.

Please report security issues through GitHub security advisories.
