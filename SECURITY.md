# Security Policy

## Reporting a vulnerability
If you discover a security issue in this repository, please avoid opening a public issue with sensitive details.
Instead, notify the repository owner/maintainer through a private channel.

## Notes for operators
- This script retrieves passwords from CyberArk and passes them to Veeam in-memory.
- Passwords are not written to logs.
- Avoid enabling TLS certificate validation bypass unless absolutely necessary:
  - `-SkipCertificateCheck`
- Protect log files and configuration files:
  - restrict filesystem permissions
  - avoid committing real configuration values to GitHub
