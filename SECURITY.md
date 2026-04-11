# Security Policy — RedCheck246

## Supported Versions

| Version | Supported          |
|---------|--------------------|| 0.3.x   | :white_check_mark: || 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in RedCheck246, please report it responsibly.

### How to Report

1. **Do NOT open a public issue** for security vulnerabilities.
2. Email: **security@server246.dev** (or open a private security advisory on GitHub).
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected versions
   - Potential impact

### Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgement | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix development | Within 14 business days (critical), 30 days (other) |
| Public disclosure | After fix is released and users notified |

### Scope

The following are in scope for security reports:

- **Authentication bypass** — Activation engine, policy gates
- **Cryptographic weaknesses** — AES-256-GCM, PBKDF2, Ed25519, HMAC
- **Injection vulnerabilities** — CLI input, YAML parsing, plugin execution
- **Data exposure** — Evidence encryption, audit log integrity
- **Supply chain** — Dependency confusion, typosquatting in own deps
- **Privilege escalation** — Plugin capability enforcement

### Out of Scope

- Issues in third-party dependencies (report upstream)
- Denial of service via intended scanning features
- Social engineering

## Security Controls

RedCheck246 implements the following security controls:

- **Policy gating** — All scans require valid RoE + activation code
- **AES-256-GCM** — Evidence encryption with PBKDF2-HMAC-SHA512 key derivation
- **Ed25519 + HMAC-SHA256** — Document and evidence signing
- **Argon2id** — Activation code hashing (with SHA-512 fallback)
- **Hash-chained audit log** — Tamper-evident, append-only
- **Structured logging** — Via structlog, no secrets in logs
- **Rate limiting** — Activation attempts and scan requests
- **Non-root containers** — Docker runs as UID 1000

## Dependencies

All dependencies are pinned in `pyproject.toml` and monitored via:
- GitHub Dependabot (weekly scans)
- `pip-audit` in CI pipeline
- CodeQL analysis (weekly + on PR)
