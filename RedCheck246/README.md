

# RedCheck246

[![CI](https://github.com/SERVER-246/RedCheck246/actions/workflows/ci.yml/badge.svg)](https://github.com/SERVER-246/RedCheck246/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE.txt)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

**Policy-gated, plugin-based security assessment framework.**

> All active operations require a validated Rules of Engagement (RoE) document and a verified activation code. No exceptions.

## Features

- 🔒 **Policy-gated execution** — Every scan requires valid RoE + activation code
- 🔌 **5 built-in plugins** — Passive recon, SAST, DAST, protocol fuzzing, supply chain audit
- 🔐 **Military-grade crypto** — AES-256-GCM evidence encryption, Ed25519 signatures, Argon2id
- 📋 **Hash-chained audit log** — Tamper-evident, append-only, encrypted
- 🚀 **Async-first** — All network plugins use `httpx.AsyncClient`
- 🐳 **Docker-ready** — Multi-stage Dockerfile with non-root user
- ✅ **157+ tests** — Full coverage across Python 3.10–3.13
- 📊 **Rich CLI** — Beautiful terminal output with tables, banners, JSON export

## Quick Start

```bash
# Clone and install
git clone https://github.com/SERVER-246/RedCheck246.git
cd RedCheck246
pip install -e ".[dev]"

# Set activation code
redcheck activate --set

# Initialize engagement
redcheck init my-engagement

# Edit the RoE template
nano my-engagement/roe.yaml

# Validate RoE
redcheck verify-roe my-engagement/roe.yaml

# Dry-run recon
redcheck recon --roe my-engagement/roe.yaml --dry-run

# Run full scan (requires activation)
redcheck run passive-recon --roe my-engagement/roe.yaml

# List plugins
redcheck list-plugins

# Check status
redcheck status
```

## Plugin Catalog

| Plugin | Category | Capability | Description |
|--------|----------|------------|-------------|
| `passive-recon` | Recon | Passive | DNS, WHOIS, cert transparency, subdomain enum, HTTP fingerprint |
| `sast-scanner` | SAST | Passive | Bandit integration, 10 regex patterns, dependency audit |
| `dast-scanner` | DAST | Active | Security headers, SSL/TLS, HTTP methods, cookie analysis |
| `protocol-fuzzer` | Fuzzing | Active | HTTP param/header/body fuzzing, SQLi/XSS/CMDi payloads |
| `supply-chain-audit` | Supply Chain | Passive | OSV.dev queries, license compliance, typosquatting, SBOM |

## Architecture

```
redcheck/
├── cli.py                     # Typer CLI (7 commands)
├── config.py                  # Pydantic BaseSettings (REDCHECK_ env prefix)
├── exceptions.py              # 11 custom exception classes
├── models.py                  # 13 Pydantic v2 models
├── output.py                  # Rich terminal formatting
├── logging.py                 # structlog configuration
├── core/
│   ├── audit.py               # AES-256-GCM encrypted hash-chained audit
│   ├── orchestrator.py        # Engagement lifecycle + plugin dispatch
│   ├── policy_engine.py       # Central policy gate (RoE validation)
│   └── activation_engine.py   # Argon2id activation code management
├── plugins/
│   ├── base_plugin.py         # BasePlugin ABC + PluginRegistry
│   ├── recon/                 # Passive reconnaissance (7 async modules)
│   ├── sast/                  # Static analysis (bandit + regex)
│   ├── dast/                  # Dynamic analysis (6 async modules)
│   ├── fuzzing/               # Protocol fuzzing (200+ payloads)
│   └── supply_chain/          # Supply chain audit (OSV.dev + parsers)
└── security/
    ├── crypto.py              # AES-256-GCM, PBKDF2, HMAC, hashing
    ├── roe_validator.py       # YAML structure + time window validation
    └── signature_verifier.py  # Ed25519 + HMAC-SHA256 dual-mode signing
```

## Security Controls

| Control | Implementation |
|---------|---------------|
| Evidence encryption | AES-256-GCM with PBKDF2-HMAC-SHA512 key derivation |
| Document signing | Ed25519 public-key + HMAC-SHA256 |
| Activation codes | Argon2id (with SHA-512 fallback) |
| Audit log | Hash-chained, append-only, encrypted |
| Rate limiting | 5 attempts, 300s lockout, 2s cooldown |
| Container security | Non-root user (UID 1000), read-only filesystem |

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v --cov=redcheck

# Lint + format
ruff check redcheck/ tests/
ruff format redcheck/ tests/

# Type check
mypy --strict redcheck/

# Security scan
bandit -r redcheck/ -c pyproject.toml

# Build
python -m build

# Docker
docker build --target runtime -t redcheck246:latest .
docker build --target dev -t redcheck246:dev .
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full developer guide.

## License

Proprietary. See [LICENSE.txt](LICENSE.txt) for details.
