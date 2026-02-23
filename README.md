<div align="center">

# 🛡️ RedCheck246

**Controlled Adversary Simulation & Resilience Validation Platform**

[![CI](https://github.com/SERVER-246/RedCheck246/actions/workflows/ci.yml/badge.svg)](https://github.com/SERVER-246/RedCheck246/actions/workflows/ci.yml)
[![CodeQL](https://github.com/SERVER-246/RedCheck246/actions/workflows/codeql.yml/badge.svg)](https://github.com/SERVER-246/RedCheck246/actions/workflows/codeql.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-631%20passing-brightgreen.svg)](#)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

</div>

---

> **⚠️ Security Notice:** RedCheck246 is a professional security assessment tool. All active scanning requires a signed Rules of Engagement (RoE) document and a verified activation code. Destructive capabilities are disabled outside of isolated research environments. Use responsibly and only on authorized targets.

## What is RedCheck246?

RedCheck246 is a **policy-gated, plugin-based security assessment framework** designed for professional red teams, security researchers, and enterprise security validation. It provides controlled adversary simulation with built-in safety mechanisms that prevent unauthorized or accidental use against out-of-scope targets.

Unlike traditional scanners, RedCheck246 enforces a **4-gate authorization model** before any active operation:

```
RoE Signature → Activation Code → Runtime Mode Check → Offensive Controls Gate
```

## Key Features

### 🔒 Authorization & Governance
- **4-gate policy enforcement** — Ed25519 signed RoE, Argon2id activation, runtime mode matrix, offensive control flags
- **Scope validation** — CIDR-aware target whitelisting with hard bounds
- **Hash-chained audit log** — AES-256-GCM encrypted, tamper-evident, append-only
- **Rate limiting** — Token bucket with configurable hard caps (never exceed `constants.py`)

### 🔌 Plugin Architecture
- **19 plugins across 9 categories** — Recon, SAST, DAST, fuzzing, supply chain, network scanning, crypto analysis, OSINT, exploit verification
- **Auto-discovery** — Plugins register via `__init_subclass__` and entry points
- **Lifecycle hooks** — `setup()`, `execute()`, `teardown()`, `health_check()`, `dry_run()`
- **Capability classification** — `PASSIVE`, `ACTIVE`, `DESTRUCTIVE` with enforcement matrix

### 🌐 Network & Exploit Verification (Phase 2)
- **Network scanning** — TCP SYN/connect scanning, service fingerprinting, topology graph mapping
- **Web application testing** — Auth/session testing, IDOR validation, injection PoC simulation
- **Cryptographic analysis** — Hash strength scoring, password entropy (NIST SP 800-63B), algorithm migration guidance
- **OSINT intelligence** — Certificate Transparency monitoring, typosquat detection, breach lookup (k-anonymity)
- **Exploit verification** — CVE↔CPE mapping, EPSS probability, KEV cross-reference, sandboxed exploit validation

### 🗓️ Attack Graph Engine (Phase 3)
- **Attack path analysis** — Dijkstra shortest-path and Yen’s k-shortest-paths over probabilistic exploit graphs
- **Attacker class scoping** — 4-tier threat model (AC1–AC4) with per-class depth limits, node caps, and edge-type filtering
- **MITRE ATT&CK annotations** — Every exploit edge carries MITRE technique IDs for kill-chain mapping
- **Chain mode gating** — Requires `chain_mode` + `allow_exploit_validation` for graph construction
- **JSON round-trip** — Full serialization/deserialization for persistence and reporting

### 🔐 Cryptographic Security
- **Evidence encryption** — AES-256-GCM with PBKDF2-HMAC-SHA512 key derivation
- **Document signing** — Ed25519 public-key + HMAC-SHA256 dual-mode
- **Activation codes** — Argon2id (time=3, memory=64MB, parallelism=4)
- **Secure scanning** — Shared SSL context with TLS 1.2 minimum for all outbound connections

### 📊 Developer Experience
- **Rich CLI** — Beautiful terminal output with tables, banners, JSON export via Typer
- **Async-first** — All network plugins use `httpx.AsyncClient`
- **Docker-ready** — Multi-stage build with non-root user (UID 1000), read-only filesystem
- **Full test coverage** — 631+ tests across Python 3.10–3.13

## Quick Start

```bash
# Clone and install
git clone https://github.com/SERVER-246/RedCheck246.git
cd RedCheck246

# Set up virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows
pip install --upgrade pip
pip install -e ".[dev]"

# Set activation code
redcheck activate --set

# Initialize an engagement workspace
redcheck init my-engagement

# Edit the Rules of Engagement
nano my-engagement/roe.yaml

# Validate RoE structure
redcheck verify-roe my-engagement/roe.yaml

# Dry-run (no network calls)
redcheck recon --roe my-engagement/roe.yaml --dry-run

# Run a scan (requires valid activation)
redcheck run passive-recon --roe my-engagement/roe.yaml

# List available plugins
redcheck list-plugins

# Check framework status
redcheck status
```

## Plugin Catalog

| Plugin | Category | Capability | MITRE ATT&CK | Description |
|--------|----------|:----------:|:------------:|-------------|
| `passive-recon` | Recon | PASSIVE | T1596, T1593 | DNS resolution, WHOIS, certificate transparency, subdomain enumeration, HTTP fingerprinting |
| `sast-scanner` | SAST | PASSIVE | — | Bandit integration, 10 regex patterns, dependency audit |
| `dast-scanner` | DAST | ACTIVE | T1190 | Security headers, SSL/TLS configuration, HTTP methods, cookie analysis |
| `protocol-fuzzer` | Fuzzing | ACTIVE | T1499 | HTTP parameter/header/body fuzzing, SQLi/XSS/CMDi payload library (200+) |
| `supply-chain-audit` | Supply Chain | PASSIVE | T1195.002 | OSV.dev vulnerability queries, license compliance, typosquatting detection, SBOM |
| `network-scanner` | Network | ACTIVE | T1046, T1595.001 | TCP SYN/connect scanning, service fingerprinting, topology mapping |
| `auth-session-tester` | DAST | ACTIVE | T1078, T1110.001 | Session fixation, cookie security, auth bypass, CSRF token validation |
| `idor-validator` | DAST | ACTIVE | T1565.001 | Insecure direct object reference detection with UUID/integer ID permutation |
| `injection-poc-simulator` | DAST | ACTIVE | T1190, T1059 | SQLi/XSS/CMDi proof-of-concept generation with safe payload library |
| `hash-strength-analyzer` | Crypto | PASSIVE | T1110.002 | Algorithm identification, collision resistance scoring, migration recommendations |
| `password-entropy-scorer` | Crypto | PASSIVE | T1110, T1078 | Shannon entropy, charset analysis, dictionary proximity, NIST SP 800-63B compliance |
| `ct-log-monitor` | OSINT | PASSIVE | T1596.003 | Certificate Transparency log monitoring, rogue cert detection, domain alerting |
| `typosquat-detector` | OSINT | PASSIVE | T1583.001 | Levenshtein/homoglyph/bitsquat domain permutation with DNS live-check |
| `breach-lookup` | OSINT | PASSIVE | T1589.001 | Credential breach database queries with k-anonymity (HIBP-compatible) |
| `cve-mapper` | Exploit | PASSIVE | T1595.002 | CPE↔CVE mapping, CVSS v3.1 scoring, EPSS probability, KEV cross-reference |
| `exploit-verifier` | Exploit | DESTRUCTIVE | T1203, T1190 | Safe exploit validation with sandbox isolation and rollback verification |

## Architecture

```
redcheck/
├── cli.py                     # Typer CLI (7 commands)
├── config.py                  # Pydantic v2 BaseSettings (REDCHECK_ env prefix)
├── exceptions.py              # 11 custom exception classes
├── models.py                  # 7 enums + 8 Pydantic v2 models
├── output.py                  # Rich terminal formatting
├── logging.py                 # structlog JSON configuration
├── core/
│   ├── audit.py               # AES-256-GCM encrypted hash-chained audit
│   ├── orchestrator.py        # Engagement lifecycle + plugin dispatch
│   ├── policy_engine.py       # Central policy gate (RoE × mode × capability)
│   ├── activation_engine.py   # Argon2id activation code management
│   ├── rate_limiter.py        # Token-bucket rate limiting
│   └── metrics.py             # Prometheus-compatible metrics collector
├── plugins/
│   ├── _http.py               # Shared SSL context (scanning_ssl_context)
│   ├── base_plugin.py         # BasePlugin ABC + PluginRegistry
│   ├── recon/                 # Passive reconnaissance (7 async modules)
│   ├── sast/                  # Static analysis (bandit + regex)
│   ├── dast/                  # Dynamic analysis (6 async modules)
│   ├── fuzzing/               # Protocol fuzzing (200+ payloads)
│   ├── supply_chain/          # Supply chain audit (OSV.dev + parsers)
│   ├── network/               # Network scanning & topology mapping
│   ├── crypto/                # Hash analysis & password entropy scoring
│   ├── osint/                 # CT logs, typosquat detection, breach lookup
    └── exploit/               # CVE mapping, exploit verification & attack graphs
├── data/
│   ├── cve_cache.json         # Local CVE/CPE cache
│   └── payloads/              # Safe exploit payload library
└── security/
    ├── crypto.py              # AES-256-GCM, PBKDF2, HMAC, hashing
    ├── roe_validator.py       # YAML structure + time window validation
    └── signature_verifier.py  # Ed25519 + HMAC-SHA256 dual-mode signing
```

## Security Controls

| Control | Implementation | Status |
|---------|---------------|:------:|
| Evidence encryption | AES-256-GCM with PBKDF2-HMAC-SHA512 key derivation | ✅ |
| Document signing | Ed25519 public-key + HMAC-SHA256 | ✅ |
| Activation codes | Argon2id (time=3, mem=64MB, p=4) with SHA-512 fallback | ✅ |
| Audit log | Hash-chained, append-only, AES-256-GCM encrypted | ✅ |
| Brute-force protection | 5 attempts, 300s lockout, 2s cooldown | ✅ |
| Container security | Non-root user (UID 1000), read-only filesystem | ✅ |
| Code scanning | GitHub CodeQL with `security-extended` queries | ✅ |
| Dependency monitoring | Dependabot weekly updates, OSV.dev audits | ✅ |
| SSL/TLS for scanning | Shared `scanning_ssl_context()` — TLS 1.2 minimum | ✅ |

## Runtime Mode Matrix

| Mode | PASSIVE | ACTIVE | DESTRUCTIVE | Use Case |
|------|:-------:|:------:|:-----------:|----------|
| `DEV` | ✅ | ✅ (dry-run) | ❌ | Local development |
| `CI` | ✅ | ❌ | ❌ | Continuous integration |
| `STAGING` | ✅ | ✅ | ❌ | Pre-production validation |
| `PRODUCTION` | ✅ | ✅ | ❌ | Live assessments |

## Roadmap

RedCheck246 follows a phased development approach. See [next_phase_execution_plan.md](../next_phase_execution_plan.md) for full specifications.

| Phase | Scope | Target |
|:-----:|-------|--------|
| ✅ 1–16 | Core framework, 5 plugins, crypto, CI/CD | v0.2.0 |
| ✅ Phase 1 | Foundation engines — models, orchestrator, rate limiting, metrics | v0.2.5 |
| ✅ Phase 2 | Scanners — network, web, credential, OSINT, exploit verification | v0.3.0-rc1 |
| ✅ Phase 3 | Attack graph — path analysis, kill-chain, attacker-class scoping | v0.3.0-rc2 |
| 📋 Phase 4 | Detection validation — MITRE coverage, alert latency | v0.3.0-rc3 |
| 📋 Phase 5 | Commercial readiness — multi-tenant, RBAC, reporting | v0.3.0 GA |

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run full test suite
pytest tests/ -v --cov=redcheck

# Quick smoke test
pytest tests/ -q --tb=short

# Lint + format
ruff check redcheck/ tests/
ruff format redcheck/ tests/

# Type checking
mypy --strict redcheck/

# Security audit
bandit -r redcheck/ -c pyproject.toml

# Build wheel
python -m build

# Docker (runtime)
docker build --target runtime -t redcheck246:latest .

# Docker (development)
docker build --target dev -t redcheck246:dev .
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full developer guide. All contributions must pass:

- `ruff check` — zero warnings
- `mypy --strict` — zero errors
- `bandit` — zero CRITICAL/HIGH findings
- `pytest` — all tests passing
- CodeQL — zero open findings

## License

Proprietary. See [LICENSE](LICENSE) for details.

---

<div align="center">

**Built for security professionals. Gated by design. No exceptions.**

</div>
