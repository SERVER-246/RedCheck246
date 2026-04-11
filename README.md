<div align="center">

# 🛡️ RedCheck246

**Controlled Adversary Simulation & Resilience Validation Platform**

[![CI](https://github.com/SERVER-246/RedCheck246/actions/workflows/ci.yml/badge.svg)](https://github.com/SERVER-246/RedCheck246/actions/workflows/ci.yml)
[![CodeQL](https://github.com/SERVER-246/RedCheck246/actions/workflows/codeql.yml/badge.svg)](https://github.com/SERVER-246/RedCheck246/actions/workflows/codeql.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-2365%2B%20passing-brightgreen.svg)](#)
[![Coverage](https://img.shields.io/badge/coverage-92%25-brightgreen.svg)](#)
[![Mutation](https://img.shields.io/badge/mutation%20score-95%25-brightgreen.svg)](#)
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
- **23 plugins across 10 categories** — Recon, SAST, DAST, fuzzing, supply chain, network scanning, crypto analysis, OSINT, exploit verification, detection validation
- **Auto-discovery** — Plugins register via `__init_subclass__` with `pkgutil.walk_packages` package scanning
- **Fuzzy name matching** — Misspelled plugin names return ranked suggestions via `difflib.get_close_matches`
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

### 🔍 Detection Validation (Phase 4)
- **MITRE ATT&CK coverage** — 21-technique catalog with deterministic SHA-256 traffic markers and gap analysis
- **Alert latency testing** — SLA measurement with adaptive polling, probe count capping, and p95 statistics
- **Coverage computation** — Per-technique detection mapping with severity-based findings (high if <50%)
- **Offline mode** — Pre-detected technique lists and simulated latencies for CI/testing environments

### 🏢 Commercial Readiness (Phase 5)
- **Multi-tenant isolation** — Per-tenant filesystem directories with path traversal defense
- **Role-based access control** — 5-role × 6-action permission matrix (viewer→analyst→operator→admin→super_admin)
- **Report generation** — JSON/PDF/HTML output with Ed25519 digital signatures and Jinja2 templates
- **Encrypted audit export** — AES-256-GCM encrypted audit trail export/import with tamper detection
- **SBOM generation** — SPDX 2.3 JSON software bill of materials

### 🧪 Test Mode & Pipeline (Phase 6)
- **OTP-gated execution** — TOTP one-time password gate for DESTRUCTIVE plugins with email delivery
- **Plugin pipeline chaining** — Upstream findings flow to downstream plugins via `upstream_findings`
- **Evidence indexing** — SHA-256 hashed evidence store with integrity verification
- **Attack path correlation** — Pipeline findings correlated into attack graphs with severity ranking
- **Dry-run mode** — All plugins support `dry_run()` for side-effect-free analysis
- **Backward compatible** — All existing `redcheck run` / `redcheck run-all` commands unchanged

### 🔎 Data Infrastructure & Validation (Phase 7)
- **Internal network discovery** — ARP scan, UDP probe, OS fingerprinting with scope enforcement
- **Advanced web crawling** — API spec discovery, form enumeration, login flow detection, parameter mapping
- **Vulnerability signature database** — Lazy-loaded JSON signature files for web, service, and injection vulns
- **Service fingerprinting** — 120+ patterns with CPE identifiers and CVE correlation
- **Target identity validation** — TLS certificate, DNS consistency, and ownership checks before engagement

### 🔐 Cryptographic Security
- **Evidence encryption** — AES-256-GCM with PBKDF2-HMAC-SHA512 key derivation
- **Document signing** — Ed25519 public-key + HMAC-SHA256 dual-mode
- **Activation codes** — Argon2id (time=3, memory=64MB, parallelism=4)
- **Secure scanning** — Shared SSL context with TLS 1.2 minimum for all outbound connections

### 📊 Developer Experience
- **Rich CLI** — 12 commands with `--output-dir` / `--report-format` flags, Rich tables, banners, JSON export via Typer
- **Async-first** — All network plugins use `httpx.AsyncClient`
- **Docker-ready** — Multi-stage build with non-root user (UID 1000), read-only filesystem
- **Full test coverage** — 1 666 tests, 93% line coverage, mutation testing (≥95%) across Python 3.10–3.13

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
| `detection-coverage` | Detection | ACTIVE | T1562.001 | MITRE ATT&CK coverage validation with 21-technique catalog and gap analysis |
| `alert-latency` | Detection | ACTIVE | T1562.006 | Alert pipeline latency measurement with SLA thresholds and p95 stats |
| `persistence-validator` | Detection | ACTIVE | T1547, T1053 | Persistence mechanism detection with registry, cron, and service enumeration |
| `detection-response-recorder` | Detection | ACTIVE | T1562 | Detection response recording with alert correlation and timeline reconstruction |
| `container-analyzer` | Recon | ACTIVE | T1610, T1613 | Docker/OCI container security analysis — image scanning, config audit |
| `lateral-movement-analyzer` | Recon | ACTIVE | T1021, T1570 | Lateral movement path analysis with credential relay and pivot detection |
| `network-discovery` | Recon | ACTIVE | T1046, T1018 | Internal network discovery via ARP scan, UDP probe, OS fingerprinting |

## Architecture

```
redcheck/
├── cli.py                     # Typer CLI (12 commands)
├── config.py                  # Pydantic v2 BaseSettings (REDCHECK_ env prefix)
├── constants.py               # Immutable hard-cap constants
├── exceptions.py              # 23 custom exception classes
├── models.py                  # 6 enums + 10 Pydantic v2 models
├── output.py                  # Rich terminal formatting
├── logging.py                 # structlog JSON configuration
├── core/
│   ├── activation_engine.py   # Argon2id activation code management
│   ├── attack_path_correlator.py  # Finding → attack graph correlation
│   ├── audit.py               # AES-256-GCM encrypted hash-chained audit
│   ├── audit_export.py        # AES-256-GCM encrypted audit export/import
│   ├── evidence_store.py      # SHA-256 indexed evidence with integrity verification
│   ├── metrics.py             # Prometheus-compatible metrics collector
│   ├── multi_tenant.py        # Per-tenant filesystem isolation
│   ├── network_guard.py       # Outbound scope validation with anti-pivot
│   ├── orchestrator.py        # Engagement lifecycle + plugin dispatch
│   ├── otp_engine.py          # TOTP one-time password gate
│   ├── pipeline.py            # Plugin pipeline chaining engine
│   ├── policy_engine.py       # Central policy gate (RoE × mode × capability)
│   ├── rbac.py                # 5-role × 6-action RBAC permission matrix
│   ├── reporting.py           # JSON/PDF/HTML report generation + Ed25519 signing
│   ├── report_adapter.py      # Plugin result → ScanReport bridge
│   ├── sbom_integration.py    # SPDX 2.3 SBOM generation
│   ├── scope_validator.py     # CIDR-aware in-scope validation
│   ├── target_validator.py    # Pre-flight TLS/DNS identity verification
│   ├── test_mode.py           # Test mode runtime support
│   ├── token_bucket.py        # Token-bucket rate limiting
│   ├── topology.py            # Network topology graph engine
│   ├── vuln_db.py             # Lazy-loaded vulnerability signature database
│   └── report_templates/      # Jinja2 report templates (executive, technical, compliance)
├── plugins/                   # 23 auto-registered plugins
│   ├── _http.py               # Shared SSL context (scanning_ssl_context)
│   ├── base_plugin.py         # BasePlugin ABC + PluginRegistry
│   ├── recon/                 # Passive recon, network scanning, network discovery
│   ├── sast/                  # Static analysis (bandit + regex)
│   ├── dast/                  # Dynamic analysis, web crawling, auth/injection testing
│   ├── fuzzing/               # Protocol fuzzing (200+ payloads)
│   ├── supply_chain/          # Supply chain audit (OSV.dev + parsers)
│   ├── crypto/                # Hash analysis & password entropy scoring
│   ├── osint/                 # CT logs, typosquat detection, breach lookup
│   ├── detection/             # MITRE coverage, alert latency, persistence, response
│   └── exploit/               # CVE mapping, exploit verification & attack graphs
├── data/
│   ├── safe_poc_library.json  # Safe exploit PoC payloads
│   ├── service_fingerprints.yaml  # 120+ service fingerprint patterns with CPE
│   ├── service_versions.json  # Service+version → CVE mapping
│   └── vuln_signatures/       # Web, service, and injection vulnerability signatures
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
| `RESEARCH` | ✅ | ✅ | ✅ (gated) | Isolated research labs |
| `TEST` | ✅ | ✅ | ✅ (OTP-gated) | Test mode with full pipeline |

## Roadmap

RedCheck246 follows a phased development approach. See [next_phase_execution_plan.md](../next_phase_execution_plan.md) for full specifications.

| Phase | Scope | Target |
|:-----:|-------|--------|
| ✅ 1–16 | Core framework, 5 plugins, crypto, CI/CD | v0.2.0 |
| ✅ Phase 1 | Foundation engines — models, orchestrator, rate limiting, metrics | v0.2.5 |
| ✅ Phase 2 | Scanners — network, web, credential, OSINT, exploit verification | v0.3.0-rc1 |
| ✅ Phase 3 | Attack graph — path analysis, kill-chain, attacker-class scoping | v0.3.0-rc2 |
| ✅ Phase 4 | Detection validation — MITRE coverage, alert latency | v0.3.0-rc3 |
| ✅ Phase 5 | Commercial readiness — multi-tenant, RBAC, reporting, SBOM | v0.3.0 GA |
| ✅ Phase 6 | Integration testing — end-to-end pipeline, backward compat | v0.3.1-rc1 |
| ✅ Phase 7 | Data infrastructure — vuln DB, network discovery, target validation | v0.3.1-rc2 |

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

# Mutation testing (requires mutmut 2.x)
mutmut run --paths-to-mutate=redcheck/core/policy_engine.py --tests-dir=tests/ --runner="pytest -x -q"
mutmut results

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
- `ruff format --check` — zero formatting diffs
- `mypy --strict` — zero errors
- `bandit` — zero CRITICAL/HIGH findings
- `pytest` — all 1 666 tests passing, ≥93% line coverage
- `mutmut` — ≥95% mutation score on core modules
- CodeQL — zero open findings

## License

Proprietary. See [LICENSE](LICENSE) for details.

---

<div align="center">

**Built for security professionals. Gated by design. No exceptions.**

</div>
