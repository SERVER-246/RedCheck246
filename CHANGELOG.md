# Changelog

All notable changes to RedCheck246 are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] — 2026-04-10

### 🔬 Phases A–F — Architecture Hardening & Live Validation

#### Added

- **Plugin dependency graph** (Phase A) — Topological ordering with cycle detection, `DependencyGraph` class, 23 plugins correctly ordered
- **Tier 2 plugin expansion** (Phase B) — Network scanner (TCP SYN/connect, service fingerprinting), crypto analyser (hash strength, entropy scoring), OSINT (CT monitoring, breach lookup), exploit verifier (CVE↔CPE, EPSS, KEV), detection coverage validator
- **Auth session tester** (Phase C) — CSRF token validation, session fixation detection, cookie scope analysis
- **Attack chain scoring** (Phase D) — Cross-plugin finding correlation via Dijkstra/Yen's k-shortest-paths over probabilistic exploit graphs, MITRE ATT&CK annotations
- **Mode separation** (Phase E) — `TEST_MODE` vs `LIVE_MODE` field segregation ensuring simulated findings are never mixed with live results
- **Deep codebase audit** (Phase pre-F) — 3 integrity/safety fixes: evidence data corruption guard, silent failure suppression removal, encrypted integrity check hardening. 16 false positives dismissed, all imports AST-verified
- **End-to-end validation** (Phase F) — Programmatic live run of all 18 ROE-listed plugins against evil.com in TEST_MODE. 18/18 pass, 105 findings, 341.3s. 18 JSON reports, 14 evidence files generated
- Coverage tests for `cve_mapper`, `idor_checker`, `target_validator` (push coverage to 90.69%)
- `tests/phase_f_validation.py` — Standalone E2E validation script

#### Changed

- `pyproject.toml` — Added per-file-ignores for validation script (T201, F401)
- README badges — Updated test count (2195) and coverage (90%)

#### Fixed

- `orchestrator._index_evidence` — Skip missing files instead of storing corrupt data
- `fake_metric_detector._downgrade_finding` — Explicit try/except + logging instead of silent `contextlib.suppress`
- `evidence_store.verify_integrity` — SHA-256 check for encrypted entries
- Bandit B105 false-positive suppressed on `auth_tester` probe credential

---

## [0.3.0] — 2025-06-22

### 🏢 Phase 5 — Commercial Readiness

#### Added

- **Multi-Tenant Isolation** (`redcheck/core/multi_tenant.py`)
  - Per-tenant directory sandboxing with `0o700` permissions
  - Path traversal attack prevention (blocks `../`, null bytes, separators)
  - Tenant ID validation (2–64 chars, strict alphanumeric pattern)
  - Cross-tenant access detection and `TenantFilesystemManager` lifecycle

- **Role-Based Access Control** (`redcheck/core/rbac.py`)
  - 5-role × 6-action explicit permission matrix (no implicit inheritance)
  - Roles: VIEWER, OPERATOR, SENIOR_OPERATOR, ADMIN, AUDITOR
  - DESTRUCTIVE confirmation gate, `RBACEnforcer` and `RBACAction` enum

- **Reporting & Evidence Export** (`redcheck/core/reporting.py`)
  - JSON report generation with Ed25519 digital signatures
  - Jinja2 HTML templates (`executive_summary.j2`, `technical_detail.j2`)
  - PDF via optional weasyprint; graceful JSON-only fallback
  - `ReportExporter` unified high-level API

- **Audit Trail Export** (`redcheck/core/audit_export.py`)
  - AES-256-GCM encrypted audit export/import with AAD

- **SBOM Integration** (`redcheck/core/sbom_integration.py`)
  - SPDX 2.3 JSON SBOM generation from installed packages

- **CI/CD Expansion** — 5-job pipeline + mutation testing (`mutmut`) + `docker-compose.test.yml`
- **New dependencies:** `jinja2>=3.1`, optional `weasyprint>=60.0`, dev `mutmut>=2.4`
- **Version:** `0.3.0rc3` → `0.3.0` GA

## [0.2.0] — 2026-02-20

### Added

- **Pydantic v2 models** — 13 validated data models (`EngagementContext`, `Finding`, `PluginResult`, `RoEDocument`, `ScanReport`, etc.)
- **Typer + Rich CLI** — 7 commands (`init`, `recon`, `run`, `list-plugins`, `verify-roe`, `activate`, `status`) with `--format json|text`, `--verbose`, `--version`
- **Structured logging** — `structlog` + stdlib integration across all modules
- **AES-256-GCM evidence encryption** — PBKDF2-HMAC-SHA512 key derivation, HKDF, hash-chained audit
- **Ed25519 + HMAC-SHA256 signatures** — Dual-mode document and evidence signing
- **Argon2id activation** — Password hashing with rate limiting (5 attempts, 300s lockout)
- **Passive recon plugin** — 7 async modules (DNS, reverse DNS, WHOIS, cert transparency, HTTP fingerprint, subdomain enum, email harvest)
- **SAST plugin** — Bandit integration, 10 custom regex patterns, dependency file scanner
- **DAST plugin** — 6 async modules (security headers, SSL/TLS, HTTP methods, cookies, directory discovery, redirects)
- **Protocol fuzzer plugin** — HTTP param/header/body fuzzing, SQLi/XSS/CMDi payloads, crash detection
- **Supply chain audit plugin** — OSV.dev vulnerability queries, license compliance, typosquatting detection, SBOM generation
- **Plugin capability system** — `PASSIVE`, `ACTIVE`, `DESTRUCTIVE` risk classification
- **Plugin lifecycle hooks** — `setup()`, `teardown()`, `health_check()`
- **Entry point discovery** — Plugins discoverable via `importlib.metadata`
- **11 custom exceptions** — Typed error hierarchy with `to_dict()` serialization
- **157 tests** — Full test suite across 15 files
- **Docker support** — Multi-stage Dockerfile (builder → runtime → dev), docker-compose.yml
- **CI/CD pipeline** — 5-job GitHub Actions (lint, test matrix, security, build, docker)
- **Dependabot** — Weekly dependency scanning (pip, GitHub Actions, Docker)
- **CodeQL** — Weekly static analysis
- **Pre-commit hooks** — ruff, mypy, bandit, trailing whitespace, private key detection
- **Makefile** — `make test`, `make lint`, `make build`, `make docker`, `make ci`
- **SECURITY.md** — Responsible disclosure policy
- **CONTRIBUTING.md** — Developer guide

### Changed

- Build system migrated from `setuptools` to `hatchling`
- All modules now use `structlog` instead of `print()`/`logging`
- Plugin stubs replaced with full implementations
- `crypto.py` — XOR fallback removed; `cryptography` is a hard dependency
- `activation_engine.py` — Upgraded from SHA-512 to Argon2id
- `signature_verifier.py` — Added Ed25519 alongside HMAC-SHA256
- `roe_validator.py` — Imports `RoEValidationError` from `exceptions.py`
- `base_plugin.py` — Added `PluginCapability`, lifecycle hooks, entry point discovery
- `orchestrator.py` — Added timing (`duration_ms`), structured logging, `PolicyDeniedException`

### Fixed

- Python 3.10 `datetime.fromisoformat("...Z")` crash (Z → `+00:00` normalization)
- Invalid SPDX license identifier (`"Proprietary"` → `"LicenseRef-Proprietary"`)
- Build backend path (`setuptools.backends._legacy:_Backend` → `setuptools.build_meta`)

## [0.1.0] — 2026-02-19

### Added

- Initial framework scaffold (12 directive phases)
- Policy engine with RoE validation
- Activation engine with SHA-512 hashing
- Plugin registry with auto-registration
- Basic orchestrator
- 5 plugin stubs (recon, sast, dast, fuzzing, supply chain)
- Security modules (crypto, RoE validator, signature verifier)
- 33 initial tests
- GitHub Actions CI pipeline
