# Changelog

All notable changes to RedCheck246 are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
