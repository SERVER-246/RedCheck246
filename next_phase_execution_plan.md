# NEXT_PHASE_EXECUTION_PLAN.md — v3.0

**Created:** 2026-02-20 UTC
**Restructured:** 2026-02-20 UTC (v3.0 — sequenced phases + measurable outcomes)
**Predecessor:** `EXECUTION_PLAN.md` (Phases 1–16 — ALL COMPLETE, commit `7a489ce`)
**Current Baseline:** RedCheck246 v0.2.0 — 157/157 tests, 5 plugins, 12 CodeQL findings fixed
**Target:** v0.3.0 (Resilience Engine) → v1.0.0 (Production)
**Branch:** `next-phase/redcheck-resilience` (fork from `dev/redcheck-architecture-bootstrap-20260219-134306`)

---

## EXECUTIVE SUMMARY

This plan transitions RedCheck246 from a **hardened scanning framework** (v0.2.0) into a **controlled adversary simulation and resilience validation platform** across **5 sequenced phases**, each with explicit entry criteria, measurable outcomes, and a Definition of Done.

### Phase Map (Critical Path)

```
┌──────────────────────────┐
│   PHASE 1: FOUNDATION    │  Core models, orchestrator, rate limiting,
│   (Weeks 1–3)            │  scope validation, metrics, BasePlugin
│   v0.2.0 → v0.2.5       │  extensions, constants
└────────────┬─────────────┘
             │ unlocks all scanning
             ▼
┌──────────────────────────┐
│   PHASE 2: SCANNERS &    │  Network discovery, web app testing,
│   EXPLOIT VERIFICATION   │  credential analysis, OSINT, safe PoC
│   (Weeks 4–8)            │  execution, CVE mapping
│   v0.2.5 → v0.3.0-rc1   │
└────────────┬─────────────┘
             │ unlocks chaining
             ▼
┌──────────────────────────┐
│   PHASE 3: ATTACK GRAPH  │  Attack path analysis, kill-chain
│   & CHAINING             │  construction, multi-hop simulation,
│   (Weeks 9–10)           │  MITRE ATT&CK mapping
│   v0.3.0-rc1 → rc2      │
└────────────┬─────────────┘
             │ unlocks validation
             ▼
┌──────────────────────────┐
│   PHASE 4: DETECTION     │  Detection coverage validation, alert
│   VALIDATION             │  latency testing, blue-team gap analysis,
│   (Weeks 11–12)          │  SIEM integration
│   v0.3.0-rc2 → rc3      │
└────────────┬─────────────┘
             │ unlocks commercialization
             ▼
┌──────────────────────────┐
│   PHASE 5: COMMERCIAL    │  Multi-tenant isolation, RBAC, templated
│   READINESS              │  reporting, CI/CD expansion, integration
│   (Weeks 13–16)          │  hardening, v0.3.0 GA release
│   v0.3.0-rc3 → v0.3.0   │
└──────────────────────────┘
```

### Deployment Targets

| Target | Label | Description |
|--------|-------|-------------|
| **A** | Enterprise deployment | Production-safe scanning with full RoE/activation gates |
| **B** | Research-grade experimentation | Isolated lab with RESEARCH mode, Docker sandbox |
| **C** | Private lab extensibility | Gated, isolated, operator-confirmed destructive testing |
| **D** | Commercial production readiness | Multi-tenant, RBAC, compliance reporting, SBOM |

---

## TABLE OF CONTENTS

1. [Executive Summary](#executive-summary)
2. [Existing Codebase Inventory](#section-0--existing-codebase-inventory-baseline)
3. [Mandatory Principles & Hard Constraints](#section-1--mandatory-principles--hard-constraints)
4. [New Data Models](#section-2--new-data-models-exact-definitions)
5. [**PHASE 1 — Foundation Engines**](#phase-1--foundation-engines-weeks-13)
6. [**PHASE 2 — Scanners & Exploit Verification**](#phase-2--scanners--exploit-verification-weeks-48)
7. [**PHASE 3 — Attack Graph & Chaining**](#phase-3--attack-graph--chaining-weeks-910)
8. [**PHASE 4 — Detection Validation**](#phase-4--detection-validation-weeks-1112)
9. [**PHASE 5 — Commercial Readiness**](#phase-5--commercial-readiness-weeks-1316)
10. [Capability Enforcement Matrix](#capability-enforcement-matrix)
11. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
12. [Research Mode Rules](#research-mode-rules)
13. [Key Constants](#key-constants)
14. [Risk Classification & Mitigation](#risk-classification--mitigation)
15. [Release Strategy](#release-strategy)
16. [Binding Specifications](#binding-specifications)
17. [Estimated Effort Summary](#estimated-effort-summary)

---

## SECTION 0 — EXISTING CODEBASE INVENTORY (BASELINE)

### 0.1 Current File Structure (v0.2.0 — as-built)

```
RedCheck246/
├── pyproject.toml                  # hatchling build, v0.2.0, Python ≥3.10
├── redcheck/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                      # typer CLI with rich output
│   ├── config.py                   # RedCheckConfig(BaseSettings) — REDCHECK_ prefix
│   ├── exceptions.py               # 11 exception classes
│   ├── logging.py                  # structlog setup
│   ├── models.py                   # 6 enums + 8 Pydantic v2 models
│   ├── output.py                   # rich console output helpers
│   ├── py.typed                    # PEP 561 marker
│   ├── core/
│   │   ├── __init__.py
│   │   ├── activation_engine.py    # Argon2id activation, brute-force lockout
│   │   ├── audit.py                # AES-256-GCM encrypted hash-chain audit
│   │   ├── orchestrator.py         # engagement lifecycle + plugin dispatch
│   │   └── policy_engine.py        # RoE validation, authorization gate
│   ├── plugins/
│   │   ├── __init__.py
│   │   ├── _http.py                # shared SSL context helper
│   │   ├── base_plugin.py          # BasePlugin ABC + PluginRegistry
│   │   ├── dast/                   # DAST scanner (live, deterministic)
│   │   ├── fuzzing/                # protocol fuzzer (live, deterministic)
│   │   ├── recon/                  # passive recon (DNS, WHOIS, CT logs)
│   │   ├── sast/                   # SAST scanner (AST-based, live)
│   │   └── supply_chain/           # supply chain audit (OSV API, live)
│   └── security/
│       ├── __init__.py
│       ├── crypto.py               # AES-256-GCM + HKDF key derivation
│       ├── roe_validator.py        # RoE YAML structural validation
│       └── signature_verifier.py   # Ed25519 signature verification
├── tests/                          # 157 tests, 16 test files, conftest.py
├── Dockerfile                      # multi-stage build
├── docker-compose.yml              # dev/test services
├── Makefile                        # dev workflow targets
├── .pre-commit-config.yaml         # ruff, mypy, bandit hooks
└── docs/                           # ARCHITECTURE.md, SECURITY.md, API_REFERENCE.md
```

### 0.2 Current Models (redcheck/models.py — 282 lines)

| Model | Fields | Status |
|-------|--------|--------|
| `RuntimeMode` (enum) | `DEV`, `CI`, `STAGING`, `PRODUCTION` | **Needs `RESEARCH` added** |
| `PluginCapability` (enum) | `PASSIVE`, `ACTIVE`, `DESTRUCTIVE` | ✅ Complete |
| `FindingSeverity` (enum) | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` | ✅ Complete |
| `AuditLevel` (enum) | `INFO`, `WARNING`, `ERROR`, `CRITICAL`, `SECURITY` | ✅ Complete |
| `TargetSpec` | `host`, `ports`, `protocols`, `excluded_paths` | ✅ Reusable |
| `Finding` | `finding_type`, `target`, `severity`, `detail`, `cvss_score`, `cwe_id`, `remediation`, `metadata` | **Needs extension** |
| `Evidence` | `evidence_type`, `path`, `sha256`, `timestamp`, `encrypted`, `size_bytes` | **Needs extension** |
| `PluginResult` (Pydantic) | `plugin_name`, `success`, `findings`, `evidence`, `errors`, `metadata`, `duration_ms`, `mode` | ✅ Complete |
| `EngagementContext` | `engagement_id`, `authorizer`, `targets`, etc. | **Needs extension** |
| `RoEDocument` | `engagement_id`, `authorizer`, `authorized_targets`, etc. | ✅ Complete |
| `AuditEntry` | `timestamp`, `level`, `action`, `details`, etc. | ✅ Complete |
| `ScanReport` | `engagement_id`, `scanner`, `start_time`, etc. | ✅ Complete |

### 0.3 Current Config (redcheck/config.py — 136 lines)

Already implemented rate limits with hard caps:
- `max_requests_per_second`: default=10, cap=50
- `request_timeout_seconds`: default=10, cap=30
- `scan_timeout_seconds`: default=300, cap=600
- `max_concurrent_plugins`: default=1, cap=10

**Needs addition:** TCP rate limits, per-target timeouts, concurrent target limits, RESEARCH mode profile.

### 0.4 Current Exceptions (redcheck/exceptions.py — 226 lines)

11 exceptions: `RedCheckError`, `PolicyDeniedException`, `ActivationError`, `RoEValidationError`, `ConfigurationError`, `CryptoError`, `PluginError`, `PluginNotFoundError`, `ContextValidationError`, `NetworkError`, `ScanTimeoutError`, `ScopeViolationError`.

### 0.5 Current BasePlugin (redcheck/plugins/base_plugin.py — 204 lines)

- ABC with `execute(context: dict) -> PluginResult`
- Auto-registration via `__init_subclass__`
- Entry-point discovery via `importlib.metadata`
- Lifecycle hooks: `setup()`, `teardown()`, `health_check()`
- `dry_run()` and `validate_context()` provided

**Needs addition:** `aexecute()` async method, `required_controls` list, `timeout_seconds`, `rate_limit_rps` class attrs.

### 0.6 Current Orchestrator (redcheck/core/orchestrator.py — 237 lines)

- Dataclass-based `EngagementContext` (separate from Pydantic model in models.py) — **TO BE UNIFIED**
- `load_engagement()`, `activate()`, `run_plugin()`, `shutdown()`
- Policy gate enforcement via `PolicyEngine.authorize()`

### 0.7 Current Dependencies (pyproject.toml)

```
pydantic>=2.0, pydantic-settings>=2.0, PyYAML>=6.0, cryptography>=41.0,
typer>=0.9, rich>=13.0, structlog>=23.0, httpx>=0.25, dnspython>=2.4,
python-whois>=0.9, anyio>=4.0, argon2-cffi>=23.1
```

---

## SECTION 1 — MANDATORY PRINCIPLES & HARD CONSTRAINTS

**P1.** No placeholders. No stubs. All function bodies must contain deterministic logic.
**P2.** No implicit behavior. Every decision point must be explicit, recorded in code, and covered by tests.
**P3.** All capabilities MUST remain gated by at least four independent checks:

| Gate | Implementation | Existing? |
|------|---------------|-----------|
| 1. Signed RoE | Ed25519 via `security/signature_verifier.py` | ✅ Yes |
| 2. Activation Code | Argon2id via `core/activation_engine.py` | ✅ Yes |
| 3. RuntimeMode | `models.RuntimeMode` enum check in `policy_engine.py` | ✅ Yes (add `RESEARCH`) |
| 4. Offensive Controls | **NEW** `OffensiveControls` Pydantic model | ❌ Must create |

**P4.** Forbidden functionality (hard ban — must not exist anywhere in codebase):
- No covert C2 systems, reverse shells, EDR bypass logic, kernel tampering
- No persistence implants, stealth malware, obfuscated-purpose code
- No automatic data exfiltration beyond 256 bytes sampling (gated by `allow_data_sampling`)

**P5.** All adversary behaviors must be simulation-based, non-implant, auditable, and reversible. Evidence collection must be minimal, encrypted (AES-256-GCM), and provenance-tagged.

---

## SECTION 2 — NEW DATA MODELS (EXACT DEFINITIONS)

### 2.1 RuntimeMode Extension

**File:** `redcheck/models.py` — Add `RESEARCH` to existing enum.

```python
class RuntimeMode(str, enum.Enum):
    DEV = "dev"
    CI = "ci"
    STAGING = "staging"
    PRODUCTION = "production"
    RESEARCH = "research"          # ← NEW: isolated lab only
```

### 2.2 OffensiveControls Model (NEW)

**File:** `redcheck/models.py` — Add after `PluginCapability` enum.

```python
class OffensiveControls(BaseModel):
    """Explicit boolean flags gating each offensive capability.

    Every flag defaults to False (safe-by-default posture).
    Each flag maps to a specific set of plugin `required_controls`.
    """
    model_config = ConfigDict(frozen=True)

    allow_auth_testing: bool = False       # Web auth session testing (DAST auth_tester)
    allow_exploit_validation: bool = False  # Safe PoC execution (exploit/safe_poc)
    allow_data_sampling: bool = False       # Evidence sampling up to 256 bytes
    allow_credential_spraying: bool = False # Offline hash strength analysis
    allow_privesc_probing: bool = False     # Privilege escalation indicator checks
    chain_mode: bool = False               # Multi-hop attack path chaining

    def has_controls(self, required: list[str]) -> bool:
        """Check if all required control flags are True."""
        for ctrl in required:
            if not getattr(self, ctrl, False):
                return False
        return True
```

### 2.3 EngagementContext Extension

**File:** `redcheck/models.py` — Add new fields to existing `EngagementContext`.

```python
# NEW fields to add to existing EngagementContext:
tenant_id: str | None = None
offensive_controls: OffensiveControls = Field(default_factory=OffensiveControls)
safe_mode: bool = True
runtime_mode: RuntimeMode = RuntimeMode.DEV
session_id: str | None = None
```

**Migration note:** The existing orchestrator.py has its own dataclass `EngagementContext`. This MUST be eliminated — the Pydantic model in `models.py` becomes the single source of truth.

### 2.4 PluginMetadata Model (NEW)

**File:** `redcheck/models.py` — Add after `OffensiveControls`.

```python
class PluginMetadata(BaseModel):
    """Declarative metadata attached to each plugin class."""
    model_config = ConfigDict(frozen=True)

    name: str
    capability: PluginCapability
    required_controls: list[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=60, ge=1, le=600)
    rate_limit_rps: int = Field(default=10, ge=1, le=50)
    mitre_techniques: list[str] = Field(default_factory=list)
    requires_isolation: bool = False
```

### 2.5 Finding Extension

Add to existing `Finding` model:

```python
plugin: str | None = None
timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
evidence_digest: str | None = None
sampled_data_len: int | None = None
mitre_technique: str | None = None
```

### 2.6 Evidence Extension

Add to existing `Evidence` model:

```python
provenance_tag: str | None = None  # engagement_id:plugin_name:timestamp hash
```

### 2.7 New Exceptions

**File:** `redcheck/exceptions.py` — Add to existing hierarchy.

```python
class OffensiveControlError(PolicyDeniedException):
    """Raised when required offensive control flags are not enabled."""

class IsolationError(RedCheckError):
    """Raised when a DESTRUCTIVE plugin runs without Docker sandbox."""

class RateLimitExceeded(RedCheckError):
    """Raised when a plugin exceeds its rate limit allocation."""

class TenantIsolationError(RedCheckError):
    """Raised on cross-tenant access attempts."""

class ChainModeError(PolicyDeniedException):
    """Raised when attack path chaining is attempted without chain_mode=True."""
```

---

# ═══════════════════════════════════════════════════════════════════
# PHASE 1 — FOUNDATION ENGINES (Weeks 1–3)
# ═══════════════════════════════════════════════════════════════════

## Entry Criteria

- v0.2.0 baseline: 157/157 tests passing, 0 CodeQL findings, CI green
- All existing plugins functional and covered

## Exit Criteria (Phase Gate)

- All Phase 1 modules pass their individual Definition of Done
- Total test count ≥ 270 (157 existing + ~113 new)
- Coverage ≥ 90% line, ≥ 78% branch across all modified/new files
- Zero regressions in existing tests
- Ruff clean, Bandit clean, mypy strict clean on new files
- Version bumped to v0.2.5

---

### Module 1.1 — Core Model Extensions

**New/Modified Files:**
- `redcheck/models.py` (extend)
- `redcheck/exceptions.py` (extend)
- `redcheck/constants.py` (new)
- `tests/unit/test_offensive_controls.py` (new)
- `tests/unit/test_plugin_metadata.py` (new)

**Scope:**
1. Add `RESEARCH` to `RuntimeMode` enum
2. Create `OffensiveControls` Pydantic model (frozen, safe-by-default)
3. Extend `EngagementContext` with `tenant_id`, `offensive_controls`, `safe_mode`, `runtime_mode`, `session_id`
4. Create `PluginMetadata` model
5. Extend `Finding` with `plugin`, `timestamp`, `evidence_digest`, `sampled_data_len`, `mitre_technique`
6. Extend `Evidence` with `provenance_tag`
7. Create `OperatorRole` enum (`VIEWER`, `OPERATOR`, `SENIOR_OPERATOR`, `ADMIN`, `AUDITOR`)
8. Add 5 new exceptions to `exceptions.py`
9. Create `constants.py` with all hard-coded immutable constants (see Section: Key Constants)

**Definition of Done:**

| Criterion | Metric | Validation Method |
|-----------|--------|-------------------|
| All new models instantiate with defaults | 100% of models create with `Model()` | Unit test: `test_model_defaults()` |
| `OffensiveControls` safe-by-default | All 6 flags `False` on `OffensiveControls()` | Unit test: assert every field is `False` |
| `has_controls()` gate works | 100% of control permutations tested | Parametrized test: ≥ 20 of 64 combinations |
| Frozen model rejects mutation | `ValidationError` on field assignment | Unit test: `pytest.raises(ValidationError)` |
| `PluginMetadata` validates bounds | `timeout_seconds` ∈ [1, 600], `rate_limit_rps` ∈ [1, 50] | Boundary tests: 0, 1, 50, 51, 600, 601 |
| Constants match hard caps | Every config field ≤ corresponding constant | Unit test: iterate config fields vs constants |
| New exceptions inherit correctly | Each exception is `isinstance(RedCheckError)` | Unit test: 5 assertions |
| Backward compatibility | All 157 existing tests still pass | `pytest tests/ -q` → 157 passed |
| **Test count** | **≥ 30 new tests** | `pytest tests/unit/ -v` |

---

### Module 1.2 — Orchestrator Unification & Async

**Modified Files:**
- `redcheck/core/orchestrator.py` (refactor)
- `tests/test_orchestrator.py` (update)

**Scope:**
1. Remove dataclass `EngagementContext` from `orchestrator.py`
2. Import Pydantic `EngagementContext` from `models.py`
3. Adapt `from_roe()` / `from_yaml()` to use Pydantic model's `from_roe_yaml()`
4. Replace `to_dict()` calls with `model_dump()`
5. Add `arun_plugin()` async method with 11-step enforcement sequence
6. Implement `OffensiveControls` check (Step 7 of enforcement)
7. Implement isolation check (Step 8 of enforcement)

**11-Step Enforcement Sequence (hard-coded, ordered):**

| Step | Check | Failure → Exception |
|------|-------|---------------------|
| 1 | Resolve plugin in `PluginRegistry` | `PluginNotFoundError` |
| 2 | Validate `EngagementContext` (Pydantic strict) | `ContextValidationError` |
| 3 | Check engagement time window | `PolicyDeniedException` |
| 4 | Verify RoE signature | `RoEValidationError` |
| 5 | Verify activation code | `ActivationError` |
| 6 | Check `RuntimeMode` × `PluginCapability` matrix | `PolicyDeniedException` |
| 7 | Check `OffensiveControls.has_controls(plugin.required_controls)` | `OffensiveControlError` |
| 8 | Confirm isolation for DESTRUCTIVE plugins | `IsolationError` |
| 9 | Enforce rate limits + concurrency | `RateLimitExceeded` |
| 10 | If `dry_run`: log + return simulated `PluginResult` | — |
| 11 | Execute: `asyncio.wait_for(plugin.aexecute(...), timeout)` | `ScanTimeoutError` |

**Definition of Done:**

| Criterion | Metric | Validation Method |
|-----------|--------|-------------------|
| Single `EngagementContext` source | Zero imports of dataclass version | `grep -r "class EngagementContext" redcheck/` → 1 hit in `models.py` |
| Async execution works | `arun_plugin()` completes within timeout | Integration test with mock plugin: < 2s |
| All 11 enforcement steps fire in order | Each step raises correct exception | 11 parametrized unit tests |
| Pydantic model round-trips | `model_dump()` → reconstruct | Unit test: `EngagementContext(**ctx.model_dump()) == ctx` |
| Backward compatibility | All existing orchestrator tests pass | `pytest tests/test_orchestrator.py -v` |
| **Test count** | **≥ 20 new/modified tests** | Count in test file |

---

### Module 1.3 — Rate Limiting & Scope Validation

**New Files:**
- `redcheck/core/token_bucket.py` (new)
- `redcheck/core/scope_validator.py` (new)
- `redcheck/config/runtime_profiles.yaml` (new)
- `tests/unit/test_token_bucket.py` (new)
- `tests/unit/test_scope_validator.py` (new)

**Modified Files:**
- `redcheck/config.py` (extend with new rate limit fields)

**Class: `TokenBucket`**

```python
class TokenBucket:
    """Thread-safe token bucket rate limiter with async support."""
    def __init__(self, rate: float, burst: int | None = None):
        self.rate = rate
        self.burst = burst or int(rate * 2)

    async def acquire(self, tokens: int = 1) -> None:
        """Acquire tokens, blocking if necessary."""

    def try_acquire(self, tokens: int = 1) -> bool:
        """Non-blocking acquire attempt."""
```

**Class: `ScopeValidator`**

```python
class ScopeValidator:
    """Enforce target scope boundaries defined in RoE."""

    @staticmethod
    def validate_targets(requested: list[str], authorized: list[str]) -> tuple[bool, list[str]]:
        """Returns (all_valid, list_of_violations)."""

    @staticmethod
    def expand_cidr(cidr: str, max_hosts: int = 256) -> list[str]:
        """Deterministic CIDR expansion with hard cap."""
```

**Config Extensions:**
```python
tcp_connections_per_second: int = Field(default=5, ge=1, le=20)
max_concurrent_targets: int = Field(default=3, ge=1, le=10)
per_target_timeout_seconds: int = Field(default=60, ge=1, le=120)
payload_batch_size: int = Field(default=50, ge=1, le=200)
osint_api_rate_rps: int = Field(default=5, ge=1, le=20)
metrics_db_path: Path | None = None
metrics_rotation_days: int = Field(default=1, ge=1, le=30)
multi_tenant_enabled: bool = False
default_tenant_id: str = "default"
```

**Definition of Done:**

| Criterion | Metric | Validation Method |
|-----------|--------|-------------------|
| TokenBucket enforces rate | 100 requests at rate=10 complete in ~10s ± 0.5s | Timed unit test with `asyncio.run()` |
| TokenBucket burst works | Burst of `rate × 2` tokens available immediately | Unit test: `try_acquire(burst)` → `True` |
| Scope validator blocks OOB | Out-of-scope targets return violations | Unit test: 10 OOB targets → all flagged |
| CIDR expansion capped | `/16` expansion stops at 256 hosts | Unit test: `expand_cidr("10.0.0.0/16")` → 256 |
| Wildcard matching | `*.example.com` matches `sub.example.com` | Unit test: 5 wildcard cases |
| Port range validation | Port 0 and 65536 rejected | Boundary unit tests |
| Config hard caps enforced | `tcp_connections_per_second=25` → `ValidationError` | Unit test |
| Profile loading | `runtime_profiles.yaml` loads all 3 profiles | Unit test: parse + validate |
| **Test count** | **≥ 25 new tests** | Count across test files |

---

### Module 1.4 — BasePlugin Extensions & CLI

**Modified Files:**
- `redcheck/plugins/base_plugin.py` (extend)
- `redcheck/cli.py` (extend with new commands)
- `tests/test_base_plugin.py` (update)

**Scope:**
1. Add `required_controls`, `timeout_seconds`, `rate_limit_rps`, `mitre_techniques`, `requires_isolation` to `BasePlugin`
2. Add `aexecute()` async method with sync fallback
3. Extend CLI: `redcheck research`, `redcheck report`, `redcheck tenant`

**Definition of Done:**

| Criterion | Metric | Validation Method |
|-----------|--------|-------------------|
| Existing plugins inherit defaults | All 5 plugins get `required_controls=[]`, `timeout=60` | Unit test: iterate registry |
| `aexecute()` delegates to sync | Calls `execute()` when not overridden | Unit test with mock plugin |
| New CLI commands exist | 3 new commands registered | `redcheck --help` shows them |
| CLI `--help` works | All new commands produce help without error | Subprocess test |
| **Test count** | **≥ 10 new tests** | Count in test file |

---

### Module 1.5 — Metrics & Observability

**New Files:**
- `redcheck/core/metrics.py` (new)
- `tests/unit/test_metrics.py` (new)

**Class: `MetricsCollector`**

```python
class MetricsCollector:
    """Persist metrics to local SQLite with atomic writes.

    Schema (table: metrics_ts):
        name TEXT NOT NULL,
        value REAL NOT NULL,
        tags JSON,
        ts_utc TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    """
    def record(self, name: str, value: float, tags: dict | None = None) -> None: ...
    def flush_summary(self, output_path: Path) -> None: ...
    def rotate(self) -> None: ...
```

**Standard Metric Names:**
- `plugin.execution_time_ms`, `plugin.findings_count`, `plugin.error_rate`
- `scan.targets_scanned`, `scan.scope_violations`
- `rate_limit.throttle_count`, `audit.entries_written`

**Definition of Done:**

| Criterion | Metric | Validation Method |
|-----------|--------|-------------------|
| Metrics persist | `record()` followed by SELECT returns the row | Unit test with tmp SQLite |
| Atomic writes | Concurrent `record()` calls don't corrupt DB | Stress test: 100 concurrent writes |
| Rotation works | `rotate()` archives old DB, creates new one | Unit test: file count before/after |
| Summary export | `flush_summary()` writes valid JSON with all metric names | Unit test: JSON schema validation |
| Signed manifest | Export includes SHA-256 digest of summary | Unit test: verify digest |
| **Test count** | **≥ 15 new tests** | Count in test file |

---

### Phase 1 Summary

| Module | Est. Lines | New Files | New Tests | Depends On |
|--------|:----------:|:---------:|:---------:|:----------:|
| 1.1 Core Models | ~400 | 1 + extend 2 | ~30 | Baseline |
| 1.2 Orchestrator | ~300 | extend 1 | ~20 | 1.1 |
| 1.3 Rate Limiting & Scope | ~400 | 3 | ~25 | 1.1 |
| 1.4 BasePlugin & CLI | ~200 | extend 2 | ~10 | 1.1 |
| 1.5 Metrics | ~300 | 1 | ~15 | 1.1 |
| **Phase 1 Total** | **~1,600** | **5 new + 5 mod** | **~100** | |

---

# ═══════════════════════════════════════════════════════════════════
# PHASE 2 — SCANNERS & EXPLOIT VERIFICATION (Weeks 4–8)
# ═══════════════════════════════════════════════════════════════════

## Entry Criteria

- Phase 1 complete: all modules pass DoD, v0.2.5 tagged
- Orchestrator async execution verified
- Rate limiting and scope validation operational

## Exit Criteria (Phase Gate)

- All Phase 2 modules pass their individual Definition of Done
- Total test count ≥ 420 (270 from Phase 1 + ~150 new)
- All new plugins register in `PluginRegistry` and respond to `health_check()`
- Integration tests pass against Docker test fixtures
- Coverage ≥ 91% line, ≥ 79% branch
- Version bumped to v0.3.0-rc1

---

### Module 2.1 — Network & Infrastructure Discovery

**New Files:**
- `redcheck/plugins/recon/network_scan.py` — `NetworkScanner` plugin
- `redcheck/plugins/recon/packet_craft.py` — `PacketCraft` bounded sender
- `redcheck/core/topology.py` — `TopologyEngine` graph inference
- `redcheck/data/service_fingerprints.yaml` — fingerprint database
- `tests/unit/test_network_scanner.py`
- `tests/integration/containers/network_fixture/` (Dockerfile + tcp_responder.py)

**Plugin Spec:**
```
name = "network-scanner"
capability = PluginCapability.ACTIVE
required_controls = ["allow_auth_testing"]
timeout_seconds = 120
rate_limit_rps = 10
mitre_techniques = ["T1046", "T1595.001"]
```

**Deterministic Logic:**
1. `scan_targets()` — validate scope → rate-limited `tcp_syn_probe()` → audit log
2. `ServiceVersionDetector.detect()` — fingerprint scoring (exact=1.0, Levenshtein≤2=0.7, else unknown)
3. `OSFingerprint.heuristic_identify()` — read-only: TTL, window size, banners → confidence [0,1]
4. `TopologyEngine.infer()` — union-find clustering, reverse-DNS, traceroute hops
5. `PacketCraft.bound_send()` — hard bounds: 4096B payload, 3 repeats, 1.0s gap

**New dependency:** `scapy>=2.5` (optional — graceful fallback to raw sockets)

**Definition of Done:**

| Criterion | Metric | Validation Method |
|-----------|--------|-------------------|
| Port scan accuracy | ≥ 95% true-positive on 20 known-open ports | Integration test vs `network_fixture` |
| Port scan speed | 100 ports in < 30s at rate=10 rps | Timed integration test |
| False-positive rate | ≤ 5% on 50-port mock (max 2–3 false opens) | Integration test: 50 closed + 10 open |
| Service fingerprint accuracy | ≥ 90% correct on 20 known services | Unit test with fixture responses |
| Topology inference | Correct clustering: 3 subnets × 5 hosts | Unit test with deterministic input |
| Scope enforcement | OOB target → `ScopeViolationError` | Unit test: 5 OOB → 5 exceptions |
| Rate limiting | ≤ 12 req/sec at rate=10 (burst tolerance) | Timed unit test with counter |
| PacketCraft bounds | Payload > 4096B → rejected at construction | Unit test: `pytest.raises(ValueError)` |
| **Test count** | **≥ 35 tests** | Unit + integration |

---

### Module 2.2 — Web Application Resilience

**New Files:**
- `redcheck/plugins/dast/crawler.py` — `AdvancedCrawler` BFS engine
- `redcheck/plugins/dast/auth_tester.py` — `AuthenticatedSessionTester`
- `redcheck/plugins/dast/idor_checker.py` — `IDORValidator`
- `redcheck/plugins/dast/injection_sim.py` — `InjectionProofOfCondition`
- `tests/unit/test_crawler.py`, `tests/unit/test_auth_tester.py`
- `tests/integration/containers/webapp_fixture/` (Dockerfile + app.py)

**Deterministic Logic:**
1. `AdvancedCrawler.crawl(seed_urls, max_pages=100, max_depth=5)` — BFS, respects `robots.txt`, rate-limited
2. `AuthenticatedSessionTester.test()` — gated by `allow_auth_testing`, RoE-only credentials
3. `IDORValidator.check()` — fixed RNG seed, RoE-provided allowed IDs only
4. `InjectionProofOfCondition.run()` — safe PoC only: timing oracle + ephemeral canary, gated by `allow_exploit_validation` + `--confirm-exploit` + re-verified activation

**Definition of Done:**

| Criterion | Metric | Validation Method |
|-----------|--------|-------------------|
| Crawler completeness | ≥ 95% of reachable pages in 20-page mock | Integration test: compare URLs |
| Depth limit enforced | `max_depth=3` → no depth-4 URLs | Unit test with mock link tree |
| Page limit enforced | `max_pages=10` → stops after 10 | Unit test with 50-page fixture |
| robots.txt compliance | Skips `/admin/` when disallowed | Unit test with mock robots.txt |
| Auth tester gate | Without `allow_auth_testing` → `OffensiveControlError` | Unit test |
| IDOR deterministic | Same seed + inputs → same output twice | Unit test: compare 2 runs |
| Injection safe PoC | ≥ 80% detection of `SLEEP(5)` responses | Integration test |
| Injection cleanup | Canary file removed after teardown | Integration test: assert deleted |
| **Test count** | **≥ 30 tests** | Unit + integration |

---

### Module 2.3 — Credential & Cryptographic Resilience

**New Files:**
- `redcheck/plugins/crypto/__init__.py`
- `redcheck/plugins/crypto/hash_strength.py` — `OfflineHashStrengthAnalyzer`
- `redcheck/plugins/crypto/password_policy.py` — `PasswordEntropyScorer`
- `redcheck/plugins/crypto/gpu_adapter.py` — `GPUAdapter` (simulation mode for CI)
- `tests/unit/test_hash_strength.py`, `tests/unit/test_password_policy.py`

**Plugin Spec:**
```
name = "hash-strength-analyzer"
capability = PluginCapability.ACTIVE
required_controls = ["allow_credential_spraying"]
timeout_seconds = 300
rate_limit_rps = 5
mitre_techniques = ["T1110.002"]
```

**Deterministic Logic:**
1. `analyze()` — Shannon entropy + NIST cracking curves + fixed GPU reference table → `crackability_score` [0,1]
2. `PasswordEntropyScorer.score()` — returns 0–100, charset × length, pattern penalties, no API calls
3. `GPUAdapter` — `simulate_mode=True` in CI; real GPU gated by activation + `allow_privesc_probing`

**Definition of Done:**

| Criterion | Metric | Validation Method |
|-----------|--------|-------------------|
| Crackability accuracy | MD5("password") ≥ 0.95; Argon2id(complex) ≤ 0.05 | Unit test: 10 known samples |
| Deterministic output | Same input → same score on 3 runs | Unit test: assert equality |
| Entropy range | All scores ∈ [0, 100] for any input | Property test: 1000 random strings |
| Pattern penalties | "qwerty123" < 30; random 20-char > 80 | Unit test |
| GPU adapter fallback | `simulate_mode=True` → no GPU import | Unit test: mock `cupy` unavailable |
| Gate enforcement | Without `allow_credential_spraying` → `OffensiveControlError` | Unit test |
| **Test count** | **≥ 20 tests** | Unit tests |

---

### Module 2.4 — OSINT & Passive Intelligence

**New Files:**
- `redcheck/plugins/osint/__init__.py`
- `redcheck/plugins/osint/ct_watch.py` — Certificate Transparency monitor
- `redcheck/plugins/osint/typosquat.py` — Typosquatting detector
- `redcheck/plugins/osint/breach_lookup.py` — Breach database correlator
- `tests/unit/test_osint.py`

**All OSINT plugins:** `PASSIVE`, no offensive controls, rate=5 rps, timeout=60s.

**Definition of Done:**

| Criterion | Metric | Validation Method |
|-----------|--------|-------------------|
| Typosquat accuracy | ≥ 90% of 20 known typosquats detected | Unit test with fixture list |
| False-positive rate | ≤ 10% from 50 legitimate domains | Unit test |
| CT Watch parsing | ≥ 95% SAN extraction from 10 mock responses | Unit test with fixture JSON |
| Rate limiting | 100 rapid calls at rate=5 → actual ≤ 6 rps | Timed unit test |
| Cache hit rate | Second call returns cached (0 API calls) | Unit test with mock HTTP |
| Cache eviction | Size 2000 evicts LRU on 2001st insert | Unit test |
| Passive-only | No POST/PUT/DELETE requests sent | Static analysis + unit test |
| **Test count** | **≥ 20 tests** | Unit tests |

---

### Module 2.5 — Exploit Verification & Safe PoC

**New Files:**
- `redcheck/plugins/exploit/__init__.py`
- `redcheck/plugins/exploit/safe_poc.py` — `ExploitVerifier`
- `redcheck/plugins/exploit/cve_mapper.py` — CVE-to-service mapper
- `redcheck/data/safe_poc_library.json` — curated non-destructive PoC catalog
- `tests/unit/test_exploit_verifier.py`, `tests/unit/test_cve_mapper.py`

**Plugin Spec:**
```
name = "exploit-verifier"
capability = PluginCapability.DESTRUCTIVE
required_controls = ["allow_exploit_validation"]
requires_isolation = True
timeout_seconds = 120
rate_limit_rps = 2
mitre_techniques = ["T1203", "T1190"]
```

**Definition of Done:**

| Criterion | Metric | Validation Method |
|-----------|--------|-------------------|
| CVE mapping accuracy | 100% of 15 curated CVE→service mappings | Unit test with fixture |
| CVE mapping determinism | Same CVE → same result on 3 runs | Unit test |
| PoC safety | 0 destructive operations in library | CI: run all PoCs, assert no state mutation |
| Verification confidence | Vulnerable mock → `confidence ≥ 0.8` | Integration test |
| Non-vulnerable rejection | Patched mock → `verified=False`, `confidence ≤ 0.2` | Integration test |
| Gate enforcement | Missing `allow_exploit_validation` → `OffensiveControlError` | Unit test |
| Isolation enforcement | Non-isolated → `IsolationError` | Unit test |
| Timeout enforcement | Hanging PoC killed after `timeout_seconds` | Unit test with sleep mock |
| **Test count** | **≥ 25 tests** | Unit + integration |

---

### Phase 2 Summary

| Module | Est. Lines | New Files | New Tests | Depends On |
|--------|:----------:|:---------:|:---------:|:----------:|
| 2.1 Network Discovery | ~800 | 4 + fixtures | ~35 | Phase 1 |
| 2.2 Web App Resilience | ~700 | 4 + fixtures | ~30 | Phase 1 |
| 2.3 Credential & Crypto | ~500 | 3 | ~20 | Phase 1 |
| 2.4 OSINT & Passive | ~500 | 3 | ~20 | Phase 1 |
| 2.5 Exploit Verification | ~600 | 4 | ~25 | Phase 1 |
| **Phase 2 Total** | **~3,100** | **18 + fixtures** | **~130** | |

---

# ═══════════════════════════════════════════════════════════════════
# PHASE 3 — ATTACK GRAPH & CHAINING (Weeks 9–10)
# ═══════════════════════════════════════════════════════════════════

## Entry Criteria

- Phase 2 complete: all scanners operational, exploit verifier passes DoD
- Network scanner can produce host/service inventory
- Exploit verifier can produce `proof_of_condition` outputs
- v0.3.0-rc1 tagged

## Exit Criteria (Phase Gate)

- Attack graph constructs from real scan data
- Kill-chain analysis produces ranked paths
- Total test count ≥ 450
- Version bumped to v0.3.0-rc2

---

### Module 3.1 — Attack Path Graph Engine

**New Files:**
- `redcheck/plugins/exploit/attack_graph.py` — `AttackPathGraph`
- `tests/unit/test_attack_graph.py`

**New dependency:** `networkx>=3.0`

**Deterministic Logic:**
1. Nodes = `Asset(id, host, role)` from targets; Edges = `ExploitAttempt(proof, probability)`
2. Most-likely path: Dijkstra on `-log(prob)` — deterministic, fixed RNG seeds
3. **Chain Mode Gate:** requires `chain_mode=True` AND `allow_exploit_validation=True`; without → graph builds but no multi-hop execution
4. Graph bounds: `MAX_NODES=1000`, `MAX_EDGES=5000` — truncation + warning on overflow

**Definition of Done:**

| Criterion | Metric | Validation Method |
|-----------|--------|-------------------|
| Graph construction speed | 50 assets + 100 edges in < 1s | Timed unit test |
| Dijkstra correctness | Matches hand-calculated path on 3 fixed graphs | Unit test with expected output |
| Deterministic output | Same input + seed → identical ranking on 5 runs | Unit test: 5 runs, assert equality |
| Node cap enforcement | 1001 nodes → truncates to 1000 + warning | Unit test |
| Edge cap enforcement | 5001 edges → truncates to 5000 | Unit test |
| Chain mode gate | `chain_mode=False` → no multi-hop execution | Unit test: verify no `aexecute()` |
| Chain requires both flags | `chain_mode=True` + `allow_exploit=False` → `ChainModeError` | Unit test |
| MITRE annotations | Each edge has MITRE technique ID | Unit test: verify metadata |
| JSON export | `to_dict()` round-trips with ranked paths | Unit test: JSON serialize/deserialize |
| **Test count** | **≥ 20 tests** | Unit tests |

---

### Phase 3 Summary

| Module | Est. Lines | New Files | New Tests | Depends On |
|--------|:----------:|:---------:|:---------:|:----------:|
| 3.1 Attack Path Graph | ~600 | 1 | ~20 | Phase 2 (2.1, 2.5) |
| **Phase 3 Total** | **~600** | **1** | **~20** | |

---

# ═══════════════════════════════════════════════════════════════════
# PHASE 4 — DETECTION VALIDATION (Weeks 11–12)
# ═══════════════════════════════════════════════════════════════════

## Entry Criteria

- Phase 3 complete: attack graph operational, v0.3.0-rc2 tagged
- MITRE ATT&CK mapping available for all plugins
- Network scanner + exploit verifier produce structured findings

## Exit Criteria (Phase Gate)

- Detection coverage validator produces % coverage against MITRE framework
- Alert latency tester measures response times within bounds
- Total test count ≥ 480
- Version bumped to v0.3.0-rc3

---

### Module 4.1 — Detection Coverage Validator

**New Files:**
- `redcheck/plugins/detection/__init__.py`
- `redcheck/plugins/detection/coverage_validator.py` — `DetectionCoverageValidator`
- `tests/unit/test_detection_coverage.py`

**Plugin Spec:**
```
name = "detection-coverage"
capability = PluginCapability.ACTIVE
required_controls = ["allow_auth_testing"]
timeout_seconds = 180
rate_limit_rps = 5
mitre_techniques = ["T1562.001"]
```

**Logic:** Generate deterministic traffic patterns → validate detection alerts → map to MITRE techniques → return `coverage_percentage` + `uncovered_techniques`

**Hard Rule:** No evasion techniques (payload morphing, encoding bypass) implemented.

**Definition of Done:**

| Criterion | Metric | Validation Method |
|-----------|--------|-------------------|
| Coverage calculation | 15/20 detected → `coverage = 75.0%` | Integration test vs SIEM fixture |
| Uncovered list accuracy | Correctly identifies all 5 uncovered techniques | Integration test: compare lists |
| Deterministic output | Same fixture → same % on 3 runs | Unit test |
| MITRE completeness | All 18+ mapped techniques included | Unit test: assert all IDs present |
| No evasion logic | No encoding/morphing functions exist | Static analysis + code review |
| **Test count** | **≥ 15 tests** | Unit + integration |

---

### Module 4.2 — Alert Latency Tester

**New Files:**
- `redcheck/plugins/detection/latency_tester.py` — `AlertLatencyTester`
- `tests/integration/containers/siem_fixture/` (Dockerfile + alert_server.py)
- `tests/unit/test_alert_latency.py`

**Logic:** Inject timestamp marker → wait bounded TTL → compute `latency_ms` → return `within_sla: bool`

**Definition of Done:**

| Criterion | Metric | Validation Method |
|-----------|--------|-------------------|
| Latency accuracy | Mock 200ms delay → measured ∈ [180, 250] ms | Integration test |
| SLA detection | expected=100ms, actual=200ms → `within_sla=False` | Unit test |
| Timeout enforcement | 60s delay → timeout at `5 × expected` | Unit test with mock |
| **Test count** | **≥ 10 tests** | Unit + integration |

---

### Phase 4 Summary

| Module | Est. Lines | New Files | New Tests | Depends On |
|--------|:----------:|:---------:|:---------:|:----------:|
| 4.1 Detection Coverage | ~250 | 2 | ~15 | Phase 3 |
| 4.2 Alert Latency | ~200 | 1 + fixtures | ~10 | Phase 1 |
| **Phase 4 Total** | **~450** | **3 + fixtures** | **~25** | |

---

# ═══════════════════════════════════════════════════════════════════
# PHASE 5 — COMMERCIAL READINESS (Weeks 13–16)
# ═══════════════════════════════════════════════════════════════════

## Entry Criteria

- Phases 1–4 complete: all plugins operational, all DoDs met
- v0.3.0-rc3 tagged
- Total test count ≥ 480

## Exit Criteria (Phase Gate — RELEASE)

- Multi-tenant isolation enforced
- RBAC permission matrix enforced
- Reports generate in JSON + PDF
- Full CI pipeline green (lint, unit, integration, security, build)
- Coverage ≥ 92% line, ≥ 80% branch
- Mutation testing ≥ 80% kill rate on critical policy code
- 100-port scan performance < 120s
- v0.3.0 GA released with signed artifacts

---

### Module 5.1 — Multi-Tenant Isolation

**New Files:**
- `redcheck/core/multi_tenant.py`
- `tests/unit/test_multi_tenant.py`

**Definition of Done:**

| Criterion | Metric | Validation Method |
|-----------|--------|-------------------|
| Path isolation | Tenant A → Tenant B's path → `TenantIsolationError` | Unit test |
| Directory permissions | Evidence dirs created with `0o700` | Unit test: `stat().st_mode` |
| Path traversal blocked | `../` in tenant_id → `ValueError` | Unit test with malicious inputs |
| Tenant ID validation | Empty/null/special-char IDs rejected | Unit test: 10 invalid IDs |
| **Test count** | **≥ 12 tests** | Unit tests |

---

### Module 5.2 — RBAC (Role-Based Access Control)

**New Files:**
- `redcheck/core/rbac.py`
- `tests/unit/test_rbac.py`

**Permission Matrix:**

| Role | Read Reports | Run PASSIVE | Run ACTIVE | Run DESTRUCTIVE | Manage Tenants | Export Evidence |
|------|:---:|:---:|:---:|:---:|:---:|:---:|
| `VIEWER` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `OPERATOR` | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `SENIOR_OPERATOR` | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| `ADMIN` | ✅ | ✅ | ✅ | ✅ (confirm) | ✅ | ✅ |
| `AUDITOR` | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |

**Definition of Done:**

| Criterion | Metric | Validation Method |
|-----------|--------|-------------------|
| Matrix enforced | All 30 role×action combos produce correct result | Parametrized test: 30 cases |
| Unauthorized raises | VIEWER + ACTIVE → `PolicyDeniedException` | Unit test |
| No implicit inheritance | Each role explicitly checked | Code review + unit test |
| **Test count** | **≥ 15 tests** | Unit tests |

---

### Module 5.3 — Reporting & Evidence Export

**New Files:**
- `redcheck/core/reporting.py`, `redcheck/core/audit_export.py`, `redcheck/core/sbom_integration.py`
- `redcheck/core/report_templates/executive_summary.j2`, `technical_detail.j2`
- `redcheck/templates/engagement_template.yaml`
- `tests/unit/test_reporting.py`

**New dependencies:** `jinja2>=3.1`, `weasyprint>=60.0` (optional extra)

**Definition of Done:**

| Criterion | Metric | Validation Method |
|-----------|--------|-------------------|
| JSON report valid | Passes JSON Schema validation | Unit test |
| JSON report signed | Ed25519 signature verifies | Unit test: sign + verify |
| PDF renders | Executive summary template renders (with weasyprint) | Conditional unit test |
| PDF graceful fallback | Missing weasyprint → JSON-only export | Unit test with mocked import |
| Templates complete | 0 `{{ undefined }}` in output | Unit test: render with fixture |
| SBOM output | Valid SPDX JSON with ≥ 5 deps | Unit test |
| Audit trail export | Encrypted export decryptable with session key | Unit test: export + decrypt + verify |
| **Test count** | **≥ 15 tests** | Unit tests |

---

### Module 5.4 — CI/CD Expansion & Hardening

**Scope:**
1. Update `.github/workflows/ci.yml` with 5-job matrix (lint, unit, integration, security, build)
2. Create `docker-compose.test.yml` for integration fixtures
3. Add mutation testing (`mutmut`) on critical policy code
4. Performance benchmark: 100-port scan < 120s
5. Property-based fuzzing on HTTP input paths

**Definition of Done:**

| Criterion | Metric | Validation Method |
|-----------|--------|-------------------|
| CI green | All 5 jobs pass on clean PR | GitHub Actions |
| Unit coverage | ≥ 92% line, ≥ 80% branch | `pytest --cov` |
| Integration pass | All Docker fixture tests complete | CI job |
| Security clean | 0 CRITICAL/HIGH from bandit + CodeQL | CI job |
| Mutation kill rate | ≥ 80% on `policy_engine.py`, `orchestrator.py`, `scope_validator.py` | `mutmut` report |
| Performance | 100-port scan < 120s on CI fixture | Timed CI job |
| Build verification | Wheel installs + `redcheck --version` works | CI job |

---

### Module 5.5 — Final Validation & v0.3.0 Release

**Scope:**
1. Full integration test suite against all Docker fixtures
2. Fix regressions and coverage gaps
3. Bump version to `0.3.0` in `pyproject.toml`
4. Generate CHANGELOG.md entry
5. Create release PR: `dev` → `release/0.3.0` → `main`
6. Tag `v0.3.0` with signed annotated tag
7. Create GitHub release with signed artifacts

**Definition of Done:**

| Criterion | Metric | Validation Method |
|-----------|--------|-------------------|
| All DoDs met | Every Phase 1–5 module passes its DoD | Audit checklist |
| Zero regressions | Original 157 + all new tests pass | Full `pytest` |
| Coverage target | ≥ 92% line, ≥ 80% branch | Coverage report |
| Release artifact | `redcheck246-0.3.0.whl` installs and runs | `pip install` + `redcheck --version` |
| Signed tag | `v0.3.0` verifiable | `git tag -v v0.3.0` |
| CHANGELOG updated | v0.3.0 entry with all modules listed | File review |

---

### Phase 5 Summary

| Module | Est. Lines | New Files | New Tests | Depends On |
|--------|:----------:|:---------:|:---------:|:----------:|
| 5.1 Multi-Tenant | ~250 | 1 | ~12 | Phase 1 (1.2) |
| 5.2 RBAC | ~300 | 1 | ~15 | Phase 1 (1.1) |
| 5.3 Reporting | ~500 | 6 | ~15 | Phase 1 (1.5) |
| 5.4 CI/CD & Hardening | ~200 | 2 | ~5 | Phases 2–4 |
| 5.5 Release | ~100 | 0 | ~20 | All |
| **Phase 5 Total** | **~1,350** | **10 + mod** | **~67** | |

---

# ═══════════════════════════════════════════════════════════════════
# CROSS-CUTTING SPECIFICATIONS
# ═══════════════════════════════════════════════════════════════════

## Capability Enforcement Matrix

**Capability × RuntimeMode:**

| RuntimeMode | PASSIVE | ACTIVE | DESTRUCTIVE |
|-------------|:-------:|:------:|:-----------:|
| `DEV` | ✅ | ✅ (dry-run only) | ❌ |
| `CI` | ✅ | ❌ | ❌ |
| `STAGING` | ✅ | ✅ | ❌ |
| `PRODUCTION` | ✅ | ✅ | ❌ (hard-disabled) |
| `RESEARCH` | ✅ | ✅ | ✅ (isolation + confirm) |

**Gate Requirements:**

| Gate | PASSIVE | ACTIVE | DESTRUCTIVE |
|------|:-------:|:------:|:-----------:|
| `EngagementContext` | YES | YES | YES |
| Signed RoE | NO | YES | YES |
| Activation code | NO | YES | YES |
| `allowed_tests` match | NO | YES | YES |
| Offensive control flags | NO | YES | YES + confirm |
| Explicit `--confirm` | NO | NO | YES |
| Docker isolation | NO | NO | YES |
| Rate-limit enforced | NO | YES | YES |

---

## Concurrency Model

```
Global Orchestrator
├── plugin_semaphore(max_concurrent_plugins)     # default=3, cap=10
│   └── Per-plugin slot
│       ├── TokenBucket(rate=plugin.rate_limit_rps)
│       └── target_semaphore(min(4, max_concurrent))
│           └── Per-target connection slot
```

---

## MITRE ATT&CK Mapping

| Plugin | Technique | Name | Phase |
|--------|-----------|------|:-----:|
| `network-scanner` | T1046 | Network Service Discovery | 2 |
| `network-scanner` | T1595.001 | Active Scanning: IP Blocks | 2 |
| `passive-recon` | T1596 | Search Open Technical Databases | — |
| `passive-recon` | T1593 | Search Open Websites/Domains | — |
| `dast-scanner` | T1190 | Exploit Public-Facing Application | — |
| `crawler` | T1595.002 | Vulnerability Scanning | 2 |
| `auth-tester` | T1078 | Valid Accounts | 2 |
| `idor-checker` | T1078.003 | Local Accounts | 2 |
| `injection-sim` | T1059 | Command and Scripting Interpreter | 2 |
| `hash-strength` | T1110.002 | Password Cracking | 2 |
| `exploit-verifier` | T1203 | Exploitation for Client Execution | 2 |
| `exploit-verifier` | T1190 | Exploit Public-Facing Application | 2 |
| `detection-coverage` | T1562.001 | Disable or Modify Tools | 4 |
| `alert-latency` | T1562.006 | Indicator Blocking | 4 |
| `ct-watch` | T1596.003 | Digital Certificates | 2 |
| `typosquat` | T1583.001 | Acquire Infrastructure: Domains | 2 |
| `protocol-fuzzer` | T1499 | Endpoint Denial of Service | — |
| `supply-chain` | T1195.002 | Supply Chain Compromise | — |

---

## Research Mode Rules

1. **Docker isolation required:** `docker == true` AND (`network_mode == none` OR private testbed)
2. **Lab marker:** `engagement_template.yaml` must specify `LAB_ONLY: true`
3. **External targeting blocked:** Orchestrator refuses external IP ranges
4. **Logging:** All entries include `RESEARCH_MODE: true`
5. **DESTRUCTIVE plugins:** Allowed ONLY in RESEARCH mode
6. **Evidence retention:** Auto-purge after 72h unless operator extends

```yaml
profiles:
  research:
    runtime_mode: research
    require_docker: true
    network_mode: none
    lab_only: true
    max_concurrent_plugins: 3
    evidence_retention_hours: 72
    destructive_allowed: true
    external_targets_blocked: true

  production:
    runtime_mode: production
    require_docker: false
    max_concurrent_plugins: 1
    destructive_allowed: false
    evidence_retention_hours: 8760

  ci:
    runtime_mode: ci
    require_docker: true
    max_concurrent_plugins: 1
    destructive_allowed: false
    active_allowed: false
```

---

## Key Constants

**File:** `redcheck/constants.py` — All values immutable. Config can be LOWER but never HIGHER.

```python
"""RedCheck246 — Immutable constants."""

# ── Rate Limits ──────────────────────────────────────────────────
HTTP_RPS_DEFAULT = 10;        HTTP_RPS_HARD_CAP = 50
TCP_CPS_DEFAULT = 5;          TCP_CPS_HARD_CAP = 20
PAYLOAD_BATCH_SIZE_DEFAULT = 50;  PAYLOAD_BATCH_SIZE_HARD = 200
OSINT_API_RATE_DEFAULT = 5;   OSINT_API_RATE_HARD = 20
MAX_CONCURRENT_PLUGINS_DEFAULT = 3;  MAX_CONCURRENT_PLUGINS_HARD = 10
MAX_CONCURRENT_TARGETS_DEFAULT = 3;  MAX_CONCURRENT_TARGETS_HARD = 10

# ── Timeouts ─────────────────────────────────────────────────────
PER_REQUEST_TIMEOUT_DEFAULT = 10;  PER_REQUEST_TIMEOUT_HARD = 30
PER_TARGET_TIMEOUT_DEFAULT = 60;   PER_TARGET_TIMEOUT_HARD = 120
GLOBAL_SCAN_TIMEOUT_DEFAULT = 300; GLOBAL_SCAN_TIMEOUT_HARD = 600

# ── Activation (Argon2id) ───────────────────────────────────────
ARGON2_TIME = 3;  ARGON2_MEMORY_KB = 65536
ARGON2_PARALLELISM = 4;  ARGON2_HASHLEN = 32
ACTIVATION_MAX_ATTEMPTS = 5;  ACTIVATION_LOCKOUT_SECONDS = 300;  ACTIVATION_COOLDOWN_SECONDS = 2

# ── Audit ────────────────────────────────────────────────────────
AUDIT_IV_BYTES = 12;  AUDIT_AAD = b"redcheck-audit-v1";  AUDIT_HASH_TRUNCATION = 16

# ── Packet Craft ─────────────────────────────────────────────────
PACKET_MAX_PAYLOAD_BYTES = 4096;  PACKET_MAX_REPEAT = 3;  PACKET_INTER_GAP_SECONDS = 1.0

# ── Evidence ─────────────────────────────────────────────────────
EVIDENCE_MAX_SAMPLE_BYTES = 256
EVIDENCE_RETENTION_HOURS_DEFAULT = 72;  EVIDENCE_RETENTION_HOURS_PRODUCTION = 8760

# ── OSINT Cache ──────────────────────────────────────────────────
OSINT_CACHE_TTL_SECONDS = 3600;  OSINT_CACHE_LRU_SIZE = 2000

# ── Typosquatting ────────────────────────────────────────────────
TYPOSQUAT_LEVENSHTEIN_THRESHOLD = 2

# ── Scope ────────────────────────────────────────────────────────
SCOPE_MAX_CIDR_EXPANSION = 256

# ── Crawler ──────────────────────────────────────────────────────
CRAWLER_MAX_PAGES_DEFAULT = 100;  CRAWLER_MAX_DEPTH_DEFAULT = 5

# ── Attack Graph ─────────────────────────────────────────────────
ATTACK_GRAPH_MAX_NODES = 1000;  ATTACK_GRAPH_MAX_EDGES = 5000

# ── Metrics ──────────────────────────────────────────────────────
METRICS_ROTATION_DAYS_DEFAULT = 1;  METRICS_TABLE_NAME = "metrics_ts"
```

---

## New File Structure (Complete)

```
redcheck/
├── constants.py                         # Phase 1
├── core/
│   ├── audit_export.py                  # Phase 5
│   ├── metrics.py                       # Phase 1
│   ├── multi_tenant.py                  # Phase 5
│   ├── rbac.py                          # Phase 5
│   ├── reporting.py                     # Phase 5
│   ├── scope_validator.py               # Phase 1
│   ├── sbom_integration.py              # Phase 5
│   ├── token_bucket.py                  # Phase 1
│   ├── topology.py                      # Phase 2
│   └── report_templates/               # Phase 5
├── plugins/
│   ├── crypto/                          # Phase 2
│   │   ├── hash_strength.py
│   │   ├── password_policy.py
│   │   └── gpu_adapter.py
│   ├── dast/                            # Phase 2 additions
│   │   ├── crawler.py
│   │   ├── auth_tester.py
│   │   ├── idor_checker.py
│   │   └── injection_sim.py
│   ├── detection/                       # Phase 4
│   │   ├── coverage_validator.py
│   │   └── latency_tester.py
│   ├── exploit/                         # Phase 2–3
│   │   ├── safe_poc.py
│   │   ├── cve_mapper.py
│   │   └── attack_graph.py
│   ├── osint/                           # Phase 2
│   │   ├── ct_watch.py
│   │   ├── typosquat.py
│   │   └── breach_lookup.py
│   └── recon/                           # Phase 2 additions
│       ├── network_scan.py
│       └── packet_craft.py
├── data/                                # Phase 2
│   ├── service_fingerprints.yaml
│   └── safe_poc_library.json
├── config/                              # Phase 1
│   └── runtime_profiles.yaml
└── templates/                           # Phase 5
    └── engagement_template.yaml
```

**Total: ~30 new files, 6 extended, 4 new plugin directories.**

---

## Risk Classification Matrix

| Severity | Trigger | Required Action | CI Gate |
|----------|---------|----------------|---------|
| **CRITICAL** | RCE PoC (non-simulated) | Abort, notify legal, forensic export | FAIL |
| **HIGH** | Active exploit PoC executed | Quarantine, manual review, isolation | MANUAL HOLD |
| **MEDIUM** | Misconfig enabling privesc | Report, remediation steps | PASS |
| **LOW** | Info leaks, missing headers | Auto-report | PASS |
| **INFO** | Observational telemetry | Summary inclusion | PASS |

---

## Risk & Mitigation

| Risk | Impact | Prob. | Mitigation |
|------|--------|:-----:|------------|
| Destructive exec in PRODUCTION | CRITICAL | LOW | Hard-disabled in matrix; Docker + signed confirm |
| Lost session code | HIGH | MED | UX warnings, metadata backup |
| Cross-tenant leakage | CRITICAL | LOW | Path prefixing + `0o700` + `TenantIsolationError` |
| Rate limit bypass | MEDIUM | LOW | `constants.py` hard caps + `field_validator` |
| Scope bypass via CIDR | HIGH | LOW | `expand_cidr()` capped at 256 |
| Destructive PoC in library | CRITICAL | VLOW | Manual curation + CI fixture verification |
| Stale OSINT cache | LOW | MED | TTL=1h, LRU=2000, force clear |

---

## Release Strategy

| Version | Scope | Phase | Status |
|---------|-------|:-----:|--------|
| v0.1.0 | Initial broken state | — | ❌ Deprecated |
| v0.2.0 | Scanning framework (157 tests) | — | ✅ Complete |
| v0.2.5 | Foundation engines | 1 | 🔄 Next |
| v0.3.0-rc1 | All scanners + exploit | 2 | 📋 Planned |
| v0.3.0-rc2 | Attack graph | 3 | 📋 Planned |
| v0.3.0-rc3 | Detection validation | 4 | 📋 Planned |
| **v0.3.0** | **Full resilience platform** | **5** | 📋 Planned |
| v1.0.0 | Commercial production | — | 📋 Future |

**Flow:** `dev → feature branches → dev → release/x.y → main + tag`

---

## Binding Specifications (Specs 22–37)

| Spec | Name | Enforced In | Phase |
|:----:|------|-------------|:-----:|
| 22 | Offensive Controls Gate | `orchestrator.py` Step 7 | 1 |
| 23 | Isolation Enforcement | `orchestrator.py` Step 8 | 1 |
| 24 | Token Bucket Rate Limiting | `token_bucket.py` + orchestrator | 1 |
| 25 | Scope Validation | `scope_validator.py` | 1 |
| 26 | RESEARCH Mode Isolation | `runtime_profiles.yaml` + orchestrator | 1 |
| 27 | Tenant Isolation | `multi_tenant.py` | 5 |
| 28 | RBAC Permission Matrix | `rbac.py` | 5 |
| 29 | Metrics Persistence | `metrics.py` | 1 |
| 30 | Evidence Provenance | `models.Evidence` | 1 |
| 31 | MITRE ATT&CK Mapping | `base_plugin.py` | 1 |
| 32 | Deterministic Reproducibility | All plugins (RNG seeds) | 2 |
| 33 | Safe PoC Library | `safe_poc_library.json` | 2 |
| 34 | Chain Mode Gate | `attack_graph.py` | 3 |
| 35 | Data Sampling Limit | `constants.EVIDENCE_MAX_SAMPLE_BYTES` | 1 |
| 36 | OSINT Rate Limiting | `osint/*.py` | 2 |
| 37 | Report Signing | `audit_export.py` | 5 |

---

## Estimated Effort Summary

| Phase | Name | Weeks | New Lines | New Files | New Tests | Cumulative |
|:-----:|------|:-----:|:---------:|:---------:|:---------:|:----------:|
| 1 | Foundation Engines | 1–3 | ~1,600 | 5 + 5 mod | ~100 | ~270 |
| 2 | Scanners & Exploit | 4–8 | ~3,100 | 18 + fixtures | ~130 | ~400 |
| 3 | Attack Graph | 9–10 | ~600 | 1 | ~20 | ~420 |
| 4 | Detection Validation | 11–12 | ~450 | 3 + fixtures | ~25 | ~450 |
| 5 | Commercial Readiness | 13–16 | ~1,350 | 10 + mod | ~67 | **~520** |
| **TOTAL** | | **16 weeks** | **~7,100** | **~37** | **~342** | **~520** |

---

**End of NEXT_PHASE_EXECUTION_PLAN.md v3.0**

*This document is the authoritative specification for RedCheck246 v0.2.5–v0.3.0. Each phase has explicit entry/exit criteria and every module has a measurable Definition of Done with quantitative metrics. No phase begins until its predecessor passes the phase gate. Implementation PRs must reference `SPEC-SECTION:X` tags.*

*Predecessor: EXECUTION_PLAN.md (Phases 1–16, Specs 1–21, commit `7a489ce`)*
*Continuation: 5 Phases (15 modules), Specs 22–37*
