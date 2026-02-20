# NEXT_PHASE_EXECUTION_PLAN.md — v2.0 (Enhanced)

**Created:** 2026-02-20 UTC
**Enhanced:** 2026-02-20 UTC
**Predecessor:** `EXECUTION_PLAN.md` (16 phases — ALL COMPLETE, commit `7a489ce`)
**Current Version:** RedCheck246 v0.2.0 → Target: v0.3.0 (Resilience Engine) → v1.0.0 (Production)
**Branch:** `next-phase/redcheck-resilience` (fork from `dev/redcheck-architecture-bootstrap-20260219-134306`)

---

## PURPOSE

Transition RedCheck246 from a **hardened scanning framework** (v0.2.0, 157/157 tests passing, 5 fully-implemented plugins) into a **controlled adversary simulation and resilience validation platform** that meets four deployment targets:

| Target | Label | Description |
|--------|-------|-------------|
| **A** | Enterprise deployment | Production-safe scanning with full RoE/activation gates |
| **B** | Research-grade experimentation | Isolated lab with RESEARCH mode, Docker sandbox |
| **C** | Private lab extensibility | Gated, isolated, operator-confirmed destructive testing |
| **D** | Commercial production readiness | Multi-tenant, RBAC, compliance reporting, SBOM |

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

| Model | Fields | Notes |
|-------|--------|-------|
| `RuntimeMode` (enum) | `DEV`, `CI`, `STAGING`, `PRODUCTION` | **Needs `RESEARCH` added** |
| `PluginCapability` (enum) | `PASSIVE`, `ACTIVE`, `DESTRUCTIVE` | ✅ Already matches plan |
| `FindingSeverity` (enum) | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` | ✅ Complete |
| `AuditLevel` (enum) | `INFO`, `WARNING`, `ERROR`, `CRITICAL`, `SECURITY` | ✅ Complete |
| `TargetSpec` | `host`, `ports`, `protocols`, `excluded_paths` | ✅ Reusable |
| `Finding` | `finding_type`, `target`, `severity`, `detail`, `cvss_score`, `cwe_id`, `remediation`, `metadata` | ✅ Extend (add `plugin`, `timestamp`, `evidence_digest`) |
| `Evidence` | `evidence_type`, `path`, `sha256`, `timestamp`, `encrypted`, `size_bytes` | ✅ Extend (add `provenance_tag`) |
| `PluginResult` (Pydantic) | `plugin_name`, `success`, `findings`, `evidence`, `errors`, `metadata`, `duration_ms`, `mode` | ✅ Complete |
| `EngagementContext` | `engagement_id`, `authorizer`, `targets`, `allowed_tests`, `start_time_utc`, `end_time_utc`, `sensitivity`, `roe_path`, `roe_signed`, `activation_verified`, `session_code` | **Needs extension** |
| `RoEDocument` | `engagement_id`, `authorizer`, `authorized_targets`, `allowed_tests`, `start_time_utc`, `end_time_utc`, `sensitivity`, `signature` | ✅ Complete |
| `AuditEntry` | `timestamp`, `level`, `action`, `details`, `operator`, `plugin`, `engagement_id`, `previous_hash`, `hash` | ✅ Complete |
| `ScanReport` | `engagement_id`, `scanner`, `start_time`, `end_time`, `findings`, `summary`, `metadata` | ✅ Complete |

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
tenant_id: str | None = None                                      # Multi-tenant isolation
offensive_controls: OffensiveControls = Field(default_factory=OffensiveControls)
safe_mode: bool = True                                            # Master safety switch
runtime_mode: RuntimeMode = RuntimeMode.DEV                       # Current runtime mode
session_id: str | None = None                                     # Unique session identifier
```

**Migration note:** The existing orchestrator.py has its own dataclass `EngagementContext`. This MUST be eliminated — the Pydantic model in `models.py` becomes the single source of truth. The orchestrator's `EngagementContext.from_roe()` / `from_yaml()` methods merge into the Pydantic model's `from_roe_yaml()`.

### 2.4 PluginMetadata Model (NEW)

**File:** `redcheck/models.py` — Add after `OffensiveControls`.

```python
class PluginMetadata(BaseModel):
    """Declarative metadata attached to each plugin class.

    Used by the orchestrator to enforce pre-execution checks.
    """
    model_config = ConfigDict(frozen=True)

    name: str
    capability: PluginCapability
    required_controls: list[str] = Field(default_factory=list)  # OffensiveControls field names
    timeout_seconds: int = Field(default=60, ge=1, le=600)
    rate_limit_rps: int = Field(default=10, ge=1, le=50)
    mitre_techniques: list[str] = Field(default_factory=list)   # e.g. ["T1046", "T1595.002"]
    requires_isolation: bool = False                            # Docker sandbox required
```

### 2.5 Finding Extension

Add to existing `Finding` model in `redcheck/models.py`:

```python
# NEW fields:
plugin: str | None = None                         # Source plugin name
timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
evidence_digest: str | None = None                 # SHA-256 of evidence artifact
sampled_data_len: int | None = None                # Bytes of sampled data (max 256)
mitre_technique: str | None = None                 # MITRE ATT&CK technique ID
```

### 2.6 Evidence Extension

Add to existing `Evidence` model in `redcheck/models.py`:

```python
# NEW field:
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

## SECTION 3 — FULL MODULE BREAKDOWN (7 MODULES)

### Module 1: Network & Infrastructure Discovery Layer

**New Files:**
- `redcheck/plugins/recon/network_scan.py` — `NetworkScanner` plugin
- `redcheck/plugins/recon/packet_craft.py` — `PacketCraft` bounded sender
- `redcheck/core/topology.py` — `TopologyEngine` graph inference
- `redcheck/data/service_fingerprints.yaml` — canonical fingerprint database

**Extends:**
- `redcheck/plugins/recon/passive_recon.py` (existing) — add network topology hooks

**Class: `NetworkScanner(BasePlugin)`**
```
name = "network-scanner"
capability = PluginCapability.ACTIVE
required_controls = ["allow_auth_testing"]
timeout_seconds = 120
rate_limit_rps = 10
mitre_techniques = ["T1046", "T1595.001"]
```

**Deterministic Logic:**
1. `scan_targets(engagement_context, targets)`:
   - Validate scope via `ScopeValidator.validate_targets(targets, context.targets)`
   - Schedule rate-limited tasks: `TokenBucket(rate=config.max_requests_per_second, burst=min(rate*2, 50))`
   - Concurrency: `asyncio.Semaphore(config.max_concurrent_plugins)`
   - Execute `tcp_syn_probe(host, port)`: open socket with `SO_RCVTIMEO=config.request_timeout_seconds`, send SYN only, wait SYN/ACK or RST; NEVER complete TCP handshake
   - Log every attempt to `AuditLogger` with `connection_attempt` event (encrypted)

2. `ServiceVersionDetector.detect(host, port)`:
   - Deterministic signature scoring against `service_fingerprints.yaml`
   - Exact string match → confidence 1.0; Levenshtein ≤ 2 → confidence 0.7; else `unknown`

3. `OSFingerprint.heuristic_identify(host)`:
   - Read-only heuristics: TTL, TCP window size, known service banners
   - Returns `os_confidence` in [0.0, 1.0]

4. `TopologyEngine.infer(graph_inputs)`:
   - Union-find clustering by responding hosts
   - Reverse-DNS mapping + traceroute-derived hop sets
   - No discovery beyond RoE subnets — enforced by `ScopeValidator`

5. `PacketCraft.bound_send(packet_spec)`:
   - Hard bounds: `max_payload=4096 bytes`, `max_repeat=3`, `inter_packet_gap=1.0s`
   - NO malformed flood attacks — enforced at construction time

**Failure Modes:** socket timeout → mark target `degraded`; service mismatch → return `unknown` with `reason` field.

**Tests:** per-target deterministic fixtures with mocked socket responses, histogram of latency metrics, unit tests for TokenBucket.

**New dependency:** `scapy>=2.5` (packet crafting, optional — graceful fallback to raw sockets)

---

### Module 2: Web Application Resilience Layer

**New Files:**
- `redcheck/plugins/dast/crawler.py` — `AdvancedCrawler` BFS engine
- `redcheck/plugins/dast/auth_tester.py` — `AuthenticatedSessionTester`
- `redcheck/plugins/dast/idor_checker.py` — `IDORValidator`
- `redcheck/plugins/dast/injection_sim.py` — `InjectionProofOfCondition`

**Extends:**
- `redcheck/plugins/dast/dast_scanner.py` (existing) — integrate with new crawler

**Deterministic Logic:**
1. `AdvancedCrawler.crawl(seed_urls, max_pages=100, max_depth=5)`:
   - BFS with URL frontier, depth tracking, `max_pages` + `max_depth` bounds
   - Obey `robots.txt` unless RoE explicitly allows bypass
   - Rate-limited via `TokenBucket(rate=config.max_requests_per_second)`

2. `AuthenticatedSessionTester.test(session_spec)`:
   - Uses credential store from RoE ONLY — no auto-login attempts
   - Gated by `OffensiveControls.allow_auth_testing == True`
   - Tests: session fixation, cookie attributes, CSRF token rotation

3. `IDORValidator.check(path_template, allowed_ids)`:
   - Generate deterministic test permutations from fixed RNG seed + RoE-provided allowed IDs
   - Never enumerate beyond allowed scope
   - Returns `is_vulnerable: bool` + `evidence_ref`

4. `InjectionProofOfCondition.run()`:
   - Safe PoC ONLY: timing-based (`SLEEP(5)` oracle), canary write to ephemeral namespace
   - Canary path: `/tmp/redcheck_canary_<engagement_id>` (auto-cleaned on teardown)
   - Requires `OffensiveControls.allow_exploit_validation == True`
   - Requires `--confirm-exploit` CLI flag OR API confirmation token
   - No data exfiltration beyond 256 bytes (gated by `allow_data_sampling`)
   - All PoC runs require `ActivationEngine.verify()` re-check

**Tests:** synthetic webapp fixture (containerized at `tests/integration/containers/webapp_fixture/`) with deterministic responses.

---

### Module 3: Credential & Cryptographic Resilience

**New Files:**
- `redcheck/plugins/crypto/__init__.py`
- `redcheck/plugins/crypto/hash_strength.py` — `OfflineHashStrengthAnalyzer`
- `redcheck/plugins/crypto/password_policy.py` — `PasswordEntropyScorer`
- `redcheck/plugins/crypto/gpu_adapter.py` — `GPUAdapter` (simulation mode for CI)

**Class: `OfflineHashStrengthAnalyzer(BasePlugin)`**
```
name = "hash-strength-analyzer"
capability = PluginCapability.ACTIVE
required_controls = ["allow_credential_spraying"]
timeout_seconds = 300
rate_limit_rps = 5
mitre_techniques = ["T1110.002"]
```

**Deterministic Logic:**
1. `analyze(hash_dump, algo_hint=None)`:
   - Entropy estimate via Shannon formula
   - Probabilistic crackability score against NIST cracking curves
   - Fixed GPU-speed reference table (SHA-256: 10B/s, bcrypt-12: 50K/s, Argon2id-t3: 5K/s)
   - Returns `crackability_score` in [0.0, 1.0] + `estimated_crack_time_seconds`

2. `PasswordEntropyScorer.score(password)`:
   - Returns 0–100 using deterministic rules: charset size × length, pattern penalties (keyboard walks, dictionary words, repeated chars)
   - No external API calls

3. `GPUAdapter`:
   - `simulate_mode=True` (default in CI): uses reference table instead of real GPU
   - Real GPU gated by `ActivationEngine` + `allow_privesc_probing`

**Hard Rule:** No brute-force execution without `allow_credential_spraying=True` AND user confirmation.

**Tests:** sample hash sets with known crackability scores, mocked GPU backend.

---

### Module 4: Exploit Verification & Safe Simulation Layer

**New Files:**
- `redcheck/plugins/exploit/__init__.py`
- `redcheck/plugins/exploit/safe_poc.py` — `ExploitVerifier`
- `redcheck/plugins/exploit/cve_mapper.py` — CVE-to-service deterministic mapper
- `redcheck/plugins/exploit/attack_graph.py` — `AttackPathGraph`
- `redcheck/data/safe_poc_library.json` — curated non-destructive PoC catalog

**Class: `ExploitVerifier(BasePlugin)`**
```
name = "exploit-verifier"
capability = PluginCapability.DESTRUCTIVE
required_controls = ["allow_exploit_validation"]
requires_isolation = True
timeout_seconds = 120
rate_limit_rps = 2
mitre_techniques = ["T1203", "T1190"]
```

**Deterministic Logic:**
1. `verify(cve_id, target)`:
   - Map CVE → service using deterministic `CVE-to-service` rules in `cve_mapper.py`
   - Select PoC from curated `safe_poc_library.json` (non-destructive only)
   - PoC execution via `ExecutionPolicy` checks + strict timeouts
   - Returns `verified: bool`, `proof_of_condition: str`, `confidence: float`

2. `AttackPathGraph`:
   - Nodes: `Asset(id, host, role)` — from engagement targets
   - Edges: `ExploitAttempt(proof_of_condition, success_probability)`
   - Most-likely path: Dijkstra on `-log(prob)` — deterministic
   - **No automatic chaining** unless `OffensiveControls.chain_mode == True` AND `allow_exploit_validation == True`
   - Graph algorithms use fixed RNG seeds for reproducibility

**Tests:** static graph unit tests with fixed seeds; PoC verification against mock targets.

**New dependency:** `networkx>=3.0` (attack graph analysis)

---

### Module 5: Detection & Defensive Coverage Validation

**New Files:**
- `redcheck/plugins/detection/__init__.py`
- `redcheck/plugins/detection/coverage_validator.py` — `DetectionCoverageValidator`
- `redcheck/plugins/detection/latency_tester.py` — `AlertLatencyTester`

**Class: `DetectionCoverageValidator(BasePlugin)`**
```
name = "detection-coverage"
capability = PluginCapability.ACTIVE
required_controls = ["allow_auth_testing"]
timeout_seconds = 180
rate_limit_rps = 5
mitre_techniques = ["T1562.001"]
```

**Deterministic Logic:**
1. `run(targets)`:
   - Generate deterministic traffic patterns at fixed seed rates and permutations
   - Purpose: validate whether detection tools generate alerts — NOT evasion
   - Map coverage results to MITRE ATT&CK techniques (see Section 11)
   - Returns `coverage_percentage: float`, `uncovered_techniques: list[str]`

2. `AlertLatencyTester.measure()`:
   - Inject timestamp marker → wait for alert TTL (bounded to `5 × expected_latency`)
   - Compute `alert_latency_ms` from injection to alert receipt
   - Returns `latency_ms: float`, `within_sla: bool`

**Hard Rule:** No evasion techniques (payload morphing, encoding bypass) are implemented.

**Tests:** containerized SIEM simulator fixture with deterministic alert generation.

---

### Module 6: OSINT & Passive Intelligence

**New Files:**
- `redcheck/plugins/osint/__init__.py`
- `redcheck/plugins/osint/ct_watch.py` — Certificate Transparency monitor
- `redcheck/plugins/osint/typosquat.py` — Typosquatting detector
- `redcheck/plugins/osint/breach_lookup.py` — Breach database correlator

**All OSINT plugins:**
```
capability = PluginCapability.PASSIVE
required_controls = []  # No offensive controls needed — passive only
timeout_seconds = 60
rate_limit_rps = 5
```

**Deterministic Logic:**
1. Passive-only collection using public APIs
2. Client-side rate limit: `OSINT_API_RATE = 5 rps` (default), enforced by `TokenBucket`
3. Response caching: LRU size=2000, TTL=1h (deterministic eviction)
4. Typosquatting: Damerau-Levenshtein distance threshold=2, TLD permutation rules
5. CT Watch: query crt.sh API, parse certificate entries, flag suspicious issuances
6. Breach Lookup: correlate domain against known breach datasets (local DB only)

**Hard Rule:** No aggressive scraping. All external calls rate-limited and batched.

**Tests:** mocked API responses with deterministic fixtures.

---

### Module 7: Governance & Commercial Readiness

**New Files:**
- `redcheck/core/multi_tenant.py` — `TenantIsolation` manager
- `redcheck/core/rbac.py` — `RBAC` role-based access control
- `redcheck/core/audit_export.py` — signed evidence export
- `redcheck/core/reporting.py` — templated report generation
- `redcheck/core/sbom_integration.py` — SBOM correlation
- `redcheck/core/report_templates/executive_summary.j2`
- `redcheck/core/report_templates/technical_detail.j2`

**Multi-Tenant Isolation:**
```python
class TenantIsolation:
    """Enforce tenant boundaries on all operations."""

    def evidence_path(self, tenant_id: str, engagement_id: str) -> Path:
        """Returns /engagements/{tenant_id}/{engagement_id}/ with 0o700 perms."""

    def validate_access(self, operator: Operator, tenant_id: str) -> bool:
        """Cross-tenant access raises TenantIsolationError."""
```

**RBAC Permission Matrix:**

| Role | Action | Allowed |
|------|--------|---------|
| `VIEWER` | Read reports, view findings | ✅ |
| `OPERATOR` | Run PASSIVE plugins, view all | ✅ |
| `SENIOR_OPERATOR` | Run ACTIVE plugins, manage engagements | ✅ |
| `ADMIN` | Run DESTRUCTIVE (with confirm), manage tenants/users | ✅ |
| `AUDITOR` | Read audit logs, export evidence | ✅ |

```python
class OperatorRole(str, enum.Enum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    SENIOR_OPERATOR = "senior_operator"
    ADMIN = "admin"
    AUDITOR = "auditor"
```

**Evidence Export:**
- Sign artifacts using Ed25519 (existing `security/signature_verifier.py`)
- Manifest includes SHA-256 digests of all evidence files
- Export formats: `report.json` (machine), `report.pdf` (Jinja2 → weasyprint), `sbom.json`

**New dependencies:** `jinja2>=3.1`, `weasyprint>=60.0` (optional, for PDF reports)

---

## SECTION 4 — FILE STRUCTURE (NEW + EXISTING)

```
redcheck/
├── __init__.py                          # EXISTING
├── __main__.py                          # EXISTING
├── cli.py                               # EXISTING → extend with new commands
├── config.py                            # EXISTING → extend (Section 5)
├── constants.py                         # NEW — all hard-coded constants (Section 15)
├── exceptions.py                        # EXISTING → extend (Section 2.7)
├── logging.py                           # EXISTING
├── models.py                            # EXISTING → extend (Sections 2.1–2.6)
├── output.py                            # EXISTING
├── py.typed                             # EXISTING
├── core/
│   ├── __init__.py                      # EXISTING
│   ├── activation_engine.py             # EXISTING
│   ├── audit.py                         # EXISTING
│   ├── audit_export.py                  # NEW — signed evidence export
│   ├── metrics.py                       # NEW — SQLite metrics collector
│   ├── multi_tenant.py                  # NEW — tenant isolation
│   ├── orchestrator.py                  # EXISTING → refactor (unify EngagementContext)
│   ├── policy_engine.py                 # EXISTING → extend (capability matrix)
│   ├── rbac.py                          # NEW — role-based access control
│   ├── reporting.py                     # NEW — templated reports
│   ├── scope_validator.py               # NEW — target scope enforcement
│   ├── sbom_integration.py              # NEW — SBOM correlation
│   ├── token_bucket.py                  # NEW — generic rate limiter
│   ├── topology.py                      # NEW — network topology inference
│   └── report_templates/
│       ├── executive_summary.j2         # NEW
│       └── technical_detail.j2          # NEW
├── plugins/
│   ├── __init__.py                      # EXISTING
│   ├── base_plugin.py                   # EXISTING → extend (Section 6)
│   ├── dast/                            # EXISTING → add new files
│   │   ├── __init__.py                  # EXISTING
│   │   ├── dast_scanner.py              # EXISTING
│   │   ├── wordlists.py                 # EXISTING
│   │   ├── crawler.py                   # NEW
│   │   ├── auth_tester.py               # NEW
│   │   ├── idor_checker.py              # NEW
│   │   └── injection_sim.py             # NEW
│   ├── fuzzing/                         # EXISTING (no changes)
│   ├── recon/                           # EXISTING → add new files
│   │   ├── __init__.py                  # EXISTING
│   │   ├── passive_recon.py             # EXISTING
│   │   ├── wordlists.py                 # EXISTING
│   │   ├── network_scan.py              # NEW
│   │   └── packet_craft.py              # NEW
│   ├── sast/                            # EXISTING (no changes)
│   ├── supply_chain/                    # EXISTING (no changes)
│   ├── crypto/                          # NEW directory
│   │   ├── __init__.py
│   │   ├── hash_strength.py
│   │   ├── password_policy.py
│   │   └── gpu_adapter.py
│   ├── exploit/                         # NEW directory
│   │   ├── __init__.py
│   │   ├── safe_poc.py
│   │   ├── cve_mapper.py
│   │   └── attack_graph.py
│   ├── detection/                       # NEW directory
│   │   ├── __init__.py
│   │   ├── coverage_validator.py
│   │   └── latency_tester.py
│   └── osint/                           # NEW directory
│       ├── __init__.py
│       ├── ct_watch.py
│       ├── typosquat.py
│       └── breach_lookup.py
├── security/                            # EXISTING (no changes)
├── data/                                # NEW directory
│   ├── service_fingerprints.yaml
│   └── safe_poc_library.json
├── config/                              # NEW directory
│   └── runtime_profiles.yaml
└── templates/                           # NEW directory
    └── engagement_template.yaml
```

**Summary:** 30 new files, 6 files to extend, 4 new directories under `plugins/`, 3 new directories under root.

---

## SECTION 5 — CONFIG EXTENSIONS (redcheck/config.py)

Add to existing `RedCheckConfig(BaseSettings)`:

```python
# TCP rate limits (NEW)
tcp_connections_per_second: int = Field(default=5, ge=1, le=20)

# Per-target limits (NEW)
max_concurrent_targets: int = Field(default=3, ge=1, le=10)
per_target_timeout_seconds: int = Field(default=60, ge=1, le=120)

# Payload limits (NEW)
payload_batch_size: int = Field(default=50, ge=1, le=200)

# OSINT rate limit (NEW)
osint_api_rate_rps: int = Field(default=5, ge=1, le=20)

# Metrics (NEW)
metrics_db_path: Path | None = None
metrics_rotation_days: int = Field(default=1, ge=1, le=30)

# Multi-tenant (NEW)
multi_tenant_enabled: bool = False
default_tenant_id: str = "default"
```

---

## SECTION 6 — BASE PLUGIN EXTENSIONS (redcheck/plugins/base_plugin.py)

Add to existing `BasePlugin` ABC:

```python
class BasePlugin(ABC):
    # ... existing attrs ...

    # NEW class-level attributes
    required_controls: list[str] = []           # OffensiveControls field names
    timeout_seconds: int = 60                   # Per-execution timeout
    rate_limit_rps: int = 10                    # Plugin-level rate limit
    mitre_techniques: list[str] = []            # MITRE ATT&CK technique IDs
    requires_isolation: bool = False            # Requires Docker sandbox

    # NEW async execution method
    async def aexecute(self, context: dict[str, Any]) -> PluginResult:
        """Async execution — default delegates to sync execute()."""
        return self.execute(context)
```

---

## SECTION 7 — CAPABILITY ENFORCEMENT MATRIX

**Entry point:** `Orchestrator.run_plugin(plugin_name, context, dry_run=False)`

**11-step enforcement sequence (hard-coded, ordered):**

| Step | Check | Failure → Exception | Existing? |
|------|-------|---------------------|-----------|
| 1 | Resolve plugin in `PluginRegistry` | `PluginNotFoundError` | ✅ |
| 2 | Validate `EngagementContext` (Pydantic strict) | `ContextValidationError` | ✅ |
| 3 | Check engagement time window | `PolicyDeniedException` | ✅ |
| 4 | Verify RoE signature: `RoEVerifier.verify(roe_path)` | `RoEValidationError` | ✅ |
| 5 | Verify activation code: `ActivationEngine.verify(code)` | `ActivationError` | ✅ |
| 6 | Check `RuntimeMode` × `PluginCapability` matrix | `PolicyDeniedException` | ✅ (extend) |
| 7 | Check `OffensiveControls.has_controls(plugin.required_controls)` | `OffensiveControlError` | ❌ NEW |
| 8 | Confirm isolation for DESTRUCTIVE plugins | `IsolationError` | ❌ NEW |
| 9 | Enforce rate limits + concurrency via `TokenBucket` + `Semaphore` | `RateLimitExceeded` | ❌ NEW |
| 10 | If `dry_run`: log + return simulated `PluginResult` | — | ✅ |
| 11 | Execute: `asyncio.wait_for(plugin.aexecute(...), timeout)` | `ScanTimeoutError` | ✅ |

**Capability × RuntimeMode Matrix (hard-coded, deterministic):**

| RuntimeMode | PASSIVE | ACTIVE | DESTRUCTIVE |
|-------------|:-------:|:------:|:-----------:|
| `DEV` | ✅ | ✅ (dry-run only) | ❌ |
| `CI` | ✅ | ❌ | ❌ |
| `STAGING` | ✅ | ✅ | ❌ |
| `PRODUCTION` | ✅ | ✅ | ❌ (hard-disabled) |
| `RESEARCH` | ✅ | ✅ | ✅ (with isolation + confirm) |

**Capability Gate Requirements:**

| Gate | PASSIVE | ACTIVE | DESTRUCTIVE |
|------|:-------:|:------:|:-----------:|
| Requires `EngagementContext` | YES | YES | YES |
| Requires signed RoE | NO | YES | YES |
| Requires activation code | NO | YES | YES |
| Requires `allowed_tests` match | NO | YES | YES |
| Requires offensive control flags | NO | YES (per-plugin) | YES (per-plugin + confirm) |
| Requires explicit `--confirm` | NO | NO | YES |
| Requires Docker isolation | NO | NO | YES |
| Global rate-limit enforced | NO | YES | YES |

---

## SECTION 8 — ORCHESTRATOR REFACTOR

### 8.1 Unify EngagementContext

The current orchestrator (`core/orchestrator.py`) defines its own dataclass `EngagementContext` (line 24–74) which duplicates the Pydantic model in `models.py`. **This must be eliminated.**

**Migration steps:**
1. Delete the dataclass `EngagementContext` from `orchestrator.py`
2. Import `from redcheck.models import EngagementContext` instead
3. Adapt `from_roe()` / `from_yaml()` to use the Pydantic model's `from_roe_yaml()`
4. Update `to_dict()` calls → `model_dump()`
5. Update all test files that import from `orchestrator`

### 8.2 Async Orchestrator

Add `async def arun_plugin()` to the Orchestrator for async plugin execution:

```python
async def arun_plugin(
    self,
    plugin_name: str,
    dry_run: bool = False,
    extra_context: dict[str, Any] | None = None,
) -> PluginResult:
    """Async plugin execution with timeout enforcement."""
    # Steps 1-9 from enforcement sequence
    # Step 10: dry_run shortcut
    # Step 11:
    import asyncio
    return await asyncio.wait_for(
        plugin.aexecute(context),
        timeout=plugin.timeout_seconds,
    )
```

### 8.3 Concurrency Model

```
Global Orchestrator
├── plugin_semaphore: asyncio.Semaphore(max_concurrent_plugins)  # default=3, cap=10
│   └── Per-plugin execution slot
│       ├── token_bucket: TokenBucket(rate=plugin.rate_limit_rps)
│       └── target_semaphore: asyncio.Semaphore(min(4, max_concurrent_plugins))
│           └── Per-target connection slot
```

**TokenBucket implementation** (`redcheck/core/token_bucket.py`):
```python
class TokenBucket:
    """Thread-safe token bucket rate limiter with async support."""
    def __init__(self, rate: float, burst: int | None = None):
        self.rate = rate
        self.burst = burst or int(rate * 2)
        self._tokens = float(self.burst)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: int = 1) -> None:
        """Acquire tokens, blocking if necessary."""

    def try_acquire(self, tokens: int = 1) -> bool:
        """Non-blocking acquire attempt."""
```

---

## SECTION 9 — SCOPE VALIDATOR (NEW)

**File:** `redcheck/core/scope_validator.py`

```python
class ScopeValidator:
    """Enforce target scope boundaries defined in RoE.

    All scan targets must be explicitly listed in EngagementContext.targets.
    Wildcard/CIDR expansion is deterministic and bounded.
    """

    @staticmethod
    def validate_targets(
        requested: list[str],
        authorized: list[str],
    ) -> tuple[bool, list[str]]:
        """Returns (all_valid, list_of_violations).

        Checks:
        1. Exact hostname match
        2. CIDR subnet containment (IPv4/IPv6)
        3. Wildcard subdomain match (*.example.com)
        4. Port range validation
        """

    @staticmethod
    def expand_cidr(cidr: str, max_hosts: int = 256) -> list[str]:
        """Deterministic CIDR expansion with hard cap."""
```

**Hard rule:** Any target not in the authorized list raises `ScopeViolationError` (existing exception).

---

## SECTION 10 — METRICS & OBSERVABILITY

**File:** `redcheck/core/metrics.py`

```python
class MetricsCollector:
    """Persist metrics to local SQLite with atomic writes.

    Schema (table: metrics_ts):
        name TEXT NOT NULL,
        value REAL NOT NULL,
        tags JSON,
        ts_utc TIMESTAMP DEFAULT CURRENT_TIMESTAMP

    Rotation: daily (configurable via config.metrics_rotation_days).
    """

    def __init__(self, db_path: Path):
        ...

    def record(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:
        """Atomic write of a single metric."""

    def flush_summary(self, output_path: Path) -> None:
        """Export aggregated metrics to metrics_summary.json with signed manifest."""

    def rotate(self) -> None:
        """Archive and create new daily metrics DB."""
```

**Standard metric names:**
- `plugin.execution_time_ms` — per-plugin execution duration
- `plugin.findings_count` — findings per execution
- `plugin.error_rate` — failure rate (0.0–1.0)
- `scan.targets_scanned` — total targets in engagement
- `scan.scope_violations` — attempted out-of-scope accesses
- `rate_limit.throttle_count` — rate limit enforcements
- `audit.entries_written` — audit log entries per session

---

## SECTION 11 — MITRE ATT&CK MAPPING

Each new plugin maps to specific MITRE ATT&CK techniques for detection coverage validation:

| Plugin | MITRE Technique | Technique Name |
|--------|----------------|----------------|
| `network-scanner` | T1046 | Network Service Discovery |
| `network-scanner` | T1595.001 | Active Scanning: Scanning IP Blocks |
| `passive-recon` (existing) | T1596 | Search Open Technical Databases |
| `passive-recon` (existing) | T1593 | Search Open Websites/Domains |
| `dast-scanner` (existing) | T1190 | Exploit Public-Facing Application |
| `crawler` | T1595.002 | Active Scanning: Vulnerability Scanning |
| `auth-tester` | T1078 | Valid Accounts |
| `idor-checker` | T1078.003 | Valid Accounts: Local Accounts |
| `injection-sim` | T1059 | Command and Scripting Interpreter |
| `hash-strength-analyzer` | T1110.002 | Brute Force: Password Cracking |
| `exploit-verifier` | T1203 | Exploitation for Client Execution |
| `exploit-verifier` | T1190 | Exploit Public-Facing Application |
| `detection-coverage` | T1562.001 | Impair Defenses: Disable or Modify Tools |
| `alert-latency` | T1562.006 | Impair Defenses: Indicator Blocking |
| `ct-watch` | T1596.003 | Search Open Technical Databases: Digital Certificates |
| `typosquat-detector` | T1583.001 | Acquire Infrastructure: Domains |
| `protocol-fuzzer` (existing) | T1499 | Endpoint Denial of Service |
| `supply-chain-audit` (existing) | T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain |

---

## SECTION 12 — RESEARCH MODE RULES

`RuntimeMode.RESEARCH` specifics (enforced in `runtime_profiles.yaml` AND code):

1. **Docker isolation required:** `docker == true` AND (`network_mode == none` OR custom internal-only network mapped to private testbed)
2. **Lab marker:** `engagement_template.yaml` must specify `LAB_ONLY: true`
3. **External targeting blocked:** Orchestrator refuses external IP ranges when `runtime_mode == RESEARCH`
4. **Logging:** All log entries include `RESEARCH_MODE: true` and `lab_evidence: true`
5. **DESTRUCTIVE plugins:** Allowed ONLY in RESEARCH mode (see Capability Matrix, Section 7)
6. **Evidence retention:** Auto-purge after 72h unless operator explicitly extends

**runtime_profiles.yaml:**
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
    evidence_retention_hours: 8760  # 1 year

  ci:
    runtime_mode: ci
    require_docker: true
    max_concurrent_plugins: 1
    destructive_allowed: false
    active_allowed: false
```

---

## SECTION 13 — CI/CD EXPANSION

### 13.1 Current CI State

No `.github/workflows/` directory exists yet. This plan creates it.

### 13.2 GitHub Actions Matrix

**File:** `.github/workflows/ci.yml`

```yaml
jobs:
  lint:
    # ruff check, mypy --strict, pre-commit hooks
    # Fail on warnings
  unit-test:
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12"]
    # pytest --maxfail=1 --durations=10
    # Coverage: ≥90% total, ≥80% branch
  integration-test:
    # Docker-based RESEARCH sandbox
    # Runs containerized fixtures (webapp, SIEM, network)
    # Must pass before build
    needs: [lint, unit-test]
  build:
    # python -m build (wheel + sdist)
    # pip install verification in ephemeral venv
    needs: [integration-test]
  security-scan:
    # bandit, safety check, gitleaks
    # Fail on CRITICAL or HIGH findings
    needs: [lint]
```

### 13.3 Protected Branch Rules

- `main` protected: require `lint`, `unit-test`, `integration-test`, `security-scan` to pass
- Require code owners review
- Require signed commits for release tags

---

## SECTION 14 — TEST PLAN

### 14.1 Coverage Targets

| Category | Target | Scope |
|----------|--------|-------|
| Unit tests | ≥92% line, ≥80% branch | All models, policy, activation, orchestrator, plugins |
| Integration tests | 100% of plugin categories | Containerized in RESEARCH sandbox |
| Mutation tests | ≥80% mutant kill rate | `policy_engine.py`, `orchestrator.py`, `scope_validator.py` |
| Fuzz tests | All HTTP input paths | Detection-only payloads, no destructive behavior |
| Performance | 100-port scan < 120s | On CI fixture under default rate limits |

### 14.2 Test Structure

```
tests/
├── conftest.py                           # EXISTING → extend fixtures
├── unit/                                 # NEW directory
│   ├── test_offensive_controls.py
│   ├── test_plugin_metadata.py
│   ├── test_scope_validator.py
│   ├── test_token_bucket.py
│   ├── test_rbac.py
│   ├── test_multi_tenant.py
│   ├── test_metrics.py
│   ├── test_capability_matrix.py
│   └── test_attack_graph.py
├── integration/                          # NEW directory
│   ├── test_network_scan_integration.py
│   ├── test_dast_integration.py
│   ├── test_exploit_integration.py
│   ├── test_detection_integration.py
│   └── containers/
│       ├── webapp_fixture/
│       │   ├── Dockerfile
│       │   └── app.py                    # Deterministic Flask/FastAPI test server
│       ├── siem_fixture/
│       │   ├── Dockerfile
│       │   └── alert_server.py           # Mock SIEM alert endpoint
│       └── network_fixture/
│           ├── Dockerfile
│           └── tcp_responder.py          # Mock TCP service for recon tests
├── fixtures/                             # NEW directory
│   ├── rng_seeds.json                    # Fixed RNG seeds for reproducibility
│   ├── network_responses.json            # Mocked socket responses
│   ├── poc_test_vectors.json             # PoC verification test vectors
│   └── hash_samples.json                 # Known hash crackability samples
└── # ... existing 16 test files remain ...
```

### 14.3 Docker Compose for Integration Tests

```yaml
# docker-compose.test.yml
services:
  webapp-fixture:
    build: tests/integration/containers/webapp_fixture/
    ports: ["8888:8888"]
    networks: [redcheck-test]

  siem-fixture:
    build: tests/integration/containers/siem_fixture/
    ports: ["9999:9999"]
    networks: [redcheck-test]

  network-fixture:
    build: tests/integration/containers/network_fixture/
    ports: ["7777:7777"]
    networks: [redcheck-test]

networks:
  redcheck-test:
    driver: bridge
    internal: true  # No external access
```

---

## SECTION 15 — KEY CONSTANTS (COPY INTO redcheck/constants.py VERBATIM)

```python
"""RedCheck246 — Immutable constants.

All values in this file are hard-coded and CANNOT be overridden by config.
Config values can be LOWER than these but never HIGHER.
"""

# ── Rate Limits ──────────────────────────────────────────────────
HTTP_RPS_DEFAULT = 10
HTTP_RPS_HARD_CAP = 50
TCP_CPS_DEFAULT = 5
TCP_CPS_HARD_CAP = 20
MAX_CONCURRENT_TARGETS_DEFAULT = 3
MAX_CONCURRENT_TARGETS_HARD = 10
PAYLOAD_BATCH_SIZE_DEFAULT = 50
PAYLOAD_BATCH_SIZE_HARD = 200
OSINT_API_RATE_DEFAULT = 5
OSINT_API_RATE_HARD = 20
MAX_CONCURRENT_PLUGINS_DEFAULT = 3
MAX_CONCURRENT_PLUGINS_HARD = 10

# ── Timeouts ─────────────────────────────────────────────────────
PER_REQUEST_TIMEOUT_DEFAULT = 10
PER_REQUEST_TIMEOUT_HARD = 30
PER_TARGET_TIMEOUT_DEFAULT = 60
PER_TARGET_TIMEOUT_HARD = 120
GLOBAL_SCAN_TIMEOUT_DEFAULT = 300
GLOBAL_SCAN_TIMEOUT_HARD = 600

# ── Activation (Argon2id) ───────────────────────────────────────
ARGON2_TIME = 3
ARGON2_MEMORY_KB = 65536
ARGON2_PARALLELISM = 4
ARGON2_HASHLEN = 32
ACTIVATION_MAX_ATTEMPTS = 5
ACTIVATION_LOCKOUT_SECONDS = 300
ACTIVATION_COOLDOWN_SECONDS = 2

# ── Audit ────────────────────────────────────────────────────────
AUDIT_IV_BYTES = 12
AUDIT_AAD = b"redcheck-audit-v1"
AUDIT_HASH_TRUNCATION = 16  # hex chars

# ── Packet Craft ─────────────────────────────────────────────────
PACKET_MAX_PAYLOAD_BYTES = 4096
PACKET_MAX_REPEAT = 3
PACKET_INTER_GAP_SECONDS = 1.0

# ── Evidence ─────────────────────────────────────────────────────
EVIDENCE_MAX_SAMPLE_BYTES = 256
EVIDENCE_RETENTION_HOURS_DEFAULT = 72
EVIDENCE_RETENTION_HOURS_PRODUCTION = 8760

# ── OSINT Cache ──────────────────────────────────────────────────
OSINT_CACHE_TTL_SECONDS = 3600
OSINT_CACHE_LRU_SIZE = 2000

# ── Typosquatting ────────────────────────────────────────────────
TYPOSQUAT_LEVENSHTEIN_THRESHOLD = 2

# ── Scope ────────────────────────────────────────────────────────
SCOPE_MAX_CIDR_EXPANSION = 256

# ── Crawler ──────────────────────────────────────────────────────
CRAWLER_MAX_PAGES_DEFAULT = 100
CRAWLER_MAX_DEPTH_DEFAULT = 5

# ── Attack Graph ─────────────────────────────────────────────────
ATTACK_GRAPH_MAX_NODES = 1000
ATTACK_GRAPH_MAX_EDGES = 5000

# ── Metrics ──────────────────────────────────────────────────────
METRICS_ROTATION_DAYS_DEFAULT = 1
METRICS_TABLE_NAME = "metrics_ts"
```

---

## SECTION 16 — RISK CLASSIFICATION MATRIX

| Severity | Trigger | Required Action | CI Gate | Sign-off |
|----------|---------|----------------|---------|----------|
| **CRITICAL** | Remote code execution PoC (non-simulated) | Abort engagement, notify legal, full forensic export | FAIL | SOC Lead + Legal |
| **HIGH** | Active exploit proof-of-condition executed | Quarantine results, manual review, require isolation | MANUAL HOLD | SOC Lead |
| **MEDIUM** | Misconfiguration enabling privesc indicators | Report to stakeholder, remediation steps | PASS | Security Eng |
| **LOW** | Info leaks, missing headers | Auto-report | PASS | Operator |
| **INFO** | Observational telemetry | Include in summary | PASS | — |

**Note:** Under default posture (all `OffensiveControls` flags `False`), CRITICAL findings must be impossible. Only explicitly-enabled destructive controls in RESEARCH mode can trigger CRITICAL-level outcomes.

---

## SECTION 17 — RELEASE STRATEGY

### 17.1 Version Progression

| Version | Codename | Scope | Status |
|---------|----------|-------|--------|
| v0.1.0 | — | Initial broken state | ❌ Deprecated |
| v0.2.0 | Bootstrap | Full scanning framework (157 tests) | ✅ Complete |
| **v0.3.0** | **Resilience Engine** | This plan — Modules 1–6 + core extensions | 🔄 Next |
| **v0.4.0** | **Governance** | Module 7 — multi-tenant, RBAC, reporting | 📋 Planned |
| **v1.0.0** | **Production** | Full integration, hardening, commercial readiness | 📋 Planned |

### 17.2 SemVer Rules

- Breaking API change → MAJOR bump
- New plugin / feature module → MINOR bump
- Bug / security fix → PATCH bump

### 17.3 Release Flow

```
dev → feature branches → dev (merge) → release/x.y → main (merge + tag)
```

1. Create release PR from `dev` to `release/x.y` with CHANGELOG entry
2. Run full CI (lint, unit, integration, security, build)
3. Tag annotated git tag `vx.y.z` using `bump2version --commit --tag`
4. Publish wheel + create GitHub release with signed artifacts

---

## SECTION 18 — NEW DEPENDENCIES

Add to `pyproject.toml` under `[project.dependencies]`:

```toml
# Network scanning
"scapy>=2.5",          # Packet crafting (optional graceful fallback)

# Attack graph analysis
"networkx>=3.0",       # Graph algorithms for attack path analysis

# Reporting
"jinja2>=3.1",         # Report template rendering

# Optional (extras)
[project.optional-dependencies]
reporting = ["weasyprint>=60.0"]  # PDF generation
gpu = ["cupy>=12.0"]              # GPU-accelerated hash analysis
```

Add to `[project.optional-dependencies].dev`:
```toml
"mutmut>=2.4",         # Mutation testing
"hypothesis>=6.0",     # Property-based testing / fuzzing
```

---

## SECTION 19 — PHASED IMPLEMENTATION ORDER

### Phase 17: Core Model Extensions (est. ~400 lines)
**Depends on:** Phase 16 complete (v0.2.0 baseline)

1. Add `RESEARCH` to `RuntimeMode` enum in `redcheck/models.py`
2. Create `OffensiveControls` model in `redcheck/models.py`
3. Extend `EngagementContext` with `tenant_id`, `offensive_controls`, `safe_mode`, `runtime_mode`, `session_id`
4. Create `PluginMetadata` model in `redcheck/models.py`
5. Extend `Finding` with `plugin`, `timestamp`, `evidence_digest`, `sampled_data_len`, `mitre_technique`
6. Extend `Evidence` with `provenance_tag`
7. Create `OperatorRole` enum in `redcheck/models.py`
8. Add 5 new exceptions to `redcheck/exceptions.py`
9. Create `redcheck/constants.py` with all hard-coded constants
10. Write unit tests for all new/modified models

**Acceptance:** All existing 157 tests still pass + new model tests pass.

---

### Phase 18: Orchestrator Unification & Async (est. ~300 lines)
**Depends on:** Phase 17

1. Remove dataclass `EngagementContext` from `orchestrator.py`
2. Import Pydantic `EngagementContext` from `models.py`
3. Adapt `load_engagement()` to use Pydantic model
4. Add `arun_plugin()` async method with 11-step enforcement
5. Implement `OffensiveControls` check (Step 7)
6. Implement isolation check (Step 8)
7. Update all orchestrator tests
8. Verify existing 157 tests still pass after refactor

**Acceptance:** Orchestrator uses single EngagementContext, async execution works, all tests pass.

---

### Phase 19: Rate Limiting & Scope Validation (est. ~400 lines)
**Depends on:** Phase 18

1. Create `redcheck/core/token_bucket.py` with async support
2. Create `redcheck/core/scope_validator.py` with CIDR expansion
3. Extend `RedCheckConfig` with new rate limit fields
4. Integrate `TokenBucket` into orchestrator concurrency model
5. Integrate `ScopeValidator` into policy engine enforcement
6. Create `redcheck/config/runtime_profiles.yaml`
7. Write unit tests for TokenBucket, ScopeValidator, config extensions

**Acceptance:** Rate limiting provably enforced, scope violations blocked, profile loading works.

---

### Phase 20: Network & Infrastructure Discovery (est. ~800 lines)
**Depends on:** Phase 19

1. Create `redcheck/plugins/recon/network_scan.py` — `NetworkScanner` plugin
2. Create `redcheck/plugins/recon/packet_craft.py` — `PacketCraft` bounded sender
3. Create `redcheck/core/topology.py` — `TopologyEngine` graph inference
4. Create `redcheck/data/service_fingerprints.yaml` — fingerprint database
5. Add `load_fingerprints()` parser with deterministic sorting
6. Write unit tests with mocked socket responses
7. Write integration test fixtures (`tests/integration/containers/network_fixture/`)

**Acceptance:** Network scanner executes against mock fixture, fingerprints load, topology infers correctly.

---

### Phase 21: Web Application Resilience (est. ~700 lines)
**Depends on:** Phase 20

1. Create `redcheck/plugins/dast/crawler.py` — BFS crawler with rate limiting
2. Create `redcheck/plugins/dast/auth_tester.py` — session testing (gated)
3. Create `redcheck/plugins/dast/idor_checker.py` — IDOR validation
4. Create `redcheck/plugins/dast/injection_sim.py` — safe PoC injection
5. Create `tests/integration/containers/webapp_fixture/` — deterministic test server
6. Write unit tests for each new DAST plugin
7. Write integration test against webapp fixture

**Acceptance:** Crawler BFS completes deterministically, auth testing gated by OffensiveControls, injection PoC safe.

---

### Phase 22: Credential & Cryptographic Resilience (est. ~500 lines)
**Depends on:** Phase 19

1. Create `redcheck/plugins/crypto/` directory and `__init__.py`
2. Create `hash_strength.py` — `OfflineHashStrengthAnalyzer` with Shannon entropy
3. Create `password_policy.py` — `PasswordEntropyScorer` deterministic scoring
4. Create `gpu_adapter.py` — `GPUAdapter` with simulation mode
5. Write unit tests with known hash samples

**Acceptance:** Hash analysis returns deterministic crackability scores, GPU adapter degrades gracefully.

---

### Phase 23: Exploit Verification & Attack Graphs (est. ~600 lines)
**Depends on:** Phase 19, Phase 22

1. Create `redcheck/plugins/exploit/` directory and `__init__.py`
2. Create `safe_poc.py` — `ExploitVerifier` with curated PoC library
3. Create `cve_mapper.py` — deterministic CVE-to-service mapping
4. Create `attack_graph.py` — `AttackPathGraph` with Dijkstra
5. Create `redcheck/data/safe_poc_library.json` — curated PoC catalog
6. Write unit tests with fixed RNG seeds for graph algorithms
7. Write integration test for PoC verification against mock targets

**Acceptance:** CVE mapping deterministic, attack path analysis reproducible, chaining gated by OffensiveControls.

---

### Phase 24: Detection & Coverage Validation (est. ~400 lines)
**Depends on:** Phase 20

1. Create `redcheck/plugins/detection/` directory and `__init__.py`
2. Create `coverage_validator.py` — MITRE technique coverage mapping
3. Create `latency_tester.py` — alert latency measurement
4. Create `tests/integration/containers/siem_fixture/` — mock SIEM
5. Write unit tests + integration test against SIEM fixture

**Acceptance:** Coverage validator maps to MITRE techniques, latency tester measures within bounds.

---

### Phase 25: OSINT & Passive Intelligence (est. ~500 lines)
**Depends on:** Phase 19

1. Create `redcheck/plugins/osint/` directory and `__init__.py`
2. Create `ct_watch.py` — Certificate Transparency monitor
3. Create `typosquat.py` — Damerau-Levenshtein typosquatting detector
4. Create `breach_lookup.py` — breach database correlator (local DB)
5. Write unit tests with mocked API responses

**Acceptance:** All OSINT plugins passive-only, rate-limited, cached, deterministic.

---

### Phase 26: Metrics & Observability (est. ~300 lines)
**Depends on:** Phase 17

1. Create `redcheck/core/metrics.py` — SQLite metrics collector
2. Integrate metrics recording into orchestrator execution path
3. Implement daily rotation and signed summary export
4. Write unit tests for metric recording, rotation, export

**Acceptance:** Metrics persist atomically, rotate daily, export with signed manifest.

---

### Phase 27: Governance — Multi-Tenant & RBAC (est. ~500 lines)
**Depends on:** Phase 18

1. Create `redcheck/core/multi_tenant.py` — tenant isolation with `0o700` perms
2. Create `redcheck/core/rbac.py` — role-based access control with permission matrix
3. Create `redcheck/core/audit_export.py` — signed evidence export
4. Create `redcheck/core/sbom_integration.py` — SBOM correlation
5. Write unit tests for tenant isolation, RBAC enforcement, export signing

**Acceptance:** Cross-tenant access blocked, RBAC enforces permission matrix, exports signed.

---

### Phase 28: Reporting & Templates (est. ~400 lines)
**Depends on:** Phase 27

1. Create `redcheck/core/reporting.py` — Jinja2 templated report generator
2. Create `redcheck/core/report_templates/executive_summary.j2`
3. Create `redcheck/core/report_templates/technical_detail.j2`
4. Create `redcheck/templates/engagement_template.yaml`
5. Write unit tests for report generation with fixture data

**Acceptance:** Reports render correctly from fixtures, PDF generation works (optional weasyprint).

---

### Phase 29: CI/CD Expansion (est. ~200 lines)
**Depends on:** Phase 20–25 (all plugins implemented)

1. Create `.github/workflows/ci.yml` with 5-job matrix
2. Create `docker-compose.test.yml` for integration fixtures
3. Add mutation testing job (`mutmut`)
4. Add security scan job (bandit, safety, gitleaks)
5. Configure protected branch rules documentation

**Acceptance:** Full CI pipeline green, integration tests pass in Docker, security scan clean.

---

### Phase 30: BasePlugin Extensions & CLI (est. ~200 lines)
**Depends on:** Phase 17

1. Add `required_controls`, `timeout_seconds`, `rate_limit_rps`, `mitre_techniques`, `requires_isolation` to `BasePlugin`
2. Add `aexecute()` async method with sync fallback
3. Extend CLI with new commands: `redcheck research`, `redcheck report`, `redcheck tenant`
4. Write unit tests for new BasePlugin attributes

**Acceptance:** Existing plugins inherit new attrs with safe defaults, CLI commands functional.

---

### Phase 31: Integration Testing & Hardening (est. ~500 lines)
**Depends on:** Phases 20–28 all complete

1. Run full integration test suite against all Docker fixtures
2. Run mutation testing on critical policy code (≥80% kill rate)
3. Run property-based fuzzing on HTTP input paths
4. Performance test: 100-port scan < 120s
5. Fix any regressions or coverage gaps

**Acceptance:** All acceptance criteria from Phases 17–30 verified, coverage ≥92% / branch ≥80%.

---

### Phase 32: Final Validation & v0.3.0 Release (est. ~100 lines)
**Depends on:** Phase 31

1. Bump version to `0.3.0` in `pyproject.toml`
2. Generate CHANGELOG.md entry
3. Create release PR: `dev` → `release/0.3.0` → `main`
4. Tag `v0.3.0` with signed annotated tag
5. Verify wheel builds and installs cleanly
6. Create GitHub release with signed artifacts

**Acceptance:** v0.3.0 released, all CI green, documentation updated.

---

## SECTION 20 — BINDING SPECIFICATIONS (CONTINUATION FROM v0.2.0)

The original EXECUTION_PLAN.md defined Specs 1–21. This plan continues:

| Spec | Name | Description | Enforced In |
|------|------|-------------|-------------|
| **22** | Offensive Controls Gate | All ACTIVE/DESTRUCTIVE plugins must check `OffensiveControls.has_controls()` before execution | `orchestrator.py` Step 7 |
| **23** | Isolation Enforcement | DESTRUCTIVE plugins require Docker sandbox verification | `orchestrator.py` Step 8 |
| **24** | Token Bucket Rate Limiting | All ACTIVE/DESTRUCTIVE plugins use `TokenBucket` for rate enforcement | `token_bucket.py`, orchestrator Step 9 |
| **25** | Scope Validation | All scan targets validated against RoE authorized list | `scope_validator.py` |
| **26** | RESEARCH Mode Isolation | RESEARCH mode requires Docker + internal network + LAB_ONLY flag | `runtime_profiles.yaml`, orchestrator |
| **27** | Tenant Isolation | All evidence paths prefixed with `tenant_id`, `0o700` permissions | `multi_tenant.py` |
| **28** | RBAC Permission Matrix | Role-based access checked before every operation | `rbac.py` |
| **29** | Metrics Persistence | All plugin executions record metrics to SQLite atomically | `metrics.py` |
| **30** | Evidence Provenance | All evidence artifacts include provenance tag + SHA-256 digest | `models.Evidence` |
| **31** | MITRE ATT&CK Mapping | All plugins declare MITRE techniques in `PluginMetadata` | `base_plugin.py` |
| **32** | Deterministic Reproducibility | All RNG-dependent operations use fixed seeds from `rng_seeds.json` | All plugins |
| **33** | Safe PoC Library | Exploit verification uses only curated, non-destructive PoCs | `safe_poc_library.json` |
| **34** | Chain Mode Gate | Attack path chaining requires `chain_mode=True` + `allow_exploit_validation=True` | `attack_graph.py` |
| **35** | Data Sampling Limit | Evidence sampling capped at 256 bytes, requires `allow_data_sampling=True` | `constants.EVIDENCE_MAX_SAMPLE_BYTES` |
| **36** | OSINT Rate Limiting | All external API calls rate-limited to `OSINT_API_RATE` rps with LRU cache | `osint/*.py` |
| **37** | Report Signing | All exported reports include Ed25519 signature + manifest | `audit_export.py` |

---

## SECTION 21 — ESTIMATED EFFORT

| Phase | Name | New Lines (est.) | New Files | Tests |
|-------|------|:-----------------:|:---------:|:-----:|
| 17 | Core Model Extensions | ~400 | 1 | ~30 |
| 18 | Orchestrator Unification | ~300 | 0 | ~20 |
| 19 | Rate Limiting & Scope | ~400 | 3 | ~25 |
| 20 | Network Discovery | ~800 | 4+fixtures | ~35 |
| 21 | Web App Resilience | ~700 | 4+fixtures | ~30 |
| 22 | Credential & Crypto | ~500 | 3 | ~20 |
| 23 | Exploit Verification | ~600 | 4 | ~25 |
| 24 | Detection Validation | ~400 | 2+fixtures | ~20 |
| 25 | OSINT & Passive Intel | ~500 | 3 | ~20 |
| 26 | Metrics & Observability | ~300 | 1 | ~15 |
| 27 | Governance (Tenant/RBAC) | ~500 | 4 | ~25 |
| 28 | Reporting & Templates | ~400 | 4 | ~15 |
| 29 | CI/CD Expansion | ~200 | 3 | ~5 |
| 30 | BasePlugin & CLI | ~200 | 0 | ~10 |
| 31 | Integration & Hardening | ~500 | fixtures | ~50 |
| 32 | Final Validation | ~100 | 0 | ~5 |
| **TOTAL** | | **~6,800** | **~30+** | **~350** |

---

## SECTION 22 — RISK & MITIGATION

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Accidental destructive execution in PRODUCTION | CRITICAL | LOW | DESTRUCTIVE hard-disabled in PRODUCTION (Capability Matrix); `--force-isolated` requires Docker evidence + signed confirmation |
| Lost session code → unreadable audit logs | HIGH | MEDIUM | Operator training, clear UX warnings, separate backup of engagement metadata (not session keys) |
| Cross-tenant data leakage | CRITICAL | LOW | `TenantIsolation` enforces path prefixing + `0o700` perms; `TenantIsolationError` on violation |
| Rate limit bypass via config override | MEDIUM | LOW | Hard caps in `constants.py` cannot be raised by config; validated in `field_validator` |
| Scope validator bypass via malformed CIDR | HIGH | LOW | `ScopeValidator.expand_cidr()` hard-capped at 256 hosts; invalid CIDR raises `ValueError` |
| PoC library contains actually-destructive payloads | CRITICAL | VERY LOW | `safe_poc_library.json` curated manually; CI runs PoCs against fixture to verify non-destructive behavior |
| Stale OSINT cache serves outdated data | LOW | MEDIUM | TTL=1h enforced; LRU eviction at 2000 entries; operator can force cache clear |

---

## SECTION 23 — DELIVERY ARTIFACTS

Each sprint produces:
1. **Plugin implementation** — fully-deterministic, no stubs
2. **Unit tests** — per-function coverage, deterministic fixtures
3. **Integration test container** — Docker fixture with deterministic responses
4. **Audit evidence sample** — encrypted AES-256-GCM with provenance tags

**Evidence export formats:**
- `report.json` — machine-readable, signed
- `report.pdf` — human-readable (Jinja2 template → weasyprint)
- `sbom.json` — SPDX-compatible SBOM
- `metrics_summary.json` — aggregated metrics with signed manifest
- `audit_trail.enc` — encrypted hash-chain audit log

---

**End of NEXT_PHASE_EXECUTION_PLAN.md v2.0 (Enhanced)**

*This document is the authoritative specification for RedCheck246 v0.3.0–v1.0.0 development. All implementations must follow the file paths, constant names, enforcement sequences, and acceptance criteria defined herein. Implementation PRs must reference sections with `SPEC-SECTION:X` tags (e.g., `SPEC-SECTION:7` for capability matrix).*

*Predecessor: EXECUTION_PLAN.md (Phases 1–16, Specs 1–21, commit 7a489ce)*
*Continuation: Phases 17–32, Specs 22–37*
