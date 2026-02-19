# EXECUTION PLAN — RedCheck246 Full Production Build

**Date**: 2026-02-19  
**Status**: AWAITING CONFIRMATION  
**Scope**: Fix all bugs, implement all plugins (zero stubs), modernize full stack, Docker, CI/CD, tests, infrastructure  
**Result**: Every file functional. No placeholders. Production-ready.

---

## CURRENT STATE (HONEST)

- Build system is **broken** (`pyproject.toml` has wrong build backend — `pip install` will crash)
- 4 of 5 plugins are **empty stubs** returning `{"status": "not-yet-implemented"}`
- 4 test files **missing** (crypto, orchestrator, CLI, config)
- No `conftest.py` — tests contaminate each other via leaked singletons
- No Docker support
- No structured logging, no async, no runtime validation
- CLI uses `argparse` + `print()` — no colors, no completions
- Using setuptools 65.5.0 (2022) with broken backend path
- No lockfile, no pre-commit hooks, no dependabot, no SECURITY.md, no Makefile

---

## TECHNOLOGY STACK (AFTER COMPLETION)

| Layer | Current (broken/outdated) | After (2025/2026 state-of-the-art) |
|-------|--------------------------|-------------------------------------|
| Build system | `setuptools.backends._legacy:_Backend` (crash) | `hatchling` (modern, fast, correct) |
| Package manager | `pip` + loose `requirements.txt` | `uv` with `uv.lock` (reproducible, 100x faster) |
| Data validation | stdlib `dataclasses` (no runtime checks) | `pydantic v2` (runtime validation, JSON schema, serialization) |
| CLI framework | `argparse` + `print()` | `typer` + `rich` (auto-completions, colored tables, spinners) |
| Logging | Custom JSON lines + `print()` | `structlog` + stdlib `logging` (structured, filterable, leveled) |
| HTTP client | None | `httpx` (async-first, HTTP/2, connection pooling) |
| DNS | None | `dnspython` (full DNS resolution, all record types) |
| Async | None | `asyncio` + `anyio` (concurrent plugin execution) |
| Containers | None | Multi-stage `Dockerfile` + `docker-compose.yml` |
| Secret scanning | `grep` in CI | `gitleaks` GitHub Action |
| Pre-commit | None | `pre-commit` with ruff, mypy, bandit, gitleaks |
| Type checking | `mypy` with `disallow_untyped_defs=false` | `mypy --strict` |
| Test isolation | None (singletons leak) | `conftest.py` with reset fixtures + `tmp_path` |

### New Dependencies (Production)

```
pydantic>=2.9,<3.0          # Runtime data validation + JSON schema
typer>=0.12,<1.0             # Modern CLI framework
rich>=13.9,<14.0             # Terminal formatting (tables, colors, progress)
structlog>=24.4,<25.0        # Structured logging
httpx>=0.27,<1.0             # Async HTTP client (DAST, recon, supply chain)
dnspython>=2.7,<3.0          # DNS resolution (recon)
python-whois>=0.9,<1.0       # WHOIS lookups (recon)
anyio>=4.6,<5.0              # Async abstraction layer
cryptography>=43.0,<45.0     # AES-256-GCM (already present, pin updated)
argon2-cffi>=23.1,<24.0      # Argon2id password hashing (activation engine, Spec 12)
PyYAML>=6.0,<7.0             # YAML parsing (already present)
```

### New Dependencies (Dev)

```
pytest>=8.3,<9.0             # Test framework (bumped)
pytest-cov>=6.0,<7.0         # Coverage (bumped)
pytest-asyncio>=0.24,<1.0    # Async test support
ruff>=0.8,<1.0               # Linter + formatter (bumped)
mypy>=1.13,<2.0              # Type checker (bumped)
bandit>=1.8,<2.0             # Security linter (bumped)
pre-commit>=4.0,<5.0         # Git hooks
types-PyYAML>=6.0            # Type stubs
types-python-whois>=0.9      # Type stubs
```

---

## SPECIFICATION 1: POLICY ENFORCEMENT CONTRACT (BINDING)

Every plugin execution — sync or async — MUST pass through this exact sequence. No shortcuts. No bypass. This is hardcoded in `Orchestrator.run_plugin()` and `Orchestrator.arun_plugin()`.

### Enforcement Sequence (Deterministic)

```
Orchestrator.run_plugin(plugin_name, context, dry_run):

    STEP 1 — Resolve Plugin
        plugin = PluginRegistry.get_instance(plugin_name)
        IF plugin is None → raise PluginNotFoundError(plugin_name)

    STEP 2 — Validate EngagementContext (Pydantic)
        IF context is None → raise ContextValidationError("No engagement context")
        context.validate()  # Pydantic runtime validation
        IF validation fails → raise ContextValidationError(details)

    STEP 3 — Validate Time Window
        IF not context.is_within_window() →
            raise PolicyDeniedException(plugin_name, "Outside engagement time window")

    STEP 4 — Check RuntimeMode Restrictions
        mode = get_config().runtime_mode
        IF mode == PRODUCTION and plugin.capability == DESTRUCTIVE →
            raise PolicyDeniedException(plugin_name, "DESTRUCTIVE plugins disabled in PRODUCTION mode")
        IF mode == CI and plugin.capability in (ACTIVE, DESTRUCTIVE) →
            raise PolicyDeniedException(plugin_name, "ACTIVE/DESTRUCTIVE plugins disabled in CI mode")

    STEP 5 — Capability-Based Authorization
        IF plugin.capability == PASSIVE →
            # Requires valid EngagementContext only (already validated in Step 2)
            PASS

        IF plugin.capability == ACTIVE →
            a. PolicyEngine.validate_roe(context.roe_path) → must return (True, _, _)
               IF False → raise PolicyDeniedException(plugin_name, roe_message)
            b. PolicyEngine.validate_activation_code(code) → must return True
               IF False → raise PolicyDeniedException(plugin_name, "Invalid activation code")
            c. Check plugin_name in context.allowed_tests
               IF not in list → raise PolicyDeniedException(plugin_name, "Not in allowed_tests")

        IF plugin.capability == DESTRUCTIVE →
            a-c. Same as ACTIVE (all three checks)
            d. Require explicit user confirmation (CLI: typer.confirm(), API: confirmation_token)
               IF not confirmed → raise PolicyDeniedException(plugin_name, "User did not confirm destructive action")
            e. Verify environment isolation (Docker or sandbox detected)
               IF not isolated → raise PolicyDeniedException(plugin_name, "DESTRUCTIVE requires isolated environment")

    STEP 6 — Plugin Context Validation
        valid, reason = plugin.validate_context(context.model_dump())
        IF not valid → raise ContextValidationError(reason)

    STEP 7 — Dry Run Short-Circuit
        IF dry_run is True →
            AuditLogger.log(PLUGIN_DRY_RUN, plugin_name)
            return plugin.dry_run(context.model_dump())

    STEP 8 — Execute
        AuditLogger.log(PLUGIN_EXECUTE_START, plugin_name, context.engagement_id)
        start_time = now()
        try:
            result = plugin.execute(context.model_dump())
            OR
            result = await plugin.aexecute(context.model_dump())
        except asyncio.TimeoutError:
            raise ScanTimeoutError(plugin_name, timeout_seconds)
        except Exception as e:
            AuditLogger.log(PLUGIN_EXECUTE_FAILED, plugin_name, str(e))
            raise PluginError(plugin_name, str(e))
        end_time = now()
        result.duration_ms = (end_time - start_time).total_seconds() * 1000

    STEP 9 — Log Completion
        AuditLogger.log(PLUGIN_EXECUTE_COMPLETE, plugin_name, findings=len(result.findings))
        MetricsCollector.record_execution(plugin_name, result)
        return result
```

This sequence is **not configurable**. It is the same for CLI invocation, API invocation, and programmatic use. The only variable is `dry_run` (Step 7) which skips Steps 5c confirmation and Step 8 execution.

---

## SPECIFICATION 2: RISK CLASSIFICATION POLICY (BINDING)

### Plugin Capability Levels

```python
class PluginCapability(str, Enum):
    PASSIVE     = "passive"      # Read-only, no target interaction
    ACTIVE      = "active"       # Sends requests to targets, non-destructive
    DESTRUCTIVE = "destructive"  # May cause service disruption
```

### Plugin-to-Capability Mapping (Hardcoded)

| Plugin | Capability | Justification |
|--------|-----------|---------------|
| `passive-recon` | **PASSIVE** | DNS/WHOIS/cert lookups only. No packets sent to target infrastructure directly. |
| `sast-scanner` | **PASSIVE** | Analyzes source code files locally. No network interaction. |
| `supply-chain-audit` | **PASSIVE** | Queries public APIs (OSV.dev, PyPI). No target interaction. |
| `dast-scanner` | **ACTIVE** | Sends HTTP requests to targets. Reads headers, checks paths. Non-destructive. |
| `protocol-fuzzer` | **DESTRUCTIVE** | Sends malformed inputs that may crash services. |

### Capability Enforcement Matrix

| Constraint | PASSIVE | ACTIVE | DESTRUCTIVE |
|-----------|---------|--------|-------------|
| Requires valid EngagementContext | YES | YES | YES |
| Requires time window check | YES | YES | YES |
| Requires signed RoE | NO | YES | YES |
| Requires activation code | NO | YES | YES |
| Requires `allowed_tests` match | NO | YES | YES |
| Requires user confirmation | NO | NO | YES |
| Requires isolated environment | NO | NO | YES |
| Allowed in `DEV` mode | YES | YES | YES |
| Allowed in `CI` mode | YES | NO | NO |
| Allowed in `STAGING` mode | YES | YES | NO |
| Allowed in `PRODUCTION` mode | YES | YES | NO |
| Rate limiting enforced | NO | YES (50 req/s default) | YES (10 req/s hard cap) |
| Global timeout enforced | NO | YES (300s default) | YES (120s hard cap) |

This matrix is enforced in `Orchestrator.run_plugin()` Step 4 and Step 5. Not configurable per-plugin. Only the rate limit defaults can be overridden downward (never upward beyond the hard cap).

---

## SPECIFICATION 3: FUZZING CONSTRAINTS (BINDING)

### Rate Limits

| Parameter | Default | Hard Cap (cannot exceed) | Configurable |
|-----------|---------|--------------------------|-------------|
| HTTP requests per second per target | 10 | 50 | YES (downward only) |
| TCP connections per second per target | 5 | 20 | YES (downward only) |
| Total concurrent targets | 3 | 10 | YES (downward only) |
| Payload batch size | 50 | 200 | YES (downward only) |

### Timeouts

| Parameter | Default | Hard Cap |
|-----------|---------|----------|
| Per-target scan timeout | 60 seconds | 120 seconds |
| Per-request timeout | 10 seconds | 30 seconds |
| Global fuzzing session timeout | 300 seconds (5 min) | 600 seconds (10 min) |
| TCP connection timeout | 5 seconds | 10 seconds |

### Production Safeguard (Hardcoded — Not Configurable)

```python
# In Orchestrator.run_plugin(), Step 4:
if get_config().runtime_mode == RuntimeMode.PRODUCTION:
    if plugin.capability == PluginCapability.DESTRUCTIVE:
        raise PolicyDeniedException(
            plugin_name,
            "DESTRUCTIVE plugins are unconditionally disabled in PRODUCTION mode. "
            "This is a hardcoded safety constraint and cannot be overridden."
        )
```

This check exists BEFORE any RoE or activation validation. It is the first capability check. It cannot be bypassed by configuration, environment variables, or code modification without changing the `Orchestrator` source.

### Fuzzing Behavioral Constraints

The fuzzer will **NEVER**:
- Send more than `hard_cap` requests per second (enforced by `asyncio.Semaphore` + token bucket)
- Continue after global timeout expiration (enforced by `asyncio.wait_for()`)
- Open more than `max_concurrent_targets` simultaneous connections
- Retry failed requests (one attempt per payload, failure = skip)
- Escalate payload severity automatically (no adaptive attack chains)

---

## SPECIFICATION 4: RUNTIME MODE DEFINITION (BINDING)

### Modes

```python
class RuntimeMode(str, Enum):
    DEV        = "dev"          # Developer workstation — all plugins allowed
    CI         = "ci"           # Continuous integration — PASSIVE only
    STAGING    = "staging"      # Pre-production — PASSIVE + ACTIVE allowed
    PRODUCTION = "production"   # Live engagement — PASSIVE + ACTIVE allowed, DESTRUCTIVE blocked
```

### Mode Detection

Mode is determined by, in priority order:
1. `REDCHECK_RUNTIME_MODE` environment variable (explicit)
2. `runtime_mode` field in `redcheck.yaml` config file
3. Auto-detection:
   - If `CI=true` or `GITHUB_ACTIONS=true` in environment → `CI`
   - If `REDCHECK_PRODUCTION=true` in environment → `PRODUCTION`
   - Otherwise → `DEV`

### Per-Mode Constraints

| Constraint | DEV | CI | STAGING | PRODUCTION |
|-----------|-----|-----|---------|------------|
| Allowed plugin capabilities | ALL | PASSIVE | PASSIVE, ACTIVE | PASSIVE, ACTIVE |
| Default log level | DEBUG | INFO | INFO | WARNING |
| Log format | colored text | JSON | JSON | JSON |
| Network isolation required | NO | NO | NO | YES (Docker or sandboxed) |
| Evidence encryption at rest | optional | optional | REQUIRED | REQUIRED |
| Audit log enabled | YES | YES | YES | YES |
| Metrics collection enabled | NO | YES | YES | YES |
| Auto-purge evidence after | never | 24 hours | 7 days | per retention policy |

### Mode Enforcement Location

Mode is checked in:
- `Orchestrator.run_plugin()` Step 4 (capability gate)
- `CryptoEngine.encrypt_evidence()` (enforce encryption in STAGING/PRODUCTION)
- `setup_logging()` (log level and format)
- `RedCheckConfig.__post_init__()` (validate config against mode)

---

## SPECIFICATION 5: CONCURRENCY SAFETY BOUNDARIES (BINDING)

### Thread-Safety of Audit Chain

The audit log hash chain is protected by `asyncio.Lock` (for async contexts) and `threading.Lock` (for sync contexts):

```python
class AuditLogger:
    _sync_lock = threading.Lock()
    _async_lock: asyncio.Lock  # created lazily per event loop

    def log(self, ...):
        with self._sync_lock:
            entry = self._build_entry(...)
            self._append(entry)

    async def alog(self, ...):
        async with self._async_lock:
            entry = self._build_entry(...)
            self._append(entry)
```

Both locks protect:
1. Reading `_previous_hash`
2. Computing new hash
3. Writing entry to file
4. Updating `_previous_hash`

These four operations are **atomic** within the lock. No interleaving possible.

### Async-Safe Logging (structlog)

`structlog` is configured with `AsyncBoundLogger` when running in async context. All structlog processors are stateless (no shared mutable state).

### Plugin Timeout and Cancellation

```python
async def arun_plugin(self, plugin_name, context, dry_run=False):
    timeout = self._get_timeout(plugin)  # from capability hard caps
    try:
        result = await asyncio.wait_for(
            plugin.aexecute(context.model_dump()),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        # Convert to domain exception
        await self.audit.alog(
            action="PLUGIN_TIMEOUT",
            plugin=plugin_name,
            timeout_seconds=timeout,
        )
        raise ScanTimeoutError(plugin_name, timeout)
    except asyncio.CancelledError:
        # Graceful cancellation — preserve partial results
        await self.audit.alog(
            action="PLUGIN_CANCELLED",
            plugin=plugin_name,
        )
        return PluginResult(
            plugin_name=plugin_name,
            success=False,
            errors=["Plugin execution was cancelled"],
            metadata={"cancelled": True, "partial": True},
        )
```

### Graceful Shutdown Protocol

```python
async def shutdown(self):
    # 1. Set shutdown flag — prevents new plugin executions
    self._shutting_down = True

    # 2. Cancel all running plugin tasks with 5-second grace period
    for task in self._running_tasks:
        task.cancel()
    await asyncio.gather(*self._running_tasks, return_exceptions=True)

    # 3. Flush audit log
    await self.audit.aflush()

    # 4. Log shutdown
    await self.audit.alog(action="ORCHESTRATOR_SHUTDOWN")

    # 5. Clear engagement
    self._current_engagement = None
    self._running_tasks.clear()
```

### Concurrent Plugin Execution Limits

```python
# Semaphore-based concurrency control
self._plugin_semaphore = asyncio.Semaphore(config.max_concurrent_plugins)

async def arun_plugin(self, ...):
    async with self._plugin_semaphore:
        # Only N plugins can execute simultaneously
        ...
```

Default `max_concurrent_plugins = 3`. Hard cap = 10. Configured in `RedCheckConfig`.

---

## SPECIFICATION 6: RESOURCE ISOLATION CONTROLS (BINDING)

### Docker Security Hardening (Deterministic)

The `Dockerfile` and `docker-compose.yml` will enforce ALL of the following. These are not suggestions — they are written into the compose file.

```yaml
# docker-compose.yml — redcheck service
services:
  redcheck:
    build: .
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp:size=100M,noexec,nosuid
    pids_limit: 100
    mem_limit: 512m
    memswap_limit: 512m
    cpus: "2.0"
    ulimits:
      nofile:
        soft: 1024
        hard: 2048
      nproc:
        soft: 256
        hard: 512
    networks:
      - redcheck-net
    dns:
      - 8.8.8.8
      - 1.1.1.1
    volumes:
      - ./engagements:/app/engagements:rw
      - ./evidence:/app/evidence:rw
      - ./logs:/app/logs:rw
    environment:
      - REDCHECK_RUNTIME_MODE=production
      - REDCHECK_LOG_FORMAT=json
```

### Network Mode

| Mode | Network Setting | Reason |
|------|----------------|--------|
| `production` | `bridge` (isolated network) | Targets must be explicitly reachable |
| `dev` | `host` (optional) | Developer convenience |
| `ci` | `none` (no network) | PASSIVE-only plugins don't need network for code scanning |

### Dockerfile Security

```dockerfile
# Non-root user
RUN groupadd -r redcheck && useradd -r -g redcheck -d /app -s /sbin/nologin redcheck
USER redcheck:redcheck

# No setuid/setgid binaries
RUN find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["redcheck", "status", "--format", "json"]
```

---

## SPECIFICATION 7: SUPPLY CHAIN PLUGIN SAFEGUARDS (BINDING)

### OSV API Constraints

| Parameter | Value |
|-----------|-------|
| API endpoint | `https://api.osv.dev/v1/query` (POST) and `/v1/querybatch` (POST) |
| Rate limit | 10 requests per second (client-side enforced) |
| Request timeout | 15 seconds per request |
| Batch size | 100 packages per batch query |
| Cache TTL | 1 hour (in-memory LRU cache, max 5000 entries) |
| Cache storage | In-memory only. Not persisted to disk. |
| Max retries on failure | 2 (with exponential backoff: 1s, 3s) |

### API Failure Handling (Deterministic)

```python
async def query_osv(self, package, version, ecosystem):
    for attempt in range(3):  # 1 initial + 2 retries
        try:
            response = await self._client.post(
                "https://api.osv.dev/v1/query",
                json={"package": {"name": package, "ecosystem": ecosystem}, "version": version},
                timeout=15.0,
            )
            response.raise_for_status()
            return response.json()
        except (httpx.TimeoutException, httpx.HTTPStatusError) as e:
            if attempt < 2:
                await asyncio.sleep(backoff[attempt])  # 1s, 3s
                continue
            # All retries exhausted — DEGRADE, do not fail
            return {
                "degraded": True,
                "reason": f"OSV API unreachable after 3 attempts: {e}",
                "package": package,
                "version": version,
            }
```

When OSV is unreachable:
- Plugin result `success = True` (the scan completed)
- Plugin result `metadata["degraded"] = True`
- Plugin result `metadata["degraded_reason"] = "OSV API unreachable"`
- Finding is generated: type=`api_degraded`, severity=`INFO`, detail includes unreachable packages
- The scan does NOT fail. Other checks (license, typosquatting, SBOM) continue independently.

### PyPI API Constraints

| Parameter | Value |
|-----------|-------|
| API endpoint | `https://pypi.org/pypi/{package}/json` |
| Rate limit | 5 requests per second (client-side) |
| Request timeout | 10 seconds |
| Cache TTL | 1 hour |

Same degradation pattern as OSV — mark degraded, do not fail.

---

## SPECIFICATION 8: DATA RETENTION & EVIDENCE POLICY (BINDING)

### Evidence Directory Structure

```
engagement-name/
  evidence/           # chmod 700 (owner-only access)
    findings.json     # Encrypted at rest in STAGING/PRODUCTION
    sbom.json         # Encrypted at rest in STAGING/PRODUCTION
    scan-report.json  # Encrypted at rest in STAGING/PRODUCTION
    raw/              # Raw scan outputs, encrypted
  logs/
    audit.log.enc     # Hash-chained + AES-256-GCM encrypted at rest (session code required to open)
  reports/
    summary.md        # Human-readable report
```

### Permissions (Enforced on Creation)

| Path | Permissions | Enforced By |
|------|------------|-------------|
| `evidence/` | `0o700` (owner rwx only) | `cmd_init()` and `Orchestrator.load_engagement()` |
| `evidence/*.json` | `0o600` (owner rw only) | `CryptoEngine.encrypt_evidence()` |
| `.activation/` | `0o700` | `ActivationEngine.set_code()` |
| `.activation/activation.enc` | `0o600` | `ActivationEngine.set_code()` |
| `logs/` | `0o700` (owner rwx only) | `setup_logging()` |
| `logs/audit.log.enc` | `0o600` (owner rw only) | `AuditLogger.__init__()` |

On Windows, `chmod` calls are best-effort (logged as warning if they fail). On Linux/macOS, they are mandatory — failure raises `ConfigurationError`.

### Encryption at Rest

| Runtime Mode | Evidence Encryption | Audit Log Encryption |
|-------------|--------------------|--------------------|
| DEV | Optional (default: off) | **REQUIRED** (session code) |
| CI | Optional (default: off) | **REQUIRED** (session code) |
| STAGING | **REQUIRED** (enforced by Orchestrator) | **REQUIRED** (session code) |
| PRODUCTION | **REQUIRED** (enforced by Orchestrator) | **REQUIRED** (session code) |

Evidence encryption uses `CryptoEngine.encrypt_evidence()` with AES-256-GCM. The passphrase is derived from the activation code (never stored — user must provide it to decrypt).

### Audit Log Encryption Policy (BINDING)

Audit logs are encrypted **in all runtime modes, unconditionally**. This is not optional.

**Session Code**: Before each session (CLI: `redcheck session start`, API: `Orchestrator.start_session()`), the operator provides a **session code** — a passphrase used exclusively for audit log encryption within that session.

```python
class AuditLogger:
    def start_session(self, session_code: str):
        """Initialize encrypted audit logging for this session.
        Must be called before any audit events are logged."""
        # Derive session-scoped encryption key
        self._session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._session_id.encode("utf-8"),
            info=b"redcheck-audit-v1",
        ).derive(session_code.encode("utf-8"))
        self._session_active = True

    def log(self, action: str, **kwargs):
        """Write an encrypted, hash-chained audit entry."""
        if not self._session_active:
            raise AuditError("No active session. Call start_session() first.")

        # Step 1: Build plaintext entry (hash-chained as before)
        entry = self._build_entry(action, **kwargs)
        entry["previous_hash"] = self._previous_hash
        entry_json = json.dumps(entry, sort_keys=True)

        # Step 2: Update hash chain (computed on plaintext)
        self._previous_hash = hashlib.sha256(entry_json.encode()).hexdigest()
        entry["hash"] = self._previous_hash
        entry_json = json.dumps(entry, sort_keys=True)

        # Step 3: Encrypt the entry
        iv = os.urandom(12)
        aesgcm = AESGCM(self._session_key)
        ciphertext = aesgcm.encrypt(
            iv,
            entry_json.encode("utf-8"),
            self._session_id.encode("utf-8"),  # AAD = session_id
        )

        # Step 4: Write encrypted record (one per line, base64-encoded)
        record = base64.b64encode(iv + ciphertext).decode("ascii")
        self._file.write(record + "\n")
        self._file.flush()
```

**Key Properties**:
- Hash chain is computed on **plaintext** before encryption → chain integrity is verified after decryption
- Each entry gets a **fresh IV** (`os.urandom(12)`) — never reused
- AAD = `session_id` — entries cannot be moved between sessions
- File format: one base64-encoded encrypted record per line (`.enc` extension)
- Session code is **never stored** — operator must provide it to read logs

**Reading Encrypted Audit Logs**:
```bash
# CLI command to decrypt and view audit logs:
redcheck audit read --session-code <code> --engagement <id>

# Decrypt and verify hash chain integrity:
redcheck audit verify --session-code <code> --engagement <id>

# Export decrypted logs (for legal review, incident response):
redcheck audit export --session-code <code> --engagement <id> --output audit_plain.json
```

**Session Code vs. Activation Code**:
| | Activation Code | Session Code |
|---|---|---|
| Purpose | Plugin authorization gate | Audit log encryption |
| Scope | Per-engagement (persisted as hash) | Per-session (never persisted) |
| Storage | Argon2id hash in `.activation/` | NOT stored anywhere |
| Required for | Running ACTIVE/DESTRUCTIVE plugins | ALL audit logging |
| Loss impact | Cannot run gated plugins (re-set via CLI) | Cannot read that session's audit logs (permanent) |

**If session code is lost**: The audit logs for that session are **permanently unreadable**. This is by design — there is no recovery mechanism, no master key, no backdoor. The operator is warned of this at `session start`.

### Retention Policy

| Runtime Mode | Auto-Purge After | Configurable |
|-------------|-----------------|-------------|
| DEV | Never (manual cleanup) | N/A |
| CI | 24 hours | YES (minimum 1 hour) |
| STAGING | 7 days | YES (minimum 24 hours) |
| PRODUCTION | 90 days (default) | YES (minimum 30 days, maximum 365 days) |

Auto-purge is implemented in `Orchestrator.shutdown()` and as a CLI command `redcheck purge --older-than <days>`. Purge is logged to audit trail before deletion. Purge deletes evidence files AND expired audit logs (both are encrypted at rest). The final purge event itself is written to the current session's audit log before the old files are removed.

---

## SPECIFICATION 9: OFFENSIVE CAPABILITY CONTROLS (BINDING)

### Controlled Parameter — Not a Hard Ban

The following capabilities are implemented as **switchable controls** — not hard-coded exclusions. Each defaults to **OFF** (safe) but can be toggled by the operator via the RoE `offensive_controls` block or CLI flags. This gives the operator full authority within their authorized scope.

**File**: `RedCheck246/redcheck/models.py` — `OffensiveControls` Pydantic model  
**Enforced in**: `Orchestrator.run_plugin()` Step 5 (read from EngagementContext)

```python
class OffensiveControls(BaseModel):
    """Controlled parameters for offensive capabilities.
    All default to False (safe). Operator must explicitly enable."""

    allow_auth_testing: bool = False        # Control 1
    allow_privesc_probing: bool = False     # Control 2
    allow_credential_spraying: bool = False # Control 3
    allow_sustained_load: bool = False      # Control 4
    allow_data_sampling: bool = False       # Control 5
    allow_lateral_discovery: bool = False   # Control 6
    allow_persistence_check: bool = False   # Control 7
    allow_exploit_validation: bool = False  # Control 8
```

### Control Definitions

| # | Control | Default | When OFF (default) | When ON | Requires |
|---|---------|---------|-------------------|---------|----------|
| 1 | `allow_auth_testing` | **OFF** | Only checks *presence* of auth controls (e.g., login page exists, MFA headers present). No credential submission. | Sends test credentials (from RoE-supplied wordlist) to check for weak auth. Rate-limited (Spec 3). | ACTIVE or DESTRUCTIVE capability + RoE `authorized_auth_targets` list |
| 2 | `allow_privesc_probing` | **OFF** | No privilege escalation probes of any kind. | Checks for common misconfigurations that *could* allow privesc (e.g., writable PATH dirs, SUID binaries). Read-only checks — no exploitation. | ACTIVE capability + explicit RoE flag |
| 3 | `allow_credential_spraying` | **OFF** | No credential attempts. Fuzzer sends malformed *data*, not valid credentials. | Password spray using RoE-supplied credential list. Enforces lockout-aware throttling (max 1 attempt per account per 30 minutes). | DESTRUCTIVE capability + RoE `credential_list_path` + user confirmation |
| 4 | `allow_sustained_load` | **OFF** | Fuzzer moves to next target if current becomes unresponsive. Stops sending. | Continues sending at configured rate even if target slows. Still respects Spec 3 hard caps. Used for resilience testing. | DESTRUCTIVE capability + user confirmation |
| 5 | `allow_data_sampling` | **OFF** | Findings report the *existence* of issues. No data content captured. | Captures first 256 bytes of exposed data as evidence (e.g., first row of exposed DB query, sample of directory listing). Encrypted at rest (Spec 8). | ACTIVE capability + RoE `allow_evidence_sampling: true` |
| 6 | `allow_lateral_discovery` | **OFF** | Scans ONLY targets in RoE `authorized_targets`. Discovered hosts are reported but NOT contacted. | Discovered hosts within RoE-authorized subnets are added to scan scope. Still bounded by `authorized_targets` subnet masks. | ACTIVE capability + RoE `authorized_subnets` list |
| 7 | `allow_persistence_check` | **OFF** | No persistence mechanism detection probes. | Checks for existing persistence (cron jobs, scheduled tasks, startup items) via non-invasive read-only queries. Does NOT install anything. | ACTIVE capability |
| 8 | `allow_exploit_validation` | **OFF** | Detects vulnerability *indicators* only (misconfigs, missing headers, known CVEs). No proof-of-concept execution. | Executes safe PoC payloads (from curated set in `payloads.py`) to confirm exploitability. Payloads are non-destructive (e.g., `sleep(5)` for blind SQLi timing, canary file write to /tmp). | DESTRUCTIVE capability + user confirmation + isolated environment |

### Default Posture

With all controls at default (OFF), RedCheck246 operates as a **pure detection tool**:
- Scans for indicators, misconfigurations, and known CVEs
- Reports findings without interaction beyond safe HTTP requests
- Never submits credentials, never writes to targets, never pivots

The operator turns controls ON at their discretion, accepting responsibility per Spec 13 (Legal Boundary).

### RoE Configuration Example

```yaml
# In rules_of_engagement.yaml:
offensive_controls:
  allow_auth_testing: true
  allow_data_sampling: true
  # All others remain false (safe default)
```

### CLI Override

```bash
# Enable specific control for a single run:
redcheck scan --enable-control auth_testing --enable-control data_sampling

# Disable all controls (force safe mode regardless of RoE):
redcheck scan --safe-mode
```

`--safe-mode` overrides ALL controls to OFF. It takes precedence over RoE settings. Logged as `SAFE_MODE_OVERRIDE` in audit trail.

### Enforcement in Orchestrator

```python
# In Orchestrator.run_plugin(), after Step 5 capability checks:
def _check_offensive_controls(self, plugin, context):
    controls = context.offensive_controls  # OffensiveControls model

    # Map plugin requirements to controls
    required = plugin.required_controls()  # e.g., ["allow_auth_testing"]
    for control_name in required:
        if not getattr(controls, control_name, False):
            raise PolicyDeniedException(
                plugin.name,
                f"Plugin requires '{control_name}' to be enabled. "
                f"Set it in RoE offensive_controls or use --enable-control {control_name}"
            )

    # Capability gate: control requiring DESTRUCTIVE cannot run with ACTIVE plugin
    for control_name in required:
        min_cap = CONTROL_CAPABILITY_REQUIREMENTS[control_name]
        if plugin.capability.value < min_cap.value:
            raise PolicyDeniedException(
                plugin.name,
                f"Control '{control_name}' requires {min_cap.value} capability, "
                f"but plugin has {plugin.capability.value}"
            )
```

### Fuzzer Scope Boundary (Still Applies When Controls Are OFF)

With default controls (all OFF), the protocol fuzzer:
- Sends **detection probes** (e.g., `' OR 1=1--`) to check if the application reflects or errors
- Does NOT send **exploitation payloads** (e.g., full SQL injection chains to extract data)
- Does NOT chain vulnerabilities (e.g., XSS → session hijack → admin access)
- Reports anomalous responses as findings — does NOT attempt to confirm exploitability

This distinction is enforced by the payload sets in `payloads.py` — which contain detection-only payloads, not exploitation chains.

When `allow_exploit_validation = True`, the fuzzer additionally:
- Loads `payloads_validation.py` (curated PoC set, separate from detection payloads)
- Executes timing-based confirmation (e.g., `SLEEP(5)` to confirm blind injection)
- Still respects all Spec 3 rate limits and timeouts
- Requires DESTRUCTIVE capability + user confirmation + isolation

---

## SPECIFICATION 10: VERSIONING STRATEGY (BINDING)

### Semantic Versioning (SemVer 2.0.0)

Format: `MAJOR.MINOR.PATCH`

| Change Type | Version Bump | Example |
|------------|-------------|---------|
| Breaking API change (models, plugin interface, CLI flags removed) | MAJOR | 1.0.0 → 2.0.0 |
| New feature (new plugin, new CLI command, new config option) | MINOR | 0.2.0 → 0.3.0 |
| Bug fix, security patch, dependency update | PATCH | 0.2.0 → 0.2.1 |

### Current Version

`0.2.0` — This release (after execution plan completion).

Pre-1.0: No stability guarantees. API may change between minor versions.
Post-1.0: Plugin interface (`BasePlugin`, `PluginResult`, `Finding`) is stable. Breaking changes require MAJOR bump.

### Plugin Compatibility Contract

| Component | Stability | Breaking Change Policy |
|-----------|----------|----------------------|
| `BasePlugin` abstract class | Stable after 1.0 | Methods can be added (with defaults), never removed |
| `PluginResult` model | Stable after 1.0 | Fields can be added, never removed or renamed |
| `Finding` model | Stable after 1.0 | Fields can be added, never removed or renamed |
| `EngagementContext` model | Stable after 1.0 | Fields can be added, never removed or renamed |
| CLI commands | Stable after 1.0 | Commands can be added, flags can be added, never removed |
| CLI exit codes | Stable now | Fixed: 0, 1, 2, 3, 130 |
| Config keys | Stable after 1.0 | Keys can be added, never removed or renamed |
| Audit log format | Stable now | Fields can be added, never removed |

### CHANGELOG Format

[Keep a Changelog](https://keepachangelog.com/) format. Categories: Added, Changed, Deprecated, Removed, Fixed, Security.

---

## SPECIFICATION 11: OBSERVABILITY METRICS (BINDING)

### MetricsCollector

**File**: `RedCheck246/redcheck/metrics.py` (NEW — added to Phase 3)

All metrics are collected in-memory and flushed to structured log on shutdown. No external metrics backend required.

### Collected Metrics

| Metric | Type | Source |
|--------|------|--------|
| `plugin.execution.duration_ms` | Histogram | Orchestrator, per plugin run |
| `plugin.execution.success` | Counter | Orchestrator, incremented on success |
| `plugin.execution.failure` | Counter | Orchestrator, incremented on failure |
| `plugin.execution.timeout` | Counter | Orchestrator, incremented on ScanTimeoutError |
| `plugin.findings.count` | Gauge | Per plugin run, by severity |
| `plugin.findings.by_severity` | Counter | Aggregated: CRITICAL/HIGH/MEDIUM/LOW/INFO |
| `network.requests.total` | Counter | httpx event hooks |
| `network.requests.failed` | Counter | httpx event hooks |
| `network.requests.latency_ms` | Histogram | httpx event hooks |
| `activation.attempts.total` | Counter | ActivationEngine |
| `activation.attempts.failed` | Counter | ActivationEngine |
| `policy.denials.total` | Counter | PolicyEngine |
| `policy.denials.by_reason` | Counter | PolicyEngine, bucketed by reason category |
| `audit.entries.total` | Counter | AuditLogger |
| `scan.total_duration_ms` | Gauge | Orchestrator, full scan lifecycle |

### Metrics Output

```python
class MetricsCollector:
    def flush_to_log(self):
        """Emit all metrics as a single structured log entry on shutdown."""
        structlog.get_logger().info(
            "metrics_summary",
            **self._metrics,
        )

    def to_dict(self) -> dict:
        """Export all metrics as dict (for CLI status --format json)."""
        return self._metrics.copy()
```

Metrics are:
- Emitted to structlog on `Orchestrator.shutdown()`
- Available via `redcheck status --format json` (includes `metrics` key)
- Included in `ScanReport.metadata.metrics`
- NOT sent to any external service (no Prometheus, no StatsD — keep it self-contained)

---

## SPECIFICATION 12: ACTIVATION ENGINE HARDENING (BINDING)

### Hashing Algorithm

Primary: **Argon2id** (via `argon2-cffi` package — added to dependencies)
Fallback: **SHA-512 with HMAC** (if `argon2-cffi` not available — detected at import time)

### Argon2id Parameters (Deterministic)

| Parameter | Value | Justification |
|-----------|-------|---------------|
| Time cost (iterations) | 3 | OWASP 2024 recommendation for Argon2id |
| Memory cost | 65536 KiB (64 MB) | OWASP 2024 minimum for Argon2id |
| Parallelism | 4 | Standard for server-side hashing |
| Hash length | 32 bytes (256-bit) | Standard output length |
| Salt length | 32 bytes (256-bit) | Generated via `os.urandom(32)` |

### SHA-512 Fallback Parameters

| Parameter | Value |
|-----------|-------|
| Algorithm | HMAC-SHA-512 |
| Salt length | 32 bytes |
| Iterations (PBKDF2) | 600,000 |
| Key length | 64 bytes |

### Lockout Policy (Hardcoded)

```python
MAX_VERIFY_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 300  # 5 minutes
COOLDOWN_BETWEEN_ATTEMPTS_SECONDS = 2  # minimum gap between attempts

class ActivationEngine:
    def verify_code(self, code: str) -> bool:
        # Check lockout
        if self._is_locked_out():
            remaining = self._lockout_remaining_seconds()
            raise ActivationError(
                f"Account locked. Too many failed attempts. "
                f"Try again in {remaining} seconds."
            )

        # Enforce cooldown
        if self._time_since_last_attempt() < COOLDOWN_BETWEEN_ATTEMPTS_SECONDS:
            raise ActivationError("Too fast. Wait before retrying.")

        self._record_attempt()

        result = self._verify_hash(code)

        if not result:
            self._failed_attempts += 1
            if self._failed_attempts >= MAX_VERIFY_ATTEMPTS:
                self._lockout_until = now() + timedelta(seconds=LOCKOUT_DURATION_SECONDS)
                self.audit.log(action="ACTIVATION_LOCKOUT", level="WARN")
        else:
            self._failed_attempts = 0  # reset on success

        return result
```

### Salt Rotation

Salt is generated fresh on every `set_code()` call. There is no automatic rotation.
Manual rotation = call `set_code()` with a new code (which generates a new salt).

Lockout state is **in-memory only**. Restarting the process resets the lockout counter. This is intentional — persistent lockout would create a denial-of-service vector against the operator.

---

## SPECIFICATION 13: LEGAL BOUNDARY (BINDING)

### Legal Use Statement (Embedded in Code)

The following text is:
- Printed by `redcheck --version`
- Displayed in `redcheck status`
- Included in `README.md`
- Included as a docstring in `redcheck/__init__.py`
- Included in every `ScanReport` output

```
RedCheck246 is an AUTHORIZED SECURITY ASSESSMENT TOOL.

Usage of this tool against systems, networks, or applications without
explicit written authorization from the system owner is ILLEGAL and may
violate federal and state computer fraud laws including but not limited to:

  - Computer Fraud and Abuse Act (CFAA) — 18 U.S.C. Section 1030
  - UK Computer Misuse Act 1990
  - EU Directive 2013/40/EU on attacks against information systems

The operator is solely responsible for:
  1. Obtaining written authorization (Rules of Engagement) before ANY scan
  2. Restricting scans to ONLY the targets listed in the RoE
  3. Operating within the time window specified in the RoE
  4. Complying with all applicable local, state, federal, and international laws

This tool enforces authorization via policy gating (RoE validation +
activation codes) but technical controls are NOT a substitute for legal
authorization. The existence of a valid RoE file does not constitute
legal authorization — it is a technical control only.

SERVER-246 accepts no liability for unauthorized use of this tool.
```

### Misuse Detection (Implemented in Orchestrator)

The following conditions are detected and logged as `SECURITY_WARNING` audit entries:

1. **Target outside RoE** — If a plugin attempts to contact a host not in `authorized_targets`, the request is blocked and logged. Enforced by `httpx` transport wrapper that validates target against RoE.

2. **Scan outside time window** — Checked at execution start (Spec 1, Step 3) and periodically during long scans (every 60 seconds). If window expires mid-scan, execution is halted.

3. **Repeated activation failures** — After lockout (Spec 12), a `SECURITY_WARNING` is logged with timestamp and source.

4. **Unsigned RoE used** — If RoE has no signature field, a warning is generated (scan may proceed for PASSIVE plugins, but ACTIVE/DESTRUCTIVE are blocked).

### Compliance Requirements (Operator Responsibility)

RedCheck246 provides the following technical controls to ASSIST with compliance. They do NOT replace legal review:

| Control | Mechanism | Operator Responsibility |
|---------|-----------|------------------------|
| Authorization verification | RoE validation + activation code | Obtain actual legal authorization |
| Scope restriction | `authorized_targets` enforcement | Verify targets are correct |
| Time bounding | Time window validation | Set correct engagement dates |
| Audit trail | Hash-chained + AES-256-GCM encrypted (session code) | Preserve session codes for log decryption & legal review |
| Evidence encryption | AES-256-GCM at rest | Manage encryption keys securely |
| Non-destructive default | Dry-run mode, capability gating | Review scan scope before active execution |

---

## SPECIFICATION 14: COMPATIBILITY CONSTRAINTS (BINDING)

### Python Version Support

| Version | Status | CI Tested | Notes |
|---------|--------|-----------|-------|
| 3.9 and below | NOT SUPPORTED | NO | Union type syntax (`X | Y`) requires 3.10+ |
| 3.10 | Supported | YES | Minimum version. `match` statement available. |
| 3.11 | Supported | YES | ExceptionGroups, `tomllib` in stdlib |
| 3.12 | Supported | YES | Improved error messages, f-string improvements |
| 3.13 | Supported | YES | Primary development/test target |
| 3.14+ | Best-effort | NO | Not tested until release |

### OS Support

| OS | Status | Notes |
|----|--------|-------|
| Linux (Kali, Ubuntu, Debian) | **Primary target** | Full feature parity |
| macOS | Supported | Full feature parity |
| Windows | Supported (dev) | `chmod` calls are best-effort; Docker recommended for production |

### Dependency Compatibility Windows

All dependency version ranges are tested together. The following are the **pinned lower bounds** (minimum versions that work together):

```
pydantic>=2.9       # model_config changes in 2.9
typer>=0.12         # rich integration stabilized
rich>=13.9          # Panel, Table, Progress API stable
structlog>=24.4     # AsyncBoundLogger available
httpx>=0.27         # HTTP/2 support stable
dnspython>=2.7      # asyncresolver stable
cryptography>=43.0  # AESGCM API stable
argon2-cffi>=23.1   # Argon2id parameter API stable
anyio>=4.6          # asyncio backend stable
```

Upper bounds are set to `<next_major` to prevent accidental breaking upgrades.

---

## SPECIFICATION 15: ROE SIGNATURE TRUST MODEL (BINDING)

### Trust Policy Per Capability Level

| Capability | Signature Required | Timestamp Validation | Policy on Missing Signature |
|-----------|-------------------|---------------------|----------------------------|
| PASSIVE | **Optional** | Not checked | Scan proceeds. Audit log: `ROE_UNSIGNED` (INFO level) |
| ACTIVE | **Mandatory** | Must be ≤ 30 days old | Scan blocked. `PolicyDeniedException("ACTIVE requires signed RoE")` |
| DESTRUCTIVE | **Mandatory** | Must be ≤ 7 days old | Scan blocked. `PolicyDeniedException("DESTRUCTIVE requires recently signed RoE")` |

### Supported Signature Algorithms

| Algorithm | Status | Use Case |
|-----------|--------|----------|
| HMAC-SHA256 | Supported (current) | Shared-secret environments, single operator |
| Ed25519 | Supported (new) | Asymmetric, multi-signer, recommended for teams |

Algorithm is auto-detected from the RoE `signature` block:
```yaml
signature:
  algorithm: "ed25519"        # or "hmac-sha256"
  value: "base64-encoded..."
  signer_id: "operator-1"     # identifies which key signed
  timestamp: "2026-02-19T10:00:00Z"
```

### Public Key Storage

```
~/.redcheck/
  trusted_keys/
    operator-1.pub         # Ed25519 public key, PEM format
    operator-2.pub         # Each file = one trusted signer
    team-lead.pub
  hmac_secrets/
    default.key            # HMAC shared secret, chmod 600
```

- **Ed25519 public keys**: Stored in `~/.redcheck/trusted_keys/` as PEM files. File name = `signer_id` from RoE.
- **HMAC secrets**: Stored in `~/.redcheck/hmac_secrets/`. File permissions enforced: `0o600` (Linux/macOS) or owner-only ACL (Windows).
- Keys are NEVER embedded in the RoE file itself.
- Keys are NEVER committed to git (`.gitignore` pattern: `.redcheck/`).

### Key Rotation

```python
class KeyRotationPolicy:
    max_key_age_days: int = 365        # Warn if key is older than this
    revocation_list_path: Path | None  # Optional path to revoked key IDs
```

- On signature verification, if the signing key file's `mtime` is older than `max_key_age_days`, emit audit warning: `KEY_AGE_WARNING`.
- If `signer_id` appears in `revocation_list_path` (one ID per line), signature is rejected: `PolicyDeniedException("Signing key has been revoked")`.
- Rotation is manual: operator generates new key, distributes `.pub`, removes old file. No automatic rotation.

### Multiple Signers

- Multiple keys CAN exist in `trusted_keys/`.
- RoE `signer_id` field determines which key is used for verification.
- If `signer_id` is not found in `trusted_keys/`, signature verification fails: `SignatureVerificationError("Unknown signer: {signer_id}")`.
- There is no "any key" mode — the signer must be explicitly identified.

### Signature Timestamp Validation

```python
def validate_signature_age(timestamp: datetime, capability: PluginCapability) -> bool:
    age = datetime.utcnow() - timestamp
    max_age = {
        PluginCapability.PASSIVE: timedelta(days=365),    # Effectively unchecked
        PluginCapability.ACTIVE: timedelta(days=30),
        PluginCapability.DESTRUCTIVE: timedelta(days=7),
    }
    if age > max_age[capability]:
        raise PolicyDeniedException(
            f"RoE signature is {age.days} days old. "
            f"{capability.value} plugins require signature within {max_age[capability].days} days."
        )
```

Timestamp is parsed from RoE `signature.timestamp` field. If the field is missing, timestamp validation fails for ACTIVE/DESTRUCTIVE (treated as infinitely old).

---

## SPECIFICATION 16: TARGET SCOPE ENFORCEMENT (BINDING)

### Scope Validation Rules (Deterministic)

Every outbound HTTP/TCP connection from DAST or Fuzzer plugins passes through `ScopeValidator` before the connection is opened.

**File**: `RedCheck246/redcheck/security/scope_validator.py` (NEW)

```python
class ScopeValidator:
    """Validates that a target is within the authorized scope."""

    def __init__(self, authorized_targets: list[str]):
        self._exact_hosts: set[str] = set()
        self._wildcard_domains: list[str] = []
        self._ip_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._parse_targets(authorized_targets)

    def is_in_scope(self, target: str) -> tuple[bool, str]:
        """Returns (allowed, reason)."""
        ...
```

### Target Matching Rules

| RoE Target Format | Interpretation | Example Match | Example Non-Match |
|-------------------|---------------|---------------|-------------------|
| `example.com` | Exact hostname only | `example.com` | `sub.example.com`, `notexample.com` |
| `*.example.com` | Any subdomain (one level) | `app.example.com` | `deep.sub.example.com`, `example.com` |
| `**.example.com` | Any subdomain (recursive) | `a.b.c.example.com`, `app.example.com` | `example.com` |
| `192.168.1.0/24` | IP CIDR range | `192.168.1.50` | `192.168.2.1` |
| `10.0.0.5` | Exact IP | `10.0.0.5` | `10.0.0.6` |
| `2001:db8::/32` | IPv6 CIDR range | `2001:db8::1` | `2001:db9::1` |

### DNS Resolution and IP Verification

```python
async def validate_resolved_target(self, hostname: str) -> tuple[bool, str]:
    """Validates both the hostname AND its resolved IPs."""
    # Step 1: Check hostname against scope
    hostname_ok, reason = self.is_in_scope(hostname)
    if not hostname_ok:
        return False, reason

    # Step 2: Resolve hostname to IPs
    resolved_ips = await self._resolve(hostname)

    # Step 3: Check each resolved IP against scope
    for ip in resolved_ips:
        ip_ok, ip_reason = self.is_in_scope(str(ip))
        if not ip_ok:
            return False, (
                f"Hostname '{hostname}' resolves to {ip} which is "
                f"outside authorized scope. {ip_reason}"
            )

    return True, "in scope"
```

**Rule**: If a hostname is in scope but resolves to an IP NOT in scope, the connection is **BLOCKED**. This prevents DNS rebinding attacks and scope escape via resolution.

### Redirect Handling

```python
# httpx event hook — registered in DAST and Fuzzer HTTP clients
async def on_redirect(request: httpx.Request, response: httpx.Response):
    redirect_url = response.headers.get("location")
    if redirect_url:
        redirect_host = urlparse(redirect_url).hostname
        in_scope, reason = scope_validator.is_in_scope(redirect_host)
        if not in_scope:
            # Block the redirect — do NOT follow it
            audit.log(
                action="REDIRECT_BLOCKED",
                original_target=str(request.url),
                redirect_target=redirect_url,
                reason=reason,
                level="SECURITY_WARNING",
            )
            raise ScopeViolationError(
                f"Redirect to '{redirect_host}' blocked: outside authorized scope"
            )
```

**Rule**: Redirects to hosts outside scope are **never followed**. The redirect is logged as `SECURITY_WARNING` and the request chain stops. The original request's response (the 3xx) is preserved as a finding.

### Private/Reserved IP Protection

Unless the RoE explicitly lists private ranges, the following are **always blocked** from DAST/Fuzzer (prevents SSRF-style scope escapes):

| Range | Blocked Unless Authorized |
|-------|---------------------------|
| `127.0.0.0/8` | Localhost |
| `10.0.0.0/8` | Private |
| `172.16.0.0/12` | Private |
| `192.168.0.0/16` | Private |
| `169.254.0.0/16` | Link-local |
| `::1/128` | IPv6 localhost |
| `fc00::/7` | IPv6 ULA |
| `fe80::/10` | IPv6 link-local |

The operator can explicitly authorize private ranges by including them in `authorized_targets`. This is logged as `PRIVATE_RANGE_AUTHORIZED` (INFO).

---

## SPECIFICATION 17: FUZZER PAYLOAD BOUNDARIES (BINDING)

### Numerical Payload Constraints

| Parameter | Hard Limit | Default | Configurable |
|-----------|-----------|---------|-------------|
| Maximum payload length | 1024 bytes | 256 bytes | YES (upward to hard limit only) |
| Maximum URL parameter length | 512 bytes | 128 bytes | YES (upward to hard limit only) |
| Maximum header value length | 8192 bytes | 2048 bytes | YES (upward to hard limit only) |
| Maximum body payload size | 65536 bytes (64KB) | 4096 bytes (4KB) | YES (upward to hard limit only) |
| Maximum reflection analysis depth | 3 response hops | 1 | YES (upward to hard limit only) |
| Maximum recursion depth (template expansion) | 5 levels | 3 levels | YES (upward to hard limit only) |
| Maximum payloads per parameter | 50 | 20 | YES (upward to hard limit only) |
| Maximum total payloads per target | 500 | 200 | YES (upward to hard limit only) |

Payloads exceeding the hard limit are **silently truncated** and logged as `PAYLOAD_TRUNCATED` (DEBUG).

### Excluded Techniques (When `allow_exploit_validation = False`)

| Technique | Status | Reason |
|-----------|--------|--------|
| Timing-based blind injection (`SLEEP`, `BENCHMARK`) | **EXCLUDED** | Can cause service slowdown; constitutes active exploitation |
| Out-of-band interaction (DNS/HTTP callbacks) | **EXCLUDED** | Requires external infrastructure; not a detection probe |
| Multi-stage probing (use response A to craft payload B) | **EXCLUDED** | Constitutes exploit chaining |
| Payload mutation/evolution (adaptive fuzzing) | **EXCLUDED** | No automatic escalation — static payload sets only |
| Binary protocol fuzzing (non-HTTP) | **EXCLUDED** | Only HTTP/HTTPS protocols in scope for v0.2 |
| Authentication token manipulation | **EXCLUDED** | Requires `allow_auth_testing = True` |

When `allow_exploit_validation = True` (Spec 9, Control 8), timing-based blind injection and multi-stage probing are **unlocked**, but still bounded by Spec 3 rate limits and the hard limits above.

### Payload Validation (Pre-Send)

```python
def validate_payload(payload: bytes, config: FuzzerConfig) -> bytes:
    """Validate and constrain payload before sending."""
    if len(payload) > config.max_payload_length:
        logger.debug("payload_truncated", original=len(payload), max=config.max_payload_length)
        payload = payload[:config.max_payload_length]

    # No null bytes in HTTP payloads (causes parsing issues)
    if b"\x00" in payload and config.protocol == "http":
        payload = payload.replace(b"\x00", b"")

    return payload
```

### Response Analysis Constraints

| Parameter | Value |
|-----------|-------|
| Maximum response body to analyze | 1 MB (larger responses are truncated for analysis) |
| Maximum response headers to store | 64 headers |
| Maximum evidence snippet per finding | 512 bytes (from response body) |
| Timeout for response analysis | 5 seconds (prevents ReDoS in regex matching) |

---

## SPECIFICATION 18: EVIDENCE ENCRYPTION KEY HANDLING (BINDING)

### Key Derivation Function

```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_evidence_key(activation_code: str, engagement_id: str) -> bytes:
    """Derive a 256-bit AES key from activation code + engagement context."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,           # 256-bit key
        salt=engagement_id.encode("utf-8"),   # Salt is engagement-scoped
        info=b"redcheck-evidence-v1",         # Domain separation
    )
    return hkdf.derive(activation_code.encode("utf-8"))
```

### KDF Parameters (Deterministic)

| Parameter | Value | Justification |
|-----------|-------|---------------|
| Algorithm | HKDF-SHA256 | Standard KDF for key derivation from existing key material |
| Key length | 32 bytes (256-bit) | AES-256-GCM key size |
| Salt | `engagement_id.encode("utf-8")` | Per-engagement. Different engagements with same activation code produce different keys |
| Info/Context | `b"redcheck-evidence-v1"` | Domain separation string. Versioned for future algorithm changes |
| Input key material | `activation_code.encode("utf-8")` | User-provided passphrase |

### IV (Initialization Vector) Policy

| Parameter | Value | Scope |
|-----------|-------|-------|
| IV length | 12 bytes (96-bit) | Standard for AES-GCM |
| IV generation | `os.urandom(12)` | Cryptographically random |
| IV scope | **Per-file** | Every `encrypt_evidence()` call generates a fresh IV |
| IV storage | Prepended to ciphertext | Format: `[12-byte IV][ciphertext][16-byte GCM tag]` |

**Critical**: IV is NEVER reused. Each file encryption gets a fresh `os.urandom(12)`. Reusing an IV with the same key would catastrophically break AES-GCM confidentiality.

### GCM Authentication Tag

| Parameter | Value |
|-----------|-------|
| Tag length | 16 bytes (128-bit) | 
| Tag scope | Per-file |
| Authenticated data (AAD) | `engagement_id + "." + filename` |
| Tag storage | Appended to ciphertext (handled by `AESGCM.encrypt()`) |

The AAD binds the ciphertext to its engagement and filename. Moving an encrypted evidence file to a different engagement directory will cause decryption to fail with `InvalidTag`. This is intentional — it prevents evidence tampering via file relocation.

### Encrypted File Format

```
+---+---+---+---+---+---+---+---+---+---+---+---+---...---+---...---+
| IV (12 bytes)                     | Ciphertext      | GCM Tag   |
|                                   | (variable len)  | (16 bytes)|
+---+---+---+---+---+---+---+---+---+---+---+---+---...---+---...---+
```

File extension: `.enc` (e.g., `findings.json.enc`)

### Metadata Authentication

Metadata (engagement_id, filename) is authenticated via AAD — it is NOT encrypted. This means:
- An attacker who sees the file can determine which engagement it belongs to (from filename/path)
- But they CANNOT modify the metadata without invalidating the GCM tag
- They CANNOT decrypt the content without the activation code
- They CANNOT move the file to a different engagement without decryption failing

### Activation Code Rotation Mid-Engagement

```python
def rotate_activation_code(self, old_code: str, new_code: str, engagement_id: str):
    """Re-encrypt all evidence files with new activation code."""
    old_key = derive_evidence_key(old_code, engagement_id)
    new_key = derive_evidence_key(new_code, engagement_id)

    evidence_dir = self.config.engagement_dir / engagement_id / "evidence"
    for enc_file in evidence_dir.glob("*.enc"):
        # Decrypt with old key
        plaintext = self._decrypt_file(enc_file, old_key)
        # Re-encrypt with new key (new IV generated automatically)
        self._encrypt_file(enc_file, plaintext, new_key, engagement_id)

    # Update activation hash
    self.activation_engine.set_code(new_code)

    self.audit.log(
        action="ACTIVATION_CODE_ROTATED",
        engagement_id=engagement_id,
        files_re_encrypted=len(list(evidence_dir.glob("*.enc"))),
    )
```

Key rotation:
- Is a CLI command: `redcheck rotate-key --engagement <id>`
- Prompts for old code, then new code
- Re-encrypts ALL `.enc` files in the engagement
- Generates fresh IVs for every re-encrypted file
- Logs the rotation event (NOT the codes themselves)
- If interrupted mid-rotation, partially re-encrypted files are detected by failed AAD validation on next access

---

## SPECIFICATION 19: METRICS PERSISTENCE & LIFECYCLE (BINDING)

### Engagement Scoping

Metrics are **engagement-scoped**. Each `Orchestrator.load_engagement()` call resets the `MetricsCollector` to zero.

```python
def load_engagement(self, engagement_id: str):
    # ... load engagement context ...
    self.metrics = MetricsCollector(engagement_id=engagement_id)
    # Previous engagement's metrics are gone (already flushed or lost)
```

### Reset Between Engagements

| Event | Metrics Behavior |
|-------|------------------|
| `load_engagement()` | RESET to zero. New `MetricsCollector` created. |
| `shutdown()` | FLUSH to structured log, then discard. |
| Between plugins (same engagement) | ACCUMULATE. Metrics are additive within one engagement. |
| `status --format json` | SNAPSHOT. Returns current accumulated metrics without resetting. |

### Crash Handling

```python
import atexit
import signal

class MetricsCollector:
    def __init__(self, engagement_id: str):
        self._engagement_id = engagement_id
        self._metrics: dict[str, float] = {}
        self._checkpoint_file: Path | None = None

        # Register crash handlers
        atexit.register(self._emergency_flush)
        signal.signal(signal.SIGTERM, self._signal_handler)
        # SIGINT handled by Orchestrator graceful shutdown

    def _emergency_flush(self):
        """Best-effort metric preservation on crash/exit."""
        try:
            checkpoint = self.config.logs_dir / f"metrics_checkpoint_{self._engagement_id}.json"
            checkpoint.write_text(json.dumps({
                "engagement_id": self._engagement_id,
                "timestamp": datetime.utcnow().isoformat(),
                "partial": True,
                "metrics": self._metrics,
            }))
        except Exception:
            pass  # Best-effort — if we can't write, we can't write

    def _signal_handler(self, signum, frame):
        self._emergency_flush()
        sys.exit(128 + signum)
```

### Partial Metrics Recovery

On next startup, if a `metrics_checkpoint_*.json` file exists:
1. Log `METRICS_RECOVERED` with engagement_id and timestamp
2. Include in status output as `previous_partial_metrics`
3. Do NOT merge into current engagement's metrics (they are separate engagements)
4. Delete checkpoint file after logging

### Metrics Are NOT Authoritative

Metrics are **observability aids**, not audit records. The audit log (hash-chained + encrypted) is the authoritative record. If metrics and audit log disagree, the audit log is correct. Note: reading the audit log requires the session code used when it was written.

---

## SPECIFICATION 20: WINDOWS PERMISSION HANDLING (BINDING)

### Policy

On Windows, POSIX `chmod()` calls are **best-effort** because Windows uses ACLs, not POSIX permission bits. The behavior is explicitly defined:

### Behavior Per Operation

| Operation | Linux/macOS | Windows |
|-----------|------------|----------|
| `chmod(path, 0o700)` | Enforced. Failure → `ConfigurationError` | Attempted. Failure → `SECURITY_WARNING` log + continue |
| `chmod(path, 0o600)` | Enforced. Failure → `ConfigurationError` | Attempted. Failure → `SECURITY_WARNING` log + continue |
| Directory permission check | `stat.S_IMODE()` verified | Skipped (unreliable on Windows) |

### Windows ACL Handling

```python
import platform

def set_secure_permissions(path: Path, mode: int) -> None:
    """Set POSIX permissions or Windows ACLs."""
    if platform.system() == "Windows":
        try:
            # Attempt POSIX-style chmod (works on some Windows/NTFS configs)
            path.chmod(mode)
        except OSError:
            # Fallback: use icacls to restrict to current user
            try:
                import subprocess
                username = os.environ.get("USERNAME", "")
                if username:
                    subprocess.run(
                        ["icacls", str(path), "/inheritance:r",
                         "/grant:r", f"{username}:(F)"],
                        capture_output=True, check=True,
                    )
                    logger.info("windows_acl_set", path=str(path), user=username)
                else:
                    logger.warning(
                        "permission_not_set",
                        path=str(path),
                        reason="Cannot determine USERNAME for ACL",
                        level="SECURITY_WARNING",
                    )
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                logger.warning(
                    "permission_not_set",
                    path=str(path),
                    reason=str(e),
                    level="SECURITY_WARNING",
                )
    else:
        # Linux/macOS — mandatory
        try:
            path.chmod(mode)
        except OSError as e:
            raise ConfigurationError(
                f"Failed to set permissions {oct(mode)} on {path}: {e}"
            )
```

### Log Severity

All Windows permission failures are logged at `SECURITY_WARNING` severity — not `ERROR`, not `INFO`. This ensures:
- They appear in production logs (which filter at WARNING level, per Spec 4)
- They do NOT cause scan failure (best-effort)
- They are distinguishable from operational errors

---

## SPECIFICATION 21: DEPENDENCY RESOLUTION REPRODUCIBILITY (BINDING)

### Lockfile Policy

| Environment | Lockfile Required | Behavior if Missing/Outdated |
|-------------|------------------|------------------------------|
| DEV | Recommended | `uv sync` generates/updates lockfile. Warning logged. |
| CI | **MANDATORY** | `uv sync --frozen` — fails if `uv.lock` is missing or outdated |
| STAGING | **MANDATORY** | Same as CI |
| PRODUCTION | **MANDATORY** | Same as CI |

### CI Enforcement

```yaml
# In .github/workflows/ci.yml:
steps:
  - name: Install dependencies (frozen)
    run: |
      uv sync --frozen
      # --frozen: fail if uv.lock doesn't exist or is outdated
      # This ensures CI uses EXACTLY the same deps as the developer committed

  - name: Verify lockfile is current
    run: |
      uv lock --check
      # --check: exits non-zero if pyproject.toml and uv.lock are out of sync
      # This catches cases where someone edited pyproject.toml but forgot to run uv lock
```

If either command fails, the CI pipeline **fails** and the PR cannot merge.

### Dependency Hash Verification

```toml
# In pyproject.toml:
[tool.uv]
verify-hashes = true
```

When `verify-hashes = true`:
- `uv.lock` contains SHA-256 hashes for every downloaded wheel/sdist
- On `uv sync`, hashes are verified against the lockfile
- If a hash mismatch is detected: `uv sync` fails with `HashMismatchError`
- This prevents supply-chain attacks where a package is replaced on PyPI after the lockfile was generated

### Developer Workflow

```bash
# Add a new dependency:
uv add httpx
# uv automatically updates pyproject.toml AND uv.lock

# Update all dependencies to latest within version constraints:
uv lock --upgrade
uv sync

# Verify everything is in sync before committing:
uv lock --check  # should exit 0
```

### Lockfile in Git

`uv.lock` is **committed to git**. It is NOT in `.gitignore`. This is mandatory for reproducibility.

---

## UPDATED FILE CHANGE SUMMARY (Post-Specifications)

The following files are **added** to the plan based on Specifications 1-14:

| # | Path | Specification | Purpose |
|---|------|--------------|---------|
| 34 | `RedCheck246/redcheck/metrics.py` | Spec 11 | MetricsCollector |
| 35 | `RedCheck246/redcheck/constants.py` | Specs 3,4,12 | All hardcoded constants (rate limits, timeouts, lockout params, mode definitions) |
| 36 | `RedCheck246/tests/test_metrics.py` | Spec 11 | Metrics collection tests |
| 37 | `RedCheck246/tests/test_concurrency.py` | Spec 5 | Async safety, timeout, cancellation tests |
| 38 | `RedCheck246/tests/test_enforcement.py` | Specs 1,2 | Full enforcement sequence tests (every step) |
| 39 | `RedCheck246/tests/test_lockout.py` | Spec 12 | Lockout, cooldown, rate limiting tests |

**Updated total: 60 files (39 new + 21 rewritten/updated)**  
**Updated estimated lines: ~8,000-10,000**

---

## PHASE 1: CRITICAL BUG FIXES & FOUNDATION

**Goal**: Make the project installable and testable. Zero broken state.

### 1.1 — Fix `pyproject.toml` (BROKEN BUILD)

**File**: `RedCheck246/pyproject.toml`  
**Action**: REWRITE  
**Changes**:
- Build backend: `setuptools.backends._legacy:_Backend` → `hatchling`
- Add all new dependencies (pydantic, typer, rich, structlog, httpx, dnspython, python-whois, anyio)
- Add all dev dependencies (pytest-asyncio, pre-commit, type stubs)
- Set `mypy` to `strict = true`
- Update ruff config with full rule set
- Add `[tool.hatch.build.targets.wheel]` for proper package inclusion
- Python 3.10 minimum maintained (3.10+ union syntax used throughout)

### 1.2 — Create Error Hierarchy

**File**: `RedCheck246/redcheck/exceptions.py` (NEW)  
**Contents**: Complete exception hierarchy:
- `RedCheckError(Exception)` — Base for all framework errors
- `PolicyDeniedException(RedCheckError)` — Policy gate denial (move from policy_engine.py)
- `ActivationError(RedCheckError)` — Activation code failures
- `ConfigurationError(RedCheckError)` — Config loading/validation failures
- `CryptoError(RedCheckError)` — Encryption/decryption failures
- `RoEValidationError(RedCheckError)` — RoE structural/temporal failures (move from roe_validator.py)
- `PluginError(RedCheckError)` — Plugin execution failures
- `PluginNotFoundError(PluginError)` — Plugin not in registry
- `ContextValidationError(PluginError)` — Bad plugin context
- `NetworkError(RedCheckError)` — HTTP/DNS/network failures
- `ScanTimeoutError(NetworkError)` — Scan timed out

All exceptions include structured fields (plugin_name, engagement_id, etc.) for logging integration.

### 1.3 — Add `py.typed` Marker (PEP 561)

**File**: `RedCheck246/redcheck/py.typed` (NEW)  
**Contents**: Empty file — signals to mypy/pyright that this package ships type info.

### 1.4 — Update `__init__.py`

**File**: `RedCheck246/redcheck/__init__.py`  
**Action**: REWRITE  
**Contents**: Proper public API exports — `__version__`, `__all__`, key classes.

---

## PHASE 2: MODERNIZE CORE — PYDANTIC MODELS

**Goal**: Replace all `dataclasses` with Pydantic v2 models. Runtime validation on every data structure.

### 2.1 — Pydantic Models

**File**: `RedCheck246/redcheck/models.py` (NEW)  
**Contents**: All data models as Pydantic `BaseModel`:

```
EngagementContext       — engagement_id, authorizer, targets, allowed_tests, time window, sensitivity
                          Validators: targets non-empty, time window valid, authorizer non-empty
                          Methods: from_roe_yaml(), from_roe_dict(), is_within_window()

PluginResult            — plugin_name, success, findings, evidence, errors, metadata, duration_ms
                          Computed field: finding_count

Finding                 — type, target, severity (enum), detail, evidence_ref, cvss_score, cwe_id
                          Enum: FindingSeverity (CRITICAL, HIGH, MEDIUM, LOW, INFO)

Evidence                — type, path, sha256, timestamp, encrypted

TargetSpec              — host, ports, protocols, excluded_paths

RoEDocument             — All RoE fields with validators
                          Methods: is_expired(), is_active(), time_remaining()

RedCheckConfig          — All config fields with validators and env var loading via pydantic-settings
                          Methods: from_yaml(), to_yaml(), from_env() (via model_config with env_prefix)

AuditEntry              — timestamp, level, action, details, operator, plugin, engagement_id,
                          previous_hash, hash

ScanReport              — engagement_id, scanner, start_time, end_time, findings, summary, metadata
```

### 2.2 — Refactor `config.py`

**File**: `RedCheck246/redcheck/config.py`  
**Action**: REWRITE using Pydantic model from `models.py`  
**Changes**:
- Remove dataclass-based `RedCheckConfig`
- Use Pydantic `BaseSettings` with `env_prefix = "REDCHECK_"`
- No `mkdir()` in `__init__` — side effects moved to explicit `ensure_dirs()` method
- Proper path validation and type coercion

---

## PHASE 3: MODERNIZE CORE — STRUCTURED LOGGING

**Goal**: Replace custom audit logger with `structlog` integration. Maintain hash-chained audit trail.

### 3.1 — Logging Setup

**File**: `RedCheck246/redcheck/logging.py` (NEW)  
**Contents**:
- `setup_logging(level, json_output, log_file)` — Configure structlog + stdlib logging
- Processors: timestamp (UTC ISO), log level, caller info, JSON serialization
- Console renderer: `rich`-powered colored output for dev, JSON for production
- File handler: Rotating log file (10MB, 5 backups)

### 3.2 — Refactor `audit.py`

**File**: `RedCheck246/redcheck/core/audit.py`  
**Action**: REWRITE  
**Changes**:
- Keep hash-chained audit trail (this is correct and good)
- **Add session-code-based AES-256-GCM encryption** — every entry encrypted before write (Spec 8 Audit Log Encryption Policy)
- Add `start_session(session_code)` method — must be called before any logging
- Add `read_session(session_code)` method — decrypt and return entries
- Add `verify_chain(session_code)` method — decrypt then verify hash chain integrity
- Key derivation: HKDF-SHA256, salt=session_id, info=`b"redcheck-audit-v1"`
- Per-entry IV: `os.urandom(12)`, AAD=session_id
- File format: `.enc` extension, one base64 record per line
- Add `structlog` integration — audit events also go through structlog pipeline (structlog sees plaintext in-memory, only disk is encrypted)
- Remove singleton `__new__` pattern — use module-level factory with explicit reset for testing
- Add `reset()` class method for test isolation
- Add async `alog()` method for async plugin contexts
- Add CLI commands: `redcheck audit read`, `redcheck audit verify`, `redcheck audit export`
- Add `redcheck session start` command (prompts for session code, warns about loss)

---

## PHASE 4: MODERNIZE CORE — CLI WITH TYPER + RICH

**Goal**: Replace argparse+print with typer+rich. Same 7 commands, better UX.

### 4.1 — Rewrite CLI

**File**: `RedCheck246/redcheck/cli.py`  
**Action**: REWRITE  
**Contents**:
- `typer.Typer()` app with 7 commands (same names, same behavior)
- `rich.console.Console` for all output
- `rich.table.Table` for `list-plugins` and `status`
- `rich.panel.Panel` for scan results
- `rich.progress.Progress` for scan progress
- `typer.prompt()` and `typer.confirm()` for activation code (replaces `getpass`)
- `--format` option on all commands: `text` (default, colored) or `json` (machine-readable)
- `--verbose` / `--quiet` global flags
- Proper exit codes (0=success, 1=error, 2=policy denied, 3=activation required, 130=interrupted)
- All plugin imports moved to dynamic discovery (see Phase 6)

### 4.2 — Add CLI Output Formatting

**File**: `RedCheck246/redcheck/output.py` (NEW)  
**Contents**:
- `format_findings(findings, format)` — Rich table or JSON output
- `format_scan_report(report, format)` — Full scan report formatting
- `format_plugin_list(plugins, format)` — Plugin table
- `format_status(status, format)` — Status dashboard
- `print_banner()` — RedCheck246 ASCII banner with version
- `create_progress()` — Progress bar factory for scans

---

## PHASE 5: IMPLEMENT PASSIVE RECON PLUGIN (REAL)

**Goal**: Fully functional passive OSINT reconnaissance. Zero placeholders.

**File**: `RedCheck246/redcheck/plugins/recon/passive_recon.py`  
**Action**: REWRITE  
**Size**: ~300 lines  
**Dependencies**: `dnspython`, `python-whois`, `httpx`

**Implemented capabilities**:
1. **DNS Resolution** — A, AAAA, MX, NS, TXT, CNAME, SOA records for each target via `dns.resolver`
2. **Reverse DNS** — PTR lookups for resolved IPs
3. **WHOIS Lookup** — Domain registration data (registrar, creation date, expiry, name servers) via `python-whois`
4. **Certificate Transparency** — Query crt.sh API via `httpx` for issued certificates, extract SANs (subdomains)
5. **HTTP Fingerprinting** — GET request to target, extract `Server`, `X-Powered-By`, `X-Generator` headers
6. **Subdomain Enumeration** — DNS brute-force against common subdomain wordlist (built-in top 100)
7. **Email Harvesting** — Extract emails from TXT/SPF/DMARC records

**Execution flow**:
```
execute(context) →
  for each target:
    async dns_resolve(target)     → Finding[]
    async reverse_dns(ips)        → Finding[]
    async whois_lookup(target)    → Finding[]
    async cert_transparency(target) → Finding[]
    async http_fingerprint(target)  → Finding[]
    async subdomain_enum(target)    → Finding[]
    async email_harvest(target)     → Finding[]
  aggregate → PluginResult
```

All network calls are async via `httpx.AsyncClient` and `dns.asyncresolver`. Errors caught per-target, never crash the whole scan.

**File**: `RedCheck246/redcheck/plugins/recon/wordlists.py` (NEW)  
**Contents**: Built-in subdomain wordlist (top 200 common subdomains: www, mail, ftp, admin, api, dev, staging, etc.)

---

## PHASE 6: IMPLEMENT SAST PLUGIN (REAL)

**Goal**: Static analysis that actually scans code and finds vulnerabilities.

**File**: `RedCheck246/redcheck/plugins/sast/sast_scanner.py`  
**Action**: REWRITE  
**Size**: ~400 lines  
**Dependencies**: `bandit` (already in dev deps — use as library)

**Implemented capabilities**:
1. **Bandit Integration** — Run `bandit` programmatically via `bandit.core.manager.BanditManager`
   - Scan Python files for: hardcoded passwords, SQL injection, shell injection, weak crypto, insecure deserialization, eval/exec usage, insecure temp files, binding to 0.0.0.0
   - Map Bandit severity/confidence to RedCheck `FindingSeverity` enum
2. **Custom Pattern Scanner** — Regex-based scanning for language-agnostic patterns:
   - Hardcoded API keys/tokens (entropy-based + pattern matching)
   - Hardcoded IP addresses and private keys
   - TODO/FIXME/HACK/XXX security comments
   - Insecure HTTP URLs in code (http:// where https:// expected)
   - Weak hash usage (MD5, SHA1 for security purposes)
3. **Dependency File Scanner** — Check requirements.txt / pyproject.toml for:
   - Unpinned dependencies (no version constraints)
   - Known-vulnerable version ranges (cross-ref with OSV data from supply chain plugin)

**Execution flow**:
```
execute(context) →
  resolve target paths (from context or cwd)
  async run_bandit_scan(paths)        → Finding[]
  async run_pattern_scan(paths)       → Finding[]
  async run_dependency_scan(paths)    → Finding[]
  deduplicate and rank → PluginResult
```

---

## PHASE 7: IMPLEMENT DAST PLUGIN (REAL)

**Goal**: Dynamic scanning of live HTTP targets. Security header analysis, SSL assessment, endpoint discovery.

**File**: `RedCheck246/redcheck/plugins/dast/dast_scanner.py`  
**Action**: REWRITE  
**Size**: ~450 lines  
**Dependencies**: `httpx`, `ssl` (stdlib)

**Implemented capabilities**:
1. **HTTP Security Headers** — Check for presence and correctness of:
   - `Strict-Transport-Security` (HSTS) — max-age, includeSubDomains, preload
   - `Content-Security-Policy` (CSP) — unsafe-inline, unsafe-eval, wildcard sources
   - `X-Frame-Options` — DENY vs SAMEORIGIN
   - `X-Content-Type-Options` — nosniff
   - `X-XSS-Protection` — deprecated but still checked
   - `Referrer-Policy` — strict-origin-when-cross-origin
   - `Permissions-Policy` — camera, microphone, geolocation
   - `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`
   - Missing headers generate findings with severity based on OWASP risk rating
2. **SSL/TLS Assessment** — Connect via `ssl` module:
   - Protocol version (TLS 1.0/1.1 = CRITICAL, TLS 1.2 = OK, TLS 1.3 = GOOD)
   - Certificate validity (expiry, issuer, SANs, self-signed check)
   - Cipher suite analysis (weak ciphers flagged)
   - HSTS preload list check
3. **HTTP Method Testing** — Send OPTIONS, check for dangerous methods (TRACE, PUT, DELETE on unexpected endpoints)
4. **Cookie Security** — Analyze Set-Cookie headers:
   - `Secure` flag missing on HTTPS
   - `HttpOnly` flag missing
   - `SameSite` attribute missing or set to `None`
   - Cookie scoping (domain, path)
5. **Directory Discovery** — HTTP GET against common sensitive paths:
   - `/.env`, `/.git/config`, `/wp-admin`, `/admin`, `/api/swagger.json`, `/.well-known/security.txt`
   - `/robots.txt` parsing for disallowed paths
   - `/sitemap.xml` parsing
   - Response code analysis (200 on sensitive paths = finding)
6. **Redirect Analysis** — Follow redirect chains, flag HTTP→HTTPS redirect absence, detect open redirects

**Execution flow**:
```
execute(context) →
  for each target (host:port):
    async check_ssl_tls(target)         → Finding[]
    async check_security_headers(target) → Finding[]
    async check_http_methods(target)     → Finding[]
    async check_cookies(target)          → Finding[]
    async discover_paths(target)         → Finding[]
    async check_redirects(target)        → Finding[]
  aggregate → PluginResult
```

**File**: `RedCheck246/redcheck/plugins/dast/wordlists.py` (NEW)  
**Contents**: Sensitive path wordlist (top 150 common paths: .env, .git, admin panels, API docs, config files, backup files)

---

## PHASE 8: IMPLEMENT FUZZING PLUGIN (REAL)

**Goal**: Protocol and HTTP parameter fuzzing with crash detection.

**File**: `RedCheck246/redcheck/plugins/fuzzing/protocol_fuzzer.py`  
**Action**: REWRITE  
**Size**: ~400 lines  
**Dependencies**: `httpx`, `asyncio`

**Implemented capabilities**:
1. **HTTP Parameter Fuzzer** — For each target endpoint:
   - Query parameter fuzzing (inject payloads into URL params)
   - Header fuzzing (Host, User-Agent, Referer, custom headers)
   - Body fuzzing (POST/PUT with malformed JSON, XML, form data)
   - Payload categories:
     - SQL injection probes (`' OR 1=1--`, `UNION SELECT`, etc.)
     - XSS probes (`<script>alert(1)</script>`, event handlers, SVG payloads)
     - Command injection probes (`; ls`, `| cat /etc/passwd`, backtick execution)
     - Path traversal probes (`../../etc/passwd`, `..%2f..%2f`)
     - SSRF probes (`http://169.254.169.254/latest/meta-data/`)
     - Format string probes (`%s%s%s%n`)
   - Response analysis: detect reflection (XSS), error messages (SQLi), timing anomalies
2. **TCP Protocol Fuzzer** — Raw socket-based:
   - Send malformed packets (oversized, truncated, invalid encoding)
   - Monitor for connection resets, timeouts, unexpected responses
   - Rate-limited to avoid DoS (configurable max RPS)
3. **Mutation Engine**:
   - Bit-flip mutation
   - Boundary value insertion (0, -1, MAX_INT, empty string, null bytes)
   - Format string expansion
   - Unicode edge cases (overlong encodings, BOM insertion)
4. **Crash Detection**:
   - Response time deviation (>3x baseline = anomaly)
   - HTTP 500 responses logged as findings
   - Connection refused after successful connection = potential crash
   - Response body error pattern matching (stack traces, debug output)

**File**: `RedCheck246/redcheck/plugins/fuzzing/payloads.py` (NEW)  
**Contents**: All fuzzing payload sets organized by category. ~200 payloads across SQLi, XSS, CMDi, path traversal, SSRF, format string.

---

## PHASE 9: IMPLEMENT SUPPLY CHAIN PLUGIN (REAL)

**Goal**: Dependency vulnerability scanning, license compliance, typosquatting detection, SBOM generation.

**File**: `RedCheck246/redcheck/plugins/supply_chain/supply_chain_audit.py`  
**Action**: REWRITE  
**Size**: ~400 lines  
**Dependencies**: `httpx` (for OSV API)

**Implemented capabilities**:
1. **Dependency Parser** — Parse all common formats:
   - `requirements.txt` (with version specifiers, -r includes, comments)
   - `pyproject.toml` (PEP 621 dependencies + optional)
   - `Pipfile` / `Pipfile.lock`
   - `package.json` / `package-lock.json` (npm)
   - `go.mod` (Go modules)
2. **Vulnerability Scanner** — Query OSV.dev API (`https://api.osv.dev/v1/query`):
   - Batch query all dependencies
   - Map CVE/GHSA IDs to findings
   - Include CVSS scores, affected version ranges, fixed versions
   - Severity mapping: CVSS 9.0+ = CRITICAL, 7.0+ = HIGH, 4.0+ = MEDIUM, else LOW
3. **License Compliance** — Check licenses against policy:
   - Parse license from PyPI API (JSON) for each dependency
   - Flag copyleft licenses (GPL, AGPL) in proprietary projects
   - Flag unknown/missing licenses
   - Configurable allow/deny list
4. **Typosquatting Detection** — For each dependency:
   - Levenshtein distance against top 5000 PyPI packages
   - Flag packages within edit distance 1-2 of popular packages
   - Check package age (< 30 days old = suspicious)
5. **SBOM Generation** — CycloneDX JSON format:
   - Component list with versions, licenses, hashes
   - Dependency tree structure
   - Output to `sbom.json` in engagement evidence directory

**File**: `RedCheck246/redcheck/plugins/supply_chain/osv_client.py` (NEW)  
**Contents**: Async OSV.dev API client with batched queries, response caching, rate limiting.

**File**: `RedCheck246/redcheck/plugins/supply_chain/parsers.py` (NEW)  
**Contents**: Dependency file parsers for all supported formats.

---

## PHASE 10: REFACTOR CORE MODULES

**Goal**: Update policy engine, activation engine, orchestrator to use new models/logging/async.

### 10.1 — Refactor `policy_engine.py`

**File**: `RedCheck246/redcheck/core/policy_engine.py`  
**Action**: REWRITE  
**Changes**:
- Use `PolicyDeniedException` from `exceptions.py`
- Use `EngagementContext` Pydantic model from `models.py`
- Use `structlog` instead of direct audit calls for operational logging
- Keep audit trail calls for compliance
- Add `reset()` class method for test isolation
- Add async `aauthorize()` for async plugin contexts
- Stricter type annotations throughout

### 10.2 — Refactor `activation_engine.py`

**File**: `RedCheck246/redcheck/core/activation_engine.py`  
**Action**: REWRITE  
**Changes**:
- Use `ActivationError` from `exceptions.py`
- Use `structlog` for logging
- Add Argon2id as preferred hash algorithm (fallback to SHA-512 if `argon2-cffi` not available)
- Add `reset()` class method for test isolation
- Add rate limiting on verify attempts (max 5 per minute)

### 10.3 — Refactor `orchestrator.py`

**File**: `RedCheck246/redcheck/core/orchestrator.py`  
**Action**: REWRITE  
**Changes**:
- Use Pydantic `EngagementContext` model
- Use `structlog` for logging
- Add async `arun_plugin()` for async plugin execution
- Add concurrent plugin execution support (respect `max_concurrent_plugins`)
- Add `ScanReport` model generation after plugin run
- Add scan timing (start_time, end_time, duration_ms)
- Proper resource cleanup in `shutdown()`

### 10.4 — Refactor `base_plugin.py`

**File**: `RedCheck246/redcheck/plugins/base_plugin.py`  
**Action**: REWRITE  
**Changes**:
- Use Pydantic `PluginResult`, `Finding` models
- Add `async aexecute(context)` abstract method alongside sync `execute()`
- Add plugin metadata Pydantic model
- Plugin discovery via `importlib.metadata` entry points (in addition to `__init_subclass__`)
- Add `PluginCapability` enum (PASSIVE, ACTIVE, DESTRUCTIVE) for risk classification
- Add plugin lifecycle hooks: `setup()`, `teardown()`, `health_check()`

### 10.5 — Refactor Security Modules

**Files**: `crypto.py`, `roe_validator.py`, `signature_verifier.py`  
**Action**: REWRITE each  
**Changes**:
- Use custom exceptions from `exceptions.py`
- Use `structlog` for logging
- `crypto.py`: Remove XOR fallback entirely (cryptography is now a hard dependency)
- `roe_validator.py`: Return Pydantic `RoEDocument` model instead of raw dict
- `signature_verifier.py`: Add async sign/verify methods, add Ed25519 option alongside HMAC

---

## PHASE 11: COMPLETE TEST SUITE

**Goal**: Every module tested. No untested code paths.

### 11.1 — Test Configuration & Fixtures

**File**: `RedCheck246/tests/conftest.py` (NEW)  
**Contents**:
- `@pytest.fixture` for `tmp_path` based engagement directories
- `@pytest.fixture(autouse=True)` for singleton reset (audit, policy, activation)
- `@pytest.fixture` for valid RoE YAML file (temp file with correct time window)
- `@pytest.fixture` for expired RoE YAML file
- `@pytest.fixture` for `EngagementContext` with all fields populated
- `@pytest.fixture` for mock HTTP server (using `pytest-httpx` or manual `httpx.MockTransport`)
- `@pytest.fixture` for `PluginRegistry` cleanup
- `@pytest.fixture` for temp config YAML

### 11.2 — Existing Tests Updated

**Files**: All 5 existing test files  
**Action**: UPDATE to use conftest fixtures, Pydantic models, new exception types

### 11.3 — New Test Files

**File**: `RedCheck246/tests/test_crypto.py` (NEW) — ~15 tests  
- AES-256-GCM encrypt/decrypt round-trip
- Wrong passphrase → decryption failure
- Empty plaintext handling
- Large file hashing (streaming)
- PBKDF2 key derivation determinism (same salt → same key)
- HMAC-SHA256 correctness
- Base64 encode/decode round-trip
- Secure compare timing safety (functional test)
- Random token uniqueness

**File**: `RedCheck246/tests/test_orchestrator.py` (NEW) — ~12 tests  
- Load engagement from valid RoE → success
- Load engagement from invalid RoE → PolicyDeniedException
- Activate with correct code → True
- Activate with wrong code → False
- Activate without loaded engagement → False
- Run plugin in dry-run → PluginResult with mode=dry-run
- Run non-existent plugin → PluginResult with error
- Run plugin without authorization → PolicyDeniedException
- Shutdown clears engagement
- Concurrent plugin execution (async)
- Scan timing recorded in result

**File**: `RedCheck246/tests/test_cli.py` (NEW) — ~15 tests  
- `init` creates directory structure
- `init` on existing directory → error
- `list-plugins` shows all 5 plugins
- `verify-roe` on valid file → success message
- `verify-roe` on invalid file → error message
- `status` shows activation state
- `--version` shows version
- `--help` shows help
- `recon --dry-run` returns results
- JSON output format (`--format json`)
- Plugin run with mock targets

**File**: `RedCheck246/tests/test_config.py` (NEW) — ~10 tests  
- Default config values
- Load from YAML file
- Load from environment variables (REDCHECK_ prefix)
- Save to YAML and reload (round-trip)
- Invalid config values → ValidationError (Pydantic)
- Path resolution
- Missing config file → defaults

**File**: `RedCheck246/tests/test_models.py` (NEW) — ~15 tests  
- EngagementContext validation (targets non-empty, time window valid)
- EngagementContext from RoE YAML
- PluginResult serialization
- Finding severity enum mapping
- RoEDocument validation
- ScanReport model
- Invalid model data → ValidationError

**File**: `RedCheck246/tests/test_recon_real.py` (NEW) — ~8 tests  
- DNS resolution with mocked resolver
- WHOIS lookup with mocked response
- Certificate transparency with mocked httpx
- HTTP fingerprinting with mocked httpx
- Subdomain enumeration with mocked DNS
- Error handling (DNS timeout, WHOIS failure)
- Multiple targets aggregation

**File**: `RedCheck246/tests/test_dast_real.py` (NEW) — ~10 tests  
- Security header analysis (all headers present → no findings)
- Missing HSTS → HIGH finding
- Missing CSP → MEDIUM finding
- SSL/TLS check with mocked ssl context
- Cookie security analysis
- Directory discovery with mocked responses
- HTTP method check
- Redirect analysis

**File**: `RedCheck246/tests/test_sast_real.py` (NEW) — ~8 tests  
- Bandit scan on test Python file with known issues
- Custom pattern scan (hardcoded password detection)
- Dependency file scan (unpinned deps)
- Clean file → no findings
- Multiple file scan

**File**: `RedCheck246/tests/test_fuzzer_real.py` (NEW) — ~8 tests  
- HTTP parameter fuzzing with mocked responses
- SQL injection detection (error-based)
- XSS reflection detection
- Response time anomaly detection
- Payload generation correctness
- Rate limiting enforcement
- Mutation engine output validation

**File**: `RedCheck246/tests/test_supply_chain_real.py` (NEW) — ~10 tests  
- requirements.txt parsing (pinned, unpinned, with extras)
- pyproject.toml parsing
- OSV API query with mocked response (vulnerable package)
- OSV API query (clean package)
- License compliance (GPL flagged)
- Typosquatting detection (reqeusts → requests)
- SBOM generation (CycloneDX format validation)
- Empty dependency file handling

**Total tests: ~160+ (up from 33)**

---

## PHASE 12: DOCKER SUPPORT

**Goal**: Full containerization. Build, run, and develop in containers.

### 12.1 — Dockerfile

**File**: `RedCheck246/Dockerfile` (NEW)  
**Contents**: Multi-stage build:
```
# Stage 1: Builder
FROM python:3.13-slim AS builder
  - Install uv
  - Copy pyproject.toml + uv.lock
  - Install dependencies into virtual env
  - Copy source code

# Stage 2: Runtime
FROM python:3.13-slim AS runtime
  - Copy venv from builder
  - Copy source
  - Install system deps (nmap, whois, dig for recon tooling)
  - Non-root user (redcheck:redcheck, UID 1000)
  - HEALTHCHECK instruction
  - ENTRYPOINT ["redcheck"]
  - Labels (OCI standard)

# Stage 3: Dev
FROM runtime AS dev
  - Install dev dependencies
  - Mount source code
  - CMD ["pytest"]
```

### 12.2 — Docker Compose

**File**: `RedCheck246/docker-compose.yml` (NEW)  
**Contents**:
```yaml
services:
  redcheck:
    build: .
    volumes:
      - ./engagements:/app/engagements
      - ./evidence:/app/evidence
      - ./logs:/app/logs
    environment:
      - REDCHECK_LOG_LEVEL=INFO
      - REDCHECK_LOG_FORMAT=json
    networks:
      - redcheck-net
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp

  redcheck-dev:
    build:
      context: .
      target: dev
    volumes:
      - .:/app
    command: pytest --cov=redcheck tests/

networks:
  redcheck-net:
    driver: bridge
```

### 12.3 — Dockerignore

**File**: `RedCheck246/.dockerignore` (NEW)  
**Contents**: `.git`, `.venv`, `__pycache__`, `.pytest_cache`, `*.pyc`, `.env`, `.activation`, `evidence/`, `logs/`, `*.skill`

---

## PHASE 13: CI/CD COMPLETE OVERHAUL

**Goal**: Production-grade GitHub Actions pipeline.

### 13.1 — Main CI Workflow

**File**: `.github/workflows/ci.yml`  
**Action**: REWRITE  
**Contents**:
```yaml
Jobs:
  lint:
    - ruff check + format
    - mypy --strict

  test:
    matrix: [3.10, 3.11, 3.12, 3.13]
    - pytest --cov=redcheck --cov-report=xml
    - Upload coverage to artifacts

  security:
    - bandit -r redcheck/
    - gitleaks detect --source .
    - pip-audit (check installed deps for CVEs)

  build:
    needs: [lint, test, security]
    - python -m build
    - Upload wheel + sdist as artifacts

  docker:
    needs: [build]
    - docker build --target runtime
    - docker build --target dev
    - Run tests inside container
    - (Optional) Push to GHCR if tagged release
```

### 13.2 — Dependabot

**File**: `.github/dependabot.yml` (NEW)  
**Contents**:
```yaml
version: 2
updates:
  - package-ecosystem: pip
    directory: /RedCheck246
    schedule:
      interval: weekly
    labels: [dependencies]
    commit-message:
      prefix: "deps:"
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
    labels: [ci]
    commit-message:
      prefix: "ci:"
  - package-ecosystem: docker
    directory: /RedCheck246
    schedule:
      interval: weekly
    labels: [docker]
```

### 13.3 — CodeQL

**File**: `.github/workflows/codeql.yml` (NEW)  
**Contents**: GitHub CodeQL analysis for Python. Runs on push to main/dev, weekly schedule.

---

## PHASE 14: INFRASTRUCTURE FILES

### 14.1 — SECURITY.md

**File**: `SECURITY.md` (NEW)  
**Contents**: Vulnerability disclosure policy — how to report security issues, PGP key reference, SLA for response/fix, scope, safe harbor statement.

### 14.2 — CODEOWNERS

**File**: `.github/CODEOWNERS` (NEW)  
**Contents**: `* @SERVER-246` — All files owned by SERVER-246.

### 14.3 — Pre-commit Config

**File**: `.pre-commit-config.yaml` (NEW)  
**Contents**:
```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    hooks: [ruff, ruff-format]
  - repo: https://github.com/pre-commit/mirrors-mypy
    hooks: [mypy]
  - repo: https://github.com/PyCQA/bandit
    hooks: [bandit]
  - repo: https://github.com/gitleaks/gitleaks
    hooks: [gitleaks]
  - repo: https://github.com/pre-commit/pre-commit-hooks
    hooks: [trailing-whitespace, end-of-file-fixer, check-yaml, check-toml, check-merge-conflict]
```

### 14.4 — Makefile

**File**: `RedCheck246/Makefile` (NEW)  
**Contents**:
```makefile
.PHONY: install dev test lint format security docker clean

install:        uv sync
dev:            uv sync --all-extras
test:           uv run pytest --cov=redcheck tests/
lint:           uv run ruff check redcheck/ tests/
format:         uv run ruff format redcheck/ tests/
typecheck:      uv run mypy redcheck/
security:       uv run bandit -r redcheck/
docker-build:   docker compose build
docker-test:    docker compose run redcheck-dev
docker-run:     docker compose run redcheck
clean:          find . -type d -name __pycache__ -exec rm -rf {} +
```

### 14.5 — CONTRIBUTING.md

**File**: `RedCheck246/CONTRIBUTING.md` (NEW)  
**Contents**: How to contribute — fork, branch naming, commit conventions, PR template, code style (ruff), test requirements, plugin development guide.

### 14.6 — CHANGELOG.md

**File**: `RedCheck246/CHANGELOG.md` (NEW)  
**Contents**: Keep-a-Changelog format. v0.1.0 (initial) and v0.2.0 (this release) entries.

---

## PHASE 15: UPDATE README & DOCUMENTATION

### 15.1 — Comprehensive README

**File**: `RedCheck246/README.md`  
**Action**: REWRITE  
**Contents**:
- Badges (CI status, Python version, license)
- Feature overview with screenshots (table format)
- Quick start (pip install, docker, uv)
- Full command reference with examples
- Architecture diagram (updated with async, Pydantic, structlog)
- Plugin catalog (all 5 with capabilities)
- Configuration reference (all settings, env vars)
- Docker usage guide
- Security model explanation
- Contributing link

### 15.2 — Plugin Development Guide

**File**: `RedCheck246/docs/plugin-development.md` (NEW)  
**Contents**: Step-by-step guide for writing new plugins — BasePlugin API, context structure, finding format, testing patterns, registration.

---

## PHASE 16: FINAL VALIDATION

### 16.1 — Run all tests (target: 160+ passing)
### 16.2 — Run mypy --strict (target: 0 errors)
### 16.3 — Run ruff check + format (target: 0 issues)
### 16.4 — Run bandit (target: 0 high/critical findings)
### 16.5 — Build wheel (`python -m build` — target: success)
### 16.6 — Docker build + test (target: container runs, tests pass inside)
### 16.7 — CLI smoke test (all 7 commands)
### 16.8 — `pip install -e .` — target: success
### 16.9 — Update PROJECT_OVERSEER_REPORT.md v3

---

## FILE CHANGE SUMMARY

### New Files (30)

| # | Path | Purpose |
|---|------|---------|
| 1 | `RedCheck246/redcheck/exceptions.py` | Complete error hierarchy |
| 2 | `RedCheck246/redcheck/models.py` | All Pydantic v2 models |
| 3 | `RedCheck246/redcheck/logging.py` | structlog setup |
| 4 | `RedCheck246/redcheck/output.py` | Rich output formatting |
| 5 | `RedCheck246/redcheck/py.typed` | PEP 561 type marker |
| 6 | `RedCheck246/redcheck/plugins/recon/wordlists.py` | Subdomain wordlist |
| 7 | `RedCheck246/redcheck/plugins/dast/wordlists.py` | Sensitive path wordlist |
| 8 | `RedCheck246/redcheck/plugins/fuzzing/payloads.py` | Fuzzing payload sets |
| 9 | `RedCheck246/redcheck/plugins/supply_chain/osv_client.py` | OSV.dev API client |
| 10 | `RedCheck246/redcheck/plugins/supply_chain/parsers.py` | Dependency file parsers |
| 11 | `RedCheck246/tests/conftest.py` | Shared fixtures |
| 12 | `RedCheck246/tests/test_crypto.py` | Crypto tests |
| 13 | `RedCheck246/tests/test_orchestrator.py` | Orchestrator tests |
| 14 | `RedCheck246/tests/test_cli.py` | CLI tests |
| 15 | `RedCheck246/tests/test_config.py` | Config tests |
| 16 | `RedCheck246/tests/test_models.py` | Pydantic model tests |
| 17 | `RedCheck246/tests/test_recon_real.py` | Recon plugin tests |
| 18 | `RedCheck246/tests/test_dast_real.py` | DAST plugin tests |
| 19 | `RedCheck246/tests/test_sast_real.py` | SAST plugin tests |
| 20 | `RedCheck246/tests/test_fuzzer_real.py` | Fuzzer plugin tests |
| 21 | `RedCheck246/tests/test_supply_chain_real.py` | Supply chain tests |
| 22 | `RedCheck246/Dockerfile` | Multi-stage container |
| 23 | `RedCheck246/docker-compose.yml` | Container orchestration |
| 24 | `RedCheck246/.dockerignore` | Docker build exclusions |
| 25 | `RedCheck246/Makefile` | Task runner |
| 26 | `RedCheck246/CONTRIBUTING.md` | Contributor guide |
| 27 | `RedCheck246/CHANGELOG.md` | Version history |
| 28 | `RedCheck246/docs/plugin-development.md` | Plugin dev guide |
| 29 | `.github/dependabot.yml` | Dependency updates |
| 30 | `.github/workflows/codeql.yml` | CodeQL analysis |
| 31 | `.github/CODEOWNERS` | Code ownership |
| 32 | `.pre-commit-config.yaml` | Git hooks |
| 33 | `SECURITY.md` | Disclosure policy |

### Rewritten Files (16)

| # | Path | Reason |
|---|------|--------|
| 1 | `RedCheck246/pyproject.toml` | Fix broken build backend, add all deps |
| 2 | `RedCheck246/redcheck/__init__.py` | Proper exports |
| 3 | `RedCheck246/redcheck/config.py` | Pydantic BaseSettings |
| 4 | `RedCheck246/redcheck/cli.py` | Typer + Rich |
| 5 | `RedCheck246/redcheck/core/audit.py` | structlog + reset() |
| 6 | `RedCheck246/redcheck/core/policy_engine.py` | New models + exceptions |
| 7 | `RedCheck246/redcheck/core/activation_engine.py` | New exceptions + Argon2 |
| 8 | `RedCheck246/redcheck/core/orchestrator.py` | Pydantic + async |
| 9 | `RedCheck246/redcheck/plugins/base_plugin.py` | Pydantic + async + lifecycle |
| 10 | `RedCheck246/redcheck/plugins/recon/passive_recon.py` | REAL implementation |
| 11 | `RedCheck246/redcheck/plugins/sast/sast_scanner.py` | REAL implementation |
| 12 | `RedCheck246/redcheck/plugins/dast/dast_scanner.py` | REAL implementation |
| 13 | `RedCheck246/redcheck/plugins/fuzzing/protocol_fuzzer.py` | REAL implementation |
| 14 | `RedCheck246/redcheck/plugins/supply_chain/supply_chain_audit.py` | REAL implementation |
| 15 | `RedCheck246/redcheck/security/crypto.py` | Remove XOR fallback |
| 16 | `RedCheck246/redcheck/security/roe_validator.py` | Pydantic model return |
| 17 | `RedCheck246/redcheck/security/signature_verifier.py` | Async + Ed25519 |
| 18 | `.github/workflows/ci.yml` | Complete overhaul |
| 19 | `RedCheck246/README.md` | Comprehensive docs |
| 20 | `RedCheck246/requirements.txt` | All production deps |
| 21 | `RedCheck246/requirements-dev.txt` | All dev deps |

### Updated Files (5)

| # | Path | Change |
|---|------|--------|
| 1-5 | `tests/test_activation.py`, `test_plugins.py`, `test_policy_engine.py`, `test_recon_dryrun.py`, `test_security.py` | Use conftest fixtures, new models, new exceptions |

### Deleted Files (0)

No files deleted.

---

## EXECUTION ORDER

```
Phase 1  → Fix pyproject.toml, exceptions.py, py.typed, __init__.py
Phase 2  → models.py, config.py rewrite
Phase 3  → logging.py, audit.py rewrite
Phase 4  → cli.py rewrite, output.py
Phase 5  → Passive Recon (real)
Phase 6  → SAST Scanner (real)
Phase 7  → DAST Scanner (real)
Phase 8  → Protocol Fuzzer (real)
Phase 9  → Supply Chain Audit (real)
Phase 10 → Refactor policy_engine, activation_engine, orchestrator, base_plugin, security modules
Phase 11 → Complete test suite (conftest + 11 new test files + 5 updated)
Phase 12 → Docker (Dockerfile, compose, .dockerignore)
Phase 13 → CI/CD overhaul
Phase 14 → Infrastructure files (SECURITY.md, CODEOWNERS, pre-commit, Makefile, CONTRIBUTING, CHANGELOG)
Phase 15 → README + docs
Phase 16 → Final validation (all tests, mypy, ruff, bandit, build, docker, smoke test)
```

**Estimated files touched: 60 (54 original + 6 from Specifications)**  
**Estimated new lines of code: ~8,000-10,000**

---

## CONFIRMATION REQUIRED

**This plan now includes 21 binding specifications (Specs 1-21) that define every deterministic constraint:**

| Specs 1-8 | Enforcement contract, risk classification, fuzzing limits, runtime modes, concurrency safety, Docker hardening, supply chain safeguards, data retention |
|-----------|---|
| **Spec 9** | **Offensive capability controls (switchable, default-safe, operator-controlled)** |
| Specs 10-14 | Versioning, observability metrics, activation hardening, legal boundaries, compatibility |
| **Spec 15** | **RoE signature trust model (key storage, rotation, multi-signer, timestamp validation)** |
| **Spec 16** | **Target scope enforcement (hostname/IP/wildcard matching, redirect blocking, private IP protection)** |
| **Spec 17** | **Fuzzer payload boundaries (numerical limits, excluded techniques, response analysis constraints)** |
| **Spec 18** | **Evidence encryption key handling (HKDF-SHA256, per-file IV, AAD binding, mid-engagement rotation)** |
| **Spec 19** | **Metrics persistence (engagement-scoped, crash checkpoints, recovery on restart)** |
| **Spec 20** | **Windows permission handling (ACL fallback via icacls, SECURITY_WARNING severity)** |
| **Spec 21** | **Dependency resolution reproducibility (uv.lock mandatory in CI, hash verification)** |

**Reply "confirmed" to begin execution. I will work through all 16 phases sequentially, implementing every specification and creating every file listed above. No stubs. No placeholders. Everything functional.**
