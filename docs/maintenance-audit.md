# RedCheck246 Maintenance Audit — Session Reference

**Branch:** `dev/redcheck-architecture-bootstrap-20260219-134306`  
**HEAD:** `c3afcc1`  
**Date:** 2025-07-14  

---

## 1. Package Version Audit

| Package | Installed | Bound | Latest (PyPI) | Status |
|---------|-----------|-------|---------------|--------|
| PyYAML | 6.0.3 | >=6.0,<7.0 | 6.0.3 | ✅ Stable |
| cryptography | 43.0.3 | >=43.0,<47.0 | 46.0.5 | ✅ Stable |
| pydantic | 2.12.5 | >=2.9,<3.0 | — | ✅ Stable |
| pydantic-settings | 2.13.1 | >=2.6,<3.0 | — | ✅ Stable |
| typer | 0.24.0 | >=0.12,<1.0 | — | ✅ Stable |
| rich | 13.9.4 | >=13.9,<15.0 | — | ✅ Stable |
| structlog | 25.5.0 | >=24.4,<26.0 | — | ✅ Stable |
| httpx | 0.28.1 | >=0.27,<1.0 | — | ✅ Stable |
| dnspython | 2.8.0 | >=2.7,<3.0 | — | ✅ Stable |
| python-whois | 0.9.6 | >=0.9,<1.0 | — | ✅ Stable |
| anyio | 4.12.1 | >=4.0,<5.0 | — | ✅ Stable |
| argon2-cffi | 23.1.0 | >=23.1,<26.0 | — | ✅ Stable |
| networkx | 3.6.1 | >=3.0,<4.0 | — | ✅ Stable |
| jinja2 | 3.1.6 | >=3.1,<4.0 | — | ✅ Stable |
| pytest | 8.4.2 | >=8.3,<10.0 | — | ✅ Stable |
| pytest-cov | 5.0.0 | >=5.0,<8.0 | — | ✅ Stable |
| pytest-asyncio | 0.26.0 | >=0.24,<2.0 | — | ✅ Stable |
| ruff | 0.15.1 | >=0.8,<1.0 | — | ✅ Stable |
| mypy | 1.19.1 | >=1.13,<2.0 | — | ✅ Stable |
| bandit | 1.9.3 | >=1.8,<2.0 | — | ✅ Stable |
| **mutmut** | **2.5.1** | **>=2.4,<4.0** | **3.5.0** | ⚠️ **`<4.0` allows 3.x which breaks CI** |

### mutmut 2.x vs 3.x

- **mutmut 2.x** (last: 2.5.1, Aug 2024): Has `--paths-to-mutate`, `--tests-dir`, `--runner` CLI options.
- **mutmut 3.x** (latest: 3.5.0, Feb 2026): Completely new CLI. Removed `--paths-to-mutate`. Requires `rich>=14.2` (via textual). Doesn't support Windows. Versions 3.0.0-3.0.4 were **yanked**.
- **Fix:** Pin to `>=2.4,<3.0` in both `pyproject.toml` and CI `pip install`.

---

## 2. CodeQL Alert #18

- **Alert:** `py/weak-sensitive-data-hashing` — "Use of a broken or weak cryptographic hashing algorithm on sensitive data"
- **File:** `redcheck/plugins/osint/breach_lookup.py:45`
- **Current code:**
  ```python
  digest = hashlib.new(  # noqa: S324
      "sha1",
      octets,
      usedforsecurity=False,  # nosec B324
  )
  ```
- **Context:** HIBP Passwords API **requires** SHA-1 as lookup key. This is a protocol-mandated format, not a security mechanism.
- **Previous fix attempts:** `usedforsecurity=False`, variable renaming, function renaming — CodeQL still flags it.
- **Solution:** Add CodeQL inline suppression: `# lgtm[py/weak-sensitive-data-hashing]`

---

## 3. Coverage Report (Current: 74%)

**Target: 90% (need ~597 more statements covered)**

| Module | Stmts | Miss | Branch | BrPart | Cover | Missing Lines |
|--------|-------|------|--------|--------|-------|---------------|
| `__main__.py` | 3 | 3 | 2 | 0 | 0% | 3-6 |
| `logging.py` | 30 | 30 | 8 | 0 | 0% | 8-106 |
| `sast_scanner.py` | 117 | 72 | 60 | 4 | 34% | 112-113, 136-201, 216-220, 225-226, 232, 244, 272-327, 343 |
| `audit.py` | 159 | 86 | 38 | 4 | 40% | 42-51, 56-63, 68-74, 106, 114-123, 136, 142, 146-150, 190-192, 206, 219-220, 241-263, 275-313, 323 |
| `cli.py` | 198 | 97 | 50 | 4 | 47% | 147, 162, 167-206, 219-220, 250, 275-303, 316->319, 346-367, 381-407, 420-433, 443-447, 451 |
| `dast_scanner.py` | 188 | 76 | 72 | 6 | 48% | 38, 71-126, 160-162, 172-182, 193-226, 262-267, 296-320, 353-354, 372, 393-414, 450, 455-457, 502-503 |
| `output.py` | 65 | 30 | 18 | 1 | 48% | 36-61, 91-117, 123-124 |
| `osv_client.py` | 81 | 34 | 28 | 3 | 51% | 36, 49-82, 101->103, 126-129, 147-153 |
| `network_scan.py` | 133 | 52 | 52 | 5 | 53% | 45-47, 100, 143, 165-273, 295-296 |
| `signature_verifier.py` | 124 | 56 | 38 | 13 | 54% | 50, 53, 60, 71-84, 88-120, 136, 149, 154-156, 172, 179, 184-191, 205, 207, 213, 215-218 |
| `policy_engine.py` | 110 | 44 | 48 | 11 | 55% | 48-49, 52, 67, 70, 81-82, 86, 88, 94, 110-115, 149, 156-189, 208 |
| `ct_watch.py` | 69 | 23 | 16 | 2 | 59% | 95-138 |
| `passive_recon.py` | 201 | 57 | 68 | 14 | 65% | 46, 60, 82, 95-111, 123-142, 151, 226-254, 273, 280, 283, 302, 307, 310, 345, 349-364, 383-390, 413-414 |
| `coverage_validator.py` | 105 | 26 | 28 | 3 | 65% | 295-307, 314, 319-337 |
| `protocol_fuzzer.py` | 142 | 38 | 46 | 6 | 66% | 60, 82, 102, 112-169, 192-202, 226-241, 286-287, 305-308, 340, 346-350, 373-376 |
| `roe_validator.py` | 77 | 22 | 40 | 14 | 68% | 55, 65-67, 70, 79, 84, 86, 91, 97-98, 101, 105, 111, 136-138, 154, 156-160 |
| `safe_poc.py` | 117 | 31 | 36 | 3 | 70% | 44-46, 87-90, 136-161, 227-228, 247, 266-267 |
| `exceptions.py` | 99 | 29 | 0 | 0 | 71% | 19, 49-51, 82-84, 127-129, 153-154, 180-182, 220-221, 251-253, 289-291, 312-314, 336-341 |
| `supply_chain_audit.py` | 153 | 47 | 48 | 6 | 72% | 102, 141-149, 157-161, 198, 220-234, 250, 326-327, 343-379, 382-384 |
| `breach_lookup.py` | 67 | 15 | 12 | 2 | 73% | 70, 76-77, 128-159 |

**Already well-covered (>80%):** `__init__.py`, `config.py`, `constants.py`, `activation_engine.py`, `audit_export.py`, `metrics.py`, `multi_tenant.py`, `orchestrator.py`, `rbac.py`, `reporting.py`, `sbom_integration.py`, `scope_validator.py`, `token_bucket.py`, `topology.py`, `models.py`, `base_plugin.py`, `gpu_adapter.py`, `hash_strength.py`, `password_policy.py`, `auth_tester.py`, `crawler.py`, `injection_sim.py`, `attack_graph.py`, `cve_mapper.py`, `typosquat.py`, `packet_craft.py`, `parsers.py`, `crypto.py`, `_http.py`, `wordlists.py`

---

## 4. mutmut CI Failure

**Root cause:** CI does `pip install mutmut` (gets latest 3.x), but commands use 2.x syntax.

**CI mutation job (ci.yml lines 108-140):**
```yaml
- name: Install dependencies
  run: |
    pip install -e ".[dev]"
    pip install mutmut     # ← gets 3.x from PyPI

- name: Run mutation tests on policy_engine
  run: |
    mutmut run --paths-to-mutate=redcheck/core/policy_engine.py \
      --tests-dir=tests/ --runner="pytest -x -q" || true
    mutmut results         # ← 2.x syntax, fails in 3.x
```

**Fix:**
1. Pin `mutmut>=2.4,<3.0` in `pyproject.toml`
2. Change CI `pip install mutmut` → `pip install "mutmut>=2.4,<3.0"`

---

## 5. Testing Conventions

- **Framework:** pytest
- **Assertion:** Plain `assert` (no assertEqual)
- **Organization:** Classes group related tests
- **Fixtures:** Shared via `tests/conftest.py`; autouse `clean_registry` and `restore_plugins`
- **CLI:** `typer.testing.CliRunner`
- **HTTP mocking:** Custom `MockTransport` for httpx
- **Function mocking:** `unittest.mock.patch` + `AsyncMock`
- **Async tests:** Inner `async def _run()` + `asyncio.run(_run())` (no pytest-asyncio markers)
- **Plugin test pattern:** Always test: metadata, dry-run, no-input edge case, execution with mocks
