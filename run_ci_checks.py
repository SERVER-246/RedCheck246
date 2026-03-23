#!/usr/bin/env python3
"""RedCheck246 — Local CI Validation Script.

Mirrors the GitHub Actions CI pipeline locally so you can catch failures
before pushing.  Runs all checks in a single process — no terminal spam.

Usage:
    python run_ci_checks.py            # Run all checks
    python run_ci_checks.py --quick    # Skip pytest (lint + security only)
    python run_ci_checks.py --no-build # Skip package build step
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration — mirrors .github/workflows/ci.yml
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable

# ANSI colour helpers (Windows 10+ and all Unix terminals)
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _header(title: str) -> None:
    width = 60
    print(f"\n{CYAN}{BOLD}{'─' * width}{RESET}")
    print(f"{CYAN}{BOLD}  {title}{RESET}")
    print(f"{CYAN}{BOLD}{'─' * width}{RESET}")


def _run(
    label: str,
    cmd: list[str],
    *,
    cwd: Path = REPO_ROOT,
    allow_fail: bool = False,
) -> tuple[bool, float]:
    """Run a command, stream output live, return (passed, elapsed_secs)."""
    print(f"\n{BOLD}▸ {label}{RESET}")
    print(f"  $ {' '.join(cmd)}\n")

    start = time.monotonic()
    result = subprocess.run(
        cmd,
        cwd=str(cwd),
        text=True,
    )
    elapsed = time.monotonic() - start

    passed = result.returncode == 0
    if passed:
        print(f"\n  {GREEN}✓ PASS{RESET}  ({elapsed:.1f}s)")
    elif allow_fail:
        print(f"\n  {YELLOW}⚠ WARN{RESET}  (exit {result.returncode}, {elapsed:.1f}s) — non-blocking")
    else:
        print(f"\n  {RED}✗ FAIL{RESET}  (exit {result.returncode}, {elapsed:.1f}s)")

    return passed or allow_fail, elapsed


def main() -> int:
    parser = argparse.ArgumentParser(description="Local CI validation for RedCheck246")
    parser.add_argument("--quick", action="store_true", help="Skip pytest, mutmut, and build (lint + security only)")
    parser.add_argument("--no-build", action="store_true", help="Skip package build verification")
    parser.add_argument("--no-mutmut", action="store_true", help="Skip mutation testing (slow)")
    args = parser.parse_args()

    results: list[tuple[str, bool, float]] = []
    overall_start = time.monotonic()

    # ── 1. Lint & Format ──────────────────────────────────────────────
    _header("1/6  Lint & Format")

    ok, t = _run("Ruff lint", [PYTHON, "-m", "ruff", "check", "redcheck/", "tests/"])
    results.append(("Ruff lint", ok, t))

    ok, t = _run("Ruff format", [PYTHON, "-m", "ruff", "format", "--check", "redcheck/", "tests/"])
    results.append(("Ruff format", ok, t))

    ok, t = _run("Mypy type check", [PYTHON, "-m", "mypy", "--strict", "redcheck/"], allow_fail=True)
    results.append(("Mypy (non-blocking)", ok, t))

    # ── 2. Security Scan ──────────────────────────────────────────────
    _header("2/6  Security Scan")

    ok, t = _run("Bandit", [PYTHON, "-m", "bandit", "-r", "-c", "pyproject.toml", "redcheck/"])
    results.append(("Bandit", ok, t))

    ok, t = _run("pip-audit", [PYTHON, "-m", "pip_audit", "--strict"], allow_fail=True)
    results.append(("pip-audit (non-blocking)", ok, t))

    # Secret detection (mirrors CI grep)
    print(f"\n{BOLD}▸ Secret detection{RESET}")
    secret_start = time.monotonic()
    secret_ok = True
    for pattern, label in [
        (r"password\s*=\s*['\"]", "hardcoded passwords"),
        (r"secret\s*=\s*['\"][^'\"]*['\"]", "hardcoded secrets"),
    ]:
        r = subprocess.run(
            [PYTHON, "-c", f"""
import re, pathlib, sys
hits = []
for p in pathlib.Path('redcheck').rglob('*.py'):
    for i, line in enumerate(p.read_text(encoding='utf-8').splitlines(), 1):
        if re.search(r'''{pattern}''', line) and 'test' not in str(p) and '#' not in line.split('=')[0]:
            hits.append(f'  {{p}}:{{i}}: {{line.strip()}}')
if hits:
    print(f'WARNING: Possible {label} found:')
    print(chr(10).join(hits))
    sys.exit(1)
else:
    print(f'No {label} detected')
"""],
            cwd=str(REPO_ROOT),
            text=True,
        )
        if r.returncode != 0:
            secret_ok = False
    secret_t = time.monotonic() - secret_start
    if secret_ok:
        print(f"\n  {GREEN}✓ PASS{RESET}  ({secret_t:.1f}s)")
    else:
        print(f"\n  {RED}✗ FAIL{RESET}  ({secret_t:.1f}s)")
    results.append(("Secret detection", secret_ok, secret_t))

    # ── 3. Tests ──────────────────────────────────────────────────────
    if not args.quick:
        _header("3/6  Tests")

        ok, t = _run(
            "Pytest (full suite)",
            [
                PYTHON, "-m", "pytest",
                "--cov=redcheck", "--cov-branch",
                "--cov-report=term-missing:skip-covered",
                "--cov-fail-under=90",
                "tests/", "-v", "--tb=short",
            ],
        )
        results.append(("Pytest", ok, t))
    else:
        results.append(("Pytest", True, 0.0))
        print(f"\n{YELLOW}⚠ Skipping pytest (--quick){RESET}")

    # ── 4. Mutation Testing ────────────────────────────────────────────
    if not args.quick and not args.no_mutmut:
        _header("4/6  Mutation Testing (mutmut)")

        mutmut_targets = [
            "redcheck/core/policy_engine.py",
            "redcheck/core/orchestrator.py",
            "redcheck/core/scope_validator.py",
        ]
        for target in mutmut_targets:
            name = Path(target).stem
            ok, t = _run(
                f"mutmut — {name}",
                [PYTHON, "-m", "mutmut", "run", f"--paths-to-mutate={target}", "-s"],
                allow_fail=True,
            )
            results.append((f"mutmut {name} (non-blocking)", ok, t))

        ok, t = _run("mutmut results", [PYTHON, "-m", "mutmut", "results"], allow_fail=True)
        results.append(("mutmut summary (non-blocking)", ok, t))
    else:
        if not args.quick:
            print(f"\n{YELLOW}⚠ Skipping mutmut (--no-mutmut){RESET}")

    # ── 5. Build & Verify ─────────────────────────────────────────────
    if not args.no_build and not args.quick:
        _header("5/6  Build & Verify Package")

        ok, t = _run("Build package", [PYTHON, "-m", "build"])
        results.append(("Build", ok, t))

        if ok:
            # Find the built wheel
            wheels = list((REPO_ROOT / "dist").glob("*.whl"))
            if wheels:
                latest = max(wheels, key=lambda p: p.stat().st_mtime)
                ok2, t2 = _run(
                    "Verify wheel installs",
                    [PYTHON, "-m", "pip", "install", "--force-reinstall", str(latest), "-q"],
                )
                results.append(("Wheel install", ok2, t2))
                ok3, t3 = _run("Smoke test", [PYTHON, "-m", "redcheck", "--version"])
                results.append(("Smoke test", ok3, t3))
            else:
                results.append(("Wheel install", False, 0.0))
    else:
        if not args.quick:
            print(f"\n{YELLOW}⚠ Skipping build (--no-build){RESET}")

    # ── 6. Summary ────────────────────────────────────────────────────
    _header("6/6  Summary")

    total_time = time.monotonic() - overall_start
    any_fail = False

    for name, ok, t in results:
        icon = f"{GREEN}✓{RESET}" if ok else f"{RED}✗{RESET}"
        time_str = f"{t:.1f}s" if t > 0 else "skip"
        print(f"  {icon}  {name:<30s}  {time_str}")
        if not ok:
            any_fail = True

    print(f"\n  Total: {total_time:.1f}s")

    if any_fail:
        print(f"\n{RED}{BOLD}  ✗ CI WOULD FAIL — fix issues above before pushing{RESET}\n")
        return 1
    else:
        print(f"\n{GREEN}{BOLD}  ✓ ALL CHECKS PASSED — safe to push{RESET}\n")
        return 0


if __name__ == "__main__":
    sys.exit(main())
