"""RedCheck246 — SAST Plugin: Static Application Security Testing.

Analyzes source code for security vulnerabilities without execution.

Capabilities:
  1. Bandit Integration  — Python-specific security linting via bandit API
  2. Custom Pattern Scanner  — Regex-based detection of secrets, weak crypto, etc.
  3. Dependency File Scanner  — Unpinned deps, insecure URLs in requirements
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from redcheck.plugins.base_plugin import BasePlugin, PluginResult

# ---------------------------------------------------------------------------
# Custom regex patterns
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "hardcoded_api_key",
        "HIGH",
        re.compile(
            r"""(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)"""
            r"""\s*[=:]\s*['"]([A-Za-z0-9_\-]{16,})['"]""",
        ),
    ),
    (
        "hardcoded_password",
        "HIGH",
        re.compile(
            r"""(?i)(?:password|passwd|pwd|secret)\s*[=:]\s*['"]([^'"]{4,})['"]""",
        ),
    ),
    (
        "private_key",
        "CRITICAL",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        ),
    ),
    (
        "aws_access_key",
        "CRITICAL",
        re.compile(
            r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])",
        ),
    ),
    (
        "generic_token",
        "MEDIUM",
        re.compile(
            r"""(?i)(?:token|bearer)\s*[=:]\s*['"]([A-Za-z0-9_\-.]{20,})['"]""",
        ),
    ),
    (
        "hardcoded_ip",
        "LOW",
        re.compile(
            r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
        ),
    ),
    (
        "insecure_http",
        "MEDIUM",
        re.compile(
            r"""(?i)['"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)""",
        ),
    ),
    (
        "weak_hash",
        "MEDIUM",
        re.compile(
            r"""(?i)\b(?:hashlib\.md5|hashlib\.sha1|MD5|SHA1)\b""",
        ),
    ),
    (
        "eval_exec",
        "HIGH",
        re.compile(
            r"""\b(?:eval|exec)\s*\(""",
        ),
    ),
    (
        "security_todo",
        "INFO",
        re.compile(
            r"""(?i)#\s*(?:TODO|FIXME|HACK|XXX|SECURITY|VULN)""",
        ),
    ),
]

_DEP_UNPINNED_RE = re.compile(r"^([a-zA-Z0-9_-]+)\s*$", re.MULTILINE)
_DEP_INSECURE_URL = re.compile(r"^-i\s+http://", re.MULTILINE)

# Default directories excluded from SAST scans (S3-6).
_DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset(
    {
        "__pycache__",
        ".venv",
        "venv",
        ".env",
        "node_modules",
        ".git",
        ".hg",
        ".svn",
        "build",
        "dist",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".eggs",
        "*.egg-info",
    }
)


def _should_exclude_dir(
    dirname: str,
    exclude_dirs: frozenset[str] = _DEFAULT_EXCLUDE_DIRS,
) -> bool:
    """Return True if *dirname* should be skipped during SAST walks."""
    if dirname in exclude_dirs:
        return True
    # Handle glob-like patterns (e.g. "*.egg-info")
    return dirname.endswith(".egg-info")


# ---------------------------------------------------------------------------
# Scanner helpers
# ---------------------------------------------------------------------------


def _scan_file_patterns(file_path: Path) -> list[dict[str, Any]]:
    """Scan a single file with custom regex patterns."""
    findings: list[dict[str, Any]] = []
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return findings

    for line_no, line in enumerate(text.splitlines(), start=1):
        for pattern_name, severity, regex in _SECRET_PATTERNS:
            if regex.search(line):
                findings.append(
                    {
                        "type": f"sast_pattern_{pattern_name}",
                        "target": str(file_path),
                        "detail": f"Line {line_no}: {pattern_name} detected",
                        "data": {
                            "pattern": pattern_name,
                            "severity": severity,
                            "line": line_no,
                            "snippet": line.strip()[:120],
                        },
                    }
                )
    return findings


def _scan_bandit(paths: list[Path]) -> list[dict[str, Any]]:
    """Run bandit programmatically and collect findings."""
    findings: list[dict[str, Any]] = []
    try:
        from bandit.core import config as bandit_config  # type: ignore[import-untyped]
        from bandit.core import manager as bandit_manager  # type: ignore[import-untyped]
    except ImportError:
        findings.append(
            {
                "type": "sast_bandit",
                "target": "N/A",
                "detail": "bandit not installed — skipping bandit scan",
                "data": {"error": "missing_dependency"},
            }
        )
        return findings

    py_files = []
    for p in paths:
        if p.is_file() and p.suffix == ".py":
            py_files.append(str(p))
        elif p.is_dir():
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if not _should_exclude_dir(d)]
                for f in files:
                    if f.endswith(".py"):
                        py_files.append(os.path.join(root, f))

    if not py_files:
        return findings

    try:
        b_mgr = bandit_manager.BanditManager(
            bandit_config.BanditConfig(),
            agg_type="file",
        )
        b_mgr.discover_files(py_files)
        b_mgr.run_tests()

        severity_map = {
            "LOW": "LOW",
            "MEDIUM": "MEDIUM",
            "HIGH": "HIGH",
        }

        for issue in b_mgr.get_issue_list():
            findings.append(
                {
                    "type": "sast_bandit",
                    "target": issue.fname,
                    "detail": f"[{issue.test_id}] {issue.text} (line {issue.lineno})",
                    "data": {
                        "test_id": issue.test_id,
                        "severity": severity_map.get(issue.severity, "MEDIUM"),
                        "confidence": issue.confidence,
                        "line": issue.lineno,
                        "code": issue.get_code(max_lines=3, tabbed=False),
                    },
                }
            )
    except Exception as exc:
        findings.append(
            {
                "type": "sast_bandit",
                "target": "N/A",
                "detail": f"Bandit scan failed: {exc}",
                "data": {"error": str(exc)},
            }
        )
    return findings


def _scan_dependency_files(paths: list[Path]) -> list[dict[str, Any]]:
    """Check requirements.txt / pyproject.toml for unpinned deps, insecure URLs."""
    findings: list[dict[str, Any]] = []
    dep_files: list[Path] = []

    for p in paths:
        if p.is_file() and p.name in (
            "requirements.txt",
            "requirements-dev.txt",
            "requirements.in",
        ):
            dep_files.append(p)
        elif p.is_dir():
            for name in ("requirements.txt", "requirements-dev.txt", "requirements.in"):
                candidate = p / name
                if candidate.exists():
                    dep_files.append(candidate)

    for dep_file in dep_files:
        try:
            text = dep_file.read_text(encoding="utf-8")
        except Exception:  # noqa: S112
            continue

        # Unpinned dependencies
        for match in _DEP_UNPINNED_RE.finditer(text):
            pkg = match.group(1).strip()
            if pkg.startswith("#") or pkg.startswith("-"):
                continue
            findings.append(
                {
                    "type": "sast_dep_unpinned",
                    "target": str(dep_file),
                    "detail": f"Unpinned dependency: {pkg}",
                    "data": {"package": pkg, "severity": "MEDIUM"},
                }
            )

        # Insecure index URLs
        if _DEP_INSECURE_URL.search(text):
            findings.append(
                {
                    "type": "sast_dep_insecure_url",
                    "target": str(dep_file),
                    "detail": "Package index uses insecure HTTP",
                    "data": {"severity": "HIGH"},
                }
            )

    return findings


# ---------------------------------------------------------------------------
# Plugin class
# ---------------------------------------------------------------------------


class SASTPlugin(BasePlugin):
    """Static Application Security Testing — source code analysis."""

    name = "sast-scanner"
    version = "0.2.0"
    description = "Static application security testing — source code analysis"
    requires_authorization = True
    category = "sast"

    def execute(self, context: dict) -> PluginResult:
        """Scan target paths for security issues."""
        raw_paths = context.get("target_paths", context.get("paths", ["."]))
        if isinstance(raw_paths, str):
            raw_paths = [raw_paths]
        paths = [Path(p).resolve() for p in raw_paths]

        all_findings: list[dict[str, Any]] = []
        errors: list[str] = []

        # 1. Bandit scan
        try:
            all_findings.extend(_scan_bandit(paths))
        except Exception as exc:
            errors.append(f"Bandit scan error: {exc}")

        # 2. Custom pattern scan
        try:
            for p in paths:
                if p.is_file():
                    all_findings.extend(_scan_file_patterns(p))
                elif p.is_dir():
                    for root, dirs, files in os.walk(p):
                        dirs[:] = [d for d in dirs if not _should_exclude_dir(d)]
                        for fname in files:
                            if fname.endswith(
                                (
                                    ".py",
                                    ".js",
                                    ".ts",
                                    ".yaml",
                                    ".yml",
                                    ".json",
                                    ".toml",
                                    ".cfg",
                                    ".ini",
                                    ".env",
                                )
                            ):
                                all_findings.extend(_scan_file_patterns(Path(root) / fname))
        except Exception as exc:
            errors.append(f"Pattern scan error: {exc}")

        # 3. Dependency file scan
        try:
            all_findings.extend(_scan_dependency_files(paths))
        except Exception as exc:
            errors.append(f"Dependency scan error: {exc}")

        # Deduplicate findings by (type, target, line)
        seen: set[tuple[str, str, int]] = set()
        deduped: list[dict[str, Any]] = []
        for f in all_findings:
            key = (f.get("type", ""), f.get("target", ""), f.get("data", {}).get("line", 0))
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=deduped,
            errors=errors,
            metadata={
                "scan_paths": [str(p) for p in paths],
                "total_findings": len(deduped),
                "modules": ["bandit", "pattern_scanner", "dependency_scanner"],
            },
        )

    def dry_run(self, context: dict) -> PluginResult:
        """Simulate execution."""
        raw_paths = context.get("target_paths", context.get("paths", ["."]))
        if isinstance(raw_paths, str):
            raw_paths = [raw_paths]
        return PluginResult(
            plugin_name=self.name,
            success=True,
            metadata={
                "mode": "dry-run",
                "scan_paths": raw_paths,
                "modules": ["bandit", "pattern_scanner", "dependency_scanner"],
                "description": (
                    "Would scan source files with bandit, "
                    "custom regex patterns (secrets, weak crypto, eval/exec), "
                    "and dependency file checks (unpinned deps, insecure URLs)"
                ),
            },
        )
