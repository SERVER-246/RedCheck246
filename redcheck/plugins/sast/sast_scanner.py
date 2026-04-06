"""RedCheck246 — SAST Plugin: Static Application Security Testing.

Analyzes source code for security vulnerabilities without execution.

Capabilities:
  1. Bandit Integration  — Python-specific security linting via bandit API
  2. Custom Pattern Scanner  — Regex-based detection of secrets, weak crypto, etc.
  3. Dependency File Scanner  — Unpinned deps, insecure URLs in requirements
"""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path
from typing import Any

from redcheck.plugins.base_plugin import BasePlugin, PluginResult, plugin_dependencies

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
# Test-directory exclusion (Phase 5 — opt-in via context key)
# ---------------------------------------------------------------------------

_ADDITIONAL_EXCLUDE_DIRS: frozenset[str] = frozenset(
    {
        "tests",
        "test",
        "fixtures",
        "testdata",
        "test_data",
        "mocks",
        "stubs",
        "snapshots",
    }
)

_ADDITIONAL_EXCLUDE_PATTERNS: tuple[str, ...] = (
    "_test.py",
    "test_",
    "conftest.py",
)


def _is_test_file(filepath: str) -> bool:
    """Return True if *filepath* looks like a test file or fixture."""
    parts = Path(filepath).parts
    if any(p in _ADDITIONAL_EXCLUDE_DIRS for p in parts):
        return True
    name = Path(filepath).name
    return any(name.startswith(p) or name.endswith(p) for p in _ADDITIONAL_EXCLUDE_PATTERNS)


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
        from bandit.core import config as bandit_config
        from bandit.core import manager as bandit_manager
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
# N1 — Noise reduction pipeline helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

_SEVERITY_WEIGHT: dict[str, float] = {
    "info": 1.0,
    "low": 2.0,
    "medium": 3.0,
    "high": 4.0,
    "critical": 5.0,
}

_CONFIDENCE_WEIGHT: dict[str, float] = {
    "HIGH": 1.0,
    "MEDIUM": 0.7,
    "LOW": 0.4,
}

_HIGH_EXPLOIT_PATTERNS: frozenset[str] = frozenset(
    {
        "hardcoded_password",
        "private_key",
        "aws_access_key",
        "eval_exec",
        "hardcoded_api_key",
    }
)

_LOW_EXPLOIT_PATTERNS: frozenset[str] = frozenset({"hardcoded_ip", "security_todo"})

_DEFAULT_VENDOR_GLOBS: list[str] = [
    "**/vendor/**",
    "**/generated/**",
    "**/migrations/**",
    "**/*_pb2.py",
    "**/*_generated.*",
    "**/.tox/**",
]


def _filter_noise(
    findings: list[dict[str, Any]],
    min_severity: str = "medium",
    min_confidence: str = "MEDIUM",
) -> list[dict[str, Any]]:
    """Drop low-severity / low-confidence Bandit findings.

    Only applies to ``sast_bandit`` findings — custom pattern and
    dependency findings are kept regardless.
    """
    sev_threshold = _SEVERITY_ORDER.get(min_severity.lower(), 2)
    conf_threshold = _CONFIDENCE_WEIGHT.get(min_confidence, 0.7)
    result: list[dict[str, Any]] = []
    for f in findings:
        if f.get("type") == "sast_bandit":
            data = f.get("data", {})
            sev = _SEVERITY_ORDER.get(data.get("severity", "MEDIUM").lower(), 2)
            conf = _CONFIDENCE_WEIGHT.get(data.get("confidence", "MEDIUM"), 0.7)
            if sev < sev_threshold and conf < conf_threshold:
                continue
        result.append(f)
    return result


def _exclude_vendor_paths(
    findings: list[dict[str, Any]],
    patterns: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Remove findings whose target matches vendor/generated glob patterns."""
    pats = patterns if patterns is not None else _DEFAULT_VENDOR_GLOBS
    if not pats:
        return findings
    result: list[dict[str, Any]] = []
    for f in findings:
        target = f.get("target", "").replace("\\", "/")
        if not any(fnmatch.fnmatch(target, p) for p in pats):
            result.append(f)
    return result


def _dedup_by_rule(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group findings by rule ID and keep highest-severity exemplar.

    For Bandit findings the group key is ``data["test_id"]``.
    For custom pattern findings the key is ``data["pattern"]``.
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    passthrough: list[dict[str, Any]] = []
    for f in findings:
        data = f.get("data", {})
        ftype = f.get("type", "")
        rule_id = data.get("test_id") or data.get("pattern")
        if rule_id:
            key = f"{ftype}:{rule_id}"
            groups.setdefault(key, []).append(f)
        else:
            passthrough.append(f)

    result: list[dict[str, Any]] = list(passthrough)
    for group in groups.values():
        # Pick highest-severity exemplar
        group.sort(
            key=lambda x: _SEVERITY_ORDER.get(
                x.get("data", {}).get("severity", "info").lower(),
                0,
            ),
            reverse=True,
        )
        exemplar = group[0]
        exemplar.setdefault("data", {})["occurrence_count"] = len(group)
        exemplar["data"]["occurrence_files"] = sorted(
            {g.get("target", "") for g in group},
        )[:5]
        result.append(exemplar)
    return result


def _score_priority(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Assign ``priority_score`` and sort descending."""
    for f in findings:
        data = f.get("data", {})
        sev_w = _SEVERITY_WEIGHT.get(data.get("severity", "info").lower(), 1.0)
        conf_w = _CONFIDENCE_WEIGHT.get(data.get("confidence", "HIGH"), 1.0)
        pattern = data.get("pattern", "")
        if pattern in _HIGH_EXPLOIT_PATTERNS:
            exploit = 1.5
        elif pattern in _LOW_EXPLOIT_PATTERNS:
            exploit = 0.5
        else:
            exploit = 1.0
        data["priority_score"] = round(sev_w * conf_w * exploit, 2)
    findings.sort(
        key=lambda x: x.get("data", {}).get("priority_score", 0),
        reverse=True,
    )
    return findings


def _build_noise_summary(
    original_count: int,
    after_filter: int,
    after_vendor: int,
    after_dedup: int,
    final_count: int,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a metadata summary of the noise-reduction pipeline."""
    cats: dict[str, int] = {}
    for f in findings:
        ftype = f.get("type", "unknown")
        cats[ftype] = cats.get(ftype, 0) + 1

    rule_counts: dict[str, int] = {}
    for f in findings:
        data = f.get("data", {})
        rule = data.get("test_id") or data.get("pattern") or "other"
        rule_counts[rule] = rule_counts.get(rule, 0) + data.get("occurrence_count", 1)
    top_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "original_count": original_count,
        "after_severity_filter": after_filter,
        "after_vendor_exclusion": after_vendor,
        "after_rule_dedup": after_dedup,
        "final_count": final_count,
        "truncated": final_count < after_dedup,
        "category_counts": cats,
        "top_rules": [{"rule": r, "count": c} for r, c in top_rules],
    }


# ---------------------------------------------------------------------------
# Plugin class
# ---------------------------------------------------------------------------


@plugin_dependencies(
    required=[],
    optional=[],
    provides=["code_vulns", "hardcoded_creds"],
)
class SASTPlugin(BasePlugin):
    """Static Application Security Testing — source code analysis."""

    name = "sast-scanner"
    version = "0.2.0"
    description = "Static application security testing — source code analysis"
    requires_authorization = True
    category = "sast"

    def execute(self, context: dict[str, Any]) -> PluginResult:
        """Scan target paths for security issues."""
        raw_paths = context.get("target_paths", context.get("paths", ["."]))
        if isinstance(raw_paths, str):
            raw_paths = [raw_paths]
        paths = [Path(p).resolve() for p in raw_paths]

        exclude_test_dirs = bool(context.get("sast_exclude_test_dirs", False))
        exclude_dirs = _DEFAULT_EXCLUDE_DIRS
        if exclude_test_dirs:
            exclude_dirs = _DEFAULT_EXCLUDE_DIRS | _ADDITIONAL_EXCLUDE_DIRS

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
                    if exclude_test_dirs and _is_test_file(str(p)):
                        continue
                    all_findings.extend(_scan_file_patterns(p))
                elif p.is_dir():
                    for root, dirs, files in os.walk(p):
                        dirs[:] = [d for d in dirs if not _should_exclude_dir(d, exclude_dirs)]
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
                                fpath = Path(root) / fname
                                if exclude_test_dirs and _is_test_file(str(fpath)):
                                    continue
                                all_findings.extend(_scan_file_patterns(fpath))
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

        # Severity de-escalation for test-file findings
        if exclude_test_dirs:
            severity_downgrade = {
                "critical": "high",
                "high": "medium",
                "medium": "low",
                "low": "info",
            }
            for finding in deduped:
                if _is_test_file(finding.get("target", "")):
                    finding.setdefault("data", {})["likely_false_positive"] = True
                    orig = finding.get("severity", "info")
                    finding["severity"] = severity_downgrade.get(orig, orig)

        original_count = len(deduped)

        # N1 noise-reduction pipeline
        min_sev = str(context.get("sast_min_severity", "medium")).lower()
        min_conf = str(context.get("sast_min_confidence", "MEDIUM"))
        filtered = _filter_noise(deduped, min_severity=min_sev, min_confidence=min_conf)
        after_filter = len(filtered)

        vendor_pats: list[str] | None = context.get("sast_exclude_patterns")
        filtered = _exclude_vendor_paths(filtered, patterns=vendor_pats)
        after_vendor = len(filtered)

        filtered = _dedup_by_rule(filtered)
        after_dedup = len(filtered)

        filtered = _score_priority(filtered)

        max_findings = int(context.get("sast_max_findings", 200))
        final = filtered[:max_findings]

        summary = _build_noise_summary(
            original_count,
            after_filter,
            after_vendor,
            after_dedup,
            len(final),
            final,
        )

        self.capture_evidence(
            context,
            f"{len(final)} sast findings".encode(),
            "sast_scan",
        )
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=final,
            errors=errors,
            metadata={
                "scan_paths": [str(p) for p in paths],
                "total_findings": len(final),
                "modules": ["bandit", "pattern_scanner", "dependency_scanner"],
                "noise_reduction": summary,
            },
        )

    def dry_run(self, context: dict[str, Any]) -> PluginResult:
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
