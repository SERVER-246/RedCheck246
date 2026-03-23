"""RedCheck246 — Supply Chain Plugin: Dependency and Supply Chain Analysis.

Scans project dependencies for known vulnerabilities, license issues,
typosquatting indicators, and generates an SBOM.

Capabilities:
  1. Dependency Parsing    — requirements.txt, pyproject.toml, package.json
  2. Vulnerability Scanner — OSV.dev API (batched, rate-limited, degradable)
  3. License Compliance    — PyPI metadata check, copyleft flagging
  4. Typosquatting Detect  — Levenshtein distance against popular packages
  5. SBOM Generation       — CycloneDX-compatible JSON output
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx

from redcheck.plugins.base_plugin import BasePlugin, PluginResult
from redcheck.plugins.supply_chain.osv_client import OSVClient, severity_from_cvss
from redcheck.plugins.supply_chain.parsers import (
    discover_dependency_files,
    parse_dependency_file,
)

_PYPI_TIMEOUT = 10.0

# Top popular PyPI packages (subset for typosquatting check)
_POPULAR_PACKAGES: list[str] = [
    "requests",
    "flask",
    "django",
    "numpy",
    "pandas",
    "scipy",
    "boto3",
    "urllib3",
    "setuptools",
    "pip",
    "certifi",
    "charset-normalizer",
    "idna",
    "pyyaml",
    "cryptography",
    "jinja2",
    "markupsafe",
    "click",
    "pillow",
    "six",
    "python-dateutil",
    "pytz",
    "packaging",
    "wheel",
    "attrs",
    "cffi",
    "pycparser",
    "colorama",
    "aiohttp",
    "yarl",
    "multidict",
    "frozenlist",
    "aiosignal",
    "httpx",
    "httpcore",
    "anyio",
    "sniffio",
    "pydantic",
    "typer",
    "rich",
    "structlog",
    "fastapi",
    "uvicorn",
    "starlette",
    "sqlalchemy",
    "alembic",
    "celery",
    "redis",
    "psycopg2",
    "pymongo",
    "elasticsearch",
    "pytest",
    "tox",
    "black",
    "mypy",
    "ruff",
    "bandit",
    "flake8",
    "isort",
    "pre-commit",
]


def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost))
        prev = curr
    return prev[len(b)]


# ---------------------------------------------------------------------------
# Individual scan functions
# ---------------------------------------------------------------------------


async def scan_vulnerabilities(
    deps: list[dict[str, str]],
) -> list[dict[str, Any]]:
    """Query OSV for known vulnerabilities in *deps*."""
    findings: list[dict[str, Any]] = []
    client = OSVClient()

    results = await client.query_batch(
        [
            {
                "name": d["name"],
                "version": d["version"],
                "ecosystem": d.get("ecosystem", "PyPI"),
            }
            for d in deps
        ]
    )

    for result in results:
        pkg = result.get("package", "?")
        ver = result.get("version", "?")

        if result.get("degraded"):
            findings.append(
                {
                    "type": "supply_chain_api_degraded",
                    "target": pkg,
                    "detail": f"OSV API degraded for {pkg}=={ver}: {result.get('reason', '')}",
                    "data": {"severity": "INFO", "degraded": True, "package": pkg, "version": ver},
                }
            )
            continue

        for vuln in result.get("vulns", []):
            vuln_id = vuln.get("id", "?")
            summary = vuln.get("summary", "No summary")
            severity_data = vuln.get("severity", [])
            cvss_score = None
            for sev in severity_data:
                if sev.get("type") == "CVSS_V3":
                    try:  # noqa: SIM105
                        cvss_score = float(sev.get("score", 0))
                    except (ValueError, TypeError):
                        pass

            findings.append(
                {
                    "type": "supply_chain_vulnerability",
                    "target": f"{pkg}=={ver}",
                    "detail": f"{vuln_id}: {summary}",
                    "data": {
                        "severity": severity_from_cvss(cvss_score),
                        "vuln_id": vuln_id,
                        "summary": summary,
                        "cvss": cvss_score,
                        "package": pkg,
                        "version": ver,
                        "aliases": vuln.get("aliases", []),
                        "affected": vuln.get("affected", []),
                    },
                }
            )

    return findings


async def check_licenses(
    deps: list[dict[str, str]],
) -> list[dict[str, Any]]:
    """Check license metadata from PyPI for Python packages."""
    findings: list[dict[str, Any]] = []
    copyleft = {"GPL", "AGPL", "LGPL", "MPL", "EUPL", "SSPL", "OSL"}

    pypi_deps = [d for d in deps if d.get("ecosystem", "PyPI") == "PyPI"]

    async with httpx.AsyncClient(timeout=_PYPI_TIMEOUT) as client:
        for dep in pypi_deps[:50]:  # cap to avoid API abuse
            try:
                resp = await client.get(f"https://pypi.org/pypi/{dep['name']}/json")
                if resp.status_code != 200:
                    continue
                info = resp.json().get("info", {})
                license_val = info.get("license", "") or ""
                classifier_license = ""
                for classifier in info.get("classifiers", []):
                    if "License ::" in classifier:
                        classifier_license = classifier.split("::")[-1].strip()
                        break

                effective_license = license_val or classifier_license
                if not effective_license or effective_license.lower() in ("unknown", ""):
                    findings.append(
                        {
                            "type": "supply_chain_license_unknown",
                            "target": dep["name"],
                            "detail": f"Unknown or missing license for {dep['name']}",
                            "data": {"severity": "LOW", "package": dep["name"]},
                        }
                    )
                else:
                    for copyleft_kw in copyleft:
                        if copyleft_kw.lower() in effective_license.lower():
                            findings.append(
                                {
                                    "type": "supply_chain_copyleft_license",
                                    "target": dep["name"],
                                    "detail": f"Copyleft license detected: {effective_license}",
                                    "data": {
                                        "severity": "MEDIUM",
                                        "package": dep["name"],
                                        "license": effective_license,
                                    },
                                }
                            )
                            break
            except Exception:  # noqa: S112
                continue

    return findings


def check_typosquatting(deps: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Flag packages that are suspiciously similar to popular ones."""
    findings: list[dict[str, Any]] = []
    for dep in deps:
        name = dep["name"].lower().replace("-", "_")
        for popular in _POPULAR_PACKAGES:
            pop_norm = popular.lower().replace("-", "_")
            if name == pop_norm:
                continue
            dist = _levenshtein(name, pop_norm)
            if 0 < dist <= 2:
                findings.append(
                    {
                        "type": "supply_chain_typosquat",
                        "target": dep["name"],
                        "detail": (
                            f"'{dep['name']}' is similar to popular package "
                            f"'{popular}' (edit distance {dist})"
                        ),
                        "data": {
                            "severity": "HIGH",
                            "package": dep["name"],
                            "similar_to": popular,
                            "edit_distance": dist,
                        },
                    }
                )
    return findings


def generate_sbom(deps: list[dict[str, str]], engagement_id: str = "") -> dict[str, Any]:
    """Generate a CycloneDX-compatible SBOM JSON."""
    components = []
    for dep in deps:
        components.append(
            {
                "type": "library",
                "name": dep["name"],
                "version": dep.get("version", ""),
                "purl": (
                    f"pkg:{dep.get('ecosystem', 'pypi').lower()}"
                    f"/{dep['name']}@{dep.get('version', '')}"
                ),
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": [{"name": "RedCheck246", "version": "0.2.0"}],
            "component": {"type": "application", "name": engagement_id or "unknown"},
        },
        "components": components,
    }


# ---------------------------------------------------------------------------
# Plugin class
# ---------------------------------------------------------------------------


class SupplyChainPlugin(BasePlugin):
    """Dependency and supply chain vulnerability analysis."""

    name = "supply-chain-audit"
    version = "0.2.0"
    description = "Dependency and supply chain vulnerability analysis"
    requires_authorization = True
    category = "supply_chain"

    def execute(self, context: dict[str, Any]) -> PluginResult:
        """Scan project dependencies for vulnerabilities, license issues, etc."""
        scan_root = Path(context.get("project_root", context.get("scan_root", ".")))
        engagement_id = context.get("engagement_id", "")
        all_findings: list[dict[str, Any]] = []
        errors: list[str] = []
        metadata: dict[str, Any] = {"modules": []}

        # 1. Discover and parse dependency files
        dep_files = discover_dependency_files(scan_root)
        all_deps: list[dict[str, str]] = []
        for df in dep_files:
            try:
                parsed = parse_dependency_file(df)
                all_deps.extend(parsed)
            except Exception as exc:
                errors.append(f"Error parsing {df}: {exc}")

        metadata["dependency_files"] = [str(f) for f in dep_files]
        metadata["total_dependencies"] = len(all_deps)

        if not all_deps:
            return PluginResult(
                plugin_name=self.name,
                success=True,
                findings=[],
                metadata={**metadata, "note": "No dependency files found"},
            )

        # 2. Vulnerability scan (async)
        try:
            vuln_findings = asyncio.run(scan_vulnerabilities(all_deps))
            all_findings.extend(vuln_findings)
            metadata["modules"].append("vulnerability_scanner")
        except Exception as exc:
            errors.append(f"Vulnerability scan error: {exc}")

        # 3. License compliance (async)
        try:
            license_findings = asyncio.run(check_licenses(all_deps))
            all_findings.extend(license_findings)
            metadata["modules"].append("license_compliance")
        except Exception as exc:
            errors.append(f"License check error: {exc}")

        # 4. Typosquatting detection
        try:
            typo_findings = check_typosquatting(all_deps)
            all_findings.extend(typo_findings)
            metadata["modules"].append("typosquatting_detection")
        except Exception as exc:
            errors.append(f"Typosquatting check error: {exc}")

        # 5. SBOM generation
        try:
            sbom = generate_sbom(all_deps, engagement_id)
            metadata["sbom_components"] = len(sbom.get("components", []))
            metadata["modules"].append("sbom_generation")
            # Store SBOM as evidence if evidence_dir is available
            evidence_dir = context.get("evidence_dir")
            if evidence_dir:
                sbom_path = Path(evidence_dir) / "sbom.json"
                sbom_path.parent.mkdir(parents=True, exist_ok=True)
                sbom_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
                metadata["sbom_path"] = str(sbom_path)
        except Exception as exc:
            errors.append(f"SBOM generation error: {exc}")

        metadata["total_findings"] = len(all_findings)
        # Check degradation
        degraded = any(f.get("data", {}).get("degraded") for f in all_findings)
        metadata["degraded"] = degraded

        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=all_findings,
            errors=errors,
            metadata=metadata,
        )

    def dry_run(self, context: dict[str, Any]) -> PluginResult:
        """Simulate execution."""
        scan_root = Path(context.get("project_root", context.get("scan_root", ".")))
        dep_files = discover_dependency_files(scan_root)
        return PluginResult(
            plugin_name=self.name,
            success=True,
            metadata={
                "mode": "dry-run",
                "dependency_files": [str(f) for f in dep_files],
                "modules": [
                    "vulnerability_scanner",
                    "license_compliance",
                    "typosquatting_detection",
                    "sbom_generation",
                ],
                "description": (
                    "Would parse dependency files, query OSV.dev for known vulnerabilities, "
                    "check licenses against policy, detect typosquatting, "
                    "and generate a CycloneDX SBOM"
                ),
            },
        )
