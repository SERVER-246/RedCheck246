"""RedCheck246 — Vulnerability Signature Database.

Lazy-loaded JSON vulnerability signatures for web vulns, service vulns,
and injection patterns. Provides matching APIs for DAST scanning and
service version correlation.
"""

from __future__ import annotations

import importlib.resources
import json
from dataclasses import dataclass
from typing import Any

import structlog

from redcheck.constants import (
    MAX_INJECTION_PAYLOADS_PER_CATEGORY,
    MAX_VULN_MATCHES_PER_SERVICE,
    VULN_DB_SCHEMA_VERSION,
)

log = structlog.get_logger(__name__)


@dataclass
class VulnMatch:
    """A matched vulnerability from the signature database."""

    vuln_id: str
    name: str
    category: str
    severity: str
    cwe: str
    description: str
    cve: str | None = None
    cpe_match: str | None = None
    matched_version: str | None = None


class VulnerabilityDatabase:
    """Lazy-loaded vulnerability signature database.

    Loads JSON signature files from ``redcheck/data/vuln_signatures/``
    on first access. Provides matching APIs for:
    - Service version → CVE matching
    - Web vulnerability pattern matching
    - Injection payload retrieval
    """

    def __init__(self) -> None:
        self._web_vulns: list[dict[str, Any]] | None = None
        self._service_vulns: list[dict[str, Any]] | None = None
        self._injection_patterns: dict[str, Any] | None = None
        self._loaded = False

    def _load(self) -> None:
        """Load all signature files lazily."""
        if self._loaded:
            return

        try:
            pkg = importlib.resources.files("redcheck.data.vuln_signatures")

            web_ref = pkg.joinpath("web_vulns.json")
            web_data = json.loads(web_ref.read_text(encoding="utf-8"))
            if web_data.get("schema_version") == VULN_DB_SCHEMA_VERSION:
                self._web_vulns = web_data.get("vulnerabilities", [])
            else:
                log.warning("web_vulns_schema_mismatch")
                self._web_vulns = []

            svc_ref = pkg.joinpath("service_vulns.json")
            svc_data = json.loads(svc_ref.read_text(encoding="utf-8"))
            if svc_data.get("schema_version") == VULN_DB_SCHEMA_VERSION:
                self._service_vulns = svc_data.get("vulnerabilities", [])
            else:
                log.warning("service_vulns_schema_mismatch")
                self._service_vulns = []

            inj_ref = pkg.joinpath("injection_patterns.json")
            inj_data = json.loads(inj_ref.read_text(encoding="utf-8"))
            if inj_data.get("schema_version") == VULN_DB_SCHEMA_VERSION:
                self._injection_patterns = inj_data.get("categories", {})
            else:
                log.warning("injection_patterns_schema_mismatch")
                self._injection_patterns = {}

        except Exception:
            log.warning("vuln_db_load_failed", exc_info=True)
            self._web_vulns = self._web_vulns or []
            self._service_vulns = self._service_vulns or []
            self._injection_patterns = self._injection_patterns or {}

        self._loaded = True

    def match_service(
        self,
        service_name: str,
        version: str | None = None,
    ) -> list[VulnMatch]:
        """Match a service name and optional version against known vulns.

        Args:
            service_name: Service name (e.g. "Apache HTTP Server").
            version: Optional version string (e.g. "2.4.49").

        Returns:
            List of ``VulnMatch`` objects, capped at
            ``MAX_VULN_MATCHES_PER_SERVICE``.
        """
        self._load()
        matches: list[VulnMatch] = []

        for vuln in self._service_vulns or []:
            if len(matches) >= MAX_VULN_MATCHES_PER_SERVICE:
                break

            if vuln.get("service", "").lower() != service_name.lower():
                continue

            affected = vuln.get("affected_versions", [])
            if version and version not in affected:
                continue

            matches.append(
                VulnMatch(
                    vuln_id=vuln.get("id", ""),
                    name=f"{vuln.get('service', '')} {vuln.get('cve', '')}",
                    category="service",
                    severity=vuln.get("severity", "unknown"),
                    cwe=vuln.get("cwe", ""),
                    description=vuln.get("description", ""),
                    cve=vuln.get("cve"),
                    cpe_match=vuln.get("cpe_match"),
                    matched_version=version,
                )
            )

        return matches

    def get_injection_payloads(
        self,
        category: str,
    ) -> list[str]:
        """Get injection test payloads for a given category.

        Args:
            category: Injection category (e.g. "sql_injection",
                "command_injection", "ldap_injection").

        Returns:
            List of payload strings, capped at
            ``MAX_INJECTION_PAYLOADS_PER_CATEGORY``.
        """
        self._load()
        patterns = self._injection_patterns or {}
        cat_data = patterns.get(category, {})
        payloads = cat_data.get("payloads", [])
        return payloads[:MAX_INJECTION_PAYLOADS_PER_CATEGORY]

    def match_web_vuln(
        self,
        response_body: str,
        response_headers: dict[str, str] | None = None,
    ) -> list[VulnMatch]:
        """Match response content against web vulnerability patterns.

        Args:
            response_body: HTTP response body text.
            response_headers: Optional HTTP response headers.

        Returns:
            List of ``VulnMatch`` objects for matching patterns.
        """
        self._load()
        matches: list[VulnMatch] = []

        for vuln in self._web_vulns or []:
            patterns = vuln.get("patterns", [])
            matched = False

            for pattern in patterns:
                if pattern and pattern.lower() in response_body.lower():
                    matched = True
                    break

            if not matched and response_headers:
                header_str = " ".join(f"{k}: {v}" for k, v in response_headers.items())
                for pattern in patterns:
                    if pattern and pattern.lower() in header_str.lower():
                        matched = True
                        break

            if matched:
                matches.append(
                    VulnMatch(
                        vuln_id=vuln.get("id", ""),
                        name=vuln.get("name", ""),
                        category=vuln.get("category", ""),
                        severity=vuln.get("severity", "unknown"),
                        cwe=vuln.get("cwe", ""),
                        description=vuln.get("description", ""),
                    )
                )

        return matches

    def get_detection_patterns(self, category: str) -> list[str]:
        """Get detection patterns for a given injection category.

        These are response patterns that indicate a successful injection.
        """
        self._load()
        patterns = self._injection_patterns or {}
        cat_data = patterns.get(category, {})
        return cat_data.get("detection_patterns", [])

    @property
    def web_vuln_count(self) -> int:
        self._load()
        return len(self._web_vulns or [])

    @property
    def service_vuln_count(self) -> int:
        self._load()
        return len(self._service_vulns or [])

    @property
    def injection_category_count(self) -> int:
        self._load()
        return len(self._injection_patterns or {})
