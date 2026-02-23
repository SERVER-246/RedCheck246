"""RedCheck246 — SBOM Integration (Module 5.3).

Generates Software Bill of Materials (SBOM) in SPDX JSON format
by inspecting installed Python packages.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from importlib.metadata import distributions
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from pathlib import Path

log = structlog.get_logger(__name__)


def _get_installed_packages() -> list[dict[str, str]]:
    """Collect installed Python package metadata."""
    packages = []
    seen: set[str] = set()

    for dist in distributions():
        name = dist.metadata["Name"]
        if name in seen:
            continue
        seen.add(name)
        packages.append({
            "name": name,
            "version": dist.metadata["Version"],
            "license": dist.metadata.get("License") or "NOASSERTION",
        })

    return sorted(packages, key=lambda p: p["name"].lower())


class SBOMGenerator:
    """Generate SPDX 2.3 JSON SBOM from the current Python environment."""

    SPDX_VERSION = "SPDX-2.3"
    DATA_LICENSE = "CC0-1.0"

    def __init__(
        self,
        *,
        document_name: str = "redcheck246-sbom",
        creator_tool: str = "RedCheck246-SBOMGenerator",
        namespace_base: str = "https://redcheck246.local/sbom",
    ) -> None:
        self._document_name = document_name
        self._creator_tool = creator_tool
        self._namespace_base = namespace_base

    def generate(
        self,
        *,
        min_packages: int = 5,
        extra_packages: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Generate an SPDX JSON SBOM.

        Args:
            min_packages: Minimum number of packages expected (for validation).
            extra_packages: Additional package entries to include.

        Returns:
            SPDX 2.3 JSON-compatible dict.

        Raises:
            ValueError: If fewer than *min_packages* are found.
        """
        packages = _get_installed_packages()
        if extra_packages:
            packages.extend(extra_packages)

        if len(packages) < min_packages:
            raise ValueError(
                f"Expected at least {min_packages} packages, found {len(packages)}"
            )

        now = datetime.now(timezone.utc).isoformat()

        # Build SPDX packages list
        spdx_packages: list[dict[str, Any]] = []
        for pkg in packages:
            spdx_id = f"SPDXRef-Package-{pkg['name']}"
            spdx_packages.append({
                "SPDXID": spdx_id,
                "name": pkg["name"],
                "versionInfo": pkg["version"],
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": pkg.get("license", "NOASSERTION"),
                "licenseDeclared": pkg.get("license", "NOASSERTION"),
                "copyrightText": "NOASSERTION",
                "filesAnalyzed": False,
            })

        # Build SPDX document
        doc_namespace = f"{self._namespace_base}/{self._document_name}-{now}"
        sbom: dict[str, Any] = {
            "spdxVersion": self.SPDX_VERSION,
            "dataLicense": self.DATA_LICENSE,
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": self._document_name,
            "documentNamespace": doc_namespace,
            "creationInfo": {
                "created": now,
                "creators": [f"Tool: {self._creator_tool}"],
                "licenseListVersion": "3.19",
            },
            "packages": spdx_packages,
            "documentDescribes": [p["SPDXID"] for p in spdx_packages],
        }

        log.info("sbom_generated", package_count=len(spdx_packages))
        return sbom

    def save(
        self,
        output_path: Path,
        **kwargs: Any,
    ) -> Path:
        """Generate and save SBOM to a JSON file."""
        sbom = self.generate(**kwargs)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(sbom, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        log.info("sbom_saved", path=str(output_path))
        return output_path
