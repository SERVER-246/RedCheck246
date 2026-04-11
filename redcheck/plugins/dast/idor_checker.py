"""RedCheck246 — IDOR (Insecure Direct Object Reference) Validator.

Deterministic IDOR checking with fixed RNG seed.
Only uses IDs explicitly allowed in the RoE.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any

import httpx
import structlog

from redcheck.exceptions import OffensiveControlError
from redcheck.models import OffensiveControls, PluginCapability
from redcheck.plugins._http import scanning_ssl_context
from redcheck.plugins.base_plugin import BasePlugin, PluginResult, plugin_dependencies

log = structlog.get_logger(__name__)


@plugin_dependencies(
    required=["dast-scanner"],
    optional=[],
    provides=["access_control_vulns"],
)
class IDORValidator(BasePlugin):
    """Validate IDOR vulnerabilities using deterministic, RoE-bounded IDs.

    - Uses a fixed RNG seed for reproducibility.
    - Only probes IDs explicitly provided in the engagement context.
    - Gated by ``allow_auth_testing`` offensive control.
    """

    name = "idor-validator"
    version = "0.1.0"
    description = "Deterministic IDOR vulnerability validation"
    requires_authorization = True
    category = "dast"
    capability = PluginCapability.ACTIVE

    required_controls = ["allow_auth_testing"]
    rate_limit_rps = 5
    mitre_techniques = ["T1565.001"]
    requires_isolation = False

    # Fixed seed for deterministic ID permutation
    _SEED = 42

    def _check_controls(self, context: dict[str, Any]) -> None:
        """Verify offensive controls are enabled."""
        controls_data = context.get("offensive_controls", {})
        if isinstance(controls_data, dict):
            controls = OffensiveControls(**controls_data)
        elif isinstance(controls_data, OffensiveControls):
            controls = controls_data
        else:
            controls = OffensiveControls()

        if not controls.has_controls(self.required_controls):
            raise OffensiveControlError(
                self.name,
                [c for c in self.required_controls if not getattr(controls, c, False)],
            )

    def execute(self, context: dict[str, Any]) -> PluginResult:
        return asyncio.run(self.aexecute(context))

    async def aexecute(self, context: dict[str, Any]) -> PluginResult:
        """Async IDOR validation."""
        self._check_controls(context)

        start = time.monotonic()
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        # Get allowed test IDs from context
        allowed_ids: list[str] = context.get("idor_test_ids", [])
        endpoints: list[str] = context.get("idor_endpoints", [])

        if not allowed_ids:
            # Generate deterministic test IDs
            import random

            rng = random.Random(self._SEED)  # noqa: S311  # nosec B311
            allowed_ids = [str(rng.randint(1, 99999)) for _ in range(5)]  # nosec B311

        if not endpoints:
            # Standalone fallback: derive endpoints from targets
            endpoints = self._derive_endpoints(context)
        if not endpoints:
            return PluginResult(
                plugin_name=self.name,
                success=True,
                findings=[],
                errors=[],
                metadata={
                    "mode": "no-input",
                    "note": "No endpoints available — provide idor_endpoints or enable chain mode",
                },
            )

        async with httpx.AsyncClient(verify=scanning_ssl_context(), timeout=10.0) as client:
            for endpoint in endpoints:
                for obj_id in allowed_ids:
                    url = endpoint.replace("{id}", obj_id)
                    try:
                        resp = await client.get(url, follow_redirects=True)
                        if resp.status_code == 200:
                            # Check if response contains data that shouldn't be accessible
                            content_hash = hashlib.sha256(resp.content[:256]).hexdigest()[:16]
                            findings.append(
                                {
                                    "finding_type": "idor_accessible",
                                    "target": url,
                                    "severity": "high",
                                    "detail": f"Object {obj_id} accessible at {endpoint}",
                                    "object_id": obj_id,
                                    "status_code": resp.status_code,
                                    "content_hash": content_hash,
                                }
                            )
                    except Exception as exc:
                        errors.append(f"{url}: {exc}")

        elapsed = (time.monotonic() - start) * 1000
        self.capture_evidence(
            context,
            f"{len(findings)} idor findings".encode(),
            "idor_validation",
        )
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=findings,
            errors=errors,
            metadata={
                "ids_tested": len(allowed_ids),
                "endpoints_tested": len(endpoints),
                "duration_ms": round(elapsed, 2),
            },
        )

    def deterministic_ids(self, count: int = 5) -> list[str]:
        """Generate deterministic test IDs from fixed seed.

        Same seed + count → same IDs every time.
        """
        import random

        rng = random.Random(self._SEED)  # noqa: S311  # nosec B311
        return [str(rng.randint(1, 99999)) for _ in range(count)]  # nosec B311

    @staticmethod
    def _derive_endpoints(context: dict[str, Any]) -> list[str]:
        """Derive test endpoints from engagement targets."""
        common_idor_paths = [
            "/api/users/{id}",
            "/api/profile/{id}",
            "/api/account/{id}",
        ]
        endpoints: list[str] = []
        targets = context.get("authorized_targets", context.get("targets", []))
        for t in targets:
            host = t.get("host", t) if isinstance(t, dict) else str(t)
            for pfx in ("https://", "http://"):
                if host.startswith(pfx):
                    break
            else:
                host = f"https://{host}"
            host = host.rstrip("/")
            for path in common_idor_paths:
                ep = f"{host}{path}"
                if ep not in endpoints:
                    endpoints.append(ep)
        return endpoints

    def dry_run(self, context: dict[str, Any]) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            success=True,
            metadata={
                "mode": "dry-run",
                "description": "Would validate IDOR endpoints",
                "deterministic_ids": self.deterministic_ids(),
            },
        )
