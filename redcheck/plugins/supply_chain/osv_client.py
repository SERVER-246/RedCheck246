"""RedCheck246 — Async OSV.dev API client.

Batched queries, rate limiting, in-memory caching.
Follows Spec 7 constraints from EXECUTION_PLAN.md.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

_OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_REQUEST_TIMEOUT = 15.0
_BATCH_SIZE = 100
_MAX_RETRIES = 2
_BACKOFF = [1.0, 3.0]
_MAX_RPS = 10


class OSVClient:
    """Async client for the OSV.dev vulnerability database."""

    def __init__(self) -> None:
        self._interval = 1.0 / _MAX_RPS
        self._last_request = 0.0
        self._cache: dict[str, Any] = {}

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self._interval:
            await asyncio.sleep(self._interval - elapsed)
        self._last_request = time.monotonic()

    async def query(
        self,
        package: str,
        version: str,
        ecosystem: str,
    ) -> dict[str, Any]:
        """Query OSV for vulnerabilities affecting a specific package version.

        On failure after retries, returns a degraded result (Spec 7).
        """
        cache_key = f"{ecosystem}:{package}:{version}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        payload: dict[str, Any] = {
            "package": {"name": package, "ecosystem": ecosystem},
        }
        if version:
            payload["version"] = version

        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
            for attempt in range(1 + _MAX_RETRIES):
                await self._rate_limit()
                try:
                    resp = await client.post(_OSV_QUERY_URL, json=payload)
                    resp.raise_for_status()
                    result = resp.json()
                    self._cache[cache_key] = result
                    return result
                except (httpx.TimeoutException, httpx.HTTPStatusError) as exc:
                    if attempt < _MAX_RETRIES:
                        await asyncio.sleep(_BACKOFF[attempt])
                        continue
                    # All retries exhausted — degrade gracefully
                    degraded: dict[str, Any] = {
                        "degraded": True,
                        "reason": f"OSV API unreachable after {1 + _MAX_RETRIES} attempts: {exc}",
                        "package": package,
                        "version": version,
                    }
                    self._cache[cache_key] = degraded
                    return degraded

        return {"degraded": True, "reason": "unexpected fallthrough", "package": package}

    async def query_batch(
        self,
        packages: list[dict[str, str]],
    ) -> list[dict[str, Any]]:
        """Batch query multiple packages.

        *packages* is a list of dicts with keys: name, version, ecosystem.
        """
        results: list[dict[str, Any]] = []

        for i in range(0, len(packages), _BATCH_SIZE):
            batch = packages[i : i + _BATCH_SIZE]
            queries = []
            for pkg in batch:
                q: dict[str, Any] = {
                    "package": {"name": pkg["name"], "ecosystem": pkg.get("ecosystem", "PyPI")},
                }
                if pkg.get("version"):
                    q["version"] = pkg["version"]
                queries.append(q)

            await self._rate_limit()
            try:
                async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
                    resp = await client.post(
                        _OSV_BATCH_URL,
                        json={"queries": queries},
                    )
                    resp.raise_for_status()
                    data = resp.json()

                for idx, result_obj in enumerate(data.get("results", [])):
                    vulns = result_obj.get("vulns", [])
                    pkg = batch[idx] if idx < len(batch) else {}
                    results.append(
                        {
                            "package": pkg.get("name", "?"),
                            "version": pkg.get("version", "?"),
                            "ecosystem": pkg.get("ecosystem", "?"),
                            "vulns": vulns,
                        }
                    )
            except Exception as exc:
                # Degrade entire batch
                for pkg in batch:
                    results.append(
                        {
                            "package": pkg.get("name", "?"),
                            "version": pkg.get("version", "?"),
                            "ecosystem": pkg.get("ecosystem", "?"),
                            "degraded": True,
                            "reason": str(exc),
                            "vulns": [],
                        }
                    )

        return results


def severity_from_cvss(score: float | None) -> str:
    """Map a CVSS score to a FindingSeverity string."""
    if score is None:
        return "MEDIUM"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"
