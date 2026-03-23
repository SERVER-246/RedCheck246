"""RedCheck246 — Advanced Web Crawler (BFS).

Rate-limited, depth-bounded, ``robots.txt``-respecting web crawler.
Discovers pages, forms, and endpoints for downstream DAST testing.
"""

from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, cast
from urllib.parse import urljoin, urlparse

import httpx
import structlog

from redcheck.constants import (
    CRAWLER_MAX_API_PATHS,
    CRAWLER_MAX_DEPTH_DEFAULT,
    CRAWLER_MAX_FORMS_PER_PAGE,
    CRAWLER_MAX_PAGES_DEFAULT,
)
from redcheck.core.token_bucket import TokenBucket
from redcheck.plugins._http import scanning_ssl_context

log = structlog.get_logger(__name__)

_LINK_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
_FORM_ACTION_RE = re.compile(r"<form[^>]*action=[\"']([^\"']*)[\"'][^>]*>", re.IGNORECASE)
_FORM_RE = re.compile(r"<form[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_INPUT_NAME_RE = re.compile(r"name=[\"']([^\"']*)[\"']", re.IGNORECASE)
_INPUT_TYPE_RE = re.compile(r"type=[\"']([^\"']*)[\"']", re.IGNORECASE)
_INPUT_TAG_RE = re.compile(r"<input[^>]*?>", re.IGNORECASE)
_TEXTAREA_RE = re.compile(r"<textarea[^>]*name=[\"']([^\"']*)[\"'][^>]*>", re.IGNORECASE)
_SELECT_RE = re.compile(r"<select[^>]*name=[\"']([^\"']*)[\"'][^>]*>", re.IGNORECASE)
_API_SPEC_PATHS = (
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api-docs",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/v3/openapi.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/.well-known/openapi.json",
)
_LOGIN_INDICATORS = re.compile(
    r"(login|signin|sign-in|authenticate|auth|log-in|sso)",
    re.IGNORECASE,
)
_FILE_UPLOAD_RE = re.compile(r'type=["\']file["\']', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Data classes for enhanced crawl results
# ---------------------------------------------------------------------------


@dataclass
class FormDescriptor:
    """Describes a discovered HTML form."""

    page_url: str
    action: str
    method: str
    fields: list[dict[str, str]] = field(default_factory=list)
    has_file_upload: bool = False
    is_login_form: bool = False


# ---------------------------------------------------------------------------
# robots.txt parser (minimal)
# ---------------------------------------------------------------------------


class RobotsTxtParser:
    """Minimal ``robots.txt`` parser respecting ``Disallow`` rules."""

    def __init__(self) -> None:
        self._disallowed: list[str] = []
        self._loaded = False

    async def load(self, base_url: str, client: httpx.AsyncClient) -> None:
        """Fetch and parse ``robots.txt`` from the target."""
        try:
            url = urljoin(base_url, "/robots.txt")
            resp = await client.get(url, timeout=5.0)
            if resp.status_code == 200:
                self._parse(resp.text)
            self._loaded = True
        except Exception:
            self._loaded = True  # fail open — treat as no restrictions

    def _parse(self, text: str) -> None:
        in_wildcard = False
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith("user-agent:"):
                agent = line.split(":", 1)[1].strip()
                in_wildcard = agent == "*"
            elif in_wildcard and line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    self._disallowed.append(path)

    def is_allowed(self, url: str) -> bool:
        """Check if the URL path is allowed by ``robots.txt``."""
        parsed = urlparse(url)
        path = parsed.path or "/"
        return not any(path.startswith(d) for d in self._disallowed)


# ---------------------------------------------------------------------------
# Advanced Crawler
# ---------------------------------------------------------------------------


class AdvancedCrawler:
    """BFS web crawler with rate limiting, depth cap, and page cap.

    Args:
        max_pages: Maximum number of pages to crawl.
        max_depth: Maximum link depth from seed URL.
        rate_rps: Requests per second limit.
        respect_robots: Whether to respect ``robots.txt``.
    """

    def __init__(
        self,
        *,
        max_pages: int = CRAWLER_MAX_PAGES_DEFAULT,
        max_depth: int = CRAWLER_MAX_DEPTH_DEFAULT,
        rate_rps: float = 5.0,
        respect_robots: bool = True,
    ) -> None:
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.rate_rps = rate_rps
        self.respect_robots = respect_robots
        self._visited: set[str] = set()
        self._discovered: list[dict[str, Any]] = []
        self._forms: list[dict[str, Any]] = []

    async def crawl(
        self,
        seed_urls: list[str],
        client: httpx.AsyncClient | None = None,
    ) -> dict[str, Any]:
        """BFS crawl from seed URLs.

        Returns:
            Dict with ``pages``, ``forms``, ``total_pages``, ``duration_ms``.
        """
        start = time.monotonic()
        own_client = client is None
        if own_client:
            client = httpx.AsyncClient(verify=scanning_ssl_context(), timeout=10.0)
        client = cast("httpx.AsyncClient", client)

        bucket = TokenBucket(rate=self.rate_rps)
        robots = RobotsTxtParser()

        # Parse base URL for robots.txt and same-domain checking
        base_domains: set[str] = set()
        queue: deque[tuple[str, int]] = deque()

        for url in seed_urls:
            parsed = urlparse(url)
            base_domains.add(parsed.netloc)
            queue.append((url, 0))

        if self.respect_robots and seed_urls:
            base = f"{urlparse(seed_urls[0]).scheme}://{urlparse(seed_urls[0]).netloc}"
            await robots.load(base, client)

        try:
            while queue and len(self._visited) < self.max_pages:
                url, depth = queue.popleft()

                # Normalize URL
                url = self._normalize(url)
                if url in self._visited:
                    continue
                if depth > self.max_depth:
                    continue
                if self.respect_robots and not robots.is_allowed(url):
                    log.debug("crawl_robots_blocked", url=url)
                    continue

                # Check same-domain
                parsed = urlparse(url)
                if parsed.netloc not in base_domains:
                    continue

                await bucket.acquire()
                self._visited.add(url)

                try:
                    resp = await client.get(url, follow_redirects=True, timeout=10.0)
                except Exception as exc:
                    log.debug("crawl_error", url=url, error=str(exc))
                    self._discovered.append(
                        {
                            "url": url,
                            "status": 0,
                            "depth": depth,
                            "error": str(exc),
                        }
                    )
                    continue

                content_type = resp.headers.get("content-type", "")
                if "text/html" not in content_type:
                    self._discovered.append(
                        {
                            "url": url,
                            "status": resp.status_code,
                            "depth": depth,
                            "content_type": content_type,
                        }
                    )
                    continue

                self._discovered.append(
                    {
                        "url": url,
                        "status": resp.status_code,
                        "depth": depth,
                        "content_type": content_type,
                    }
                )

                # Extract links
                body = resp.text
                for href in _LINK_RE.findall(body):
                    abs_url = urljoin(url, href)
                    norm = self._normalize(abs_url)
                    if norm not in self._visited:
                        queue.append((norm, depth + 1))

                # Extract forms
                for action in _FORM_ACTION_RE.findall(body):
                    abs_action = urljoin(url, action) if action else url
                    self._forms.append(
                        {
                            "page": url,
                            "action": abs_action,
                            "depth": depth,
                        }
                    )

        finally:
            if own_client:
                await client.aclose()

        elapsed = (time.monotonic() - start) * 1000
        return {
            "pages": self._discovered,
            "forms": self._forms,
            "total_pages": len(self._visited),
            "total_forms": len(self._forms),
            "duration_ms": round(elapsed, 2),
        }

    @staticmethod
    def _normalize(url: str) -> str:
        """Normalize URL by removing fragment and trailing slash."""
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        return f"{parsed.scheme}://{parsed.netloc}{path}"

    @property
    def visited_urls(self) -> set[str]:
        return self._visited.copy()

    # ------------------------------------------------------------------
    # Enhanced discovery methods (Phase 7 — §26)
    # ------------------------------------------------------------------

    async def discover_api_specs(
        self,
        base_url: str,
        client: httpx.AsyncClient | None = None,
    ) -> list[dict[str, Any]]:
        """Probe well-known paths for OpenAPI / Swagger specs.

        Returns list of dicts with ``url``, ``status``, ``content_type``.
        """
        own_client = client is None
        if own_client:
            client = httpx.AsyncClient(verify=scanning_ssl_context(), timeout=10.0)
        client = cast("httpx.AsyncClient", client)

        results: list[dict[str, Any]] = []
        try:
            for path in _API_SPEC_PATHS:
                if len(results) >= CRAWLER_MAX_API_PATHS:
                    break
                url = urljoin(base_url, path)
                try:
                    resp = await client.get(url, follow_redirects=True, timeout=5.0)
                    if resp.status_code == 200:
                        ct = resp.headers.get("content-type", "")
                        results.append(
                            {
                                "url": url,
                                "status": resp.status_code,
                                "content_type": ct,
                                "finding_type": "api_spec_discovered",
                            }
                        )
                except Exception:  # noqa: S110
                    pass
        finally:
            if own_client:
                await client.aclose()

        return results

    def enumerate_forms(self, url: str, html: str) -> list[FormDescriptor]:
        """Parse HTML and extract all form descriptors.

        Args:
            url: The page URL (used for resolving relative actions).
            html: Raw HTML content of the page.

        Returns:
            List of ``FormDescriptor`` objects, capped at
            ``CRAWLER_MAX_FORMS_PER_PAGE``.
        """
        forms: list[FormDescriptor] = []

        for match in _FORM_RE.finditer(html):
            if len(forms) >= CRAWLER_MAX_FORMS_PER_PAGE:
                break

            form_html = match.group(0)

            # Extract action
            action_match = _FORM_ACTION_RE.search(form_html)
            raw_action = action_match.group(1) if action_match else ""
            action = urljoin(url, raw_action) if raw_action else url

            # Extract method
            method_match = re.search(r"method=[\"'](\w+)[\"']", form_html, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else "GET"

            # Extract fields
            fields: list[dict[str, str]] = []
            for inp in _INPUT_TAG_RE.finditer(form_html):
                tag = inp.group(0)
                name_m = _INPUT_NAME_RE.search(tag)
                type_m = _INPUT_TYPE_RE.search(tag)
                name = name_m.group(1) if name_m else ""
                input_type = type_m.group(1) if type_m else "text"
                if name:
                    fields.append({"name": name, "type": input_type})
            for ta in _TEXTAREA_RE.finditer(form_html):
                fields.append({"name": ta.group(1), "type": "textarea"})
            for sel in _SELECT_RE.finditer(form_html):
                fields.append({"name": sel.group(1), "type": "select"})

            has_upload = bool(_FILE_UPLOAD_RE.search(form_html))
            is_login = bool(_LOGIN_INDICATORS.search(form_html))

            forms.append(
                FormDescriptor(
                    page_url=url,
                    action=action,
                    method=method,
                    fields=fields,
                    has_file_upload=has_upload,
                    is_login_form=is_login,
                )
            )

        return forms

    def discover_login_flows(self, crawled_urls: list[str]) -> list[dict[str, Any]]:
        """Identify likely login/authentication URLs from crawled pages.

        Uses URL-path heuristics (login, signin, auth, sso) to detect
        authentication endpoints.
        """
        login_flows: list[dict[str, Any]] = []
        seen: set[str] = set()

        for url in crawled_urls:
            parsed = urlparse(url)
            path = parsed.path.lower()
            if _LOGIN_INDICATORS.search(path) and url not in seen:
                seen.add(url)
                login_flows.append(
                    {
                        "url": url,
                        "finding_type": "login_flow_detected",
                        "path": parsed.path,
                    }
                )

        return login_flows

    def map_parameters(self, crawled_urls: list[str]) -> list[dict[str, Any]]:
        """Extract query parameters from crawled URLs.

        Returns list of parameter mappings for fuzz targeting.
        """
        param_map: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()

        for url in crawled_urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            for part in parsed.query.split("&"):
                if "=" not in part:
                    continue
                name = part.split("=", 1)[0]
                key = (parsed.path, name)
                if key not in seen:
                    seen.add(key)
                    param_map.append(
                        {
                            "url": url,
                            "path": parsed.path,
                            "parameter": name,
                            "finding_type": "parameter_mapped",
                        }
                    )

        return param_map
