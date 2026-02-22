"""RedCheck246 — Advanced Web Crawler (BFS).

Rate-limited, depth-bounded, ``robots.txt``-respecting web crawler.
Discovers pages, forms, and endpoints for downstream DAST testing.
"""

from __future__ import annotations

import re
import time
from collections import deque
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
import structlog

from redcheck.constants import CRAWLER_MAX_DEPTH_DEFAULT, CRAWLER_MAX_PAGES_DEFAULT
from redcheck.core.token_bucket import TokenBucket
from redcheck.plugins._http import scanning_ssl_context

log = structlog.get_logger(__name__)

_LINK_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
_FORM_ACTION_RE = re.compile(r"<form[^>]*action=[\"']([^\"']*)[\"'][^>]*>", re.IGNORECASE)


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
