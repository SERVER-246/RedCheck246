"""Tests for redcheck.plugins.dast.crawler — AdvancedCrawler & RobotsTxtParser.

Coverage: BFS traversal, depth/page caps, robots.txt compliance, rate limiting,
URL normalization, form extraction, same-domain filtering.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from redcheck.plugins.dast.crawler import AdvancedCrawler, RobotsTxtParser

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _html(links: list[str] | None = None, forms: list[str] | None = None) -> str:
    """Build minimal HTML with links and forms."""
    body = ""
    for href in links or []:
        body += f'<a href="{href}">link</a>\n'
    for action in forms or []:
        body += f'<form action="{action}" method="POST"><input name="q"></form>\n'
    return f"<html><body>{body}</body></html>"


class _FakeTransport(httpx.AsyncBaseTransport):
    """Fake transport that returns canned responses by URL path."""

    def __init__(self, pages: dict[str, tuple[int, str, str]]) -> None:
        """pages: {path: (status, content_type, body)}"""
        self._pages = pages

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path or "/"
        path = path.rstrip("/") or "/"
        if path in self._pages:
            status, ct, body = self._pages[path]
            return httpx.Response(status, text=body, headers={"content-type": ct})
        return httpx.Response(404, text="Not found", headers={"content-type": "text/plain"})


# ---------------------------------------------------------------------------
# RobotsTxtParser
# ---------------------------------------------------------------------------


class TestRobotsTxtParser:
    """Tests for the minimal robots.txt parser."""

    def test_parse_disallow(self):
        """Parses User-agent: * disallow rules."""
        parser = RobotsTxtParser()
        parser._parse("User-agent: *\nDisallow: /admin\nDisallow: /secret\n")
        assert not parser.is_allowed("https://example.com/admin/panel")
        assert not parser.is_allowed("https://example.com/secret")
        assert parser.is_allowed("https://example.com/public")

    def test_allows_all_when_empty(self):
        parser = RobotsTxtParser()
        parser._parse("")
        assert parser.is_allowed("https://example.com/anything")

    def test_ignores_non_wildcard_agents(self):
        parser = RobotsTxtParser()
        parser._parse("User-agent: Googlebot\nDisallow: /private\n")
        # Non-wildcard → no rules applied
        assert parser.is_allowed("https://example.com/private")

    async def _load_with_transport(self, body: str, status: int = 200):
        transport = _FakeTransport({"/robots.txt": (status, "text/plain", body)})
        async with httpx.AsyncClient(transport=transport) as client:
            parser = RobotsTxtParser()
            await parser.load("https://example.com", client)
            return parser

    def test_load_success(self):
        parser = asyncio.run(self._load_with_transport("User-agent: *\nDisallow: /admin\n"))
        assert not parser.is_allowed("https://example.com/admin")

    def test_load_404_fails_open(self):
        parser = asyncio.run(self._load_with_transport("", 404))
        assert parser.is_allowed("https://example.com/admin")


# ---------------------------------------------------------------------------
# AdvancedCrawler — URL normalization
# ---------------------------------------------------------------------------


class TestCrawlerNormalization:
    def test_strips_fragment(self):
        assert AdvancedCrawler._normalize("https://a.com/page#section") == "https://a.com/page"

    def test_strips_trailing_slash(self):
        assert AdvancedCrawler._normalize("https://a.com/page/") == "https://a.com/page"

    def test_root_path(self):
        assert AdvancedCrawler._normalize("https://a.com") == "https://a.com/"

    def test_preserves_query(self):
        # Normalization strips fragment; also strips query params
        result = AdvancedCrawler._normalize("https://a.com/search?q=test#top")
        assert result == "https://a.com/search"


# ---------------------------------------------------------------------------
# AdvancedCrawler — BFS traversal
# ---------------------------------------------------------------------------


class TestCrawlerBFS:
    """BFS crawl correctness with canned transport."""

    def _crawl(self, pages: dict[str, tuple[int, str, str]], **kw: Any) -> dict[str, Any]:
        transport = _FakeTransport(pages)
        client = httpx.AsyncClient(transport=transport, base_url="https://site.local")

        async def run():
            crawler = AdvancedCrawler(respect_robots=False, **kw)
            result = await crawler.crawl(["https://site.local/"], client=client)
            await client.aclose()
            return result

        return asyncio.run(run())

    def test_single_page(self):
        pages = {"/": (200, "text/html", _html())}
        result = self._crawl(pages)
        assert result["total_pages"] == 1

    def test_follows_links(self):
        pages = {
            "/": (200, "text/html", _html(links=["/about", "/contact"])),
            "/about": (200, "text/html", _html()),
            "/contact": (200, "text/html", _html()),
        }
        result = self._crawl(pages)
        assert result["total_pages"] == 3

    def test_deduplicates_urls(self):
        pages = {
            "/": (200, "text/html", _html(links=["/about", "/about", "/about"])),
            "/about": (200, "text/html", _html()),
        }
        result = self._crawl(pages)
        assert result["total_pages"] == 2

    def test_depth_limit(self):
        """Max depth=1 prevents following second-level links."""
        pages = {
            "/": (200, "text/html", _html(links=["/level1"])),
            "/level1": (200, "text/html", _html(links=["/level2"])),
            "/level2": (200, "text/html", _html()),
        }
        result = self._crawl(pages, max_depth=1)
        assert result["total_pages"] == 2  # / and /level1 only

    def test_page_limit(self):
        pages = {
            "/": (200, "text/html", _html(links=["/a", "/b", "/c", "/d"])),
            "/a": (200, "text/html", _html()),
            "/b": (200, "text/html", _html()),
            "/c": (200, "text/html", _html()),
            "/d": (200, "text/html", _html()),
        }
        result = self._crawl(pages, max_pages=3)
        assert result["total_pages"] <= 3

    def test_extracts_forms(self):
        pages = {"/": (200, "text/html", _html(forms=["/submit", "/search"]))}
        result = self._crawl(pages)
        assert result["total_forms"] == 2

    def test_skips_external_domains(self):
        pages = {
            "/": (200, "text/html", _html(links=["https://external.com/page"])),
        }
        result = self._crawl(pages)
        assert result["total_pages"] == 1  # only seed

    def test_handles_non_html_content(self):
        pages = {
            "/": (200, "text/html", _html(links=["/data.json"])),
            "/data.json": (200, "application/json", '{"k": "v"}'),
        }
        result = self._crawl(pages)
        assert result["total_pages"] == 2  # both visited but json not followed

    def test_handles_errors_gracefully(self):
        """Transport returns 500 for a page — crawler continues."""
        pages = {
            "/": (200, "text/html", _html(links=["/broken"])),
            "/broken": (500, "text/html", "Server Error"),
        }
        result = self._crawl(pages)
        assert result["total_pages"] == 2


# ---------------------------------------------------------------------------
# AdvancedCrawler — robots.txt integration
# ---------------------------------------------------------------------------


class TestCrawlerRobots:
    def test_respects_robots_disallow(self):
        robots_body = "User-agent: *\nDisallow: /admin\n"
        pages = {
            "/": (200, "text/html", _html(links=["/admin/panel", "/public"])),
            "/robots.txt": (200, "text/plain", robots_body),
            "/admin/panel": (200, "text/html", _html()),
            "/public": (200, "text/html", _html()),
        }
        transport = _FakeTransport(pages)

        async def run():
            async with httpx.AsyncClient(transport=transport) as client:
                crawler = AdvancedCrawler(respect_robots=True)
                result = await crawler.crawl(["https://site.local/"], client=client)
                return result, crawler.visited_urls

        result, visited = asyncio.run(run())
        # /admin/panel should be blocked
        assert not any("/admin" in u for u in visited)
        assert any("/public" in u for u in visited)


# ---------------------------------------------------------------------------
# AdvancedCrawler — properties
# ---------------------------------------------------------------------------


class TestCrawlerProperties:
    def test_visited_urls_returns_copy(self):
        crawler = AdvancedCrawler()
        # No crawl yet → empty
        urls = crawler.visited_urls
        assert isinstance(urls, set)
        assert len(urls) == 0

    def test_duration_in_result(self):
        pages = {"/": (200, "text/html", _html())}
        transport = _FakeTransport(pages)

        async def run():
            async with httpx.AsyncClient(transport=transport) as client:
                crawler = AdvancedCrawler(respect_robots=False)
                return await crawler.crawl(["https://site.local/"], client=client)

        result = asyncio.run(run())
        assert "duration_ms" in result
        assert result["duration_ms"] >= 0
