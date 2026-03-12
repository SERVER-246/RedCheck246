"""Tests for AdvancedCrawler enhanced discovery methods (Phase 7, §26)."""

from __future__ import annotations

import asyncio

import httpx
import pytest

from redcheck.constants import CRAWLER_MAX_FORMS_PER_PAGE
from redcheck.plugins.dast.crawler import AdvancedCrawler, FormDescriptor


@pytest.fixture
def crawler() -> AdvancedCrawler:
    return AdvancedCrawler(max_pages=10, max_depth=2, rate_rps=100.0)


# ------------------------------------------------------------------ #
# enumerate_forms
# ------------------------------------------------------------------ #


class TestEnumerateForms:
    """Form parsing and extraction tests."""

    def test_single_form(self, crawler: AdvancedCrawler):
        html = """
        <form action="/submit" method="post">
            <input name="username" type="text">
            <input name="password" type="password">
            <button type="submit">Go</button>
        </form>
        """
        forms = crawler.enumerate_forms("https://example.com/page", html)
        assert len(forms) == 1
        f = forms[0]
        assert isinstance(f, FormDescriptor)
        assert f.action == "https://example.com/submit"
        assert f.method == "POST"
        assert len(f.fields) == 2
        assert f.has_file_upload is False
        assert f.is_login_form is False

    def test_multiple_forms(self, crawler: AdvancedCrawler):
        html = """
        <form action="/a" method="get"><input name="q" type="text"></form>
        <form action="/b" method="post"><input name="x" type="hidden"></form>
        """
        forms = crawler.enumerate_forms("https://example.com", html)
        assert len(forms) == 2
        assert forms[0].action.endswith("/a")
        assert forms[1].action.endswith("/b")

    def test_file_upload_detection(self, crawler: AdvancedCrawler):
        html = """
        <form action="/upload" method="post">
            <input name="file" type="file">
            <input name="desc" type="text">
        </form>
        """
        forms = crawler.enumerate_forms("https://example.com", html)
        assert len(forms) == 1
        assert forms[0].has_file_upload is True

    def test_login_form_detection(self, crawler: AdvancedCrawler):
        html = """
        <form action="/login" method="post">
            <input name="user" type="text">
            <input name="pass" type="password">
        </form>
        """
        forms = crawler.enumerate_forms("https://example.com/login", html)
        assert len(forms) == 1
        assert forms[0].is_login_form is True

    def test_textarea_and_select_fields(self, crawler: AdvancedCrawler):
        html = """
        <form action="/feedback" method="post">
            <textarea name="comment"></textarea>
            <select name="rating"><option value="1">1</option></select>
        </form>
        """
        forms = crawler.enumerate_forms("https://example.com", html)
        assert len(forms) == 1
        field_names = {f["name"] for f in forms[0].fields}
        assert "comment" in field_names
        assert "rating" in field_names

    def test_max_forms_cap(self, crawler: AdvancedCrawler):
        # Build HTML with more forms than cap
        form_html = '<form action="/f" method="get"><input name="x" type="text"></form>'
        html = form_html * (CRAWLER_MAX_FORMS_PER_PAGE + 5)
        forms = crawler.enumerate_forms("https://example.com", html)
        assert len(forms) == CRAWLER_MAX_FORMS_PER_PAGE

    def test_form_no_action(self, crawler: AdvancedCrawler):
        html = """
        <form method="post">
            <input name="data" type="text">
        </form>
        """
        forms = crawler.enumerate_forms("https://example.com/page", html)
        # No action → form posts to same page
        assert len(forms) == 1
        assert forms[0].action == "https://example.com/page"

    def test_default_get_method(self, crawler: AdvancedCrawler):
        html = '<form action="/s"><input name="q" type="text"></form>'
        forms = crawler.enumerate_forms("https://example.com", html)
        assert forms[0].method == "GET"


# ------------------------------------------------------------------ #
# discover_login_flows
# ------------------------------------------------------------------ #


class TestDiscoverLoginFlows:
    """Login flow detection tests."""

    def test_detects_login_paths(self, crawler: AdvancedCrawler):
        urls = [
            "https://example.com/",
            "https://example.com/login",
            "https://example.com/about",
            "https://example.com/signin",
        ]
        flows = crawler.discover_login_flows(urls)
        assert len(flows) == 2
        paths = {f["path"] for f in flows}
        assert "/login" in paths
        assert "/signin" in paths

    def test_no_login_paths(self, crawler: AdvancedCrawler):
        urls = [
            "https://example.com/",
            "https://example.com/about",
        ]
        flows = crawler.discover_login_flows(urls)
        assert flows == []

    def test_deduplication(self, crawler: AdvancedCrawler):
        urls = [
            "https://example.com/login",
            "https://example.com/login",
        ]
        flows = crawler.discover_login_flows(urls)
        assert len(flows) == 1

    def test_auth_sso_detected(self, crawler: AdvancedCrawler):
        urls = [
            "https://example.com/auth/callback",
            "https://example.com/sso/start",
        ]
        flows = crawler.discover_login_flows(urls)
        assert len(flows) == 2


# ------------------------------------------------------------------ #
# map_parameters
# ------------------------------------------------------------------ #


class TestMapParameters:
    """Parameter mapping tests."""

    def test_extracts_query_params(self, crawler: AdvancedCrawler):
        urls = [
            "https://example.com/search?q=test&page=1",
            "https://example.com/view?id=42",
        ]
        params = crawler.map_parameters(urls)
        assert len(params) == 3
        names = {p["parameter"] for p in params}
        assert names == {"q", "page", "id"}

    def test_no_query_params(self, crawler: AdvancedCrawler):
        urls = ["https://example.com/", "https://example.com/about"]
        params = crawler.map_parameters(urls)
        assert params == []

    def test_dedup_same_path_param(self, crawler: AdvancedCrawler):
        urls = [
            "https://example.com/search?q=foo",
            "https://example.com/search?q=bar",
        ]
        params = crawler.map_parameters(urls)
        assert len(params) == 1
        assert params[0]["parameter"] == "q"

    def test_finding_type(self, crawler: AdvancedCrawler):
        urls = ["https://example.com/api?token=abc"]
        params = crawler.map_parameters(urls)
        assert params[0]["finding_type"] == "parameter_mapped"


# ------------------------------------------------------------------ #
# discover_api_specs
# ------------------------------------------------------------------ #


class TestDiscoverApiSpecs:
    """API spec discovery tests (uses httpx mock transport)."""

    def test_discovers_specs(self, crawler: AdvancedCrawler):
        """discover_api_specs returns found API specs."""

        async def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path in ("/openapi.json", "/swagger.json"):
                return httpx.Response(
                    200,
                    json={"openapi": "3.0.0"},
                    headers={"content-type": "application/json"},
                )
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        specs = asyncio.run(crawler.discover_api_specs("https://example.com", client))
        assert len(specs) >= 1
        assert specs[0]["finding_type"] == "api_spec_discovered"

    def test_no_specs_found(self, crawler: AdvancedCrawler):
        """Returns empty when no API specs exist."""

        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        specs = asyncio.run(crawler.discover_api_specs("https://example.com", client))
        assert specs == []
