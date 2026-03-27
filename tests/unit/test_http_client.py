"""Tests for redcheck.plugins._http — cover RedCheckHTTPClient class."""

from __future__ import annotations

import ssl
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from redcheck.plugins._http import RedCheckHTTPClient, scanning_ssl_context


class TestScanningSSLContext:
    def test_returns_ssl_context(self):
        ctx = scanning_ssl_context()
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.check_hostname is False
        assert ctx.verify_mode == ssl.CERT_NONE


class TestRedCheckHTTPClientInit:
    def test_default_init(self):
        client = RedCheckHTTPClient()
        assert client._plugin_name == "unknown"
        assert client._rate_limiter is None

    def test_custom_init(self):
        limiter = MagicMock()
        client = RedCheckHTTPClient(plugin_name="scanner", rate_limiter=limiter, timeout=10.0)
        assert client._plugin_name == "scanner"
        assert client._rate_limiter is limiter


class TestRedCheckHTTPClientMethods:
    @pytest.fixture
    def client(self):
        c = RedCheckHTTPClient(plugin_name="test")
        return c

    @pytest.mark.asyncio
    async def test_get(self, client):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.request = MagicMock()
        mock_resp.request.method = "GET"
        mock_resp.request.url = "https://example.com"
        mock_resp.status_code = 200
        mock_resp.content = b"ok"

        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=mock_resp)

        resp = await client.get("https://example.com")
        assert resp is mock_resp
        client._client.request.assert_awaited_once_with("GET", "https://example.com")

    @pytest.mark.asyncio
    async def test_post(self, client):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.request = MagicMock()
        mock_resp.request.method = "POST"
        mock_resp.request.url = "https://example.com"
        mock_resp.status_code = 201
        mock_resp.content = b"created"

        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=mock_resp)

        resp = await client.post("https://example.com", json={"key": "val"})
        assert resp is mock_resp

    @pytest.mark.asyncio
    async def test_head(self, client):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.request = MagicMock()
        mock_resp.request.method = "HEAD"
        mock_resp.request.url = "https://example.com"
        mock_resp.status_code = 200
        mock_resp.content = b""

        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=mock_resp)

        resp = await client.head("https://example.com")
        assert resp is mock_resp

    @pytest.mark.asyncio
    async def test_rate_limiter_called(self):
        limiter = AsyncMock()
        client = RedCheckHTTPClient(plugin_name="p", rate_limiter=limiter)

        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.request = MagicMock()
        mock_resp.request.method = "GET"
        mock_resp.request.url = "https://test.com"
        mock_resp.status_code = 200
        mock_resp.content = b""

        client._client = AsyncMock()
        client._client.request = AsyncMock(return_value=mock_resp)

        await client.get("https://test.com")
        limiter.acquire.assert_awaited_once()


class TestCaptureEvidence:
    def test_builds_evidence_dict(self):
        client = RedCheckHTTPClient(plugin_name="scanner")

        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.request = MagicMock()
        mock_resp.request.method = "GET"
        mock_resp.request.url = "https://target.com/path"
        mock_resp.request.headers = {"User-Agent": "test"}
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.content = b"<html>test</html>"
        mock_resp.text = "<html>test</html>"

        ev = client.capture_evidence(mock_resp)
        assert ev["request"]["method"] == "GET"
        assert ev["response"]["status_code"] == 200
        assert ev["response"]["body_size"] == len(b"<html>test</html>")
        assert ev["plugin"] == "scanner"
        assert "captured_at" in ev
        assert "body_hash" in ev["response"]

    def test_empty_content(self):
        client = RedCheckHTTPClient(plugin_name="p")

        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.request = MagicMock()
        mock_resp.request.method = "HEAD"
        mock_resp.request.url = "https://t.com"
        mock_resp.request.headers = {}
        mock_resp.status_code = 204
        mock_resp.headers = {}
        mock_resp.content = b""
        mock_resp.text = ""

        ev = client.capture_evidence(mock_resp)
        assert ev["response"]["body_size"] == 0
        assert ev["response"]["body_preview"] == ""


class TestAsyncContextManager:
    @pytest.mark.asyncio
    async def test_aenter_aexit(self):
        async with RedCheckHTTPClient(plugin_name="ctx") as client:
            assert isinstance(client, RedCheckHTTPClient)

    @pytest.mark.asyncio
    async def test_aclose(self):
        client = RedCheckHTTPClient(plugin_name="close")
        client._client = AsyncMock()
        await client.aclose()
        client._client.aclose.assert_awaited_once()
