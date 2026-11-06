"""
Tests for the async HttpClient engine using respx mock router.
"""

import httpx
import pytest
import respx

from armorscan.core.client import HttpClient


@pytest.mark.asyncio
async def test_client_get_success():
    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://app.dev") as respx_mock:
            respx_mock.get("/api/ping").respond(status_code=200, json={"status": "pong"}, headers={"X-Test": "1"})

            resp = await client.get("https://app.dev/api/ping")
            assert resp.ok is True
            assert resp.status_code == 200
            assert resp.headers.get("X-Test") == "1"
            assert "pong" in resp.text
            assert resp.elapsed >= 0


@pytest.mark.asyncio
async def test_client_error_handling():
    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://timeout.dev") as respx_mock:
            respx_mock.get("/slow").mock(side_effect=httpx.ConnectTimeout("Timeout"))

            resp = await client.get("https://timeout.dev/slow")
            assert resp.ok is False
            assert resp.status_code == 0
            assert "timed out" in (resp.error or "")


@pytest.mark.asyncio
async def test_client_burst_requests():
    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://burst.dev") as respx_mock:
            for i in range(10):
                respx_mock.get(f"/endpoint-{i}").respond(status_code=200, text=f"resp-{i}")

            urls = [f"https://burst.dev/endpoint-{i}" for i in range(10)]
            responses = await client.burst_requests(urls, concurrency=5)

            assert len(responses) == 10
            for idx, resp in enumerate(responses):
                assert resp.ok is True
                assert resp.status_code == 200
                assert resp.text == f"resp-{idx}"
