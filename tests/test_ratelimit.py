"""
Unit tests for Rate Limiting & DoS Resilience Audit Module (ratelimit.py).
"""

import pytest
import respx

from armorscan.core.client import HttpClient
from armorscan.core.models import ScanTarget, Severity
from armorscan.modules.ratelimit import RateLimitModule


@pytest.mark.asyncio
async def test_ratelimit_throttling_429():
    module = RateLimitModule(burst_count=10, concurrency=5)
    target = ScanTarget.from_url("https://rate-limited-api.com")

    request_count = 0

    def rate_limit_handler(request):
        nonlocal request_count
        request_count += 1
        if request_count > 5:
            return respx.MockResponse(429, headers={"Retry-After": "60"}, text="Rate limit exceeded")
        return respx.MockResponse(200, text="OK")

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://rate-limited-api.com", assert_all_called=False) as respx_mock:
            respx_mock.get("/").mock(side_effect=rate_limit_handler)

            result = await module.execute(target, client)
            assert len(result.findings) == 0
            assert any("rate-limiting-enforced" in check for check in result.passed_checks)


@pytest.mark.asyncio
async def test_ratelimit_headers_active():
    module = RateLimitModule(burst_count=10, concurrency=5)
    target = ScanTarget.from_url("https://header-limited-api.com")

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://header-limited-api.com", assert_all_called=False) as respx_mock:
            respx_mock.get("/").respond(
                status_code=200,
                headers={
                    "X-RateLimit-Limit": "100",
                    "X-RateLimit-Remaining": "85",
                    "X-RateLimit-Reset": "1670000000",
                },
            )

            result = await module.execute(target, client)
            assert len(result.findings) == 0
            assert any("rate-limiting-headers-active" in check for check in result.passed_checks)


@pytest.mark.asyncio
async def test_ratelimit_missing():
    module = RateLimitModule(burst_count=10, concurrency=5)
    target = ScanTarget.from_url("https://unlimited-api.com")

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://unlimited-api.com", assert_all_called=False) as respx_mock:
            # Responds 200 with no rate limit headers
            respx_mock.get("/").respond(status_code=200, text="Unrestricted")

            result = await module.execute(target, client)
            finding_ids = [f.id for f in result.findings]

            assert "MISSING_RATE_LIMITING" in finding_ids
            finding = next(f for f in result.findings if f.id == "MISSING_RATE_LIMITING")
            assert finding.severity == Severity.MEDIUM
            assert "nginx" in finding.remediation_snippets
            assert "express" in finding.remediation_snippets
            assert "fastapi" in finding.remediation_snippets
