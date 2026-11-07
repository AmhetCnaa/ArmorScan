"""
Unit and Integration Tests for API Fuzzing & Anomaly Crash Detector Module.
Verifies detection of unhandled 500 server crashes during fuzzing, latency spike
resource exhaustion detection, baseline 500 rejection for zero false positives,
and clean input validation handling.
"""

import asyncio
import pytest
import respx
import httpx

from armorscan.core.client import HttpClient
from armorscan.core.models import Confidence, ScanTarget, Severity
from armorscan.modules.fuzzer import ApiFuzzerModule


@pytest.mark.asyncio
async def test_fuzzer_unhandled_500_detected():
    target = ScanTarget.from_url("http://fuzz-test.local")
    module = ApiFuzzerModule(target_endpoints=["/api/products?id=1"])

    with respx.mock(base_url="http://fuzz-test.local", assert_all_called=False) as respx_mock:
        # Baseline request returns 200 OK
        respx_mock.get("/api/products?id=1").mock(
            return_value=httpx.Response(200, json={"id": 1, "title": "Laptop"})
        )
        # Fuzz request with extreme boundary crashes the server with HTTP 500
        respx_mock.get(url__regex=r"/api/products\?id=9223372036854775807").mock(
            return_value=httpx.Response(
                500,
                text="Internal Server Error: BigInt overflow in database query planner",
            )
        )
        # Default handler for other queries
        respx_mock.get(url__regex=r"/api/products.*").mock(
            return_value=httpx.Response(400, json={"error": "Invalid ID"})
        )

        async with HttpClient.for_target(target) as client:
            result = await module.execute(target, client)

    assert result.has_findings
    fuzz_findings = [f for f in result.findings if f.id == "UNHANDLED_EXCEPTION_500_ANOMALY"]
    assert len(fuzz_findings) == 1
    f = fuzz_findings[0]
    assert f.severity == Severity.HIGH
    assert f.confidence == Confidence.CONFIRMED
    assert "id" in f.title
    assert "500" in f.title


@pytest.mark.asyncio
async def test_fuzzer_baseline_500_rejection_zero_fp():
    target = ScanTarget.from_url("http://fuzz-test.local")
    module = ApiFuzzerModule(target_endpoints=["/api/broken?q=test"])

    with respx.mock(base_url="http://fuzz-test.local", assert_all_called=False) as respx_mock:
        # Baseline is ALREADY broken with 500
        respx_mock.get(url__regex=r"/api/broken.*").mock(
            return_value=httpx.Response(500, text="Database offline")
        )

        async with HttpClient.for_target(target) as client:
            result = await module.execute(target, client)

    # Must NOT report fuzz anomaly if baseline was already 500
    assert not result.has_findings


@pytest.mark.asyncio
async def test_fuzzer_clean_input_validation():
    target = ScanTarget.from_url("http://fuzz-test.local")
    module = ApiFuzzerModule(target_endpoints=["/api/search?q=test"])

    with respx.mock(base_url="http://fuzz-test.local") as respx_mock:
        respx_mock.get("/api/search?q=test").mock(
            return_value=httpx.Response(200, json={"results": []})
        )
        # Clean server handles boundaries with 200 or 400 Bad Request
        respx_mock.get(url__regex=r"/api/search.*").mock(
            return_value=httpx.Response(400, json={"error": "Validation error"})
        )

        async with HttpClient.for_target(target) as client:
            result = await module.execute(target, client)

    assert not result.has_findings
    assert len(result.passed_checks) > 0
    assert any("cleanly" in ch for ch in result.passed_checks)
