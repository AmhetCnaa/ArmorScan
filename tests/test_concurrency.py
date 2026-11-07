"""
Unit and Integration Tests for Concurrency & Transaction Isolation Auditor Module.
Tests synchronized millisecond burst requests, detection of race condition state
anomalies, and verification of atomic transaction isolation / mutex locking.
"""

import pytest
import respx
import httpx

from armorscan.core.client import HttpClient
from armorscan.core.models import Confidence, ScanTarget, Severity
from armorscan.modules.concurrency import ConcurrencyAuditModule


@pytest.mark.asyncio
async def test_concurrency_race_condition_anomaly_detected():
    target = ScanTarget.from_url("http://shop-race.local")
    module = ConcurrencyAuditModule(burst_size=8, candidate_paths=["/api/coupons/apply"])

    # Simulate missing mutex: multiple concurrent requests succeed before flag is set
    request_counter = 0

    def mock_coupon_handler(request: httpx.Request):
        nonlocal request_counter
        request_counter += 1
        # First 3 concurrent requests slip through and succeed
        if request_counter <= 3:
            return httpx.Response(200, json={"status": "success", "applied": True, "discount": 50})
        return httpx.Response(400, json={"status": "error", "message": "Coupon already redeemed"})

    with respx.mock(base_url="http://shop-race.local", assert_all_called=False) as respx_mock:
        respx_mock.post("/api/coupons/apply").mock(side_effect=mock_coupon_handler)

        async with HttpClient.for_target(target) as client:
            result = await module.execute(target, client)

    assert result.has_findings
    race_findings = [f for f in result.findings if f.id == "CONCURRENCY_ISOLATION_ANOMALY"]
    assert len(race_findings) == 1
    f = race_findings[0]
    assert f.severity == Severity.HIGH
    assert f.confidence == Confidence.CONFIRMED
    assert "coupons/apply" in f.title
    assert "CWE-362" in f.cwe_id


@pytest.mark.asyncio
async def test_concurrency_properly_serialized_safe_endpoint():
    target = ScanTarget.from_url("http://safe-shop.local")
    module = ConcurrencyAuditModule(burst_size=8, candidate_paths=["/api/coupons/apply"])

    request_counter = 0

    def mock_safe_coupon_handler(request: httpx.Request):
        nonlocal request_counter
        request_counter += 1
        # Exactly 1 succeeds, remaining 7 receive 409 Conflict
        if request_counter == 1:
            return httpx.Response(200, json={"status": "success", "applied": True})
        return httpx.Response(409, json={"error": "Conflict: lock held or coupon already redeemed"})

    with respx.mock(base_url="http://safe-shop.local", assert_all_called=False) as respx_mock:
        respx_mock.post("/api/coupons/apply").mock(side_effect=mock_safe_coupon_handler)

        async with HttpClient.for_target(target) as client:
            result = await module.execute(target, client)

    assert not result.has_findings
    assert len(result.passed_checks) > 0
    assert any("properly serialized" in ch for ch in result.passed_checks)
