"""
Unit tests for Multi-Step Business Logic & Tenant Isolation Audit Module (multi_step.py).
"""

import pytest
import respx

from armorscan.core.client import HttpClient
from armorscan.core.models import Confidence, ScanTarget, Severity
from armorscan.modules.multi_step import MultiStepLogicModule


@pytest.mark.asyncio
async def test_multi_step_vulnerable_idor_detected():
    module = MultiStepLogicModule()
    target = ScanTarget.from_url("https://app.example.com/api/orders?user_id=usr_alice")

    alice_data = '{"user_id": "usr_alice", "orders": [1, 2], "balance": 500}'
    bob_data = '{"user_id": "usr_bob", "orders": [999, 1000], "balance": 185000}'

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://app.example.com", assert_all_called=False) as respx_mock:
            # Baseline request as usr_alice returns 200
            respx_mock.get("/api/orders?user_id=usr_alice").respond(
                status_code=200,
                text=alice_data,
                headers={"Content-Type": "application/json"},
            )
            # Tampered request with usr_bob also returns 200 with Bob's data (Vulnerable)
            respx_mock.get("/api/orders?user_id=usr_bob").respond(
                status_code=200,
                text=bob_data,
                headers={"Content-Type": "application/json"},
            )

            result = await module.run(target, client)

            assert len(result.findings) == 1
            f = result.findings[0]
            assert f.id == "CROSS_TENANT_OBJECT_ACCESS"
            assert f.severity == Severity.HIGH
            assert f.confidence == Confidence.CONFIRMED
            assert f.cwe_id == "CWE-639"
            assert "usr_bob" in f.evidence
            assert f.curl_command.startswith("curl")
            assert "GET" in f.request_snippet
            assert len(f.remediation_snippets) >= 2


@pytest.mark.asyncio
async def test_multi_step_safe_idor_blocked():
    module = MultiStepLogicModule()
    target = ScanTarget.from_url("https://secure.example.com/api/orders?user_id=usr_alice")

    alice_data = '{"user_id": "usr_alice", "orders": [1, 2]}'

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://secure.example.com", assert_all_called=False) as respx_mock:
            respx_mock.get("/api/orders?user_id=usr_alice").respond(
                status_code=200,
                text=alice_data,
                headers={"Content-Type": "application/json"},
            )
            # Tampered request with usr_bob properly returns 403 Forbidden
            respx_mock.get("/api/orders?user_id=usr_bob").respond(
                status_code=403,
                text='{"error": "Forbidden: unauthorized tenant object access"}',
                headers={"Content-Type": "application/json"},
            )

            result = await module.run(target, client)

            assert len(result.findings) == 0
            assert any("Cross-tenant access properly blocked" in p for p in result.passed_checks)


@pytest.mark.asyncio
async def test_multi_step_numeric_id_tampering():
    module = MultiStepLogicModule()
    target = ScanTarget.from_url("https://billing.example.com/invoices?id=101")

    rec_101 = '{"id": 101, "total": 45.00}'
    rec_102 = '{"id": 102, "total": 999.00, "client": "EvilCorp"}'

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://billing.example.com", assert_all_called=False) as respx_mock:
            respx_mock.get("/invoices?id=101").respond(
                status_code=200,
                text=rec_101,
                headers={"Content-Type": "application/json"},
            )
            respx_mock.get("/invoices?id=102").respond(
                status_code=200,
                text=rec_102,
                headers={"Content-Type": "application/json"},
            )

            result = await module.run(target, client)

            assert len(result.findings) == 1
            assert result.findings[0].id == "CROSS_TENANT_OBJECT_ACCESS"


def test_tampered_id_derivation():
    module = MultiStepLogicModule()
    assert module._get_tampered_id("usr_alice") == "usr_bob"
    assert module._get_tampered_id("usr_bob") == "usr_alice"
    assert module._get_tampered_id("alice") == "bob"
    assert module._get_tampered_id("101") == "102"
    assert module._get_tampered_id("99") == "100"
    assert module._get_tampered_id("custom_id") == "custom_id_other"
