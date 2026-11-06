"""
Unit tests for ArmorScan Authorization & Missing Auth Gate Module (authz_check.py).
Tests detection of missing authentication gates (BOLA/IDOR), safe 401/403 gate enforcement,
and login redirection validation.
"""

import httpx
import pytest
import respx

from armorscan.core.client import HttpClient
from armorscan.core.models import Confidence, ScanTarget, Severity
from armorscan.modules.authz_check import AuthzCheckModule


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_authz_check_missing_auth_gate_detected(respx_mock):
    target = ScanTarget.from_url("https://vulnerable-api.com/vuln/idor")
    client = HttpClient(verify_ssl=False)
    await client.start()

    private_json = {
        "user_id": "usr_7711",
        "username": "secret_agent",
        "email": "agent@classified.internal",
        "role": "admin",
        "balance": 999999.00,
    }

    # Both authenticated and unauthenticated return 200 with confidential user data
    respx_mock.get("https://vulnerable-api.com/vuln/idor").mock(
        return_value=httpx.Response(200, json=private_json)
    )

    module = AuthzCheckModule()
    result = await module.run(target, client)

    assert result.has_findings is True
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.id == "MISSING_AUTHENTICATION_GATE"
    assert finding.severity == Severity.CRITICAL
    assert finding.confidence == Confidence.CONFIRMED
    assert "user_id" in finding.evidence
    assert finding.cwe_id == "CWE-306"
    assert finding.curl_command is not None
    assert "curl -i -s -k -X GET 'https://vulnerable-api.com/vuln/idor'" in finding.curl_command
    assert "fastapi" in finding.remediation_snippets
    assert "express" in finding.remediation_snippets

    await client.close()


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_authz_check_properly_enforced_401(respx_mock):
    target = ScanTarget.from_url("https://secure-api.com/safe/idor")
    client = HttpClient(verify_ssl=False)
    await client.start()

    # Authenticated client gets 200, but unauthenticated gets 401
    def side_effect(request):
        if "authorization" in request.headers:
            return httpx.Response(200, json={"user": "authenticated_alice"})
        return httpx.Response(401, json={"error": "Unauthorized"})

    respx_mock.get("https://secure-api.com/safe/idor").mock(side_effect=side_effect)

    module = AuthzCheckModule()
    result = await module.run(target, client)

    assert result.has_findings is False
    assert len(result.passed_checks) >= 1
    assert any("Authentication gate properly enforced (HTTP 401)" in chk for chk in result.passed_checks)

    await client.close()


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_authz_check_login_redirect_safe(respx_mock):
    target = ScanTarget.from_url("https://web-app.com/dashboard/profile")
    client = HttpClient(verify_ssl=False)
    await client.start()

    def side_effect(request):
        if "authorization" in request.headers or "cookie" in request.headers:
            return httpx.Response(200, text="<html><body>Welcome User</body></html>")
        return httpx.Response(302, headers={"Location": "/auth/login"})

    respx_mock.get("https://web-app.com/dashboard/profile").mock(side_effect=side_effect)

    module = AuthzCheckModule()
    result = await module.run(target, client)

    assert result.has_findings is False
    assert any("safely redirected to login" in chk for chk in result.passed_checks)

    await client.close()
