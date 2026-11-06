"""
Unit tests for JWT Client Security & Lifecycle Audit module (jwt_audit.py).
"""

import base64
import json
import time
import pytest
import respx
import httpx

from armorscan.core.client import HttpClient
from armorscan.core.models import ScanTarget, Severity
from armorscan.modules.jwt_audit import JwtAuditModule


def make_jwt(header: dict, payload: dict, signature: str = "signature") -> str:
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{h_b64}.{p_b64}.{signature}"


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_jwt_audit_alg_none_detected(respx_mock):
    target = ScanTarget.from_url("https://auth-site.com")
    client = HttpClient(verify_ssl=False)
    await client.start()

    # JWT with alg: none
    token = make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "user123", "exp": time.time() + 3600})
    respx_mock.get("https://auth-site.com/").mock(
        return_value=httpx.Response(200, headers={"Set-Cookie": f"auth_token={token}; Path=/"})
    )

    module = JwtAuditModule()
    result = await module.run(target, client)
    await client.close()

    assert any(f.id == "JWT_INSECURE_ALGORITHM_NONE" and f.severity == Severity.CRITICAL for f in result.findings)


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_jwt_audit_missing_exp_detected(respx_mock):
    target = ScanTarget.from_url("https://auth-site.com")
    client = HttpClient(verify_ssl=False)
    await client.start()

    # JWT missing exp
    token = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user123", "role": "admin"})
    respx_mock.get("https://auth-site.com/").mock(
        return_value=httpx.Response(200, text=f"var token = '{token}';")
    )

    module = JwtAuditModule()
    result = await module.run(target, client)
    await client.close()

    assert any(f.id == "JWT_MISSING_EXPIRATION" and f.severity == Severity.MEDIUM for f in result.findings)


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_jwt_audit_excessive_exp_detected(respx_mock):
    target = ScanTarget.from_url("https://auth-site.com")
    client = HttpClient(verify_ssl=False)
    await client.start()

    # 100 days expiration
    token = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user123", "exp": time.time() + 100 * 86400})
    respx_mock.get("https://auth-site.com/").mock(
        return_value=httpx.Response(200, headers={"Set-Cookie": f"session={token}"})
    )

    module = JwtAuditModule()
    result = await module.run(target, client)
    await client.close()

    assert any(f.id == "JWT_EXCESSIVE_EXPIRATION" and f.severity == Severity.LOW for f in result.findings)


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_jwt_audit_sensitive_payload_credentials(respx_mock):
    target = ScanTarget.from_url("https://auth-site.com")
    client = HttpClient(verify_ssl=False)
    await client.start()

    # Leaking password in payload
    token = make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "user123", "password": "CleartextPassword123!", "exp": time.time() + 3600}
    )
    respx_mock.get("https://auth-site.com/").mock(
        return_value=httpx.Response(200, text=f'{{"access_token": "{token}"}}')
    )

    module = JwtAuditModule()
    result = await module.run(target, client)
    await client.close()

    assert any(f.id == "JWT_SENSITIVE_DATA_IN_PAYLOAD" and f.severity == Severity.HIGH for f in result.findings)


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_jwt_audit_clean_secure_token(respx_mock):
    target = ScanTarget.from_url("https://auth-site.com")
    client = HttpClient(verify_ssl=False)
    await client.start()

    # Well configured token (HS256, 15 min expiration, no sensitive payload keys)
    token = make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "user123", "role": "viewer", "exp": time.time() + 900}
    )
    respx_mock.get("https://auth-site.com/").mock(
        return_value=httpx.Response(200, headers={"Set-Cookie": f"jwt={token}; Secure; HttpOnly"})
    )

    module = JwtAuditModule()
    result = await module.run(target, client)
    await client.close()

    assert len(result.findings) == 0
    assert any("jwt-alg-valid" in c for c in result.passed_checks)
    assert any("jwt-exp-claim-enforced" in c for c in result.passed_checks)


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_jwt_audit_no_jwt(respx_mock):
    target = ScanTarget.from_url("https://no-jwt-site.com")
    client = HttpClient(verify_ssl=False)
    await client.start()

    respx_mock.get("https://no-jwt-site.com/").mock(return_value=httpx.Response(200, text="Plain landing page"))
    respx_mock.get("https://no-jwt-site.com/api/auth/token").mock(return_value=httpx.Response(404, text="Not Found"))
    respx_mock.get("https://no-jwt-site.com/api/token").mock(return_value=httpx.Response(404, text="Not Found"))
    respx_mock.get("https://no-jwt-site.com/auth/login").mock(return_value=httpx.Response(404, text="Not Found"))

    module = JwtAuditModule()
    result = await module.run(target, client)
    await client.close()

    assert len(result.findings) == 0
    assert "no-jwt-tokens-detected" in result.passed_checks
