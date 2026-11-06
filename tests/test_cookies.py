"""
Unit tests for Cookie Hygiene Audit Module (cookies.py).
"""

import pytest
import respx

from armorscan.core.client import HttpClient
from armorscan.core.models import ScanTarget, Severity
from armorscan.modules.cookies import CookieHygieneModule


@pytest.mark.asyncio
async def test_cookie_sensitive_session_missing_httponly_and_secure():
    module = CookieHygieneModule()
    target = ScanTarget.from_url("https://vulnerable-bank.com")

    # Insecure session cookie (missing HttpOnly, missing Secure)
    raw_cookie = "session_id=secret123456; Path=/; SameSite=Lax"

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://vulnerable-bank.com") as respx_mock:
            respx_mock.get("/").respond(
                status_code=200,
                headers={"Set-Cookie": raw_cookie},
            )

            result = await module.execute(target, client)
            assert result.module_name == "cookies"
            finding_ids = [f.id for f in result.findings]

            assert "COOKIE_MISSING_HTTPONLY_SESSION" in finding_ids
            assert "COOKIE_MISSING_SECURE_SESSION" in finding_ids

            httponly_finding = next(f for f in result.findings if f.id == "COOKIE_MISSING_HTTPONLY_SESSION")
            assert httponly_finding.severity == Severity.HIGH
            assert "express" in httponly_finding.remediation_snippets
            assert "fastapi" in httponly_finding.remediation_snippets
            assert "django" in httponly_finding.remediation_snippets


@pytest.mark.asyncio
async def test_cookie_normal_cookie_low_severity():
    module = CookieHygieneModule()
    target = ScanTarget.from_url("https://my-blog.com")

    # Normal preference cookie missing HttpOnly
    raw_cookie = "user_theme=dark; Secure; SameSite=Lax; Path=/"

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://my-blog.com") as respx_mock:
            respx_mock.get("/").respond(
                status_code=200,
                headers={"Set-Cookie": raw_cookie},
            )

            result = await module.execute(target, client)
            finding_ids = [f.id for f in result.findings]

            assert "COOKIE_MISSING_HTTPONLY" in finding_ids
            assert "COOKIE_MISSING_HTTPONLY_SESSION" not in finding_ids

            finding = next(f for f in result.findings if f.id == "COOKIE_MISSING_HTTPONLY")
            assert finding.severity == Severity.LOW


@pytest.mark.asyncio
async def test_cookie_samesite_none_without_secure():
    module = CookieHygieneModule()
    target = ScanTarget.from_url("https://partner-portal.com")

    raw_cookie = "cross_auth=token123; HttpOnly; SameSite=None; Path=/"

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://partner-portal.com") as respx_mock:
            respx_mock.get("/").respond(
                status_code=200,
                headers={"Set-Cookie": raw_cookie},
            )

            result = await module.execute(target, client)
            finding_ids = [f.id for f in result.findings]

            assert "COOKIE_SAMESITE_NONE_INSECURE" in finding_ids
            finding = next(f for f in result.findings if f.id == "COOKIE_SAMESITE_NONE_INSECURE")
            assert finding.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_cookie_valid_host_prefix():
    module = CookieHygieneModule()
    target = ScanTarget.from_url("https://secure-fintech.com")

    # Perfectly configured __Host- session cookie
    raw_cookie = "__Host-session=supersecrettoken; Secure; HttpOnly; SameSite=Strict; Path=/"

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://secure-fintech.com") as respx_mock:
            respx_mock.get("/").respond(
                status_code=200,
                headers={"Set-Cookie": raw_cookie},
            )

            result = await module.execute(target, client)
            assert len(result.findings) == 0
            assert "__Host-session:valid-host-prefix" in result.passed_checks
            assert "__Host-session:httponly-enabled" in result.passed_checks
            assert "__Host-session:secure-enabled" in result.passed_checks
            assert "__Host-session:samesite-strict" in result.passed_checks


@pytest.mark.asyncio
async def test_cookie_invalid_host_prefix_violations():
    module = CookieHygieneModule()
    target = ScanTarget.from_url("https://misconfigured-site.com")

    # __Host- cookie missing Secure, having Domain, and Path is not /
    raw_cookie = "__Host-jwt=abc; HttpOnly; Domain=misconfigured-site.com; Path=/api"

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://misconfigured-site.com") as respx_mock:
            respx_mock.get("/").respond(
                status_code=200,
                headers={"Set-Cookie": raw_cookie},
            )

            result = await module.execute(target, client)
            finding_ids = [f.id for f in result.findings]

            assert "INVALID_HOST_COOKIE_PREFIX_NO_SECURE" in finding_ids
            assert "INVALID_HOST_COOKIE_PREFIX_DOMAIN" in finding_ids
            assert "INVALID_HOST_COOKIE_PREFIX_PATH" in finding_ids


@pytest.mark.asyncio
async def test_cookie_no_cookies_set():
    module = CookieHygieneModule()
    target = ScanTarget.from_url("https://static-site.com")

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://static-site.com") as respx_mock:
            respx_mock.get("/").respond(status_code=200, text="Static site")
            respx_mock.get("/login").respond(status_code=404)
            respx_mock.get("/api/auth").respond(status_code=404)
            respx_mock.get("/auth/login").respond(status_code=404)

            result = await module.execute(target, client)
            assert len(result.findings) == 0
            assert "no-cookies-set-on-target" in result.passed_checks
