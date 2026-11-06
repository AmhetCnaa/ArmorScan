"""
Unit tests for the Security Headers Audit Module (headers.py).
"""

import pytest
import respx

from armorscan.core.client import HttpClient
from armorscan.core.models import ScanTarget, Severity
from armorscan.modules.headers import SecurityHeadersModule


@pytest.mark.asyncio
async def test_headers_all_missing():
    module = SecurityHeadersModule()
    target = ScanTarget.from_url("https://insecure-app.com")

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://insecure-app.com") as respx_mock:
            respx_mock.get("/").respond(status_code=200, headers={"Content-Type": "text/html"})

            result = await module.execute(target, client)
            assert result.module_name == "headers"
            assert result.has_findings is True

            finding_ids = [f.id for f in result.findings]
            assert "MISSING_HSTS" in finding_ids
            assert "MISSING_CSP" in finding_ids
            assert "MISSING_X_FRAME_OPTIONS" in finding_ids
            assert "MISSING_X_CONTENT_TYPE_OPTIONS" in finding_ids
            assert "MISSING_REFERRER_POLICY" in finding_ids
            assert "MISSING_PERMISSIONS_POLICY" in finding_ids

            # Verify remediation snippets are present
            hsts_finding = next(f for f in result.findings if f.id == "MISSING_HSTS")
            assert "nginx" in hsts_finding.remediation_snippets
            assert "express" in hsts_finding.remediation_snippets
            assert "fastapi" in hsts_finding.remediation_snippets


@pytest.mark.asyncio
async def test_headers_csp_unsafe_inline_and_eval():
    module = SecurityHeadersModule()
    target = ScanTarget.from_url("https://vulnerable-csp.com")

    bad_csp = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' *; object-src 'none'"

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://vulnerable-csp.com") as respx_mock:
            respx_mock.get("/").respond(
                status_code=200,
                headers={
                    "Content-Security-Policy": bad_csp,
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
                    "X-Frame-Options": "DENY",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "strict-origin-when-cross-origin",
                    "Permissions-Policy": "camera=()",
                },
            )

            result = await module.execute(target, client)
            finding_ids = [f.id for f in result.findings]

            assert "CSP_UNSAFE_INLINE" in finding_ids
            assert "CSP_UNSAFE_EVAL" in finding_ids
            assert "CSP_WILDCARD_SOURCE" in finding_ids

            inline_finding = next(f for f in result.findings if f.id == "CSP_UNSAFE_INLINE")
            assert inline_finding.severity == Severity.HIGH

            eval_finding = next(f for f in result.findings if f.id == "CSP_UNSAFE_EVAL")
            assert eval_finding.severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_headers_weak_hsts():
    module = SecurityHeadersModule()
    target = ScanTarget.from_url("https://short-hsts.com")

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://short-hsts.com") as respx_mock:
            respx_mock.get("/").respond(
                status_code=200,
                headers={"Strict-Transport-Security": "max-age=86400"},  # 1 day instead of 1 year
            )

            result = await module.execute(target, client)
            finding_ids = [f.id for f in result.findings]
            assert "WEAK_HSTS_MAX_AGE" in finding_ids
            assert "HSTS_MISSING_SUBDOMAINS" in finding_ids


@pytest.mark.asyncio
async def test_headers_hsts_disabled_zero():
    module = SecurityHeadersModule()
    target = ScanTarget.from_url("https://zero-hsts.com")

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://zero-hsts.com") as respx_mock:
            respx_mock.get("/").respond(
                status_code=200,
                headers={"Strict-Transport-Security": "max-age=0"},
            )

            result = await module.execute(target, client)
            finding_ids = [f.id for f in result.findings]
            assert "HSTS_DISABLED_ZERO_MAX_AGE" in finding_ids


@pytest.mark.asyncio
async def test_headers_perfect_configuration():
    module = SecurityHeadersModule()
    target = ScanTarget.from_url("https://secure-app.com")

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://secure-app.com") as respx_mock:
            respx_mock.get("/").respond(
                status_code=200,
                headers={
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
                    "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'",
                    "X-Frame-Options": "DENY",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "strict-origin-when-cross-origin",
                    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                },
            )

            result = await module.execute(target, client)
            assert len(result.findings) == 0
            assert "hsts" in result.passed_checks
            assert "csp" in result.passed_checks
            assert "x-frame-options" in result.passed_checks
            assert "x-content-type-options" in result.passed_checks
            assert "referrer-policy" in result.passed_checks
            assert "permissions-policy" in result.passed_checks


@pytest.mark.asyncio
async def test_headers_information_disclosure():
    module = SecurityHeadersModule()
    target = ScanTarget.from_url("https://leaky-app.com")

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://leaky-app.com") as respx_mock:
            respx_mock.get("/").respond(
                status_code=200,
                headers={
                    "Server": "Apache/2.4.41 (Ubuntu)",
                    "X-Powered-By": "Express",
                    "X-AspNet-Version": "4.0.30319",
                },
            )

            result = await module.execute(target, client)
            finding_ids = [f.id for f in result.findings]
            assert "SERVER_VERSION_DISCLOSURE" in finding_ids
            assert "X_POWERED_BY_DISCLOSURE" in finding_ids
            assert "ASPNET_VERSION_DISCLOSURE" in finding_ids
