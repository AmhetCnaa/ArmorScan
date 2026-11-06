"""
Unit tests for CORS Configuration & HTTP Method Security Audit Module (cors.py).
"""

import pytest
import respx

from armorscan.core.client import HttpClient
from armorscan.core.models import ScanTarget, Severity
from armorscan.modules.cors import CorsAndMethodModule


@pytest.mark.asyncio
async def test_cors_arbitrary_origin_with_credentials():
    module = CorsAndMethodModule()
    target = ScanTarget.from_url("https://vulnerable-api.com")

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://vulnerable-api.com", assert_all_called=False) as respx_mock:
            def handler(request):
                origin = request.headers.get("origin")
                headers = {}
                if origin == "https://evil-attacker.com":
                    headers["Access-Control-Allow-Origin"] = origin
                    headers["Access-Control-Allow-Credentials"] = "true"
                return respx.MockResponse(200, headers=headers)

            respx_mock.get("/").mock(side_effect=handler)
            respx_mock.request("TRACE", "/").respond(status_code=405)
            respx_mock.options("/").respond(status_code=200, headers={"Allow": "GET, POST, OPTIONS"})

            result = await module.execute(target, client)
            finding_ids = [f.id for f in result.findings]

            assert "CORS_ARBITRARY_ORIGIN_WITH_CREDENTIALS" in finding_ids
            finding = next(f for f in result.findings if f.id == "CORS_ARBITRARY_ORIGIN_WITH_CREDENTIALS")
            assert finding.severity == Severity.CRITICAL
            assert "express" in finding.remediation_snippets
            assert "fastapi" in finding.remediation_snippets
            assert "nginx" in finding.remediation_snippets


@pytest.mark.asyncio
async def test_cors_null_origin_trust():
    module = CorsAndMethodModule()
    target = ScanTarget.from_url("https://null-trust.com")

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://null-trust.com", assert_all_called=False) as respx_mock:
            def handler(request):
                origin = request.headers.get("origin")
                headers = {}
                if origin == "null":
                    headers["Access-Control-Allow-Origin"] = "null"
                    headers["Access-Control-Allow-Credentials"] = "true"
                return respx.MockResponse(200, headers=headers)

            respx_mock.get("/").mock(side_effect=handler)
            respx_mock.request("TRACE", "/").respond(status_code=405)
            respx_mock.options("/").respond(status_code=200, headers={"Allow": "GET, POST"})

            result = await module.execute(target, client)
            finding_ids = [f.id for f in result.findings]

            assert "CORS_TRUST_NULL_ORIGIN_CREDENTIALS" in finding_ids
            finding = next(f for f in result.findings if f.id == "CORS_TRUST_NULL_ORIGIN_CREDENTIALS")
            assert finding.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_cors_wildcard_credentials_conflict():
    module = CorsAndMethodModule()
    target = ScanTarget.from_url("https://conflicted-cors.com")

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://conflicted-cors.com", assert_all_called=False) as respx_mock:
            respx_mock.get("/").respond(
                status_code=200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Credentials": "true",
                },
            )
            respx_mock.request("TRACE", "/").respond(status_code=405)
            respx_mock.options("/").respond(status_code=200)

            result = await module.execute(target, client)
            finding_ids = [f.id for f in result.findings]

            assert "CORS_WILDCARD_CREDENTIALS_CONFLICT" in finding_ids
            finding = next(f for f in result.findings if f.id == "CORS_WILDCARD_CREDENTIALS_CONFLICT")
            assert finding.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_cors_regex_bypass_origin():
    module = CorsAndMethodModule()
    target = ScanTarget.from_url("https://target.com")

    post_domain = "https://target.com.attacker.com"

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://target.com", assert_all_called=False) as respx_mock:
            def handler(request):
                origin = request.headers.get("origin")
                headers = {}
                if origin == post_domain:
                    headers["Access-Control-Allow-Origin"] = post_domain
                return respx.MockResponse(200, headers=headers)

            respx_mock.get("/").mock(side_effect=handler)
            respx_mock.request("TRACE", "/").respond(status_code=405)
            respx_mock.options("/").respond(status_code=200)

            result = await module.execute(target, client)
            finding_ids = [f.id for f in result.findings]

            assert "CORS_REGEX_BYPASS_ORIGIN" in finding_ids
            finding = next(f for f in result.findings if f.id == "CORS_REGEX_BYPASS_ORIGIN")
            assert finding.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_cors_trace_method_enabled():
    module = CorsAndMethodModule()
    target = ScanTarget.from_url("https://trace-vulnerable.com")

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://trace-vulnerable.com", assert_all_called=False) as respx_mock:
            respx_mock.get("/").respond(status_code=200)

            # TRACE echoes back request
            respx_mock.request("TRACE", "/").respond(
                status_code=200,
                headers={"Content-Type": "message/http"},
                text="TRACE / HTTP/1.1\r\nHost: trace-vulnerable.com\r\nUser-Agent: ArmorScan\r\n",
            )
            respx_mock.options("/").respond(status_code=200, headers={"Allow": "GET, POST, TRACE"})

            result = await module.execute(target, client)
            finding_ids = [f.id for f in result.findings]

            assert "HTTP_TRACE_METHOD_ENABLED" in finding_ids
            finding = next(f for f in result.findings if f.id == "HTTP_TRACE_METHOD_ENABLED")
            assert finding.severity == Severity.MEDIUM
            assert "nginx" in finding.remediation_snippets
            assert "apache" in finding.remediation_snippets


@pytest.mark.asyncio
async def test_cors_clean_configuration():
    module = CorsAndMethodModule()
    target = ScanTarget.from_url("https://secure-cors.com")

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://secure-cors.com", assert_all_called=False) as respx_mock:
            # Rejects/neutral on all Origin headers
            def handler(request):
                origin = request.headers.get("origin")
                if origin:
                    return respx.MockResponse(403)
                return respx.MockResponse(200)

            respx_mock.get("/").mock(side_effect=handler)
            respx_mock.request("TRACE", "/").respond(status_code=405)
            respx_mock.options("/").respond(status_code=200, headers={"Allow": "GET, POST, OPTIONS"})

            result = await module.execute(target, client)
            assert len(result.findings) == 0
            assert "cors-origin-secure" in result.passed_checks
            assert "http-trace-disabled" in result.passed_checks
