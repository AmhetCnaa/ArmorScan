"""Unit tests for PathTraversalModule, SsrfCheckModule, and GraphqlAuditModule (tests/test_traversal.py)."""

import pytest
import respx
import httpx

from armorscan.core.client import HttpClient
from armorscan.core.models import Confidence, ScanTarget, Severity
from armorscan.modules.graphql import GraphqlAuditModule
from armorscan.modules.ssrf_check import SsrfCheckModule
from armorscan.modules.traversal import PathTraversalModule


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_traversal_poison_null_byte_detected(respx_mock):
    target = ScanTarget.from_url("http://127.0.0.1:3000")
    client = HttpClient(verify_ssl=False, proxy=None)
    await client.start()

    respx_mock.get("http://127.0.0.1:3000/armorscan-404-canary-traversal").mock(
        return_value=httpx.Response(404, text="Not Found")
    )
    respx_mock.get("http://127.0.0.1:3000/ftp/package.json.bak").mock(
        return_value=httpx.Response(403, text="ForbiddenError: Only .md and .pdf files are allowed!")
    )
    respx_mock.get("http://127.0.0.1:3000/ftp/package.json.bak%2500.md").mock(
        return_value=httpx.Response(
            200,
            text='{\n  "name": "juice-shop",\n  "version": "16.0.0",\n  "dependencies": {}\n}',
            headers={"Content-Type": "application/json"},
        )
    )

    module = PathTraversalModule()
    result = await module.run(target, client)
    await client.close()

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.id == "PATH_TRAVERSAL_DETECTED"
    assert f.severity == Severity.HIGH
    assert f.confidence == Confidence.CONFIRMED
    assert f.cwe_id == "CWE-22"


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_traversal_query_param_lfi_detected(respx_mock):
    target = ScanTarget.from_url("https://vuln.example.com/view?file=welcome.txt")
    client = HttpClient(verify_ssl=False, proxy=None)
    await client.start()

    respx_mock.get("https://vuln.example.com/armorscan-404-canary-traversal").mock(
        return_value=httpx.Response(404, text="Not Found")
    )
    respx_mock.get("https://vuln.example.com/view?file=index.html").mock(
        return_value=httpx.Response(200, text="Welcome page")
    )
    respx_mock.get(url__regex=r".*etc%2Fpasswd.*|.*etc/passwd.*").mock(
        return_value=httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
    )
    respx_mock.get(url__regex=r".*").mock(return_value=httpx.Response(404))

    module = PathTraversalModule()
    result = await module.run(target, client)
    await client.close()

    assert len(result.findings) == 1
    assert result.findings[0].id == "PATH_TRAVERSAL_DETECTED"
    assert "root:x:0:0:" in result.findings[0].evidence


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_ssrf_loopback_indicator_detected(respx_mock):
    target = ScanTarget.from_url("https://vuln.example.com/webhook?url=https://safe.com")
    client = HttpClient(verify_ssl=False, proxy=None)
    await client.start()

    respx_mock.get(url__regex=r".*example\.invalid.*").mock(
        return_value=httpx.Response(200, text="Fetched external URL")
    )
    respx_mock.get(url__regex=r".*127\.0\.0\.1.*").mock(
        return_value=httpx.Response(500, text="FetchError: request to http://127.0.0.1:80 failed, reason: connect ECONNREFUSED")
    )
    respx_mock.get(url__regex=r".*").mock(return_value=httpx.Response(200, text="OK"))

    module = SsrfCheckModule()
    result = await module.run(target, client)
    await client.close()

    assert len(result.findings) == 1
    assert result.findings[0].id == "SSRF_UNVALIDATED_OUTBOUND_REQUEST"
    assert result.findings[0].cwe_id == "CWE-918"


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_graphql_introspection_module_detected(respx_mock):
    target = ScanTarget.from_url("https://api.example.com")
    client = HttpClient(verify_ssl=False, proxy=None)
    await client.start()

    respx_mock.post("https://api.example.com/graphql").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"__schema": {"types": [{"name": "User"}, {"name": "SecretOrder"}, {"name": "__Schema"}]}}},
            headers={"Content-Type": "application/json"},
        )
    )
    respx_mock.post(url__regex=r".*").mock(return_value=httpx.Response(404))

    module = GraphqlAuditModule()
    result = await module.run(target, client)
    await client.close()

    assert len(result.findings) == 1
    assert result.findings[0].id == "GRAPHQL_INTROSPECTION_ENABLED"
    assert result.findings[0].severity == Severity.MEDIUM
