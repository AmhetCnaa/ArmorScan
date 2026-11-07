"""
Unit tests for SqliIndicationModule (test_sqli.py).
Validates safe boolean differential detection, tentative confidence, and clean endpoints.
"""

import pytest
import respx

from armorscan.core.client import HttpClient
from armorscan.core.models import Confidence, ScanTarget, Severity
from armorscan.modules.sqli import SqliIndicationModule


@pytest.mark.asyncio
async def test_sqli_boolean_differential_detected():
    base_url = "https://sqli-test.dev"
    target = ScanTarget.from_url(f"{base_url}/search?q=apple")
    module = SqliIndicationModule()

    # Vulnerable endpoint: TRUE condition returns 3 records (500B), FALSE condition returns empty data (50B)
    normal_json = '{"status":"success","data":[{"id":1,"name":"Apple Juice"},{"id":2,"name":"Apple Pomace"}]}'
    true_json = '{"status":"success","data":[{"id":1,"name":"Apple Juice"},{"id":2,"name":"Apple Pomace"},{"id":3,"name":"Apple Tart"}]}'
    false_json = '{"status":"success","data":[]}'

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url=base_url, assert_all_called=False) as respx_mock:
            respx_mock.get("/search?q=apple").respond(status_code=200, text=normal_json)
            # TRUE condition (1=1 and 2=2)
            respx_mock.get(url__regex=r".*q=apple.*1(?:=|%3D)1.*").respond(status_code=200, text=true_json)
            respx_mock.get(url__regex=r".*q=apple.*2(?:=|%3D)2.*").respond(status_code=200, text=true_json)
            # FALSE condition (1=2 and 2=3)
            respx_mock.get(url__regex=r".*q=apple.*1(?:=|%3D)2.*").respond(status_code=200, text=false_json)
            respx_mock.get(url__regex=r".*q=apple.*2(?:=|%3D)3.*").respond(status_code=200, text=false_json)

            result = await module.run(target, client)

            assert len(result.findings) == 1
            finding = result.findings[0]
            assert finding.id == "SQLI_BOOLEAN_DIFFERENCE_SUSPECTED"
            assert finding.severity == Severity.HIGH
            assert finding.confidence == Confidence.TENTATIVE
            assert "Validated across two independent canary iterations" in finding.evidence
            assert "curl" in finding.curl_command


@pytest.mark.asyncio
async def test_sqli_clean_endpoint_no_finding():
    base_url = "https://sqli-safe.dev"
    target = ScanTarget.from_url(f"{base_url}/search?q=apple")
    module = SqliIndicationModule()

    # Clean endpoint: responds consistently regardless of query text
    clean_json = '{"status":"success","data":[{"id":1,"name":"Search Result"}]}'

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url=base_url, assert_all_called=False) as respx_mock:
            respx_mock.get(url__regex=r".*").respond(status_code=200, text=clean_json)

            result = await module.run(target, client)

            assert len(result.findings) == 0
            assert "sqli-boolean-clean-q" in result.passed_checks
