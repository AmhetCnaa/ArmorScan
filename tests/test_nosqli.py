"""Unit tests for NoSQL Injection Indication Module (tests/test_nosqli.py)."""

import pytest
import respx
import httpx

from armorscan.core.client import HttpClient
from armorscan.core.models import Confidence, ScanTarget, Severity
from armorscan.modules.nosqli import NoSqliIndicationModule


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_nosqli_json_operator_bypass_detected(respx_mock):
    target = ScanTarget.from_url("https://api.example.com/rest/user/login")
    client = HttpClient(verify_ssl=False, proxy=None)
    await client.start()

    def login_handler(request: httpx.Request) -> httpx.Response:
        body = request.content.decode("utf-8", errors="ignore")
        if '"$gt"' in body or '"$ne"' in body:
            return httpx.Response(
                200,
                json={"authentication": {"token": "jwt_mock_token", "bid": 1}},
                headers={"Content-Type": "application/json"},
            )
        return httpx.Response(401, text="Invalid email or password.")

    respx_mock.post("https://api.example.com/rest/user/login").mock(side_effect=login_handler)
    respx_mock.post(url__regex=r".*").mock(return_value=httpx.Response(404))
    respx_mock.get(url__regex=r".*").mock(return_value=httpx.Response(404))

    module = NoSqliIndicationModule()
    result = await module.run(target, client)
    await client.close()

    assert len(result.findings) >= 1
    finding = result.findings[0]
    assert finding.id == "NOSQLI_OPERATOR_INJECTION_SUSPECTED"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.TENTATIVE
    assert finding.cwe_id == "CWE-943"


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_nosqli_boolean_expression_track_order_detected(respx_mock):
    target = ScanTarget.from_url("http://127.0.0.1:3000")
    client = HttpClient(verify_ssl=False, proxy=None)
    await client.start()

    respx_mock.post(url__regex=r".*").mock(return_value=httpx.Response(401, text="Unauthorized"))
    respx_mock.get("http://127.0.0.1:3000/rest/track-order/99998888").mock(
        return_value=httpx.Response(200, text='{"status":"success","data":[]}', headers={"Content-Type": "application/json"})
    )
    respx_mock.get("http://127.0.0.1:3000/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27").mock(
        return_value=httpx.Response(
            200,
            text='{"status":"success","data":[' + '{"orderId":"5267-111","email":"a@b.c","totalPrice":99.0},' * 6 + ']}',
            headers={"Content-Type": "application/json"},
        )
    )
    respx_mock.get("http://127.0.0.1:3000/rest/track-order/%27%20%26%26%20false%20%26%26%20%27").mock(
        return_value=httpx.Response(200, text='{"status":"success","data":[]}', headers={"Content-Type": "application/json"})
    )

    module = NoSqliIndicationModule()
    result = await module.run(target, client)
    await client.close()

    assert len(result.findings) == 1
    assert result.findings[0].id == "NOSQLI_OPERATOR_INJECTION_SUSPECTED"
    assert result.findings[0].confidence == Confidence.TENTATIVE


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_nosqli_clean_endpoint_zero_fp(respx_mock):
    target = ScanTarget.from_url("https://safe.example.com")
    client = HttpClient(verify_ssl=False, proxy=None)
    await client.start()

    respx_mock.post(url__regex=r".*").mock(return_value=httpx.Response(401, text="Invalid credentials"))
    respx_mock.get(url__regex=r".*").mock(return_value=httpx.Response(404, text="Not Found"))

    module = NoSqliIndicationModule()
    result = await module.run(target, client)
    await client.close()

    assert len(result.findings) == 0
    assert "no-nosqli-operator-differential-detected" in result.passed_checks
