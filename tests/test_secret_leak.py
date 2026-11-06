"""
Unit tests for DOM & Client-Side Secret Hunter module (secret_leak.py).
"""

import pytest
import respx
import httpx

from armorscan.core.client import HttpClient
from armorscan.core.models import ScanTarget, Severity
from armorscan.modules.secret_leak import SecretLeakModule


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_secret_leak_openai_and_aws_in_html(respx_mock):
    target = ScanTarget.from_url("https://vulnerable-spa.com")
    client = HttpClient(verify_ssl=False)
    await client.start()

    dummy_openai = "sk-" + "proj-" + "abcde12345ABCDE1234567890"
    dummy_aws = "AKIA" + "IOSFODNN7EXAMPLE"

    html = (
        "<!DOCTYPE html><html><body>"
        "<script>"
        f"  const OPENAI_KEY = '{dummy_openai}';"
        f"  const AWS_KEY = '{dummy_aws}';"
        "</script>"
        "</body></html>"
    )
    respx_mock.get("https://vulnerable-spa.com/").mock(return_value=httpx.Response(200, text=html))

    module = SecretLeakModule()
    result = await module.run(target, client)
    await client.close()

    assert any(f.id == "OPENAI_API_KEY_LEAK" and f.severity == Severity.CRITICAL for f in result.findings)
    assert any(f.id == "AWS_ACCESS_KEY_LEAK" and f.severity == Severity.HIGH for f in result.findings)
    # Check that secrets in evidence are properly masked
    aws_finding = next(f for f in result.findings if f.id == "AWS_ACCESS_KEY_LEAK")
    assert "AKIA" in aws_finding.evidence
    assert dummy_aws not in aws_finding.evidence  # Must be masked


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_secret_leak_github_and_stripe_in_js_bundle(respx_mock):
    target = ScanTarget.from_url("https://vulnerable-spa.com")
    client = HttpClient(verify_ssl=False)
    await client.start()

    dummy_ghp = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    dummy_stripe = "sk_" + "live_" + "51Abcdefghijklmnopqrstuvwx"

    html = '<html><head><script src="/static/bundle.main.js"></script></head><body>App</body></html>'
    respx_mock.get("https://vulnerable-spa.com/").mock(return_value=httpx.Response(200, text=html))

    js_code = (
        "var config = {"
        f"  githubToken: '{dummy_ghp}',"
        f"  stripeKey: '{dummy_stripe}'"
        "};"
    )
    respx_mock.get("https://vulnerable-spa.com/static/bundle.main.js").mock(
        return_value=httpx.Response(200, text=js_code)
    )

    module = SecretLeakModule()
    result = await module.run(target, client)
    await client.close()

    assert any(f.id == "GITHUB_PAT_LEAK" and f.severity == Severity.CRITICAL for f in result.findings)
    assert any(f.id == "STRIPE_SECRET_KEY_LEAK" and f.severity == Severity.CRITICAL for f in result.findings)


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_secret_leak_slack_and_internal_ip(respx_mock):
    target = ScanTarget.from_url("https://vulnerable-spa.com")
    client = HttpClient(verify_ssl=False)
    await client.start()

    dummy_slack = "https://" + "hooks.slack.com/services/T123456/B123456/123456789012345678"

    html = (
        "<html><body>"
        f"<!-- slack: {dummy_slack} -->"
        '<script>var internalApi = "http://192.168.1.55:8080/internal";</script>'
        "</body></html>"
    )
    respx_mock.get("https://vulnerable-spa.com/").mock(return_value=httpx.Response(200, text=html))

    module = SecretLeakModule()
    result = await module.run(target, client)
    await client.close()

    assert any(f.id == "SLACK_WEBHOOK_LEAK" and f.severity == Severity.HIGH for f in result.findings)
    assert any(f.id == "INTERNAL_IP_DISCLOSURE" and f.severity == Severity.LOW for f in result.findings)


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_secret_leak_clean_assets(respx_mock):
    target = ScanTarget.from_url("https://secure-spa.com")
    client = HttpClient(verify_ssl=False)
    await client.start()

    html = '<html><head><script src="/static/app.js"></script></head><body><h1>Welcome</h1></body></html>'
    respx_mock.get("https://secure-spa.com/").mock(return_value=httpx.Response(200, text=html))
    respx_mock.get("https://secure-spa.com/static/app.js").mock(
        return_value=httpx.Response(200, text="console.log('App running securely');")
    )

    module = SecretLeakModule()
    result = await module.run(target, client)
    await client.close()

    assert len(result.findings) == 0
    assert "no-hardcoded-secrets-in-client-assets" in result.passed_checks
