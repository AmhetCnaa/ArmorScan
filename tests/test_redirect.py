"""
Unit tests for Open Redirect and Unvalidated Navigation module (redirect.py).
"""

import pytest
import respx
import httpx

from armorscan.core.client import HttpClient
from armorscan.core.models import ScanTarget, Severity
from armorscan.modules.redirect import OpenRedirectModule


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_open_redirect_http_location_detected(respx_mock):
    target = ScanTarget.from_url("https://vulnerable-site.com/login?next=/account")
    client = HttpClient(verify_ssl=False)
    await client.start()

    def handler(request: httpx.Request):
        url_str = str(request.url)
        if "next=" in url_str:
            import urllib.parse
            parsed = urllib.parse.urlparse(url_str)
            params = urllib.parse.parse_qs(parsed.query)
            dest = params.get("next", [""])[0]
            # Reflect destination into 302 Location header
            return httpx.Response(302, headers={"Location": dest})
        return httpx.Response(200, text="Login page")

    respx_mock.get(url__regex=r"https://vulnerable-site\.com/login.*").mock(side_effect=handler)

    module = OpenRedirectModule()
    result = await module.run(target, client)
    await client.close()

    assert any(f.id == "OPEN_REDIRECT_UNVALIDATED" and f.severity == Severity.HIGH for f in result.findings)


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_open_redirect_meta_refresh_detected(respx_mock):
    target = ScanTarget.from_url("https://vulnerable-site.com/redirect?url=/home")
    client = HttpClient(verify_ssl=False)
    await client.start()

    def handler(request: httpx.Request):
        url_str = str(request.url)
        if "url=" in url_str:
            import urllib.parse
            parsed = urllib.parse.urlparse(url_str)
            params = urllib.parse.parse_qs(parsed.query)
            dest = params.get("url", [""])[0]
            html = f'<html><head><meta http-equiv="refresh" content="0; url={dest}"></head></html>'
            return httpx.Response(200, text=html)
        return httpx.Response(200, text="Redirecting...")

    respx_mock.get(url__regex=r"https://vulnerable-site\.com/redirect.*").mock(side_effect=handler)

    module = OpenRedirectModule()
    result = await module.run(target, client)
    await client.close()

    assert any(f.id == "CLIENT_SIDE_OPEN_REDIRECT" and f.severity == Severity.MEDIUM for f in result.findings)


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_open_redirect_safe_relative_path(respx_mock):
    target = ScanTarget.from_url("https://secure-site.com/login?next=/account")
    client = HttpClient(verify_ssl=False)
    await client.start()

    # Secure server: always sanitizes redirect or forces relative /account
    def handler(request: httpx.Request):
        url_str = str(request.url)
        if "next=" in url_str:
            return httpx.Response(302, headers={"Location": "/dashboard"})
        return httpx.Response(200, text="Login page")

    respx_mock.get(url__regex=r"https://secure-site\.com/login.*").mock(side_effect=handler)

    module = OpenRedirectModule()
    result = await module.run(target, client)
    await client.close()

    assert len(result.findings) == 0
    assert any("redirect-safe" in c or "no-open-redirect-detected" in c for c in result.passed_checks)
