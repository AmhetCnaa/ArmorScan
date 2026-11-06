"""
Unit tests for Input Reflection and Context Analysis module (reflection.py).
"""

import pytest
import respx
import httpx

from armorscan.core.client import HttpClient
from armorscan.core.models import ScanTarget, Severity
from armorscan.modules.reflection import InputReflectionModule


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_reflection_script_context_detected(respx_mock):
    target = ScanTarget.from_url("https://vulnerable-app.com/search?q=test")
    client = HttpClient(verify_ssl=False)
    await client.start()

    # When queried with canary probe, the server reflects it raw inside a <script> tag
    def handler(request: httpx.Request):
        url_str = str(request.url)
        if "armorscan" in url_str:
            # Extract canary from URL
            import urllib.parse
            parsed = urllib.parse.urlparse(url_str)
            params = urllib.parse.parse_qs(parsed.query)
            q_val = params.get("q", [""])[0]
            html = f"<html><body><script>var userQuery = '{q_val}';</script></body></html>"
            return httpx.Response(200, text=html)
        return httpx.Response(200, text="<html><body>Hello</body></html>")

    respx_mock.get(url__regex=r"https://vulnerable-app\.com/search.*").mock(side_effect=handler)

    module = InputReflectionModule()
    result = await module.run(target, client)
    await client.close()

    assert any(f.id == "SCRIPT_CONTEXT_INPUT_REFLECTION" and f.severity == Severity.HIGH for f in result.findings)


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_reflection_attribute_context_detected(respx_mock):
    target = ScanTarget.from_url("https://vulnerable-app.com/profile?name=test")
    client = HttpClient(verify_ssl=False)
    await client.start()

    def handler(request: httpx.Request):
        url_str = str(request.url)
        if "armorscan" in url_str:
            import urllib.parse
            parsed = urllib.parse.urlparse(url_str)
            params = urllib.parse.parse_qs(parsed.query)
            val = params.get("name", [""])[0]
            html = f'<html><body><input type="text" name="username" value="{val}"></body></html>'
            return httpx.Response(200, text=html)
        return httpx.Response(200, text="<html><body>Profile</body></html>")

    respx_mock.get(url__regex=r"https://vulnerable-app\.com/profile.*").mock(side_effect=handler)

    module = InputReflectionModule()
    result = await module.run(target, client)
    await client.close()

    assert any(f.id == "ATTRIBUTE_CONTEXT_INPUT_REFLECTION" and f.severity == Severity.MEDIUM for f in result.findings)


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_reflection_body_unescaped_detected(respx_mock):
    target = ScanTarget.from_url("https://vulnerable-app.com/index?search=test")
    client = HttpClient(verify_ssl=False)
    await client.start()

    def handler(request: httpx.Request):
        url_str = str(request.url)
        if "armorscan" in url_str:
            import urllib.parse
            parsed = urllib.parse.urlparse(url_str)
            params = urllib.parse.parse_qs(parsed.query)
            val = params.get("search", [""])[0]
            html = f"<html><body><div>Search results for: {val}</div></body></html>"
            return httpx.Response(200, text=html)
        return httpx.Response(200, text="<html><body>Search page</body></html>")

    respx_mock.get(url__regex=r"https://vulnerable-app\.com/index.*").mock(side_effect=handler)

    module = InputReflectionModule()
    result = await module.run(target, client)
    await client.close()

    assert any(f.id == "UNENCODED_HTML_INPUT_REFLECTION" and f.severity == Severity.HIGH for f in result.findings)


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_reflection_safely_encoded_or_not_reflected(respx_mock):
    target = ScanTarget.from_url("https://secure-app.com/search?q=test")
    client = HttpClient(verify_ssl=False)
    await client.start()

    def handler(request: httpx.Request):
        url_str = str(request.url)
        if "armorscan" in url_str:
            import urllib.parse
            import html
            parsed = urllib.parse.urlparse(url_str)
            params = urllib.parse.parse_qs(parsed.query)
            val = params.get("q", [""])[0]
            # Safely HTML encoded
            safe_val = html.escape(val, quote=True)
            return httpx.Response(200, text=f"<html><body>Results for {safe_val}</body></html>")
        return httpx.Response(200, text="<html><body>Welcome</body></html>")

    respx_mock.get(url__regex=r"https://secure-app\.com/search.*").mock(side_effect=handler)

    module = InputReflectionModule()
    result = await module.run(target, client)
    await client.close()

    assert len(result.findings) == 0
    assert any("safely-html-encoded" in check for check in result.passed_checks)
