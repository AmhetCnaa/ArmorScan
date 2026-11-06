"""
Unit tests for Error-Based Information and Database Leakage module (error_leak.py).
"""

import pytest
import respx
import httpx

from armorscan.core.client import HttpClient
from armorscan.core.models import ScanTarget, Severity
from armorscan.modules.error_leak import ErrorLeakModule


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_error_leak_db_mysql_detected(respx_mock):
    target = ScanTarget.from_url("https://vulnerable-db.com/product?id=1")
    client = HttpClient(verify_ssl=False)
    await client.start()

    def handler(request: httpx.Request):
        url_str = str(request.url)
        # Check if single quote probe was injected
        if "id=1%27" in url_str or "id=1'" in url_str or "%27" in url_str:
            return httpx.Response(
                500,
                text="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax near ''1''' at line 1"
            )
        return httpx.Response(200, text="Product 1 Details")

    respx_mock.get(url__regex=r"https://vulnerable-db\.com/product.*").mock(side_effect=handler)

    module = ErrorLeakModule()
    result = await module.run(target, client)
    await client.close()

    assert any(f.id == "DATABASE_ERROR_DISCLOSURE" and "MySQL" in f.title for f in result.findings)
    assert any(f.severity == Severity.HIGH for f in result.findings)


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_error_leak_python_traceback_detected(respx_mock):
    target = ScanTarget.from_url("https://vulnerable-app.com/api/users?id=10")
    client = HttpClient(verify_ssl=False)
    await client.start()

    def handler(request: httpx.Request):
        url_str = str(request.url)
        if "%27" in url_str or "'" in url_str:
            trace = (
                "Traceback (most recent call last):\n"
                '  File "/app/routes.py", line 42, in get_user\n'
                "    user_id = int(request.args['id'])\n"
                "ValueError: invalid literal for int() with base 10: '10\\''"
            )
            return httpx.Response(500, text=trace)
        return httpx.Response(200, text='{"user": "Alice"}')

    respx_mock.get(url__regex=r"https://vulnerable-app\.com/api/users.*").mock(side_effect=handler)

    module = ErrorLeakModule()
    result = await module.run(target, client)
    await client.close()

    assert any(f.id == "STACK_TRACE_DISCLOSURE" and "Python Traceback" in f.title for f in result.findings)


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_error_leak_clean_response(respx_mock):
    target = ScanTarget.from_url("https://secure-app.com/api/items?id=5")
    client = HttpClient(verify_ssl=False)
    await client.start()

    # Generic 400 or 500 without leaking internal details
    def handler(request: httpx.Request):
        url_str = str(request.url)
        if "%27" in url_str or "'" in url_str:
            return httpx.Response(400, text='{"error": "Invalid input format"}')
        return httpx.Response(200, text='{"item": "Widget"}')

    respx_mock.get(url__regex=r"https://secure-app\.com/api/items.*").mock(side_effect=handler)

    module = ErrorLeakModule()
    result = await module.run(target, client)
    await client.close()

    assert len(result.findings) == 0
    assert any("clean" in c or "no-stack-traces" in c for c in result.passed_checks)
