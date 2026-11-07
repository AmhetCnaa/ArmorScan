"""Unit and integration tests for BrowserDomModule."""

import pytest
import respx
import httpx
from unittest.mock import AsyncMock, patch, MagicMock

from armorscan.core.client import HttpClient
from armorscan.core.models import ScanTarget, Severity, Confidence
from armorscan.modules.browser_dom import BrowserDomModule, PLAYWRIGHT_AVAILABLE


@pytest.mark.asyncio
async def test_browser_dom_module_metadata():
    module = BrowserDomModule()
    assert module.name == "browser_dom"
    assert "Browser DOM" in module.display_name
    assert "DOM sinks" in module.description


@pytest.mark.asyncio
async def test_browser_dom_handles_missing_playwright():
    module = BrowserDomModule()
    target = ScanTarget.from_url("http://example.local")
    client = HttpClient(verify_ssl=False)

    with patch("armorscan.modules.browser_dom.PLAYWRIGHT_AVAILABLE", False):
        result = await module.run(target, client)
        assert len(result.findings) == 0
        assert "browser-dom-playwright-not-installed" in result.passed_checks


@pytest.mark.asyncio
async def test_browser_dom_mock_sink_detection():
    module = BrowserDomModule()
    target = ScanTarget.from_url("http://spa-test.local")
    client = HttpClient(verify_ssl=False)

    # Mock playwright async context
    mock_page = AsyncMock()
    mock_context = AsyncMock()
    mock_browser = AsyncMock()
    mock_pw = AsyncMock()

    mock_context.new_page.return_value = mock_page
    mock_browser.new_context.return_value = mock_context
    mock_pw.chromium.launch.return_value = mock_browser

    async def fake_expose(fn_name, callback):
        # Trigger mock callback simulating innerHTML reflection
        callback({
            "sink": "Element.innerHTML",
            "tag": "SPAN",
            "id": "searchValue",
            "value": "armorscan_dom_probe_12345678",
        })

    mock_page.expose_function.side_effect = fake_expose

    class FakePlaywrightCtx:
        async def __aenter__(self):
            return mock_pw

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    with patch("armorscan.modules.browser_dom.PLAYWRIGHT_AVAILABLE", True):
        with patch("armorscan.modules.browser_dom.async_playwright", return_value=FakePlaywrightCtx()):
            result = await module.run(target, client)
            assert len(result.findings) == 1
            finding = result.findings[0]
            assert finding.id == "DOM_XSS_SINK_TAINT_FLOW"
            assert finding.severity == Severity.HIGH
            assert finding.confidence == Confidence.CONFIRMED
            assert "searchValue" in finding.evidence
            assert "Element.innerHTML" in finding.evidence


@pytest.mark.asyncio
async def test_browser_dom_clean_site_no_sinks():
    module = BrowserDomModule()
    target = ScanTarget.from_url("http://clean-site.local")
    client = HttpClient(verify_ssl=False)

    mock_page = AsyncMock()
    mock_context = AsyncMock()
    mock_browser = AsyncMock()
    mock_pw = AsyncMock()

    mock_context.new_page.return_value = mock_page
    mock_browser.new_context.return_value = mock_context
    mock_pw.chromium.launch.return_value = mock_browser

    class FakePlaywrightCtx:
        async def __aenter__(self):
            return mock_pw

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    with patch("armorscan.modules.browser_dom.PLAYWRIGHT_AVAILABLE", True):
        with patch("armorscan.modules.browser_dom.async_playwright", return_value=FakePlaywrightCtx()):
            result = await module.run(target, client)
            assert len(result.findings) == 0
            assert "no-dom-sink-canary-taint-detected" in result.passed_checks
