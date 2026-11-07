"""
Unit and Integration Tests for Local Ephemeral Callback Verifier & Async SSRF Module.
Tests token registration, HTTP callback interception, and end-to-end detection
of unvalidated outbound network callbacks.
"""

import asyncio
import pytest
import respx
import httpx

from armorscan.core.callback_verifier import LocalCallbackVerifier
from armorscan.core.client import HttpClient
from armorscan.core.models import Confidence, ScanTarget, Severity
from armorscan.modules.async_ssrf import AsyncSsrfModule


@pytest.mark.asyncio
async def test_local_callback_verifier_lifecycle_and_interception():
    verifier = LocalCallbackVerifier()
    base_url = await verifier.start()
    assert verifier.port > 0
    assert "127.0.0.1" in base_url

    try:
        token, callback_url = verifier.register_probe("/api/webhook", "destination_url")
        assert f"/verify/{token}" in callback_url

        # Simulate outbound connection by target backend worker
        async with httpx.AsyncClient(timeout=5.0, trust_env=False) as client:
            resp = await client.get(callback_url)
            assert resp.status_code == 200
            assert "ARMORSCAN_CALLBACK_VERIFIED" in resp.text

        # Verify callback was recorded
        assert verifier.has_interaction(token) is True
        assert len(verifier.captured_events) == 1
        ev = verifier.captured_events[0]
        assert ev.token == token
        assert ev.endpoint == "/api/webhook"
        assert ev.parameter == "destination_url"
        assert ev.client_address == "127.0.0.1"

    finally:
        await verifier.stop()


@pytest.mark.asyncio
async def test_async_ssrf_module_detects_outbound_callback():
    target = ScanTarget.from_url("http://webhook-app.local")

    # Start a real local verifier instance
    verifier = LocalCallbackVerifier()
    await verifier.start()

    module = AsyncSsrfModule(verifier=verifier)

    try:
        # Mock application endpoint that triggers an outbound fetch when receiving a webhook URL
        with respx.mock(base_url="http://webhook-app.local", assert_all_called=False) as respx_mock:
            # Allow local callback listener traffic through
            respx_mock.route(host="127.0.0.1").pass_through()

            async def mock_webhook_handler(request: httpx.Request):
                # Simulate background worker fetching the destination URL
                body = request.read().decode("utf-8", errors="replace")
                if "/verify/" in body:
                    import re
                    match = re.search(r"http://127\.0\.0\.1:\d+/verify/[a-zA-Z0-9]+", body)
                    if match:
                        callback_target = match.group(0)
                        # Trigger async worker fetch
                        async with httpx.AsyncClient(timeout=5.0, trust_env=False) as c:
                            await c.get(callback_target)
                return httpx.Response(202, json={"status": "queued"})

            respx_mock.post("/api/webhook").mock(side_effect=mock_webhook_handler)

            async with HttpClient.for_target(target) as client:
                result = await module.execute(target, client)

        assert result.has_findings
        ssrf_findings = [f for f in result.findings if f.id == "UNVALIDATED_ASYNC_OUTBOUND_CALLBACK"]
        assert len(ssrf_findings) == 1
        f = ssrf_findings[0]
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.CONFIRMED
        assert "Blind SSRF" in f.title or "Outbound Callback" in f.title

    finally:
        await verifier.stop()


@pytest.mark.asyncio
async def test_async_ssrf_module_clean_safe_target():
    target = ScanTarget.from_url("http://safe-app.local")
    verifier = LocalCallbackVerifier()
    await verifier.start()

    module = AsyncSsrfModule(verifier=verifier)

    try:
        with respx.mock(base_url="http://safe-app.local", assert_all_called=False) as respx_mock:
            # Server safely validates and rejects outbound private IP calls
            respx_mock.post("/api/webhook").mock(
                return_value=httpx.Response(400, json={"error": "Invalid destination URL"})
            )

            async with HttpClient.for_target(target) as client:
                result = await module.execute(target, client)

        assert not result.has_findings
        assert len(result.passed_checks) > 0

    finally:
        await verifier.stop()
