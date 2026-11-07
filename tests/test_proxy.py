"""
Unit and Integration Tests for Built-in HTTP Forward Proxy & Live Traffic Auditor.
Tests request forwarding, passive live audit detection (missing headers, insecure cookies, key leaks),
and graceful server shutdown.
"""

import asyncio
import pytest
import httpx

from armorscan.core.proxy import HttpProxy, ProxyFlow


@pytest.mark.asyncio
async def test_http_proxy_forward_and_passive_audit():
    # 1. Start a mock upstream server
    async def mock_upstream_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        # Read request line & headers
        while True:
            line = await reader.readline()
            if not line or line == b"\r\n":
                break

        body = b'{"status": "ok", "leaked_key": "AKIAIOSFODNN7EXAMPLE", "data": "profile info"}'
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("utf-8") + b"\r\n"
            b"Set-Cookie: session=xyz123; Path=/\r\n"
            b"Connection: close\r\n\r\n" + body
        )
        writer.write(resp)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    upstream = await asyncio.start_server(mock_upstream_handler, "127.0.0.1", 0)
    upstream_port = upstream.sockets[0].getsockname()[1]

    # 2. Start HttpProxy on an ephemeral port
    captured: list[ProxyFlow] = []
    proxy = HttpProxy(
        host="127.0.0.1",
        port=0,
        auto_audit=True,
        console=None,
        on_flow=lambda f: captured.append(f),
    )
    server = await proxy.start()
    proxy_port = server.sockets[0].getsockname()[1]

    try:
        # 3. Issue client request through the proxy to upstream
        proxy_url = f"http://127.0.0.1:{proxy_port}"
        target_url = f"http://127.0.0.1:{upstream_port}/api/user/profile"

        async with httpx.AsyncClient(proxy=proxy_url, timeout=5.0, trust_env=False) as client:
            resp = await client.get(target_url)

        assert resp.status_code == 200
        assert "AKIAIOSFODNN7EXAMPLE" in resp.text

        # 4. Verify intercepted flow and passive findings
        assert len(proxy.captured_flows) >= 1
        flow = proxy.captured_flows[0]
        assert flow.method == "GET"
        assert "/api/user/profile" in flow.path
        assert flow.status_code == 200

        # Passive audit should have caught missing CSP, insecure cookie, and AWS key leak
        assert "MISSING_CSP" in flow.findings
        assert "COOKIE_MISSING_HTTPONLY" in flow.findings
        assert "AWS_KEY_LEAK" in flow.findings

    finally:
        await proxy.stop()
        upstream.close()
        await upstream.wait_closed()


@pytest.mark.asyncio
async def test_http_proxy_clean_shutdown():
    proxy = HttpProxy(host="127.0.0.1", port=0, auto_audit=False)
    server = await proxy.start()
    assert server.is_serving()

    await proxy.stop()
    assert not server.is_serving()
