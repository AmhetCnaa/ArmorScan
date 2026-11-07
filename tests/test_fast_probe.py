"""
Unit tests for Turbo Fast-Probe Engine (core/fast_probe.py).
Verifies micro-timeout enforcement, pre-flight TCP SYN checks, and fast-bailout.
"""

import asyncio
from unittest.mock import patch
import pytest

from armorscan.core.fast_probe import FastProbe


@pytest.mark.asyncio
async def test_fast_probe_closed_port_fast_bailout():
    """Verify that probing an unreachable port bails out in <= 800ms."""
    # Port 49999 on 127.0.0.1 is closed
    start = asyncio.get_running_loop().time()
    is_open = await FastProbe.is_port_open("127.0.0.1", port=49999, timeout=0.4)
    elapsed = asyncio.get_running_loop().time() - start

    assert is_open is False
    assert elapsed < 0.6  # Fast bailout without hanging


@pytest.mark.asyncio
async def test_fast_probe_open_port_detected():
    """Verify that an active TCP port is quickly detected as open."""
    # Start a dummy asyncio echo server
    async def dummy_cb(reader, writer):
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(dummy_cb, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    try:
        is_open = await FastProbe.is_port_open("127.0.0.1", port=port, timeout=0.5)
        assert is_open is True
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_fast_probe_tls_closed_port_returns_none():
    """Verify that probe_tls returns None immediately when port is closed."""
    res = await FastProbe.probe_tls("127.0.0.1", port=49998, tcp_timeout=0.3, tls_timeout=0.5)
    assert res is None


@pytest.mark.asyncio
async def test_fast_probe_tls_probe_success():
    """Verify that probe_tls returns metadata when connection and handshake succeed."""
    mock_cert = {
        "notAfter": "Dec 31 23:59:59 2028 GMT",
        "tls_version": "TLSv1.3",
    }
    with patch.object(FastProbe, "is_port_open", return_value=True):
        with patch.object(FastProbe, "_sync_fetch_cert", return_value=mock_cert):
            res = await FastProbe.probe_tls("example.com", port=443, tcp_timeout=0.3, tls_timeout=0.5)
            assert res is not None
            assert res["tls_version"] == "TLSv1.3"
