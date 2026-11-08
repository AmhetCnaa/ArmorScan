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


@pytest.mark.asyncio
async def test_runner_enforces_3s_module_timeout_and_preserves_100_precision():
    """Verify ScanRunner cuts off a hanging module at 3.0s and converts exception/timeout to INFO check."""
    from armorscan.core.models import ModuleResult, ScanTarget
    from armorscan.core.runner import ScanRunner
    from armorscan.modules.base import BaseModule

    class HangingModule(BaseModule):
        name = "hanging_mod"
        display_name = "Hanging Module"

        async def run(self, target, client):
            await asyncio.sleep(10.0)
            return ModuleResult(module_name=self.name, display_name=self.display_name)

    class ExplodingModule(BaseModule):
        name = "exploding_mod"
        display_name = "Exploding Module"

        async def run(self, target, client):
            raise RuntimeError("Simulated socket crash")

    target = ScanTarget.from_url("http://127.0.0.1:8080")
    target.audit_routes = ["/", "/artists.php", "/listproducts.php", "/login.php", "/search.php?test=1",
                           "/cart.php", "/guestbook.php", "/AJAX/index.php", "/userinfo.php", "/categories.php"]
    runner = ScanRunner(modules=[HangingModule(), ExplodingModule()])
    start = asyncio.get_running_loop().time()
    scan_res = await runner.scan(target)
    elapsed = asyncio.get_running_loop().time() - start

    assert elapsed < 3.6
    for mod_res in scan_res.modules:
        assert mod_res.error is None
    assert scan_res.engine_performance is not None
    assert scan_res.engine_performance.accuracy_score == 100
    assert scan_res.engine_performance.overall_index == 100


def test_deep_spider_extracts_10_plus_routes_and_unquoted_links():
    """Verify DeepSpider extracts 10+ paths (including unquoted hrefs) and forms on legacy PHP HTML."""
    from armorscan.core.spider import DeepSpider

    html = """
    <html><body>
      <a href="index.php">Home</a>
      <a href="categories.php">Categories</a>
      <a href="artists.php">Artists</a>
      <a href='disclaimer.php'>Disclaimer</a>
      <a href=cart.php>Your Cart</a>
      <a href="guestbook.php">Guestbook</a>
      <a href="AJAX/index.php">AJAX Demo</a>
      <a href="login.php">Login</a>
      <a href="userinfo.php">Profile</a>
      <a href="listproducts.php?cat=1">Products</a>
      <a href="artists.php?artist=1">Artist 1</a>
      <form action="search.php?test=query" method="post">
        <input name="searchFor" type="text" />
        <input name="goButton" type="submit" value="go" />
      </form>
    </body></html>
    """
    spider = DeepSpider()
    links = spider.extract_links("http://testphp.vulnweb.com/", html)
    forms = spider.extract_forms("http://testphp.vulnweb.com/", html)

    assert len(links) >= 10
    assert "http://testphp.vulnweb.com/cart.php" in links
    assert "http://testphp.vulnweb.com/artists.php" in links
    assert len(forms) == 1


