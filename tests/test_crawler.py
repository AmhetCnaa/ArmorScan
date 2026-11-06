"""
Unit tests for Web Crawler & Spider (crawler.py).
"""

import pytest
import respx

from armorscan.core.client import HttpClient
from armorscan.core.crawler import WebCrawler
from armorscan.core.models import ScanTarget


@pytest.mark.asyncio
async def test_crawler_discovers_same_origin_links_and_forms():
    target = ScanTarget.from_url("https://crawler-test.dev")
    crawler = WebCrawler(max_depth=2, max_pages=10)

    page_root = """
    <html>
      <body>
        <a href="/dashboard">Dashboard</a>
        <a href="/profile">Profile</a>
        <a href="https://crawler-test.dev/settings">Settings</a>
        <a href="https://external-site.com/evil">External</a>
        <a href="/logo.png">Image</a>
        <form action="/api/v1/auth" method="POST">
          <input name="user"/>
        </form>
      </body>
    </html>
    """

    page_dashboard = """
    <html>
      <body>
        <a href="/dashboard/metrics">Metrics</a>
        <a href="/logout">Logout</a>
      </body>
    </html>
    """

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://crawler-test.dev", assert_all_called=False) as respx_mock:
            respx_mock.get("/").respond(status_code=200, text=page_root, headers={"Content-Type": "text/html"})
            respx_mock.get("/dashboard").respond(status_code=200, text=page_dashboard, headers={"Content-Type": "text/html"})
            respx_mock.get("/profile").respond(status_code=200, text="Profile", headers={"Content-Type": "text/html"})
            respx_mock.get("/settings").respond(status_code=200, text="Settings", headers={"Content-Type": "text/html"})
            respx_mock.get("/dashboard/metrics").respond(status_code=200, text="Metrics", headers={"Content-Type": "text/html"})
            respx_mock.get("/logout").respond(status_code=200, text="Logged out", headers={"Content-Type": "text/html"})

            result = await crawler.crawl(target, client)

            # Discovered paths must include internal links
            assert "/dashboard" in result.discovered_paths
            assert "/profile" in result.discovered_paths
            assert "/settings" in result.discovered_paths
            assert "/dashboard/metrics" in result.discovered_paths
            assert "/logout" in result.discovered_paths

            # External links and asset files must NOT be in discovered paths
            assert not any("external-site.com" in u for u in result.discovered_urls)
            assert not any(p.endswith(".png") for p in result.discovered_paths)

            # Forms must be captured
            assert len(result.forms) >= 1
            assert any(f.action_url == "https://crawler-test.dev/api/v1/auth" for f in result.forms)
            assert result.pages_crawled >= 2


@pytest.mark.asyncio
async def test_crawler_max_pages_limit():
    target = ScanTarget.from_url("https://endless-links.dev")
    crawler = WebCrawler(max_depth=5, max_pages=3)

    # HTML page linking to many pages
    page_html = """
    <html>
      <body>
        <a href="/p1">P1</a>
        <a href="/p2">P2</a>
        <a href="/p3">P3</a>
        <a href="/p4">P4</a>
        <a href="/p5">P5</a>
      </body>
    </html>
    """

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://endless-links.dev", assert_all_called=False) as respx_mock:
            respx_mock.get(url__regex=r".*").respond(status_code=200, text=page_html, headers={"Content-Type": "text/html"})

            result = await crawler.crawl(target, client)
            assert result.pages_crawled <= 3
