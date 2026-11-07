"""
Unit tests for Deep Recursive Spider Engine (core/spider.py).
Verifies HTML form mining, link extraction from multiple tags, scope filtering,
and parameterized path crawling.
"""

import pytest
import respx

from armorscan.core.client import HttpClient
from armorscan.core.models import ScanTarget
from armorscan.core.spider import DeepSpider


def test_spider_extracts_forms_inputs_textareas_and_selects():
    spider = DeepSpider()
    html_sample = """
    <html>
      <body>
        <form action="/login.php" method="POST">
          <input type="text" name="uname" value="admin" required />
          <input type="password" name="pass" />
          <input type="hidden" name="token" value="xyz987" />
          <textarea name="comment">Default text</textarea>
          <select name="role">
            <option value="user">User</option>
            <option value="admin">Admin</option>
          </select>
        </form>
        <form action="/search.php" method="GET">
          <input type="text" name="query" />
        </form>
      </body>
    </html>
    """

    forms = spider.extract_forms("http://testphp.vulnweb.com/index.php", html_sample)
    assert len(forms) == 2

    # Form 1: login.php POST
    f1 = forms[0]
    assert f1.action_url == "http://testphp.vulnweb.com/login.php"
    assert f1.method == "POST"
    assert "uname" in f1.parameter_names
    assert "pass" in f1.parameter_names
    assert "token" in f1.parameter_names
    assert "comment" in f1.parameter_names
    assert "role" in f1.parameter_names

    # Check input field types
    types = {inp.name: inp.input_type for inp in f1.inputs}
    assert types["uname"] == "text"
    assert types["pass"] == "password"
    assert types["token"] == "hidden"
    assert types["comment"] == "textarea"
    assert types["role"] == "select"

    # Form 2: search.php GET
    f2 = forms[1]
    assert f2.action_url == "http://testphp.vulnweb.com/search.php"
    assert f2.method == "GET"
    assert "query" in f2.parameter_names


def test_spider_extracts_links_from_anchors_areas_and_iframes():
    spider = DeepSpider()
    html_sample = """
    <html>
      <body>
        <a href="artists.php?artist=1">Artists</a>
        <a href="/listproducts.php?cat=2">Products</a>
        <map name="workmap">
          <area shape="rect" coords="34,44,270,350" href="disclaimer.php">
        </map>
        <iframe src="/embedded/widget.php"></iframe>
        <a href="javascript:void(0)">Ignore JS</a>
        <a href="#section">Ignore Hash</a>
        <a href="mailto:info@testphp.vulnweb.com">Ignore Mail</a>
      </body>
    </html>
    """

    links = spider.extract_links("http://testphp.vulnweb.com/", html_sample)
    assert "http://testphp.vulnweb.com/artists.php?artist=1" in links
    assert "http://testphp.vulnweb.com/listproducts.php?cat=2" in links
    assert "http://testphp.vulnweb.com/disclaimer.php" in links
    assert "http://testphp.vulnweb.com/embedded/widget.php" in links
    assert not any("javascript:" in l for l in links)
    assert not any("mailto:" in l for l in links)


def test_spider_scope_filtering():
    spider = DeepSpider()
    # In scope
    assert spider.is_in_scope("http://testphp.vulnweb.com/artists.php", "http", "testphp.vulnweb.com", 80) is True
    assert spider.is_in_scope("http://testphp.vulnweb.com/listproducts.php?cat=1", "http", "testphp.vulnweb.com", 80) is True

    # Out of scope: external domain
    assert spider.is_in_scope("http://google.com/test", "http", "testphp.vulnweb.com", 80) is False
    assert spider.is_in_scope("http://evil-attacker.com", "http", "testphp.vulnweb.com", 80) is False

    # Out of scope: different port
    assert spider.is_in_scope("http://testphp.vulnweb.com:8080/path", "http", "testphp.vulnweb.com", 80) is False

    # Out of scope: static assets
    assert spider.is_in_scope("http://testphp.vulnweb.com/style.css", "http", "testphp.vulnweb.com", 80) is False
    assert spider.is_in_scope("http://testphp.vulnweb.com/banner.png", "http", "testphp.vulnweb.com", 80) is False


@pytest.mark.asyncio
async def test_spider_crawl_end_to_end():
    target = ScanTarget.from_url("http://testphp.vulnweb.com")
    spider = DeepSpider(max_depth=2, max_pages=10)

    html_home = """
    <html>
      <body>
        <a href="artists.php?artist=1">Artists</a>
        <a href="listproducts.php?cat=2">Products</a>
        <form action="search.php" method="GET">
          <input type="text" name="test" />
        </form>
      </body>
    </html>
    """

    html_artists = """
    <html>
      <body>
        <h1>Artists</h1>
        <a href="artist_details.php?id=3">Detail</a>
      </body>
    </html>
    """

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="http://testphp.vulnweb.com", assert_all_called=False) as respx_mock:
            respx_mock.get("/").respond(status_code=200, text=html_home)
            respx_mock.get("/artists.php?artist=1").respond(status_code=200, text=html_artists)
            respx_mock.get("/listproducts.php?cat=2").respond(status_code=200, text="Products List")
            respx_mock.get("/artist_details.php?id=3").respond(status_code=200, text="Artist 3")

            result = await spider.crawl(target, client)

            assert len(result.discovered_paths) >= 4
            assert any("/artists.php" in p for p in result.discovered_paths)
            assert any("/listproducts.php" in p for p in result.discovered_paths)
            assert any("/artist_details.php" in p for p in result.discovered_paths)
            assert len(result.forms) >= 1
            assert "test" in result.fuzzable_parameters
            assert "artist" in result.fuzzable_parameters
            assert "cat" in result.fuzzable_parameters
            assert result.pages_crawled >= 2
            assert result.duration_seconds >= 0.0
