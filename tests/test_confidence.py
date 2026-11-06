"""
Unit tests for ArmorScan Confidence ratings and rich evidence construction.
Verifies confidence levels, standardized curl generation, and response context extraction.
"""

import pytest

from armorscan.core.models import Confidence, Finding, Severity


def test_confidence_enum_and_colors():
    assert Confidence.CONFIRMED.value == "confirmed"
    assert Confidence.FIRM.value == "firm"
    assert Confidence.TENTATIVE.value == "tentative"

    assert "green" in Confidence.CONFIRMED.color
    assert "cyan" in Confidence.FIRM.color
    assert "yellow" in Confidence.TENTATIVE.color


def test_finding_build_curl_get():
    curl_cmd = Finding.build_curl(
        method="GET",
        url="https://example.com/api/search?q=test",
        headers={"User-Agent": "ArmorScan/0.4.0", "Origin": "https://evil.com"},
    )
    assert "curl -i -s -k -X GET 'https://example.com/api/search?q=test'" in curl_cmd
    assert "-H 'Origin: https://evil.com'" in curl_cmd


def test_finding_build_curl_post_with_data():
    curl_cmd = Finding.build_curl(
        method="POST",
        url="https://example.com/api/login",
        headers={"Content-Type": "application/json"},
        data='{"user": "admin"}',
    )
    assert "-X POST 'https://example.com/api/login'" in curl_cmd
    assert "-H 'Content-Type: application/json'" in curl_cmd
    assert "--data '{\"user\": \"admin\"}'" in curl_cmd


def test_extract_context_snippet_basic():
    text = (
        "line 1: safe\n"
        "line 2: safe\n"
        "line 3: vulnerable match here\n"
        "line 4: safe\n"
        "line 5: safe\n"
    )

    snippet = Finding.extract_context_snippet(text, "vulnerable match", context_lines=1)
    assert ">> line 3: vulnerable match here" in snippet
    assert "   line 2: safe" in snippet
    assert "   line 4: safe" in snippet
    assert "line 1" not in snippet
    assert "line 5" not in snippet


def test_extract_context_snippet_empty_or_missing():
    assert Finding.extract_context_snippet("", "match") == ""
    assert Finding.extract_context_snippet("some text", "") == ""
    fallback = Finding.extract_context_snippet("short line", "notfound")
    assert fallback == "notfound"
