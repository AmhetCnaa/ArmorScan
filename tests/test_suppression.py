"""
Unit tests for ArmorScan Suppression Engine (.armorscanignore).
Verifies rule parsing (YAML and line-based), URL regex matching,
expiration handling, and score exemption.
"""

from datetime import date, timedelta
from pathlib import Path
import pytest

from armorscan.core.models import Finding, ModuleResult, Severity
from armorscan.core.scoring import ScoringEngine
from armorscan.core.suppression import SuppressionEngine, SuppressionRule


def test_suppression_rule_exact_match():
    rule = SuppressionRule(finding_id="MISSING_HSTS", url_pattern=r"https://example\.com/.*", reason="Accepted risk")
    f_match = Finding(
        id="MISSING_HSTS",
        title="Missing HSTS",
        description="Desc",
        severity=Severity.HIGH,
        module="headers",
        impact="Impact",
    )
    f_other = Finding(
        id="MISSING_CSP",
        title="Missing CSP",
        description="Desc",
        severity=Severity.HIGH,
        module="headers",
        impact="Impact",
    )

    assert rule.matches(f_match, "https://example.com/login") is True
    assert rule.matches(f_match, "https://other.com/login") is False
    assert rule.matches(f_other, "https://example.com/login") is False


def test_suppression_rule_wildcard_and_case_insensitive():
    rule = SuppressionRule(finding_id="*", url_pattern=r"/api/.*", reason="Grandfathered API")
    finding = Finding(
        id="cors_arbitrary_origin",
        title="CORS Arbitrary Origin",
        description="Desc",
        severity=Severity.HIGH,
        module="cors",
        impact="Impact",
    )

    assert rule.matches(finding, "https://example.com/api/v1/users") is True
    assert rule.matches(finding, "https://example.com/web/dashboard") is False


def test_suppression_rule_expiration():
    yesterday = (date.today() - timedelta(days=1)).strftime("%Y-%m-%d")
    tomorrow = (date.today() + timedelta(days=1)).strftime("%Y-%m-%d")

    expired_rule = SuppressionRule(finding_id="LEAK", expires=yesterday)
    active_rule = SuppressionRule(finding_id="LEAK", expires=tomorrow)

    finding = Finding(
        id="LEAK",
        title="Leak",
        description="Desc",
        severity=Severity.MEDIUM,
        module="exposure",
        impact="Impact",
    )

    assert expired_rule.is_expired is True
    assert expired_rule.matches(finding, "https://example.com") is False

    assert active_rule.is_expired is False
    assert active_rule.matches(finding, "https://example.com") is True


def test_suppression_engine_from_yaml_file(tmp_path: Path):
    yaml_file = tmp_path / ".armorscanignore"
    yaml_file.write_text(
        """
suppressions:
  - id: MISSING_HSTS
    url_pattern: 'https://example\\.com.*'
    reason: "Terminated at Cloudflare CDN edge"
    expires: "2099-01-01"
  - id: OPENAI_API_KEY_LEAK
    url_pattern: '.*/test-fixtures/.*'
    reason: "Mock test keys in test fixtures"
""",
        encoding="utf-8",
    )

    engine = SuppressionEngine.from_file(yaml_file)
    assert len(engine.rules) == 2
    assert engine.rules[0].finding_id == "MISSING_HSTS"
    assert engine.rules[0].reason == "Terminated at Cloudflare CDN edge"
    assert engine.rules[1].finding_id == "OPENAI_API_KEY_LEAK"


def test_suppression_engine_from_line_based_file(tmp_path: Path):
    line_file = tmp_path / ".armorscanignore"
    line_file.write_text(
        """# Line-based suppressions
MISSING_CSP | /legacy/.* | Legacy frontend not refactored yet | 2099-12-31
COOKIE_MISSING_HTTPONLY | .* | Analytics cookie only
""",
        encoding="utf-8",
    )

    engine = SuppressionEngine.from_file(line_file)
    assert len(engine.rules) == 2
    assert engine.rules[0].finding_id == "MISSING_CSP"
    assert engine.rules[0].url_pattern_str == "/legacy/.*"
    assert engine.rules[1].finding_id == "COOKIE_MISSING_HTTPONLY"
    assert engine.rules[1].reason == "Analytics cookie only"


def test_suppression_scoring_exemption():
    f_active = Finding(
        id="UNPROTECTED_BUCKET",
        title="Bucket",
        description="Desc",
        severity=Severity.HIGH,
        module="exposure",
        impact="Impact",
    )
    f_suppressed = Finding(
        id="MISSING_HSTS",
        title="Missing HSTS",
        description="Desc",
        severity=Severity.HIGH,
        module="headers",
        impact="Impact",
        is_suppressed=True,
        suppression_reason="Known edge case",
    )

    mod = ModuleResult(
        module_name="test",
        display_name="Test Module",
        findings=[f_active, f_suppressed],
        passed_checks=["check1", "check2"],
    )

    summary = ScoringEngine.calculate_summary([mod])

    # Only 1 HIGH finding penalty (15 pts), suppressed finding must not be penalized
    assert summary.score == 85
    assert summary.high_count == 1
    assert summary.suppressed_count == 1
