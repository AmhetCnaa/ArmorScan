"""
Tests for core data models.
"""

import pytest
from armorscan.core.models import Finding, Grade, ModuleResult, ScanResult, ScanSummary, ScanTarget, Severity


def test_scan_target_parsing():
    target = ScanTarget.from_url("https://example.com/api/test")
    assert target.scheme == "https"
    assert target.host == "example.com"
    assert target.port == 443
    assert target.is_https is True
    assert target.is_localhost is False
    assert target.base_url == "https://example.com"


def test_scan_target_localhost():
    target = ScanTarget.from_url("http://127.0.0.1:8080/dashboard")
    assert target.scheme == "http"
    assert target.host == "127.0.0.1"
    assert target.port == 8080
    assert target.is_https is False
    assert target.is_localhost is True
    assert target.base_url == "http://127.0.0.1:8080"


def test_scan_target_auto_prefix():
    target = ScanTarget.from_url("example.com")
    assert target.scheme == "https"
    assert target.host == "example.com"


def test_scan_target_invalid_scheme():
    with pytest.raises(ValueError):
        ScanTarget.from_url("ftp://example.com")


def test_grade_calculation():
    assert Grade.from_score(98) == Grade.A_PLUS
    assert Grade.from_score(88) == Grade.A
    assert Grade.from_score(75) == Grade.B
    assert Grade.from_score(60) == Grade.C
    assert Grade.from_score(45) == Grade.D
    assert Grade.from_score(20) == Grade.F


def test_severity_penalties():
    assert Severity.CRITICAL.score_penalty == 25
    assert Severity.HIGH.score_penalty == 15
    assert Severity.MEDIUM.score_penalty == 8
    assert Severity.LOW.score_penalty == 3
    assert Severity.INFO.score_penalty == 0


def test_finding_and_scan_result():
    target = ScanTarget.from_url("https://test.dev")
    finding = Finding(
        id="TEST_01",
        title="Test Finding",
        description="Just a test",
        severity=Severity.HIGH,
        module="test_module",
        impact="Test impact",
    )
    mod_result = ModuleResult(
        module_name="test_module",
        display_name="Test Module",
        findings=[finding],
        passed_checks=["check_1"],
    )
    res = ScanResult(
        target=target,
        modules=[mod_result],
        summary=ScanSummary(score=85, grade=Grade.A),
    )
    assert len(res.all_findings) == 1
    assert res.all_findings[0].id == "TEST_01"
