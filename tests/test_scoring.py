"""
Tests for scoring and evaluation engine.
"""

from armorscan.core.models import Finding, Grade, ModuleResult, Severity
from armorscan.core.scoring import ScoringEngine


def test_perfect_score():
    mod1 = ModuleResult(
        module_name="headers",
        display_name="Headers",
        findings=[],
        passed_checks=["hsts", "csp", "xfo"],
    )
    summary = ScoringEngine.calculate_summary([mod1])
    assert summary.score == 100
    assert summary.grade == Grade.A_PLUS
    assert summary.total_checks == 3
    assert summary.passed_checks == 3
    assert summary.critical_count == 0


def test_penalties_and_grades():
    finding_crit = Finding(
        id="EXPOSED_ENV",
        title="Exposed .env",
        description="Public .env file",
        severity=Severity.CRITICAL,
        module="exposure",
        impact="Full compromise",
    )
    finding_high = Finding(
        id="CORS_WILDCARD_CREDS",
        title="CORS Wildcard with Credentials",
        description="Dangerous CORS",
        severity=Severity.HIGH,
        module="cors",
        impact="Data leakage",
    )
    finding_med = Finding(
        id="MISSING_HSTS",
        title="Missing HSTS",
        description="HSTS missing",
        severity=Severity.MEDIUM,
        module="headers",
        impact="MitM risk",
    )

    mod = ModuleResult(
        module_name="composite",
        display_name="Composite",
        findings=[finding_crit, finding_high, finding_med],
        passed_checks=["check_a"],
    )

    summary = ScoringEngine.calculate_summary([mod])
    # 100 - (25 + 15 + 8) = 100 - 48 = 52 -> Grade D
    assert summary.score == 52
    assert summary.grade == Grade.D
    assert summary.critical_count == 1
    assert summary.high_count == 1
    assert summary.medium_count == 1
    assert summary.total_checks == 4
