"""
Unit tests for ArmorScan finding deduplication across crawled URLs (runner.py).
"""

import pytest

from armorscan.core.models import Confidence, Finding, ModuleResult, Severity
from armorscan.core.runner import ScanRunner


def test_deduplicate_identical_findings():
    f1 = Finding(
        id="MISSING_HSTS",
        title="Missing Strict-Transport-Security Header",
        description="Desc",
        severity=Severity.HIGH,
        confidence=Confidence.FIRM,
        module="headers",
        impact="Impact",
        affected_urls=["https://example.com/page1"],
    )
    f2 = Finding(
        id="MISSING_HSTS",
        title="Missing Strict-Transport-Security Header",
        description="Desc",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        module="headers",
        impact="Impact",
        affected_urls=["https://example.com/page2"],
    )
    f3 = Finding(
        id="MISSING_CSP",
        title="Missing Content-Security-Policy Header",
        description="Desc",
        severity=Severity.HIGH,
        confidence=Confidence.FIRM,
        module="headers",
        impact="Impact",
        affected_urls=["https://example.com/page1"],
    )

    mod_result = ModuleResult(
        module_name="headers",
        display_name="Security Headers",
        findings=[f1, f2, f3],
    )

    ScanRunner.deduplicate_findings([mod_result])

    assert len(mod_result.findings) == 2
    hsts_finding = next(f for f in mod_result.findings if f.id == "MISSING_HSTS")
    assert len(hsts_finding.affected_urls) == 2
    assert "https://example.com/page1" in hsts_finding.affected_urls
    assert "https://example.com/page2" in hsts_finding.affected_urls
    # Confidence upgraded to CONFIRMED because f2 was CONFIRMED
    assert hsts_finding.confidence == Confidence.CONFIRMED

    csp_finding = next(f for f in mod_result.findings if f.id == "MISSING_CSP")
    assert len(csp_finding.affected_urls) == 1
    assert csp_finding.confidence == Confidence.FIRM
