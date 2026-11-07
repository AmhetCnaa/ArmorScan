"""Unit tests for OASIS SARIF 2.1.0 Reporter and TUI Dashboard (tests/test_sarif.py)."""

import json
from pathlib import Path
from rich.console import Console

from armorscan.core.models import (
    Confidence,
    Finding,
    Grade,
    ModuleResult,
    ScanResult,
    ScanSummary,
    ScanTarget,
    Severity,
)
from armorscan.reporters.sarif import SARIF_SCHEMA_URL, SarifReporter
from armorscan.reporters.tui import TuiDashboard


def _sample_scan_result() -> ScanResult:
    f1 = Finding(
        id="MISSING_CSP",
        title="Missing Content-Security-Policy Header",
        description="CSP header is absent.",
        severity=Severity.HIGH,
        confidence=Confidence.FIRM,
        module="headers",
        impact="Allows XSS execution.",
        evidence="No CSP header found",
        remediation="Add Content-Security-Policy header.",
        remediation_snippets={"nginx": "add_header Content-Security-Policy \"default-src 'self'\";"},
        cwe_id="CWE-693",
        owasp_category="A05:2021-Security Misconfiguration",
        affected_urls=["https://example.com/"],
    )
    f2 = Finding(
        id="SUPPRESSED_RULE",
        title="Suppressed Low Finding",
        description="Suppressed.",
        severity=Severity.LOW,
        confidence=Confidence.TENTATIVE,
        module="headers",
        impact="None",
        is_suppressed=True,
    )
    mod_res = ModuleResult(
        module_name="headers",
        display_name="Security Headers",
        findings=[f1, f2],
    )
    return ScanResult(
        target=ScanTarget.from_url("https://example.com"),
        summary=ScanSummary(score=85, grade=Grade.A, high=1, total_findings=1),
        modules=[mod_res],
    )


def test_sarif_2_1_0_schema_compliance(tmp_path):
    scan_res = _sample_scan_result()
    out_file = tmp_path / "results.sarif"
    SarifReporter.export(scan_res, out_file)

    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))

    assert data["version"] == "2.1.0"
    assert data["$schema"] == SARIF_SCHEMA_URL
    assert len(data["runs"]) == 1

    run = data["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "ArmorScan"
    assert len(driver["rules"]) == 1
    assert driver["rules"][0]["id"] == "MISSING_CSP"
    assert driver["rules"][0]["properties"]["cwe"] == "CWE-693"
    assert driver["rules"][0]["properties"]["security-severity"] == "8.0"

    # Suppressed finding must not appear in SARIF results
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["ruleId"] == "MISSING_CSP"
    assert res["level"] == "error"
    loc = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert loc == "https://example.com/"


def test_tui_dashboard_layout_and_navigation():
    scan_res = _sample_scan_result()
    console = Console(record=True, width=120)
    tui = TuiDashboard(scan_res, console=console)

    assert len(tui.findings) == 1
    assert tui.selected_index == 0

    layout = tui.build_layout()
    assert layout["header"] is not None
    assert layout["left"] is not None
    assert layout["right"] is not None

    tui.move_selection(1)
    assert tui.selected_index == 0

    # Non-TTY run renders snapshot cleanly
    tui.run()
    rendered = console.export_text()
    assert "MISSING_CSP" in rendered
    assert "ArmorScan v0.5.0" in rendered
