"""
Unit tests for Reporter modules (Console, HTML, JSON).
"""

import json
from pathlib import Path
import pytest

from armorscan.core.models import Finding, Grade, ModuleResult, ScanResult, ScanSummary, ScanTarget, Severity
from armorscan.reporters.console import ConsoleReporter
from armorscan.reporters.html import HtmlReporter
from armorscan.reporters.json_rep import JsonReporter


@pytest.fixture
def mock_scan_result() -> ScanResult:
    target = ScanTarget.from_url("https://example-test.dev")
    finding1 = Finding(
        id="MISSING_HSTS",
        title="Missing Strict-Transport-Security (HSTS)",
        description="No HSTS header returned.",
        severity=Severity.MEDIUM,
        module="headers",
        impact="MitM and SSL stripping attacks.",
        evidence="Strict-Transport-Security: absent",
        remediation_snippets={"nginx": "add_header Strict-Transport-Security ...;", "express": "app.use(helmet.hsts());"},
        cwe_id="CWE-319",
        owasp_category="A02:2021-Cryptographic Failures",
    )
    finding2 = Finding(
        id="EXPOSED_ENV_FILE",
        title="Exposed .env File",
        description="Publicly accessible .env configuration.",
        severity=Severity.CRITICAL,
        module="exposure",
        impact="Full database credential compromise.",
        evidence="DB_PASSWORD=[REDACTED]",
        remediation_snippets={"nginx": "location ~ /\\. { deny all; }"},
        cwe_id="CWE-552",
    )
    mod1 = ModuleResult(
        module_name="headers",
        display_name="Headers",
        findings=[finding1],
        passed_checks=["csp", "xfo"],
    )
    mod2 = ModuleResult(
        module_name="exposure",
        display_name="Exposure",
        findings=[finding2],
        passed_checks=["git-repo-clean"],
    )

    summary = ScanSummary(
        total_checks=5,
        passed_checks=3,
        critical_count=1,
        medium_count=1,
        score=67,
        grade=Grade.C,
    )

    return ScanResult(
        target=target,
        duration_seconds=1.23,
        summary=summary,
        modules=[mod1, mod2],
    )


def test_json_reporter(mock_scan_result, tmp_path):
    output_file = tmp_path / "report.json"
    saved_path = JsonReporter.save(mock_scan_result, output_file)

    assert Path(saved_path).exists()
    data = json.loads(Path(saved_path).read_text(encoding="utf-8"))

    assert data["target"]["raw_url"] == "https://example-test.dev"
    assert data["summary"]["score"] == 67
    assert data["summary"]["grade"] == "C"
    assert len(data["modules"]) == 2
    assert data["modules"][0]["findings"][0]["id"] == "MISSING_HSTS"


def test_html_reporter_self_contained(mock_scan_result, tmp_path):
    output_file = tmp_path / "report.html"
    saved_path = HtmlReporter.save(mock_scan_result, output_file)

    assert Path(saved_path).exists()
    content = Path(saved_path).read_text(encoding="utf-8")

    # Air-gapped validation: must NOT depend on external CDN links
    assert "https://cdn." not in content
    assert "https://cdnjs." not in content
    assert "https://unpkg.com" not in content

    # Content checks
    assert "ArmorScan" in content
    assert "https://example-test.dev" in content
    assert "MISSING_HSTS" in content
    assert "EXPOSED_ENV_FILE" in content
    assert "67 / 100" in content
    assert "CWE-319" in content
    assert "add_header Strict-Transport-Security" in content
    assert "switchTab" in content
    assert "copySnippet" in content


def test_console_reporter(mock_scan_result):
    from rich.console import Console
    import io

    string_io = io.StringIO()
    console = Console(file=string_io, force_terminal=False, color_system=None)
    reporter = ConsoleReporter(console=console)

    reporter.print_banner("https://example-test.dev")
    reporter.render_scan_results(mock_scan_result)

    output = string_io.getvalue()
    assert "ArmorScan" in output
    assert "MISSING_HSTS" in output
    assert "EXPOSED_ENV_FILE" in output
    assert "GRADE: C" in output
    assert "Security Score:" in output
