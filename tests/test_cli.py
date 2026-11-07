"""
Unit tests for ArmorScan CLI and CI/CD quality gate enforcement (cli.py).
"""

from pathlib import Path
from unittest.mock import AsyncMock, patch
import pytest
from rich.console import Console

from armorscan.cli import build_parser, get_default_modules, run_scan_async
from armorscan.core.models import Grade, ScanResult, ScanSummary, ScanTarget


def test_default_modules_count():
    modules = get_default_modules(burst_count=10)
    assert len(modules) == 19
    names = [m.name for m in modules]
    assert "headers" in names
    assert "tls_ssl" in names
    assert "cookies" in names
    assert "exposure" in names
    assert "cors" in names
    assert "ratelimit" in names
    assert "reflection" in names
    assert "redirect" in names
    assert "error_leak" in names
    assert "jwt_audit" in names
    assert "secret_leak" in names
    assert "authz_check" in names
    assert "multi_step" in names
    assert "sqli" in names
    assert "nosqli" in names
    assert "traversal" in names
    assert "ssrf_check" in names
    assert "graphql" in names
    assert "templates" in names

    # When include_browser=True, length is 20
    browser_modules = get_default_modules(burst_count=10, include_browser=True)
    assert len(browser_modules) == 20
    assert "browser_dom" in [m.name for m in browser_modules]


def test_cli_parser_defaults():
    parser = build_parser()
    args = parser.parse_args(["https://target.com"])

    assert args.target == "https://target.com"
    assert args.fail_under is None
    assert args.html == "armorscan-report.html"
    assert args.no_html is False
    assert args.json is None
    assert args.sarif is None
    assert args.templates is None
    assert args.tui is False
    assert args.insecure is False
    assert args.concurrency == 5
    assert args.burst == 18
    assert args.browser is False


def test_cli_parser_custom_flags():
    parser = build_parser()
    args = parser.parse_args([
        "https://app.dev",
        "--fail-under", "85",
        "--html", "custom-report.html",
        "--json", "custom-data.json",
        "--sarif", "custom.sarif",
        "--templates", "./my-templates",
        "--tui",
        "-k",
        "--concurrency", "8",
        "--burst", "25",
        "--browser",
        "-q",
    ])

    assert args.target == "https://app.dev"
    assert args.fail_under == 85
    assert args.html == "custom-report.html"
    assert args.json == "custom-data.json"
    assert args.sarif == "custom.sarif"
    assert args.templates == ["./my-templates"]
    assert args.tui is True
    assert args.insecure is True
    assert args.concurrency == 8
    assert args.burst == 25
    assert args.browser is True
    assert args.quiet is True


@pytest.mark.asyncio
async def test_cli_quality_gate_failed(tmp_path):
    parser = build_parser()
    html_out = str(tmp_path / "report.html")
    args = parser.parse_args(["https://vuln-site.com", "--fail-under", "80", "--html", html_out, "-q"])

    failing_result = ScanResult(
        target=ScanTarget.from_url("https://vuln-site.com"),
        summary=ScanSummary(score=65, grade=Grade.C),
    )

    console = Console(quiet=True)
    with patch("armorscan.core.runner.ScanRunner.scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = failing_result
        exit_code = await run_scan_async(args, console)

    # Must exit with code 1 because 65 < 80
    assert exit_code == 1
    assert Path(html_out).exists()


@pytest.mark.asyncio
async def test_cli_quality_gate_passed(tmp_path):
    parser = build_parser()
    html_out = str(tmp_path / "report.html")
    json_out = str(tmp_path / "report.json")
    args = parser.parse_args([
        "https://secure-site.com",
        "--fail-under", "80",
        "--html", html_out,
        "--json", json_out,
        "-q",
    ])

    passing_result = ScanResult(
        target=ScanTarget.from_url("https://secure-site.com"),
        summary=ScanSummary(score=95, grade=Grade.A_PLUS),
    )

    console = Console(quiet=True)
    with patch("armorscan.core.runner.ScanRunner.scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = passing_result
        exit_code = await run_scan_async(args, console)

    # Must exit with code 0 because 95 >= 80
    assert exit_code == 0
    assert Path(html_out).exists()
    assert Path(json_out).exists()


def test_cli_parser_ignore_file():
    parser = build_parser()
    args = parser.parse_args(["https://target.com", "--ignore-file", ".customignore"])
    assert args.ignore_file == ".customignore"


def test_cli_parser_schema():
    parser = build_parser()
    args = parser.parse_args(["https://target.com", "--schema", "swagger.json"])
    assert args.schema == "swagger.json"


@pytest.mark.asyncio
async def test_cli_benchmark_command_dispatch():
    parser = build_parser()
    args = parser.parse_args(["benchmark", "juice-shop"])
    console = Console(quiet=True)

    with patch("scripts.run_benchmark.run_real_world_benchmark_async", new_callable=AsyncMock) as mock_bench:
        mock_bench.return_value = 0
        code = await run_scan_async(args, console)
        assert code == 0
        mock_bench.assert_called_once()

