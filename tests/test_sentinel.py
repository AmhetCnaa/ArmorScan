"""
Unit tests for Autonomous Sentinel continuous monitoring engine and webhook dispatcher (tests/test_sentinel.py).
Validates interval parsing, baseline state tracking, differential detection (new findings and score drops),
and rich webhook notifications for Discord, Slack, and Telegram.
"""

from datetime import datetime, timezone
from pathlib import Path
import pytest
import respx
import httpx

from armorscan.core.models import (
    Confidence,
    Finding,
    ModuleResult,
    ScanResult,
    ScanSummary,
    ScanTarget,
    Severity,
)
from armorscan.core.sentinel import (
    SentinelBaseline,
    SentinelDiffResult,
    SentinelEngine,
    parse_interval_seconds,
)


def create_mock_scan_result(score: int, finding_ids: list[str]) -> ScanResult:
    target = ScanTarget.from_url("http://127.0.0.1:3000")
    findings = [
        Finding(
            id=fid,
            title=f"Vulnerability {fid}",
            description="Mock test finding",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            module="test",
            impact="Mock test impact statement",
            affected_urls=[f"http://127.0.0.1:3000/{fid.lower()}"],
        )
        for fid in finding_ids
    ]
    summary = ScanSummary(
        total_checks=20,
        passed_checks=20 - len(findings),
        critical_count=0,
        high_count=len(findings),
        medium_count=0,
        low_count=0,
        info_count=0,
        score=score,
    )
    mod_res = ModuleResult(
        module_name="test",
        display_name="Test Module",
        findings=findings,
        passed_checks=[],
    )
    return ScanResult(
        target=target,
        started_at=datetime.now(timezone.utc),
        duration_seconds=0.5,
        modules=[mod_res],
        summary=summary,
    )


def test_parse_interval_seconds():
    assert parse_interval_seconds("30s") == 30
    assert parse_interval_seconds("15m") == 900
    assert parse_interval_seconds("1h") == 3600
    assert parse_interval_seconds("24h") == 86400
    assert parse_interval_seconds("2d") == 172800
    assert parse_interval_seconds("120") == 120

    with pytest.raises(ValueError, match="Invalid interval format"):
        parse_interval_seconds("invalid")

    with pytest.raises(ValueError, match="Invalid interval format"):
        parse_interval_seconds("10x")


def test_sentinel_diff_engine_cycle(tmp_path: Path):
    baseline_file = tmp_path / "sentinel-baseline.json"
    sentinel = SentinelEngine(
        target_url="http://127.0.0.1:3000",
        baseline_file=baseline_file,
    )

    # Cycle 1: First scan creates baseline, no alert
    res1 = create_mock_scan_result(score=85, finding_ids=["MISSING_CSP"])
    diff1, b1 = sentinel.evaluate_scan(res1)
    assert diff1.has_alert is False
    assert diff1.score_now == 85
    assert baseline_file.exists()

    # Cycle 2: Identical scan, no new findings, no score drop -> no alert
    res2 = create_mock_scan_result(score=85, finding_ids=["MISSING_CSP"])
    diff2, b2 = sentinel.evaluate_scan(res2)
    assert diff2.has_alert is False
    assert len(diff2.new_findings) == 0

    # Cycle 3: Regression! New finding appears and score drops -> ALERT!
    res3 = create_mock_scan_result(score=60, finding_ids=["MISSING_CSP", "EXPOSED_ENV_FILE"])
    diff3, b3 = sentinel.evaluate_scan(res3)
    assert diff3.has_alert is True
    assert diff3.score_dropped is True
    assert diff3.score_before == 85
    assert diff3.score_now == 60
    assert len(diff3.new_findings) == 1
    assert diff3.new_findings[0].id == "EXPOSED_ENV_FILE"
    assert "new vulnerabilities" in diff3.alert_summary


@pytest.mark.asyncio
async def test_sentinel_webhook_dispatchers(tmp_path: Path):
    baseline_file = tmp_path / "sentinel-baseline.json"
    discord_url = "https://discord.com/api/webhooks/mock/test"
    slack_url = "https://hooks.slack.com/services/mock/test"
    telegram_token = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
    telegram_chat = "987654321"

    sentinel = SentinelEngine(
        target_url="http://127.0.0.1:3000",
        baseline_file=baseline_file,
        discord_webhook=discord_url,
        slack_webhook=slack_url,
        telegram_token=telegram_token,
        telegram_chat_id=telegram_chat,
    )

    # Initialize baseline
    res1 = create_mock_scan_result(score=90, finding_ids=[])
    sentinel.evaluate_scan(res1)

    # Regression scan
    res2 = create_mock_scan_result(score=65, finding_ids=["SQLI_BOOLEAN_DIFFERENCE_SUSPECTED"])
    diff, _ = sentinel.evaluate_scan(res2)
    assert diff.has_alert is True

    with respx.mock:
        respx.post(discord_url).respond(status_code=204)
        respx.post(slack_url).respond(status_code=200, text="ok")
        respx.post(f"https://api.telegram.org/bot{telegram_token}/sendMessage").respond(
            status_code=200,
            json={"ok": True},
        )

        dispatched = await sentinel.dispatch_notifications(diff)
        assert "discord" in dispatched
        assert "slack" in dispatched
        assert "telegram" in dispatched
