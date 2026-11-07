"""
Autonomous Sentinel — Continuous Security Watcher Daemon (core/sentinel.py).
Lightweight, deterministic async daemon that monitors target security posture at fixed intervals,
computes diffs against a local baseline, and dispatches rich alert webhooks to Discord, Slack,
and Telegram ONLY when new vulnerabilities emerge or the security posture score drops.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field

from armorscan.core.client import HttpClient
from armorscan.core.models import Finding, ScanResult, ScanTarget
from armorscan.core.runner import ScanRunner


def parse_interval_seconds(interval_str: str) -> int:
    """
    Parse a human-readable interval string (e.g. '30s', '15m', '1h', '24h', '2d')
    into integer seconds.
    """
    s = interval_str.strip().lower()
    if s.isdigit():
        return int(s)

    match = re.match(r"^(\d+)\s*([smhd])$", s)
    if not match:
        raise ValueError(
            f"Invalid interval format: '{interval_str}'. Supported formats: 30s, 15m, 1h, 24h, 2d"
        )

    val = int(match.group(1))
    unit = match.group(2)

    multipliers = {
        "s": 1,
        "m": 60,
        "h": 3600,
        "d": 86400,
    }
    return val * multipliers[unit]


class SentinelBaseline(BaseModel):
    """Persisted snapshot of baseline security findings and score."""

    target: str
    timestamp: str
    score: int
    grade: str
    findings: List[Dict[str, Any]] = Field(default_factory=list)

    @classmethod
    def load(cls, file_path: Path) -> Optional[SentinelBaseline]:
        if not file_path.exists():
            return None
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            return cls.model_validate(data)
        except Exception:
            return None

    def save(self, file_path: Path) -> None:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(self.model_dump_json(indent=2), encoding="utf-8")

    def finding_signatures(self) -> Set[Tuple[str, Tuple[str, ...]]]:
        sigs = set()
        for f in self.findings:
            fid = f.get("id", "")
            urls = tuple(sorted(f.get("affected_urls", [])))
            sigs.add((fid, urls))
        return sigs


class SentinelDiffResult(BaseModel):
    """Differential analysis between current scan result and baseline."""

    has_alert: bool
    score_dropped: bool
    score_before: int
    score_now: int
    new_findings: List[Finding] = Field(default_factory=list)
    resolved_findings: List[Dict[str, Any]] = Field(default_factory=list)
    alert_summary: str = ""


class SentinelEngine:
    """
    Deterministic difference engine and alert dispatcher for continuous monitoring.
    """

    def __init__(
        self,
        target_url: str,
        baseline_file: Path,
        discord_webhook: Optional[str] = None,
        slack_webhook: Optional[str] = None,
        telegram_token: Optional[str] = None,
        telegram_chat_id: Optional[str] = None,
    ):
        self.target_url = target_url
        self.baseline_file = Path(baseline_file)
        self.discord_webhook = discord_webhook
        self.slack_webhook = slack_webhook
        self.telegram_token = telegram_token
        self.telegram_chat_id = telegram_chat_id

    def evaluate_scan(self, current_result: ScanResult) -> Tuple[SentinelDiffResult, SentinelBaseline]:
        """Compare current scan against baseline and determine if alerts are required."""
        curr_score = current_result.summary.score
        curr_grade = current_result.summary.grade.value
        curr_findings = current_result.all_findings

        curr_finding_dicts = [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "affected_urls": f.affected_urls,
                "evidence": f.evidence,
            }
            for f in curr_findings
        ]

        baseline = SentinelBaseline.load(self.baseline_file)

        # First run: initialize baseline without firing alert
        if baseline is None:
            new_baseline = SentinelBaseline(
                target=self.target_url,
                timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                score=curr_score,
                grade=curr_grade,
                findings=curr_finding_dicts,
            )
            new_baseline.save(self.baseline_file)
            diff = SentinelDiffResult(
                has_alert=False,
                score_dropped=False,
                score_before=curr_score,
                score_now=curr_score,
                new_findings=[],
                resolved_findings=[],
                alert_summary="Baseline initialized successfully.",
            )
            return diff, new_baseline

        # Compute diff against existing baseline
        baseline_sigs = baseline.finding_signatures()
        new_findings: List[Finding] = []

        for f in curr_findings:
            sig = (f.id, tuple(sorted(f.affected_urls)))
            if sig not in baseline_sigs:
                new_findings.append(f)

        # Check resolved findings
        curr_sigs = { (f.id, tuple(sorted(f.affected_urls))) for f in curr_findings }
        resolved_findings: List[Dict[str, Any]] = []
        for bf in baseline.findings:
            bsig = (bf.get("id", ""), tuple(sorted(bf.get("affected_urls", []))))
            if bsig not in curr_sigs:
                resolved_findings.append(bf)

        score_dropped = curr_score < baseline.score
        has_alert = (len(new_findings) > 0) or score_dropped

        summary_parts = []
        if len(new_findings) > 0:
            summary_parts.append(f"{len(new_findings)} new vulnerabilities detected")
        if score_dropped:
            summary_parts.append(f"Security score dropped from {baseline.score} to {curr_score} ({curr_grade})")

        alert_summary = " | ".join(summary_parts) if summary_parts else "No regressions detected."

        diff_result = SentinelDiffResult(
            has_alert=has_alert,
            score_dropped=score_dropped,
            score_before=baseline.score,
            score_now=curr_score,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            alert_summary=alert_summary,
        )

        # Update baseline on disk if alert triggered or score improved
        updated_baseline = SentinelBaseline(
            target=self.target_url,
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            score=curr_score,
            grade=curr_grade,
            findings=curr_finding_dicts,
        )
        updated_baseline.save(self.baseline_file)

        return diff_result, updated_baseline

    async def dispatch_notifications(self, diff: SentinelDiffResult, client: Optional[httpx.AsyncClient] = None) -> List[str]:
        """Dispatch notifications to configured webhooks."""
        if not diff.has_alert:
            return []

        dispatched = []
        close_client = False
        if client is None:
            client = httpx.AsyncClient(timeout=10.0, trust_env=False)
            close_client = True

        try:
            # 1. Discord Webhook
            if self.discord_webhook:
                color = 0xEF4444 if any(f.severity.value in ("CRITICAL", "HIGH") for f in diff.new_findings) else 0xF59E0B
                fields = []
                if diff.new_findings:
                    findings_text = "\n".join(
                        f"• **[{f.severity.value}]** `{f.id}` — {f.title}" for f in diff.new_findings[:5]
                    )
                    fields.append({"name": "🚨 New Findings", "value": findings_text[:1024], "inline": False})
                if diff.score_dropped:
                    fields.append({"name": "📉 Score Drop", "value": f"`{diff.score_before}` → `{diff.score_now}`", "inline": True})

                payload = {
                    "username": "ArmorScan Sentinel",
                    "embeds": [
                        {
                            "title": "🚨 ArmorScan Sentinel Alert: Security Regression Detected",
                            "description": f"**Target:** `{self.target_url}`\n**Status:** {diff.alert_summary}",
                            "color": color,
                            "fields": fields,
                            "footer": {"text": "ArmorScan v0.6.0 Autonomous Sentinel"},
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                    ],
                }
                resp = await client.post(self.discord_webhook, json=payload)
                if resp.status_code in (200, 204):
                    dispatched.append("discord")

            # 2. Slack Webhook
            if self.slack_webhook:
                blocks = [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": "🚨 ArmorScan Sentinel Security Alert", "emoji": True},
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Target:* `{self.target_url}`\n*Alert:* {diff.alert_summary}\n*Score:* `{diff.score_before}` → *`{diff.score_now}`*",
                        },
                    },
                ]
                if diff.new_findings:
                    bullets = "\n".join(f"• *[{f.severity.value}]* `{f.id}`: {f.title}" for f in diff.new_findings[:5])
                    blocks.append({
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*New Findings ({len(diff.new_findings)}):*\n{bullets}"},
                    })

                resp = await client.post(self.slack_webhook, json={"blocks": blocks})
                if resp.status_code == 200:
                    dispatched.append("slack")

            # 3. Telegram Bot
            if self.telegram_token and self.telegram_chat_id:
                tg_url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
                text = (
                    f"🚨 *ArmorScan Sentinel Alert*\n\n"
                    f"🎯 *Target:* `{self.target_url}`\n"
                    f"⚠️ *Status:* {diff.alert_summary}\n"
                    f"📊 *Score:* `{diff.score_before}` → *`{diff.score_now}`*\n"
                )
                if diff.new_findings:
                    text += "\n*New Vulnerabilities:*\n"
                    for f in diff.new_findings[:5]:
                        text += f"• \\[{f.severity.value}\\] `{f.id}`\n"

                resp = await client.post(tg_url, json={"chat_id": self.telegram_chat_id, "text": text, "parse_mode": "Markdown"})
                if resp.status_code == 200:
                    dispatched.append("telegram")

        finally:
            if close_client:
                await client.aclose()

        return dispatched
