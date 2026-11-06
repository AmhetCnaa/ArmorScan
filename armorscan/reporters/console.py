"""
Rich Terminal Console Reporter for ArmorScan.
Renders ASCII banners, live progress indicators, structured vulnerability tables,
scorecards with letter grades, and actionable remediation snippets.
"""

from __future__ import annotations

import sys
from typing import Optional

from rich.box import ROUNDED, SIMPLE
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from armorscan import __version__
from armorscan.core.models import Grade, ScanResult, Severity

BANNER_ART = r"""[bold cyan]
    _                           ____                  
   / \   _ __ _ __ ___   ___  _ / ___|  ___ __ _ _ __  
  / _ \ | '__| '_ ` _ \ / _ \| '__\___ \ / __/ _` | '_ \ 
 / ___ \| |  | | | | | | (_) | |   ___) | (_| (_| | | | |
/_/   \_\_|  |_| |_| |_|\___/|_|  |____/ \___\__,_|_| |_|[/bold cyan]
[dim cyan]>> Modern, Fast, Developer-Centric DAST & Web Security Scanner v{version} <<[/dim cyan]
""".format(version=__version__)


class ConsoleReporter:
    """Handles all terminal formatting, tables, scorecards, and live output using Rich."""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def print_banner(self, target_url: str) -> None:
        """Render the startup banner and target information."""
        self.console.print(BANNER_ART)
        target_panel = Panel(
            Text.assemble(
                ("🎯 Target URL:   ", "bold white"),
                (f"{target_url}\n", "bold cyan underline"),
                ("🛡️ Engine:       ", "bold white"),
                ("ArmorScan Async HTTP/2 Engine (Non-Destructive DAST)\n", "green"),
                ("⚡ Architecture: ", "bold white"),
                ("Headers, TLS, Cookies, Exposures, CORS, Rate-Limiting", "dim white"),
            ),
            title="[bold green]Active Security Audit[/bold green]",
            border_style="cyan",
            box=ROUNDED,
        )
        self.console.print(target_panel)
        self.console.print()

    def render_scan_results(self, result: ScanResult) -> None:
        """Render complete findings, summary metrics, scorecard, and remediation recommendations."""
        self.console.print()

        # 1. Findings Table
        findings = result.all_findings
        if findings:
            table = Table(
                title=f"🚨 Detected Security Findings ({len(findings)})",
                box=ROUNDED,
                header_style="bold white on #1a1b1f",
                border_style="dim",
                expand=True,
            )

            table.add_column("Severity", style="bold", width=12, justify="center")
            table.add_column("Code ID", style="cyan", width=26)
            table.add_column("Finding & Security Impact", style="white", ratio=2)
            table.add_column("CWE / OWASP", style="dim cyan", width=22)

            for f in findings:
                # Severity Badge
                sev_color = f.severity.color
                sev_badge = f"[{sev_color}][ {f.severity.value} ][/{sev_color}]"
                conf_badge = f"[{f.confidence.color}][{f.confidence.value.upper()}][/{f.confidence.color}]"
                status_cell = f"{sev_badge}\n{conf_badge}"
                if f.is_suppressed:
                    status_cell += "\n[dim magenta][SUPPRESSED][/dim magenta]"

                # Description & Impact
                desc_text = f"[bold white]{f.title}[/bold white]\n[dim]{f.description}[/dim]"
                if f.evidence:
                    clean_evidence = f.evidence.strip().replace("\n", " ")
                    if len(clean_evidence) > 90:
                        clean_evidence = clean_evidence[:87] + "..."
                    desc_text += f"\n[dim yellow]⚡ Evidence: {clean_evidence}[/dim yellow]"

                if f.affected_urls and len(f.affected_urls) > 1:
                    desc_text += f"\n[cyan]🔗 Affects {len(f.affected_urls)} endpoints[/cyan]"

                if f.curl_command:
                    curl_preview = f.curl_command.splitlines()[0]
                    if len(curl_preview) > 85:
                        curl_preview = curl_preview[:82] + "..."
                    desc_text += f"\n[dim cyan]💻 Reproduce: {curl_preview}[/dim cyan]"

                if f.is_suppressed:
                    desc_text += f"\n[dim magenta]🛡️ Suppressed: {f.suppression_reason}[/dim magenta]"

                # Standard tags
                standards = []
                if f.cwe_id:
                    standards.append(f.cwe_id)
                if f.owasp_category:
                    cat_short = f.owasp_category.split("-")[0] if "-" in f.owasp_category else f.owasp_category
                    standards.append(cat_short)
                standards_str = "\n".join(standards) if standards else "-"

                table.add_row(status_cell, f.id, desc_text, standards_str)

            self.console.print(table)
            self.console.print()
        else:
            clean_panel = Panel(
                "[bold green]✨ Excellent! Zero security findings detected. All audit modules passed.[/bold green]",
                border_style="green",
                box=ROUNDED,
            )
            self.console.print(clean_panel)
            self.console.print()

        # 2. Scorecard & Summary
        self._render_scorecard(result)

        # 3. Top Actionable Remediations
        self._render_top_remediations(result)

    def _render_scorecard(self, result: ScanResult) -> None:
        """Render the visual score gauge, grade badge, and summary metrics."""
        summary = result.summary
        grade = summary.grade

        grade_text = Text()
        grade_text.append(f"\n   GRADE: {grade.value}   \n", style=f"{grade.color}")

        metrics_text = Text()
        metrics_text.append("🛡️ Security Score:  ", style="bold white")
        metrics_text.append(f"{summary.score}/100\n", style=f"{grade.color}")
        metrics_text.append("⏱️ Scan Duration:   ", style="bold white")
        metrics_text.append(f"{result.duration_seconds}s\n", style="cyan")
        metrics_text.append("✅ Passed Checks:   ", style="bold white")
        metrics_text.append(f"{summary.passed_checks}\n", style="green")
        metrics_text.append("📊 Total Audits:    ", style="bold white")
        metrics_text.append(f"{summary.total_checks}\n", style="white")

        findings_breakdown = Text()
        findings_breakdown.append("🔥 Critical: ", style="bold red")
        findings_breakdown.append(f"{summary.critical_count}    ", style="white")
        findings_breakdown.append("🔴 High: ", style="red")
        findings_breakdown.append(f"{summary.high_count}    ", style="white")
        findings_breakdown.append("🟡 Medium: ", style="yellow")
        findings_breakdown.append(f"{summary.medium_count}\n", style="white")
        findings_breakdown.append("🔵 Low: ", style="cyan")
        findings_breakdown.append(f"{summary.low_count}         ", style="white")
        findings_breakdown.append("ℹ️ Info: ", style="blue")
        findings_breakdown.append(f"{summary.info_count}\n", style="white")

        card_table = Table(box=SIMPLE, show_header=False, expand=True)
        card_table.add_column("Grade", justify="center", width=22)
        card_table.add_column("Metrics", ratio=1)
        card_table.add_column("Breakdown", ratio=1)

        card_table.add_row(grade_text, metrics_text, findings_breakdown)

        score_panel = Panel(
            card_table,
            title="[bold white]🛡️ ArmorScan Security Scorecard[/bold white]",
            border_style=grade.color.split()[0] if " " in grade.color else grade.color,
            box=ROUNDED,
        )
        self.console.print(score_panel)
        self.console.print()

    def _render_top_remediations(self, result: ScanResult) -> None:
        """Display quick copy-paste remediation code blocks for the highest severity findings."""
        actionable_findings = [f for f in result.all_findings if f.remediation_snippets]
        if not actionable_findings:
            return

        # Sort by severity priority (Critical -> High -> Medium)
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        actionable_findings.sort(key=lambda f: severity_order.get(f.severity, 5))
        top_remediations = actionable_findings[:3]

        self.console.print("[bold yellow]🛠️ Quick Action Remediation Snippets (Top Fixes):[/bold yellow]")

        for f in top_remediations:
            snippet_texts = []
            for framework, code in f.remediation_snippets.items():
                first_lines = "\n".join(code.strip().splitlines()[:6])
                snippet_texts.append(f"[bold cyan]-- {framework.upper()} --[/bold cyan]\n[dim white]{first_lines}[/dim white]")

            combined_code = "\n\n".join(snippet_texts)
            panel = Panel(
                combined_code,
                title=f"[{f.severity.color}][{f.severity.value}][/{f.severity.color}] [bold white]{f.title}[/bold white]",
                border_style="dim yellow",
                box=ROUNDED,
            )
            self.console.print(panel)

        self.console.print()
