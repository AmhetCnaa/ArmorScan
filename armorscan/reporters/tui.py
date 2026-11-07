"""
Interactive Terminal UI (TUI) & Live Security Dashboard for ArmorScan (reporters/tui.py).
Provides a split-screen interactive terminal dashboard using rich.layout and rich.live:
- Left pane: Color-coded navigable list of detected vulnerabilities (Critical -> Low).
- Right pane: Selected finding details, evidence, cURL command, and Nginx/Express/FastAPI remediation snippets.
- Keyboard controls: Up/Down/j/k to navigate, Enter/o to open target URL in default browser, q/ESC to quit.
"""

from __future__ import annotations

import sys
import webbrowser
from typing import List, Optional

from rich.box import ROUNDED
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from armorscan.core.models import Finding, ScanResult, Severity


class TuiDashboard:
    """Interactive split-screen terminal security dashboard."""

    def __init__(self, result: ScanResult, console: Optional[Console] = None):
        self.result = result
        self.console = console or Console()
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        self.findings: List[Finding] = sorted(
            [f for f in result.all_findings if not f.is_suppressed],
            key=lambda x: severity_order.get(x.severity, 5),
        )
        self.selected_index: int = 0
        self.status_message: str = "Use [↑/↓ or j/k] to navigate | [Enter/o] Open URL in browser | [q] Quit"

    def build_layout(self) -> Layout:
        layout = Layout(name="root")
        layout.split_column(
            Layout(name="header", size=4),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3),
        )
        layout["main"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=3),
        )

        layout["header"].update(self._render_header())
        layout["left"].update(self._render_findings_list())
        layout["right"].update(self._render_finding_details())
        layout["footer"].update(self._render_footer())
        return layout

    def _render_header(self) -> Panel:
        s = self.result.summary
        grade_color = s.grade.color
        header_text = Text.from_markup(
            f"🛡️ [bold cyan]ArmorScan v0.5.0 Interactive Security TUI[/bold cyan]   "
            f"Target: [bold white]{self.result.target.raw_url}[/bold white]   "
            f"Score: [bold white]{s.score}/100[/bold white]   "
            f"Grade: [{grade_color}] {s.grade.value} [/{grade_color}]   "
            f"Findings: [bold red]C:{s.critical_count}[/bold red] [red]H:{s.high_count}[/red] "
            f"[yellow]M:{s.medium_count}[/yellow] [cyan]L:{s.low_count}[/cyan]"
        )
        return Panel(header_text, box=ROUNDED, border_style="cyan")

    def _render_findings_list(self) -> Panel:
        table = Table(expand=True, box=None, show_header=True, header_style="bold white")
        table.add_column(" ", width=2)
        table.add_column("Severity", width=10)
        table.add_column("Finding ID", ratio=1)
        table.add_column("Conf.", width=9)

        if not self.findings:
            table.add_row("", "[green]PASS[/green]", "No vulnerabilities detected!", "-")
        else:
            for idx, f in enumerate(self.findings):
                is_sel = idx == self.selected_index
                pointer = "❯" if is_sel else " "
                row_style = "bold white on #1e293b" if is_sel else ""
                sev_badge = f"[{f.severity.color}]{f.severity.value}[/{f.severity.color}]"
                conf_badge = f"[{f.confidence.color}]{f.confidence.value}[/{f.confidence.color}]"
                table.add_row(pointer, sev_badge, f.id, conf_badge, style=row_style)

        return Panel(
            table,
            title=f"📋 Detected Vulnerabilities ({len(self.findings)})",
            border_style="cyan",
            box=ROUNDED,
        )

    def _render_finding_details(self) -> Panel:
        if not self.findings:
            return Panel(
                "[bold green]✅ Target passed all active security checks with zero findings![/bold green]",
                title="🔍 Finding Details",
                border_style="green",
                box=ROUNDED,
            )

        f = self.findings[self.selected_index]
        target_url = f.affected_urls[0] if f.affected_urls else self.result.target.raw_url

        parts = [
            Text.from_markup(f"[bold white]{f.title}[/bold white]"),
            Text.from_markup(
                f"[dim]Module:[/dim] [cyan]{f.module}[/cyan] | "
                f"[dim]CWE:[/dim] [yellow]{f.cwe_id or 'N/A'}[/yellow] | "
                f"[dim]OWASP:[/dim] [magenta]{f.owasp_category or 'N/A'}[/magenta]\n"
                f"[dim]Target URL:[/dim] [underline cyan]{target_url}[/underline cyan]\n"
            ),
            Text.from_markup(f"[bold yellow]Description & Impact:[/bold yellow]\n{f.description}\n[dim]{f.impact}[/dim]\n"),
        ]

        if f.evidence:
            parts.append(Text.from_markup(f"[bold cyan]Evidence:[/bold cyan]\n{f.evidence}\n"))

        if f.curl_command:
            parts.append(Text.from_markup("[bold green]Reproduction cURL:[/bold green]"))
            parts.append(Syntax(f.curl_command, "bash", theme="monokai", word_wrap=True))

        if f.remediation:
            parts.append(Text.from_markup(f"\n[bold green]Remediation Guidance:[/bold green]\n{f.remediation}"))

        if f.remediation_snippets:
            for fw, code in list(f.remediation_snippets.items())[:2]:
                lexer = "python" if fw == "fastapi" else ("javascript" if fw == "express" else "nginx")
                parts.append(Text.from_markup(f"\n[bold magenta]Fix Patch ({fw.upper()}):[/bold magenta]"))
                parts.append(Syntax(code, lexer, theme="monokai", word_wrap=True))

        return Panel(
            Group(*parts),
            title=f"🔍 [{f.severity.color}]{f.severity.value}[/{f.severity.color}] {f.id}",
            border_style="bright_blue",
            box=ROUNDED,
        )

    def _render_footer(self) -> Panel:
        return Panel(
            Text.from_markup(f"⌨️  {self.status_message}"),
            border_style="dim cyan",
            box=ROUNDED,
        )

    def move_selection(self, delta: int) -> None:
        if not self.findings:
            return
        self.selected_index = (self.selected_index + delta) % len(self.findings)

    def open_selected_url(self) -> str:
        if not self.findings:
            url = self.result.target.raw_url
        else:
            f = self.findings[self.selected_index]
            url = f.affected_urls[0] if f.affected_urls else self.result.target.raw_url
        try:
            webbrowser.open(url)
            self.status_message = f"🌐 Opened in browser: [bold cyan]{url}[/bold cyan] | [q] Quit"
        except Exception as e:
            self.status_message = f"⚠️ Could not launch browser: {e}"
        return url

    def run(self) -> None:
        """Run interactive keyboard loop if stdin is a TTY, otherwise render snapshot."""
        if not sys.stdin.isatty():
            self.console.print(self.build_layout())
            return

        import termios
        import tty

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            with Live(self.build_layout(), console=self.console, screen=True, auto_refresh=False) as live:
                while True:
                    ch = sys.stdin.read(1)
                    if ch in ("q", "Q", "\x03"):  # q or Ctrl+C
                        break
                    elif ch in ("j", "J"):
                        self.move_selection(1)
                    elif ch in ("k", "K"):
                        self.move_selection(-1)
                    elif ch in ("\r", "\n", "o", "O"):
                        self.open_selected_url()
                    elif ch == "\x1b":
                        seq = sys.stdin.read(2)
                        if seq == "[B":  # Down arrow
                            self.move_selection(1)
                        elif seq == "[A":  # Up arrow
                            self.move_selection(-1)
                        else:
                            break
                    live.update(self.build_layout(), refresh=True)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
