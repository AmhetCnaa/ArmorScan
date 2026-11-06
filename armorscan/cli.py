"""
CLI Entrypoint for ArmorScan.
Coordinates command-line options, crawler discovery, port sniffing,
module execution, console reporting, HTML/JSON report generation,
patch exports, and CI/CD quality gate enforcement.
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
import sys
from typing import List, Optional

from rich.box import ROUNDED, SIMPLE
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from armorscan import __version__
from armorscan.core.client import HttpClient
from armorscan.core.crawler import WebCrawler
from armorscan.core.models import ScanResult, ScanTarget
from armorscan.core.runner import ScanRunner
from armorscan.modules.base import BaseModule
from armorscan.modules.cookies import CookieHygieneModule
from armorscan.modules.cors import CorsAndMethodModule
from armorscan.modules.error_leak import ErrorLeakModule
from armorscan.modules.exposure import ExposureAuditModule
from armorscan.modules.headers import SecurityHeadersModule
from armorscan.modules.jwt_audit import JwtAuditModule
from armorscan.modules.ports import LocalPortSniffer
from armorscan.modules.ratelimit import RateLimitModule
from armorscan.modules.redirect import OpenRedirectModule
from armorscan.modules.reflection import InputReflectionModule
from armorscan.modules.secret_leak import SecretLeakModule
from armorscan.modules.tls_ssl import TlsSslModule
from armorscan.remediations.patch_exporter import PatchExporter
from armorscan.reporters.console import ConsoleReporter
from armorscan.reporters.html import HtmlReporter
from armorscan.reporters.json_rep import JsonReporter


def get_default_modules(burst_count: int = 18) -> List[BaseModule]:
    """Instantiate standard suite of all 11 security auditing modules."""
    return [
        SecurityHeadersModule(),
        TlsSslModule(),
        CookieHygieneModule(),
        ExposureAuditModule(),
        CorsAndMethodModule(),
        RateLimitModule(burst_count=burst_count),
        InputReflectionModule(),
        OpenRedirectModule(),
        ErrorLeakModule(),
        JwtAuditModule(),
        SecretLeakModule(),
    ]


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="armorscan",
        description="🛡️ ArmorScan: Modern, fast, developer-friendly DAST & web security scanner.",
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Target URL or command (e.g., https://example.com, 'discover', or 'benchmark')",
    )
    parser.add_argument(
        "host_or_target",
        nargs="?",
        help="Host for 'discover' command or secondary target URL",
    )
    parser.add_argument(
        "--fail-under",
        type=int,
        default=None,
        metavar="SCORE",
        help="CI/CD Quality Gate: Fail with exit code 1 if security score is below this threshold (0-100).",
    )
    parser.add_argument(
        "--crawl",
        action="store_true",
        help="Enable automated internal link spider/crawler before running security audits.",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=2,
        help="Spider maximum link depth when crawling (default: 2).",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=15,
        help="Spider maximum page limit when crawling (default: 15).",
    )
    parser.add_argument(
        "--export-patch",
        choices=["nginx", "express", "fastapi"],
        default=None,
        metavar="FRAMEWORK",
        help="Export ready-to-use security hardening patch file (nginx, express, or fastapi).",
    )
    parser.add_argument(
        "--html",
        nargs="?",
        const="armorscan-report.html",
        default="armorscan-report.html",
        metavar="PATH",
        help="Output path for interactive standalone HTML report (default: armorscan-report.html).",
    )
    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Disable HTML report generation.",
    )
    parser.add_argument(
        "--json",
        nargs="?",
        const="armorscan-report.json",
        default=None,
        metavar="PATH",
        help="Output path for machine-readable JSON report.",
    )
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="Disable SSL/TLS certificate verification (useful for self-signed or localhost development certs).",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Number of concurrent modules to execute (default: 5).",
    )
    parser.add_argument(
        "--burst",
        type=int,
        default=18,
        help="Number of concurrent burst requests for rate limiting test (default: 18).",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Quiet mode: suppress ASCII banner and live progress; only print summary and errors.",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"ArmorScan {__version__}",
    )

    return parser


async def run_discover_async(host: str, console: Console) -> int:
    """Execute local port and database discovery scan."""
    console.print(
        Panel(
            f"🔍 [bold white]Local Port & Database Sniffer[/bold white] targeting: [bold cyan]{host}[/bold cyan]\n"
            f"[dim]Checking dev web servers (3000, 5173, 8000, 8080) and unauthenticated databases (Redis, Mongo, Postgres, MySQL)[/dim]",
            border_style="cyan",
            box=ROUNDED,
        )
    )

    sniffer = LocalPortSniffer()
    with console.status("[bold cyan]Probing local ports and services...", spinner="dots"):
        result = await sniffer.scan_host(host)

    table = Table(
        title=f"🔌 Port Discovery Report for {host} ({len(result.open_ports)} Open Ports Found)",
        box=ROUNDED,
        header_style="bold white on #1a1b1f",
        expand=True,
    )
    table.add_column("Port", justify="center", style="bold cyan", width=10)
    table.add_column("Service Name", style="white", width=28)
    table.add_column("Category", style="dim", width=14)
    table.add_column("Security Status & Advice", style="white", ratio=1)

    for item in result.open_ports:
        status_text = "[bold green]Active (Local Dev)[/bold green]"
        if item.finding:
            sev_color = item.finding.severity.color
            status_text = f"[{sev_color}][ {item.finding.severity.value} ][/{sev_color}] {item.finding.title}"

        table.add_row(str(item.port), item.service_name, item.category.upper(), status_text)

    console.print(table)
    console.print()

    if result.findings:
        crit_count = sum(1 for f in result.findings if f.severity.value in ("CRITICAL", "HIGH"))
        if crit_count > 0:
            console.print(
                f"[bold red]⚠️ Warning:[/bold red] Found {crit_count} potentially dangerous database/service exposures on {host}! "
                f"Ensure database ports are bound strictly to 127.0.0.1 and protected by strong passwords."
            )
            return 1

    return 0


async def run_scan_async(args: argparse.Namespace, console: Console) -> int:
    """Asynchronous controller for the scan workflow."""
    # 1. Handle Patch Export
    if args.export_patch:
        out_file = PatchExporter.export(args.export_patch)
        console.print(
            f"✅ [bold green]Hardened {args.export_patch.capitalize()} security patch exported to:[/bold green] [bold cyan]{out_file}[/bold cyan]"
        )
        return 0

    # 2. Handle 'discover' command
    raw_target = args.target
    if raw_target and raw_target.lower() == "discover":
        host = args.host_or_target or "127.0.0.1"
        return await run_discover_async(host, console)

    # 3. Handle 'benchmark' command
    if raw_target and raw_target.lower() == "benchmark":
        from scripts.run_benchmark import main_async as run_benchmark_async
        benchmark_args = argparse.Namespace(
            url=args.host_or_target or "http://127.0.0.1:8888",
            ground_truth="benchmark/ground_truth.yaml",
            output="benchmark/results.md",
            min_precision=0.95,
            min_recall=0.95,
        )
        return await run_benchmark_async(benchmark_args)

    # 4. Handle 'scan' sub-syntax: 'armorscan scan https://...'
    if raw_target and raw_target.lower() == "scan":
        raw_target = args.host_or_target

    if not raw_target:
        console.print("[bold red]Error:[/bold red] Missing target URL. Usage: [cyan]armorscan https://example.com[/cyan], [cyan]armorscan discover[/cyan], or [cyan]armorscan benchmark[/cyan]")
        return 2

    try:
        target = ScanTarget.from_url(raw_target)
    except Exception as e:
        console.print(f"[bold red]Invalid target URL:[/bold red] {e}")
        return 2

    reporter = ConsoleReporter(console=console)
    if not args.quiet:
        reporter.print_banner(target.raw_url)

    verify_ssl = False if args.insecure else (not target.is_localhost)

    # 4. Optional Web Crawling
    if args.crawl:
        if not args.quiet:
            console.print(f"🕷️ [bold cyan]Crawling endpoints (depth={args.depth}, max_pages={args.max_pages})...[/bold cyan]")
        async with HttpClient.for_target(target, verify_ssl=verify_ssl) as client:
            crawler = WebCrawler(max_depth=args.depth, max_pages=args.max_pages)
            crawl_res = await crawler.crawl(target, client)
            if not args.quiet:
                console.print(
                    f"   Discovered [bold green]{len(crawl_res.discovered_paths)}[/bold green] paths across "
                    f"[bold green]{crawl_res.pages_crawled}[/bold green] crawled pages. "
                    f"Found {len(crawl_res.forms)} HTML forms."
                )
                console.print(f"   [dim]Sample routes: {', '.join(crawl_res.discovered_paths[:6])}[/dim]\n")

    # 5. Execute Security Audits
    modules = get_default_modules(burst_count=args.burst)
    runner = ScanRunner(modules=modules, verify_ssl=verify_ssl, concurrency=args.concurrency)

    if not args.quiet:
        with Progress(
            SpinnerColumn("dots", style="bold cyan"),
            TextColumn("[bold white]{task.description}"),
            BarColumn(bar_width=30, style="dim", complete_style="bold green"),
            TextColumn("[dim cyan]{task.completed}/{task.total} modules"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            scan_task = progress.add_task("Auditing security controls...", total=len(modules))

            def on_start(mod: BaseModule):
                progress.update(scan_task, description=f"Auditing [cyan]{mod.display_name}[/cyan]...")

            def on_complete(mod: BaseModule, res):
                progress.advance(scan_task, 1)

            scan_result = await runner.scan(
                target,
                on_module_start=on_start,
                on_module_complete=on_complete,
            )
    else:
        scan_result = await runner.scan(target)

    # 6. Render Console Output
    if not args.quiet:
        reporter.render_scan_results(scan_result)

    # 7. Generate Reports
    if not args.no_html and args.html:
        html_path = HtmlReporter.save(scan_result, args.html)
        if not args.quiet:
            console.print(f"📄 [bold green]Interactive HTML Report generated:[/bold green] [cyan]{html_path}[/cyan]")

    if args.json:
        json_path = JsonReporter.save(scan_result, args.json)
        if not args.quiet:
            console.print(f"📊 [bold green]JSON Report saved:[/bold green] [cyan]{json_path}[/cyan]")

    # 8. CI/CD Quality Gate
    if args.fail_under is not None:
        score = scan_result.summary.score
        if score < args.fail_under:
            if not args.quiet:
                console.print(
                    f"\n[bold red]❌ CI/CD Quality Gate Failed![/bold red] "
                    f"Score [bold yellow]{score}[/bold yellow] is below threshold [bold cyan]{args.fail_under}[/bold cyan]."
                )
            return 1
        else:
            if not args.quiet:
                console.print(
                    f"\n[bold green]✅ CI/CD Quality Gate Passed![/bold green] "
                    f"Score [bold green]{score}[/bold green] >= threshold [bold cyan]{args.fail_under}[/bold cyan]."
                )

    return 0


def main(argv: Optional[List[str]] = None) -> None:
    """CLI execution entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.target and not args.export_patch:
        parser.print_help()
        sys.exit(0)

    console = Console()
    try:
        exit_code = asyncio.run(run_scan_async(args, console))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ Scan aborted by user.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[bold red]Fatal error:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
