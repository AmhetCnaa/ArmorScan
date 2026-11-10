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
from armorscan.core.auth import AuthConfig
from armorscan.core.client import HttpClient
from armorscan.core.crawler import WebCrawler
from armorscan.core.models import ScanResult, ScanTarget
from armorscan.core.runner import ScanRunner
from armorscan.core.scoring import ScoringEngine
from armorscan.core.suppression import SuppressionEngine
from armorscan.core.templates import TemplateEngine
from armorscan.modules.async_ssrf import AsyncSsrfModule
from armorscan.modules.authz_check import AuthzCheckModule
from armorscan.modules.base import BaseModule
from armorscan.modules.browser_dom import BrowserDomModule
from armorscan.modules.concurrency import ConcurrencyAuditModule
from armorscan.modules.cookies import CookieHygieneModule
from armorscan.modules.cors import CorsAndMethodModule
from armorscan.modules.error_leak import ErrorLeakModule
from armorscan.modules.exposure import ExposureAuditModule
from armorscan.modules.graphql import GraphqlAuditModule
from armorscan.modules.headers import SecurityHeadersModule
from armorscan.modules.jwt_audit import JwtAuditModule
from armorscan.modules.multi_step import MultiStepLogicModule
from armorscan.modules.nosqli import NoSqliIndicationModule
from armorscan.modules.ports import LocalPortSniffer
from armorscan.modules.protocols import ProtocolsResilienceModule
from armorscan.modules.ratelimit import RateLimitModule
from armorscan.modules.redirect import OpenRedirectModule
from armorscan.modules.reflection import InputReflectionModule
from armorscan.modules.secret_leak import SecretLeakModule
from armorscan.modules.sqli import SqliIndicationModule
from armorscan.modules.ssrf_check import SsrfCheckModule
from armorscan.modules.tls_ssl import TlsSslModule
from armorscan.modules.traversal import PathTraversalModule
from armorscan.remediations.patch_exporter import PatchExporter
from armorscan.reporters.console import ConsoleReporter
from armorscan.reporters.html import HtmlReporter
from armorscan.reporters.json_rep import JsonReporter
from armorscan.reporters.sarif import SarifReporter
from armorscan.reporters.tui import TuiDashboard


def get_default_modules(
    burst_count: int = 18,
    include_browser: bool = False,
    template_paths: Optional[List[str]] = None,
    include_fuzz: bool = False,
    matrix_roles: Optional[str] = None,
    include_v1: bool = True,
) -> List[BaseModule]:
    """Instantiate standard suite of security auditing modules (22 core modules, plus optional browser, fuzz, and matrix modules)."""
    mods: List[BaseModule] = [
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
        AuthzCheckModule(),
        MultiStepLogicModule(),
        SqliIndicationModule(),
        NoSqliIndicationModule(),
        PathTraversalModule(),
        SsrfCheckModule(),
        GraphqlAuditModule(),
        TemplateEngine(template_paths=template_paths),
    ]
    if include_v1:
        mods.extend([
            AsyncSsrfModule(),
            ConcurrencyAuditModule(),
            ProtocolsResilienceModule(),
        ])
    if include_browser:
        mods.append(BrowserDomModule())
    if include_fuzz:
        from armorscan.modules.fuzzer import ApiFuzzerModule
        mods.append(ApiFuzzerModule())
    if matrix_roles:
        from armorscan.modules.auth_matrix import AuthMatrixModule, parse_matrix_roles
        mods.append(AuthMatrixModule(roles=parse_matrix_roles(matrix_roles)))
    return mods


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
        "--ignore-file",
        default=None,
        metavar="PATH",
        help="Path to .armorscanignore file for suppressing accepted security findings.",
    )
    parser.add_argument(
        "--schema",
        default=None,
        metavar="PATH_OR_URL",
        help="OpenAPI/Swagger schema file or remote URL to ingest for schema-driven endpoint discovery.",
    )
    parser.add_argument(
        "--auth-header",
        action="append",
        metavar="HEADER",
        help="Authentication header, e.g. 'Authorization: Bearer <token>'. Can be repeated.",
    )
    parser.add_argument(
        "--auth-cookie",
        action="append",
        metavar="COOKIE",
        help="Authentication session cookie, e.g. 'session=xyz'. Can be repeated.",
    )
    parser.add_argument(
        "--auth-custom-header",
        action="append",
        metavar="HEADER",
        help="Custom authentication header, e.g. 'X-API-Key: key123'. Can be repeated.",
    )
    parser.add_argument(
        "--auth-check-url",
        default=None,
        metavar="PATH",
        help="Session health check URL to verify active login state (e.g. /api/me).",
    )
    parser.add_argument(
        "--auth-check-status",
        type=int,
        default=200,
        metavar="STATUS",
        help="Expected HTTP status for valid session check (default: 200).",
    )
    parser.add_argument(
        "--auth-check-body",
        default=None,
        metavar="STRING",
        help="Expected substring in session health check response body.",
    )
    parser.add_argument(
        "--login-url",
        default=None,
        metavar="URL",
        help="Automated login macro endpoint URL (e.g. /api/login).",
    )
    parser.add_argument(
        "--login-body",
        default=None,
        metavar="DATA",
        help="Request payload for login macro (JSON or form string).",
    )
    parser.add_argument(
        "--login-token-path",
        default=None,
        metavar="PATH",
        help="JSON dot-notation path to extract token from login response (e.g. 'data.token').",
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
        "--browser",
        action="store_true",
        help="Enable headless Chromium browser-based DOM sink taint tracing (detects DOM XSS flows into innerHTML/document.write).",
    )
    parser.add_argument(
        "--templates",
        action="append",
        default=None,
        metavar="PATH",
        help="Path to custom YAML security templates directory or file (can be specified multiple times).",
    )
    parser.add_argument(
        "--sarif",
        nargs="?",
        const="armorscan-results.sarif",
        default=None,
        metavar="PATH",
        help="Output path for OASIS SARIF 2.1.0 report (for GitHub Code Scanning / Security tab).",
    )
    parser.add_argument(
        "--tui",
        action="store_true",
        help="Launch interactive split-screen Terminal UI (TUI) dashboard after scan completion.",
    )
    parser.add_argument(
        "--ai-explain",
        action="store_true",
        help="Generate AI/rule-based executive narrative and business impact analysis for findings.",
    )
    parser.add_argument(
        "--ai-patch",
        action="store_true",
        help="Generate ready-to-apply unified git diff patches for detected vulnerabilities.",
    )
    parser.add_argument(
        "--repo-path",
        default=None,
        metavar="PATH",
        help="Path to source code repository (used for contextual git patch synthesis).",
    )
    parser.add_argument(
        "--interval",
        default="1h",
        metavar="TIME",
        help="Monitoring interval for 'armorscan watch' mode (e.g. 30s, 15m, 1h, 24h; default: 1h).",
    )
    parser.add_argument(
        "--webhook",
        "--discord-webhook",
        dest="webhook",
        default=None,
        metavar="URL",
        help="Discord webhook URL for sentinel alert dispatch.",
    )
    parser.add_argument(
        "--slack-webhook",
        default=None,
        metavar="URL",
        help="Slack incoming webhook URL for sentinel alert dispatch.",
    )
    parser.add_argument(
        "--telegram-token",
        default=None,
        metavar="TOKEN",
        help="Telegram bot authentication token for sentinel alert dispatch.",
    )
    parser.add_argument(
        "--telegram-chat",
        default=None,
        metavar="CHAT_ID",
        help="Telegram target chat/channel ID for sentinel alert dispatch.",
    )
    parser.add_argument(
        "--baseline",
        default="armorscan-baseline.json",
        metavar="PATH",
        help="Path to baseline findings JSON file (default: armorscan-baseline.json).",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run sentinel checks once without sleeping (for cron / testing).",
    )
    parser.add_argument(
        "--matrix-roles",
        default=None,
        metavar="ROLES",
        help="Multi-Role BOLA/IDOR Permission Matrix (e.g. 'admin:Bearer <T1>,user:Bearer <T2>,guest:')",
    )
    parser.add_argument(
        "--fuzz",
        action="store_true",
        help="Enable non-destructive API boundary fuzzing to detect unhandled HTTP 500 exceptions and CPU lag.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        metavar="PORT",
        help="Port for 'armorscan proxy' mode (default: 8080).",
    )
    parser.add_argument(
        "--auto-audit",
        action="store_true",
        default=True,
        help="Enable live passive security auditing in proxy mode (default: True).",
    )
    parser.add_argument(
        "--no-auto-audit",
        dest="auto_audit",
        action="store_false",
        help="Disable live passive security auditing in proxy mode.",
    )
    parser.add_argument(
        "--auto-pr",
        action="store_true",
        help="Automatically open a remediation Pull Request on GitHub for detected vulnerabilities.",
    )
    parser.add_argument(
        "--github-repo",
        default=None,
        metavar="OWNER/REPO",
        help="Target GitHub repository (e.g. 'owner/repo') for automated Pull Request generation.",
    )
    parser.add_argument(
        "--github-token",
        default=None,
        metavar="TOKEN",
        help="GitHub personal access token for opening remediation Pull Requests.",
    )
    parser.add_argument(
        "--source-dir",
        default=None,
        metavar="DIR",
        help="Path to source code directory for static AST route mapping & shadow API discovery.",
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


async def run_sentinel_watch_async(target_url: str, args: argparse.Namespace, console: Console) -> int:
    """Execute continuous autonomous monitoring daemon against target."""
    from datetime import datetime, timezone
    from armorscan.core.sentinel import SentinelEngine, parse_interval_seconds

    try:
        interval_sec = parse_interval_seconds(getattr(args, "interval", "1h") or "1h")
    except ValueError as e:
        console.print(f"[bold red]Configuration Error:[/bold red] {e}")
        return 2

    baseline_path = Path(getattr(args, "baseline", "armorscan-baseline.json") or "armorscan-baseline.json")

    discord_wh = getattr(args, "webhook", None)
    slack_wh = getattr(args, "slack_webhook", None)
    tg_token = getattr(args, "telegram_token", None)
    tg_chat = getattr(args, "telegram_chat", None)

    sentinel = SentinelEngine(
        target_url=target_url,
        baseline_file=baseline_path,
        discord_webhook=discord_wh,
        slack_webhook=slack_wh,
        telegram_token=tg_token,
        telegram_chat_id=tg_chat,
    )

    console.print(
        Panel(
            f"🛡️ [bold white]ArmorScan Autonomous Sentinel Active[/bold white]\n"
            f"Target: [bold cyan]{target_url}[/bold cyan]  •  Interval: [bold yellow]{interval_sec}s[/bold yellow]  •  Baseline: [dim]{baseline_path}[/dim]\n"
            f"Alert Channels: Discord={'Yes' if discord_wh else 'No'}, Slack={'Yes' if slack_wh else 'No'}, Telegram={'Yes' if tg_token else 'No'}",
            border_style="cyan",
            box=ROUNDED,
        )
    )

    target = ScanTarget.from_url(target_url)
    verify_ssl = False if args.insecure else (not target.is_localhost)

    from armorscan.core.ownership import OwnershipGate
    async with HttpClient.for_target(target, verify_ssl=verify_ssl) as gate_client:
        ownership = await OwnershipGate.verify_target_access(
            target,
            gate_client,
            master_key=getattr(args, "master_key", None),
        )
    if not ownership.authorized:
        console.print(f"[bold red]Authorization Denied:[/bold red] {ownership.message}")
        return 3

    modules = get_default_modules(template_paths=getattr(args, "templates", None))
    runner = ScanRunner(modules=modules, verify_ssl=verify_ssl)

    cycle = 0
    while True:
        cycle += 1
        now_str = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
        console.print(f"[{now_str}] 🔍 [cyan]Sentinel Check #{cycle}:[/cyan] Auditing {target_url}...")

        scan_result = await runner.scan(target)
        diff, baseline = sentinel.evaluate_scan(scan_result)

        if diff.has_alert:
            console.print(f"[{now_str}] 🚨 [bold red]Sentinel Alert:[/bold red] {diff.alert_summary}")
            dispatched = await sentinel.dispatch_notifications(diff)
            if dispatched:
                console.print(f"[{now_str}] 📢 [bold green]Alert notification dispatched to:[/bold green] {', '.join(dispatched)}")
        else:
            console.print(f"[{now_str}] ✅ [bold green]Clean:[/bold green] Score {diff.score_now}/100. No regressions detected.")

        if getattr(args, "once", False):
            break

        await asyncio.sleep(interval_sec)

    return 0


async def run_proxy_async(args: argparse.Namespace, console: Console) -> int:
    """Execute lightweight HTTP forward proxy & live traffic auditor."""
    from armorscan.core.proxy import HttpProxy

    port = getattr(args, "port", 8080)
    host = getattr(args, "host_or_target", None) or "127.0.0.1"
    if host.startswith("http"):
        host = "127.0.0.1"
    auto_audit = getattr(args, "auto_audit", True)

    proxy = HttpProxy(host=host, port=port, auto_audit=auto_audit, console=console)
    server = await proxy.start()

    console.print(
        Panel(
            f"🛡️ [bold white]ArmorScan Live HTTP Forward Proxy Active[/bold white]\n"
            f"Listening: [bold cyan]http://{host}:{port}[/bold cyan]  •  Passive Auto-Audit: [bold green]{'Enabled' if auto_audit else 'Disabled'}[/bold green]\n"
            f"[dim]Configure browser proxy to: http://{host}:{port}[/dim]\n"
            f"[dim]Press Ctrl+C to terminate proxy and display captured session statistics.[/dim]",
            border_style="cyan",
            box=ROUNDED,
        )
    )

    try:
        while True:
            await asyncio.sleep(1)
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        await proxy.stop()
        console.print(f"\n[bold yellow]Proxy stopped.[/bold yellow] Total flows intercepted: [bold cyan]{len(proxy.captured_flows)}[/bold cyan]")

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

    # 2b. Handle 'watch' command (Autonomous Sentinel)
    if raw_target and raw_target.lower() == "watch":
        target_url = args.host_or_target
        if not target_url:
            console.print("[bold red]Error:[/bold red] Missing target URL for watch mode. Usage: [cyan]armorscan watch http://localhost:3000 --interval 1h --webhook <url>[/cyan]")
            return 2
        return await run_sentinel_watch_async(target_url, args, console)

    # 2c. Handle 'proxy' command (Live Traffic Forward Proxy & Auditor)
    if raw_target and raw_target.lower() == "proxy":
        return await run_proxy_async(args, console)

    # 3. Handle 'benchmark' command
    if raw_target and raw_target.lower() == "benchmark":
        from scripts.run_benchmark import main_async as run_benchmark_async
        sub_target = (args.host_or_target or "labapp").lower()
        if sub_target in ("juice-shop", "juice_shop", "dvwa"):
            benchmark_target = sub_target
            bench_url = None
        elif sub_target.startswith("http"):
            benchmark_target = "labapp"
            bench_url = sub_target
        else:
            benchmark_target = "labapp"
            bench_url = "http://127.0.0.1:8888"

        benchmark_args = argparse.Namespace(
            target=benchmark_target,
            url=bench_url,
            profile=None,
            ground_truth="benchmark/ground_truth.yaml",
            output=None,
            min_precision=0.95,
            min_recall=0.95,
            no_crawl=False,
        )
        return await run_benchmark_async(benchmark_args)

    # 3b. Handle 'verify-domain' command: generate unique cryptographic domain ownership token
    if raw_target and raw_target.lower() in ("verify-domain", "verify"):
        from armorscan.core.ownership import OwnershipGate
        domain_url = args.host_or_target
        if not domain_url:
            console.print("[bold red]Error:[/bold red] Missing target URL. Usage: [cyan]armorscan verify-domain https://your-domain.com[/cyan]")
            return 2
        try:
            dom_target = ScanTarget.from_url(domain_url)
        except Exception as e:
            console.print(f"[bold red]Invalid target URL:[/bold red] {e}")
            return 2
        token = OwnershipGate.generate_domain_challenge(dom_target.host)
        console.print(
            Panel(
                f"🔐 [bold white]ArmorScan Domain Ownership Challenge Generator[/bold white]\n\n"
                f"Target Host: [bold cyan]{dom_target.host}[/bold cyan]\n"
                f"Unique Verification Token (Valid Today UTC):\n"
                f"  [bold green]{token}[/bold green]\n\n"
                f"[bold yellow]Complete ANY of the following 3 verification methods on your server:[/bold yellow]\n"
                f"  [bold white]1. HTTP Well-Known File (Recommended):[/bold white]\n"
                f"     Create [cyan]{dom_target.base_url.rstrip('/')}/.well-known/armorscan-verify.txt[/cyan]\n"
                f"     containing: [green]{token}[/green]\n\n"
                f"  [bold white]2. HTML Meta Tag:[/bold white]\n"
                f"     Add to your homepage [cyan]<head>[/cyan]:\n"
                f"     [green]<meta name=\"armorscan-verification\" content=\"{token}\">[/green]\n\n"
                f"  [bold white]3. HTTP Response Header:[/bold white]\n"
                f"     Return header on [cyan]/[/cyan]:\n"
                f"     [green]X-ArmorScan-Verification: {token}[/green]",
                border_style="green",
                box=ROUNDED,
            )
        )
        return 0

    # 4. Handle 'scan' sub-syntax: 'armorscan scan https://...'
    if raw_target and raw_target.lower() == "scan":
        raw_target = args.host_or_target

    if not raw_target:
        console.print("[bold red]Error:[/bold red] Missing target URL. Usage: [cyan]armorscan https://example.com[/cyan], [cyan]armorscan verify-domain https://example.com[/cyan], or [cyan]armorscan discover[/cyan]")
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

    # 4. Authenticated Session Configuration
    auth_config = AuthConfig(
        check_url=args.auth_check_url,
        check_status=args.auth_check_status,
        check_body=args.auth_check_body,
        login_url=args.login_url,
        login_body=args.login_body,
        login_token_path=args.login_token_path,
    )
    if args.auth_header:
        for h in args.auth_header:
            auth_config.add_header(h)
    if args.auth_cookie:
        for c in args.auth_cookie:
            auth_config.add_cookie(c)
    if args.auth_custom_header:
        for ch in args.auth_custom_header:
            auth_config.add_custom_header(ch)

    if auth_config.has_auth and not args.quiet:
        console.print("🔐 [bold cyan]Authenticated scanning enabled[/bold cyan] (custom credentials / macro configured)\n")

    # 4b. Pre-Flight Zero-Trust Domain Ownership & Master Key Gate
    from armorscan.core.ownership import OwnershipGate
    async with HttpClient.for_target(target, verify_ssl=verify_ssl, auth_config=auth_config) as gate_client:
        ownership = await OwnershipGate.verify_target_access(
            target,
            gate_client,
            master_key=getattr(args, "master_key", None),
        )
    if not ownership.authorized:
        console.print(
            Panel(
                f"🛑 [bold red]TARGET AUTHORIZATION DENIED (ZERO-TRUST OWNERSHIP GATE)[/bold red]\n\n"
                f"ArmorScan strictly prohibits unauthorized scanning of third-party external websites.\n"
                f"Target [bold yellow]{target.host}[/bold yellow] does not present valid cryptographic ownership proof.\n\n"
                f"[bold white]If you are the administrator of {target.host}, verify ownership using ONE method:[/bold white]\n"
                f"  • [bold cyan]Method 1 (File):[/bold cyan] Place [green]{ownership.expected_token}[/green] inside:\n"
                f"    [underline]{target.base_url.rstrip('/')}/.well-known/armorscan-verify.txt[/underline]\n"
                f"  • [bold cyan]Method 2 (HTML):[/bold cyan] Add to homepage <head>:\n"
                f"    [green]<meta name=\"armorscan-verification\" content=\"{ownership.expected_token}\">[/green]\n"
                f"  • [bold cyan]Method 3 (Header):[/bold cyan] Add HTTP response header:\n"
                f"    [green]X-ArmorScan-Verification: {ownership.expected_token}[/green]\n\n"
                f"[dim]Tip: Run 'armorscan verify-domain {target.base_url}' for setup instructions.[/dim]",
                border_style="red",
                box=ROUNDED,
            )
        )
        return 3
    elif not args.quiet and ownership.mode != "localhost":
        console.print(f"🛡️ [bold green]Target Authorization Verified:[/bold green] {ownership.message}\n")

    # 5. Optional Web Crawling & Deep Spidering
    discovered_forms_count = 0
    if args.crawl:
        if not args.quiet:
            console.print(f"🕷️ [bold cyan]Deep Spider & Endpoint Crawl (depth={args.depth}, max_pages={args.max_pages})...[/bold cyan]")
        async with HttpClient.for_target(target, verify_ssl=verify_ssl, auth_config=auth_config) as client:
            if auth_config.login_url:
                await auth_config.perform_login(client, target.base_url)

            from armorscan.core.spider import DeepSpider
            spider = DeepSpider(max_depth=args.depth, max_pages=args.max_pages)
            spider_res = await spider.crawl(target, client)

            crawler = WebCrawler(max_depth=args.depth, max_pages=args.max_pages)
            crawl_res = await crawler.crawl(target, client, custom_schema_path=args.schema)

            combined_paths = (
                set(crawl_res.discovered_paths)
                .union(set(spider_res.discovered_paths))
                .union(set(spider_res.audit_routes))
            )
            sorted_routes = sorted(list(combined_paths))
            target.discovered_paths = sorted_routes
            target.audit_routes = sorted_routes

            # Deduplicate form actions
            unique_forms = {f"{f.method}:{f.action_url}" for f in spider_res.forms}.union(
                {f"{f.method}:{f.action_url}" for f in crawl_res.forms}
            )
            discovered_forms_count = max(len(unique_forms), len(spider_res.forms))
            target.discovered_forms_count = discovered_forms_count
            fuzzable_params_count = len(crawl_res.discovered_parameters.union(spider_res.fuzzable_parameters))

            if not args.quiet:
                console.print(
                    f"   Discovered [bold green]{len(target.audit_routes)}[/bold green] paths across "
                    f"[bold green]{max(crawl_res.pages_crawled, spider_res.pages_crawled)}[/bold green] crawled pages. "
                    f"Found [bold green]{discovered_forms_count}[/bold green] HTML forms ({fuzzable_params_count} fuzzable params)."
                )
                if crawl_res.api_endpoints:
                    console.print(f"   Parsed [bold green]{len(crawl_res.api_endpoints)}[/bold green] schema API operations from OpenAPI/Swagger/GraphQL.")
                if crawl_res.graphql_introspection_active:
                    console.print(f"   ⚡ [bold yellow]GraphQL Introspection active on:[/bold yellow] [cyan]{crawl_res.graphql_url}[/cyan]")
                console.print(f"   [dim]Sample routes: {', '.join(target.audit_routes[:8])}[/dim]\n")

    # 5b. Static AST Source Code Route Mapping & Shadow API Discovery
    shadow_api_findings = []
    ast_mapped_count = 0
    if getattr(args, "source_dir", None):
        from armorscan.core.ast_mapper import AstSourceMapper
        if not args.quiet:
            console.print(f"🧬 [bold cyan]Performing Static AST Code Mapping on:[/bold cyan] [bold]{args.source_dir}[/bold]...")
        try:
            mapper = AstSourceMapper()
            ast_res = mapper.scan_directory(args.source_dir)
            ast_mapped_count = len(ast_res.endpoints)
            for ep in ast_res.endpoints:
                if ep.path not in target.discovered_paths:
                    target.discovered_paths.append(ep.path)
            shadow_api_findings = mapper.generate_findings(ast_res, base_url=target.base_url)
            if not args.quiet:
                console.print(
                    f"   Parsed [bold green]{ast_mapped_count}[/bold green] routes across "
                    f"[bold green]{ast_res.scanned_files_count}[/bold green] source files."
                )
                if shadow_api_findings:
                    console.print(
                        f"   🚨 [bold red]Identified {len(shadow_api_findings)} unprotected shadow API route(s) lacking auth middleware![/bold red]\n"
                    )
                else:
                    console.print("   ✅ All mapped sensitive routes enforce authentication middleware.\n")
        except Exception as e:
            if not args.quiet:
                console.print(f"   [yellow]AST mapping notice:[/yellow] {e}\n")

    # 6. Execute Security Audits
    modules = get_default_modules(
        burst_count=args.burst,
        include_browser=getattr(args, "browser", False),
        template_paths=getattr(args, "templates", None),
        include_fuzz=getattr(args, "fuzz", False),
        matrix_roles=getattr(args, "matrix_roles", None),
    )
    suppression_engine = SuppressionEngine.find_and_load(custom_path=args.ignore_file)
    runner = ScanRunner(
        modules=modules,
        verify_ssl=verify_ssl,
        concurrency=args.concurrency,
        suppression_engine=suppression_engine,
        auth_config=auth_config,
    )

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

    # Append Shadow API findings if discovered from AST source analysis
    if shadow_api_findings:
        from armorscan.core.models import ModuleResult
        ast_mod_res = ModuleResult(
            module_name="ast_mapper",
            display_name="Static AST Route & Shadow API Auditor",
            findings=shadow_api_findings,
            passed_checks=[f"Mapped {ast_mapped_count} endpoints from source directory '{args.source_dir}'."],
        )
        scan_result.modules.append(ast_mod_res)
        scan_result.summary = ScoringEngine.calculate_summary(scan_result.modules)

    # Refresh engine_performance with final discovery metrics
    scan_result.engine_performance = ScoringEngine.calculate_performance_index(
        duration_seconds=scan_result.duration_seconds,
        discovered_paths_count=max(len(target.discovered_paths), len(target.audit_routes), 1),
        forms_count=discovered_forms_count,
        unhandled_errors_count=0,
    )

    # 7. Render Console Output or Interactive TUI
    if getattr(args, "tui", False):
        dashboard = TuiDashboard(scan_result, console=console)
        dashboard.run()
    elif not args.quiet:
        if scan_result.meta.get("login_success") is False:
            console.print(f"⚠️ [bold yellow]Login Macro Warning:[/bold yellow] {scan_result.meta.get('login_message')}\n")
        if scan_result.meta.get("session_verified") is False:
            console.print(f"⚠️ [bold yellow]Session Verification Warning:[/bold yellow] {scan_result.meta.get('session_message')}\n")
        reporter.render_scan_results(scan_result)

    # 7b. Generate Reports
    if not args.no_html and args.html:
        html_path = HtmlReporter.save(scan_result, args.html)
        if not args.quiet:
            console.print(f"📄 [bold green]Interactive HTML Report generated:[/bold green] [cyan]{html_path}[/cyan]")

    if args.json:
        json_path = JsonReporter.save(scan_result, args.json)
        if not args.quiet:
            console.print(f"📊 [bold green]JSON Report saved:[/bold green] [cyan]{json_path}[/cyan]")

    if getattr(args, "sarif", None):
        sarif_path = SarifReporter.export(scan_result, args.sarif)
        if not args.quiet:
            console.print(f"🛡️ [bold green]SARIF 2.1.0 Report saved:[/bold green] [cyan]{sarif_path}[/cyan]")

    # 7c. AI Vulnerability Storyteller & Auto-Patch Generation
    if getattr(args, "ai_explain", False) or getattr(args, "ai_patch", False):
        from armorscan.core.ai_patch import AiPatchEngine
        ai_engine = AiPatchEngine()
        if not args.quiet:
            console.print("\n🤖 [bold cyan]AI Vulnerability Storyteller & Auto-Patch Engine[/bold cyan]")
        for f in scan_result.all_findings:
            if getattr(args, "ai_explain", False):
                expl = await ai_engine.explain(f)
                console.print(f"\n[bold white]📋 {f.title} ({f.severity.value})[/bold white] [dim]via {expl.provider}[/dim]")
                console.print(f"[bold yellow]Executive Summary:[/bold yellow] {expl.executive_summary}")
                console.print(f"[bold red]Business Impact:[/bold red] {expl.business_impact}")
            if getattr(args, "ai_patch", False):
                patch_res = await ai_engine.generate_patch(f, repo_path=getattr(args, "repo_path", None))
                console.print(f"\n[bold green]🛠️ Unified Git Diff Patch ({patch_res.framework} -> {patch_res.target_file}):[/bold green]")
                console.print(Panel(patch_res.unified_diff, title=f"git apply patch for {f.id}", border_style="green", box=ROUNDED))

    # 7d. Self-Healing Automated GitHub Pull Request
    if getattr(args, "auto_pr", False):
        from armorscan.core.auto_pr import GitHubAutoPrEngine
        gh_repo = getattr(args, "github_repo", None)
        gh_token = getattr(args, "github_token", None)
        if not gh_repo:
            console.print("[bold red]Auto-PR Error:[/bold red] Missing --github-repo (e.g. --github-repo 'owner/repo').")
        else:
            if not args.quiet:
                console.print(f"\n🚀 [bold cyan]Opening Self-Healing Remediation Pull Request on GitHub:[/bold cyan] [bold]{gh_repo}[/bold]...")
            pr_engine = GitHubAutoPrEngine(github_repo=gh_repo, github_token=gh_token)
            pr_res = await pr_engine.create_security_pr(scan_result, repo_path=getattr(args, "repo_path", None))
            if pr_res.success:
                console.print(f"🎉 [bold green]Pull Request successfully created![/bold green] [cyan]{pr_res.pr_url}[/cyan] (Branch: [dim]{pr_res.branch}[/dim])")
            else:
                console.print(f"⚠️ [bold red]Auto-PR Failed:[/bold red] {pr_res.error}")

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
