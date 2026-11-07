#!/usr/bin/env python3
"""
CLI Script to execute ArmorScan Security Benchmarks.
Supports:
1. Controlled Ground Truth Lab (FastAPI in-process or local on 8888)
2. OWASP Juice Shop Real-World Benchmark (Docker or remote on 3000)
3. DVWA Real-World Benchmark (Docker or remote on 8080)
"""

import argparse
import asyncio
from pathlib import Path
import sys
import uvicorn
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from benchmark.labapp.app import app
from armorscan.core.benchmark import (
    BenchmarkRunner,
    RealWorldBenchmarkProfile,
    RealWorldBenchmarkReport,
    RealWorldBenchmarkRunner,
)


async def run_labapp_benchmark_async(args: argparse.Namespace, console: Console) -> int:
    """Run benchmark against the internal controlled FastAPI lab application."""
    base_url = args.url.rstrip("/") if args.url else "http://127.0.0.1:8888"
    server = None
    server_task = None

    if "127.0.0.1:8888" in base_url or "localhost:8888" in base_url:
        console.print("🚀 [yellow]Starting internal benchmark lab application on 127.0.0.1:8888...[/yellow]")
        config = uvicorn.Config(app, host="127.0.0.1", port=8888, log_level="error")
        server = uvicorn.Server(config)
        server_task = asyncio.create_task(server.serve())
        await asyncio.sleep(0.6)

    try:
        runner = BenchmarkRunner(
            ground_truth_path=Path(args.ground_truth),
            base_url=base_url,
        )

        with console.status("[bold green]Executing security modules against ground truth testbed...[/bold green]"):
            report = await runner.run_benchmark()

        table = Table(title="ArmorScan Accuracy & Verification Metrics", header_style="bold magenta")
        table.add_column("Module", style="bold cyan")
        table.add_column("TP", justify="center", style="green")
        table.add_column("FP", justify="center", style="red")
        table.add_column("FN", justify="center", style="yellow")
        table.add_column("Precision", justify="right", style="bold")
        table.add_column("Recall", justify="right", style="bold")
        table.add_column("F1-Score", justify="right", style="bold white")
        table.add_column("Status", justify="center")

        for mod_name, m in sorted(report.module_metrics.items()):
            if m.tp == 0 and m.fp == 0 and m.fn == 0:
                status = "[dim]N/A (No tests)[/dim]"
                prec_str = "-"
                rec_str = "-"
                f1_str = "-"
            else:
                status = "[bold green]PASS[/bold green]" if (m.precision >= 0.90 and m.recall >= 0.90) else "[bold yellow]WARN[/bold yellow]"
                prec_str = f"{m.precision:.1%}"
                rec_str = f"{m.recall:.1%}"
                f1_str = f"{m.f1_score:.3f}"
            table.add_row(
                mod_name,
                str(m.tp),
                str(m.fp),
                str(m.fn),
                prec_str,
                rec_str,
                f1_str,
                status,
            )

        ov = report.overall
        ov_status = "[bold green]✅ PASS[/bold green]" if (ov.precision >= args.min_precision and ov.recall >= args.min_recall) else "[bold red]❌ FAIL[/bold red]"
        table.add_section()
        table.add_row(
            "[bold white]OVERALL[/bold white]",
            f"[bold green]{ov.tp}[/bold green]",
            f"[bold red]{ov.fp}[/bold red]",
            f"[bold yellow]{ov.fn}[/bold yellow]",
            f"[bold green]{ov.precision:.1%}[/bold green]",
            f"[bold green]{ov.recall:.1%}[/bold green]",
            f"[bold white]{ov.f1_score:.3f}[/bold white]",
            ov_status,
        )

        console.print(table)

        out_path = Path(args.output or "benchmark/results.md")
        report.save_markdown(out_path)
        console.print(f"📄 [green]Benchmark results markdown saved to: [bold]{out_path}[/bold][/green]")

        if ov.precision < args.min_precision:
            console.print(
                f"[bold red]❌ CI Benchmark Gate Failed: Precision {ov.precision:.1%} is below threshold {args.min_precision:.1%}[/bold red]"
            )
            return 1

        if ov.recall < args.min_recall:
            console.print(
                f"[bold red]❌ CI Benchmark Gate Failed: Recall {ov.recall:.1%} is below threshold {args.min_recall:.1%}[/bold red]"
            )
            return 1

        console.print("[bold green]🎉 All benchmark precision and recall quality gates passed![/bold green]")
        return 0

    finally:
        if server is not None:
            server.should_exit = True
            if server_task:
                await server_task


async def run_real_world_benchmark_async(
    target_id: str,
    args: argparse.Namespace,
    console: Console,
) -> int:
    """Run benchmark against a real-world vulnerable application (Juice Shop, DVWA, or custom profile)."""
    if target_id in ("juice-shop", "juice_shop"):
        profile_path = Path("benchmark/profiles/juice_shop.yaml")
        default_url = "http://127.0.0.1:3000"
        default_output = "benchmark/juice_shop_results.md"
    elif target_id in ("dvwa",):
        profile_path = Path("benchmark/profiles/dvwa.yaml")
        default_url = "http://127.0.0.1:8080"
        default_output = "benchmark/dvwa_results.md"
    else:
        profile_path = Path(args.profile or "benchmark/profiles/juice_shop.yaml")
        default_url = "http://127.0.0.1:3000"
        default_output = f"benchmark/{target_id}_results.md"

    base_url = args.url or default_url
    output_path = Path(args.output or default_output)

    try:
        runner = RealWorldBenchmarkRunner(profile_path=profile_path, base_url=base_url)
    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        return 1

    console.print(f"🎯 Target Profile: [bold cyan]{runner.profile.name}[/bold cyan] ({runner.profile.description})")
    console.print(f"🌐 Base URL: [bold]{base_url}[/bold]")

    try:
        with console.status(f"[bold green]Running ArmorScan crawler and modules against {runner.profile.name}...[/bold green]"):
            report = await runner.run_benchmark(enable_crawler=not args.no_crawl)
    except ConnectionError as e:
        console.print(f"\n[bold red]❌ Benchmark Target Unreachable:[/bold red]\n{e}\n")
        return 2
    except Exception as e:
        console.print(f"\n[bold red]Error running benchmark:[/bold red] {e}\n")
        return 1

    # Render Terminal Metrics Table
    summary_table = Table(title=f"📊 {runner.profile.name} Benchmark Results", header_style="bold magenta")
    summary_table.add_column("Metric", style="bold white")
    summary_table.add_column("Value", justify="center", style="bold cyan")
    summary_table.add_column("Status", justify="center")

    summary_table.add_row("Precision", f"{report.precision:.1%}", "[bold green]✅ PASS[/bold green]" if report.precision >= 0.9 else "[bold yellow]WARN[/bold yellow]")
    summary_table.add_row("Recall (Coverage)", f"{report.recall:.1%}", "[bold green]✅ PASS[/bold green]" if report.recall >= 0.8 else "[bold yellow]WARN[/bold yellow]")
    summary_table.add_row("F1-Score", f"{report.f1_score:.3f}", "[bold green]✅ PASS[/bold green]" if report.f1_score >= 0.85 else "[bold yellow]WARN[/bold yellow]")
    summary_table.add_row("True Positives (Detected)", str(len(report.tp_findings)), "✅")
    summary_table.add_row("False Positives (Suppressed)", str(len(report.fp_findings)), "[bold green]✅ 0 FP[/bold green]" if len(report.fp_findings) == 0 else "[bold red]❌ FP Detected[/bold red]")
    summary_table.add_row("False Negatives (Missed)", str(len(report.fn_findings)), "[bold green]✅ 0 Missed[/bold green]" if len(report.fn_findings) == 0 else "[bold yellow]⚠️ Missed[/bold yellow]")
    summary_table.add_row("Discovered Routes", str(report.routes_discovered), "🌐")
    summary_table.add_row("Discovered Forms", str(report.forms_discovered), "📝")
    summary_table.add_row("Scan Duration", f"{report.scan_duration_seconds:.2f}s", "⚡")

    console.print(summary_table)

    # Render Expected Vulnerabilities Table
    vuln_table = Table(title="🎯 Expected Vulnerability Detection Matrix", header_style="bold cyan")
    vuln_table.add_column("Finding ID", style="bold")
    vuln_table.add_column("Module", style="dim")
    vuln_table.add_column("Expected Description", style="white")
    vuln_table.add_column("Detected?", justify="center")

    expected_map = {v.get("id"): v for v in runner.profile.expected_vulnerabilities}
    for exp_id, exp_meta in expected_map.items():
        is_detected = exp_id in report.tp_findings
        badge = "[bold green]✅ YES[/bold green]" if is_detected else "[bold red]❌ NO[/bold red]"
        vuln_table.add_row(exp_id, exp_meta.get("module", "-"), exp_meta.get("description", ""), badge)

    console.print(vuln_table)

    # Render False Positive Resilience Table
    fp_table = Table(title="🛡️ False Positive Resilience Verification", header_style="bold yellow")
    fp_table.add_column("Checked ID", style="bold")
    fp_table.add_column("Module", style="dim")
    fp_table.add_column("Resilience Requirement", style="white")
    fp_table.add_column("Status", justify="center")

    for fp_meta in runner.profile.forbidden_false_positives:
        fp_id = fp_meta.get("id")
        mod = fp_meta.get("module", "-")
        reason = fp_meta.get("reason", "")
        triggered = fp_id in report.fp_findings
        badge = "[bold red]❌ FALSE POSITIVE[/bold red]" if triggered else "[bold green]✅ CLEAN (Zero FP)[/bold green]"
        fp_table.add_row(fp_id, mod, reason, badge)

    console.print(fp_table)

    report.save_markdown(output_path)
    console.print(f"\n📄 [green]Detailed Markdown report written to: [bold]{output_path}[/bold][/green]\n")

    return 0


async def main_async(args: argparse.Namespace) -> int:
    console = Console()
    console.print(
        Panel(
            "[bold white]🛡️ ArmorScan Security Accuracy & Verification Benchmark[/bold white]\n"
            "[dim]Measuring True Positives, False Positives, False Negatives, Precision & Recall across Real Targets[/dim]",
            border_style="cyan",
        )
    )

    target_id = (args.target or "labapp").lower()
    if target_id == "labapp":
        return await run_labapp_benchmark_async(args, console)
    else:
        return await run_real_world_benchmark_async(target_id, args, console)


def main() -> None:
    parser = argparse.ArgumentParser(description="ArmorScan Ground Truth & Real-World Benchmark Runner")
    parser.add_argument(
        "target",
        nargs="?",
        default="labapp",
        choices=["labapp", "juice-shop", "juice_shop", "dvwa"],
        help="Target benchmark environment: 'labapp' (internal FastAPI), 'juice-shop', or 'dvwa' (default: labapp)",
    )
    parser.add_argument("--url", default=None, help="Target benchmark app base URL (overrides profile default)")
    parser.add_argument(
        "--profile",
        default=None,
        help="Path to custom benchmark profile YAML (for custom targets)",
    )
    parser.add_argument(
        "--ground-truth",
        default="benchmark/ground_truth.yaml",
        help="Path to ground_truth.yaml configuration for labapp",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Path to output markdown report file",
    )
    parser.add_argument(
        "--min-precision",
        type=float,
        default=0.95,
        help="Minimum required precision for CI gate (0.0 - 1.0)",
    )
    parser.add_argument(
        "--min-recall",
        type=float,
        default=0.95,
        help="Minimum required recall for CI gate (0.0 - 1.0)",
    )
    parser.add_argument(
        "--no-crawl",
        action="store_true",
        help="Disable automatic crawler during benchmark",
    )

    args = parser.parse_args()
    code = asyncio.run(main_async(args))
    sys.exit(code)


if __name__ == "__main__":
    main()
