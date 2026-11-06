#!/usr/bin/env python3
"""
CLI Script to execute ArmorScan Ground Truth Security Benchmark.
Starts the controlled FastAPI laboratory server, runs ArmorScan against ground truth endpoints,
calculates Precision/Recall/F1-score, and updates benchmark/results.md.
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
from armorscan.core.benchmark import BenchmarkRunner


async def main_async(args: argparse.Namespace) -> int:
    console = Console()
    console.print(
        Panel(
            "[bold white]🛡️ ArmorScan Ground Truth Accuracy Benchmark[/bold white]\n"
            "[dim]Measuring True Positives, False Positives, False Negatives, Precision & Recall[/dim]",
            border_style="cyan",
        )
    )

    base_url = args.url.rstrip("/")
    server = None
    server_task = None

    # If targeting local default and server is not already external, run in-process uvicorn
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

        # Display rich table in terminal
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
            status = "[bold green]PASS[/bold green]" if (m.precision >= 0.90 and m.recall >= 0.90) else "[bold yellow]WARN[/bold yellow]"
            table.add_row(
                mod_name,
                str(m.tp),
                str(m.fp),
                str(m.fn),
                f"{m.precision:.1%}",
                f"{m.recall:.1%}",
                f"{m.f1_score:.3f}",
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

        # Save to markdown
        out_path = Path(args.output)
        report.save_markdown(out_path)
        console.print(f"📄 [green]Benchmark results markdown saved to: [bold]{out_path}[/bold][/green]")

        # Check CI Quality Gates
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


def main() -> None:
    parser = argparse.ArgumentParser(description="ArmorScan Ground Truth Benchmark Runner")
    parser.add_argument("--url", default="http://127.0.0.1:8888", help="Target benchmark app base URL")
    parser.add_argument(
        "--ground-truth",
        default="benchmark/ground_truth.yaml",
        help="Path to ground_truth.yaml configuration",
    )
    parser.add_argument(
        "--output",
        default="benchmark/results.md",
        help="Path to output results.md file",
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

    args = parser.parse_args()
    code = asyncio.run(main_async(args))
    sys.exit(code)


if __name__ == "__main__":
    main()
