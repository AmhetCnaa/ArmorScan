#!/usr/bin/env python3
"""
Dedicated CLI helper to execute ArmorScan benchmarks against external / real-world targets:
- OWASP Juice Shop (Modern Angular SPA + Node/Express)
- Damn Vulnerable Web Application (DVWA - PHP/MySQL)
- Custom target profiles
"""

import argparse
import asyncio
from pathlib import Path
import sys
from rich.console import Console
from rich.panel import Panel

from scripts.run_benchmark import run_real_world_benchmark_async


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ArmorScan Real-World Vulnerability Benchmark (Juice Shop / DVWA)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Benchmark against running OWASP Juice Shop on port 3000
  python scripts/benchmark_external.py --target juice-shop

  # Benchmark against running DVWA on port 8080
  python scripts/benchmark_external.py --target dvwa

  # Benchmark against custom host/port
  python scripts/benchmark_external.py --target juice-shop --url http://192.168.1.50:3000
        """,
    )
    parser.add_argument(
        "--target",
        default="juice-shop",
        choices=["juice-shop", "juice_shop", "dvwa"],
        help="Target benchmark application to evaluate (default: juice-shop)",
    )
    parser.add_argument(
        "--url",
        default=None,
        help="Override base URL of the target application",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="Path to custom target profile YAML",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Custom output path for generated Markdown report",
    )
    parser.add_argument(
        "--no-crawl",
        action="store_true",
        help="Disable automatic crawler during scan",
    )

    args = parser.parse_args()
    console = Console()
    console.print(
        Panel(
            "[bold white]🛡️ ArmorScan Real-World Application Benchmark[/bold white]\n"
            "[dim]Evaluating detection accuracy, coverage, and false positive resilience against realistic targets[/dim]",
            border_style="cyan",
        )
    )

    code = asyncio.run(run_real_world_benchmark_async(args.target, args, console))
    sys.exit(code)


if __name__ == "__main__":
    main()
