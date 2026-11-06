"""
Automated CI Integration Test for ArmorScan Accuracy Benchmark.
Runs ArmorScan against the controlled labapp ground truth testbed and validates
that Precision, Recall, and F1-score satisfy strict CI quality gates.
"""

import asyncio
from pathlib import Path
import pytest
import uvicorn

from benchmark.labapp.app import app
from armorscan.core.benchmark import BenchmarkRunner


@pytest.mark.asyncio
async def test_ground_truth_benchmark_quality_gate():
    port = 8889
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    server_task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.6)

    try:
        runner = BenchmarkRunner(
            ground_truth_path=Path("benchmark/ground_truth.yaml"),
            base_url=f"http://127.0.0.1:{port}",
        )
        report = await runner.run_benchmark()

        # Quality Gate Assertions
        assert len(report.test_cases) == 22
        assert report.overall.precision >= 0.95, f"Precision fell below gate: {report.overall.precision:.2%}"
        assert report.overall.recall >= 0.95, f"Recall fell below gate: {report.overall.recall:.2%}"
        assert report.overall.fp == 0, f"False positives detected: {report.overall.fp}"
        assert report.overall.fn == 0, f"False negatives detected: {report.overall.fn}"

        # Module-level verification
        for mod_name, metric in report.module_metrics.items():
            assert metric.precision >= 0.90, f"Module {mod_name} precision low: {metric.precision}"
            assert metric.recall >= 0.90, f"Module {mod_name} recall low: {metric.recall}"

    finally:
        server.should_exit = True
        await server_task
