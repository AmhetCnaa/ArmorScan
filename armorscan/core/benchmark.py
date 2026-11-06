"""
Benchmark Evaluation Engine for ArmorScan.
Measures True Positives (TP), False Positives (FP), False Negatives (FN),
Precision, Recall, and F1-score against the controlled ground truth laboratory.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import yaml

from armorscan.core.client import HttpClient
from armorscan.core.models import Finding, ModuleResult, ScanTarget
from armorscan.modules.base import BaseModule
from armorscan.modules.authz_check import AuthzCheckModule
from armorscan.modules.cookies import CookieHygieneModule
from armorscan.modules.cors import CorsAndMethodModule
from armorscan.modules.error_leak import ErrorLeakModule
from armorscan.modules.exposure import ExposureAuditModule
from armorscan.modules.headers import SecurityHeadersModule
from armorscan.modules.jwt_audit import JwtAuditModule
from armorscan.modules.ratelimit import RateLimitModule
from armorscan.modules.redirect import OpenRedirectModule
from armorscan.modules.reflection import InputReflectionModule
from armorscan.modules.secret_leak import SecretLeakModule

MODULE_MAP: Dict[str, type[BaseModule]] = {
    "reflection": InputReflectionModule,
    "redirect": OpenRedirectModule,
    "error_leak": ErrorLeakModule,
    "jwt_audit": JwtAuditModule,
    "secret_leak": SecretLeakModule,
    "headers": SecurityHeadersModule,
    "cookies": CookieHygieneModule,
    "cors": CorsAndMethodModule,
    "ratelimit": RateLimitModule,
    "exposure": ExposureAuditModule,
    "authz_check": AuthzCheckModule,
}


@dataclass
class BenchmarkMetric:
    """Statistical accuracy metrics for a specific module or overall testbed."""
    name: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        total = self.tp + self.fp
        return (self.tp / total) if total > 0 else 1.0

    @property
    def recall(self) -> float:
        total = self.tp + self.fn
        return (self.tp / total) if total > 0 else 1.0

    @property
    def f1_score(self) -> float:
        p = self.precision
        r = self.recall
        return (2 * p * r / (p + r)) if (p + r) > 0 else 0.0


@dataclass
class TestCaseResult:
    test_id: str
    module: str
    target_path: str
    is_safe: bool
    expected_findings: List[str]
    actual_findings: List[str]
    tp_count: int
    fp_count: int
    fn_count: int
    passed: bool


@dataclass
class BenchmarkReport:
    """Comprehensive benchmark execution report."""
    timestamp: str
    base_url: str
    module_metrics: Dict[str, BenchmarkMetric] = field(default_factory=dict)
    test_cases: List[TestCaseResult] = field(default_factory=list)

    @property
    def overall(self) -> BenchmarkMetric:
        tot = BenchmarkMetric(name="overall")
        for m in self.module_metrics.values():
            tot.tp += m.tp
            tot.fp += m.fp
            tot.fn += m.fn
            tot.tn += m.tn
        return tot

    def to_markdown_table(self) -> str:
        """Format metrics into a GitHub-Flavored Markdown table."""
        lines = [
            "# 🛡️ ArmorScan Ground Truth Benchmark Report",
            f"\n> **Execution Date:** {self.timestamp}  ",
            f"> **Target Base URL:** `{self.base_url}`  ",
            f"> **Total Evaluated Endpoints:** {len(self.test_cases)}  \n",
            "## 📊 Module Accuracy & Verification Metrics\n",
            "| Module | True Positives (TP) | False Positives (FP) | False Negatives (FN) | Precision | Recall | F1-Score | Status |",
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
        ]

        for mod_name, m in sorted(self.module_metrics.items()):
            status = "✅ PASS" if (m.precision >= 0.90 and m.recall >= 0.90) else "⚠️ WARN"
            lines.append(
                f"| `{mod_name}` | {m.tp} | {m.fp} | {m.fn} | "
                f"{m.precision:.1%} | {m.recall:.1%} | {m.f1_score:.3f} | {status} |"
            )

        ov = self.overall
        ov_status = "✅ PASS" if (ov.precision >= 0.95 and ov.recall >= 0.95) else "❌ FAIL"
        lines.append(
            f"| **OVERALL** | **{ov.tp}** | **{ov.fp}** | **{ov.fn}** | "
            f"**{ov.precision:.1%}** | **{ov.recall:.1%}** | **{ov.f1_score:.3f}** | **{ov_status}** |"
        )

        lines.append("\n## 🔍 Endpoint Test Case Breakdown\n")
        lines.append("| Test Case ID | Module | Endpoint Path | Type | Expected | Found | Result |")
        lines.append("| :--- | :--- | :--- | :---: | :--- | :--- | :---: |")

        for tc in self.test_cases:
            tc_type = "Safe (Clean)" if tc.is_safe else "Vulnerable"
            exp_str = ", ".join(f"`{x}`" for x in tc.expected_findings) if tc.expected_findings else "*(None)*"
            found_str = ", ".join(f"`{x}`" for x in tc.actual_findings) if tc.actual_findings else "*(None)*"
            result_badge = "✅ OK" if tc.passed else "❌ FAIL"
            lines.append(
                f"| `{tc.test_id}` | `{tc.module}` | `{tc.target_path}` | {tc_type} | {exp_str} | {found_str} | {result_badge} |"
            )

        return "\n".join(lines) + "\n"

    def save_markdown(self, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.to_markdown_table(), encoding="utf-8")


class BenchmarkRunner:
    """Executes ArmorScan modules against ground truth test cases."""

    def __init__(
        self,
        ground_truth_path: Optional[Path] = None,
        base_url: str = "http://127.0.0.1:8888",
    ):
        if ground_truth_path is None:
            self.ground_truth_path = Path(__file__).resolve().parents[2] / "benchmark" / "ground_truth.yaml"
        else:
            self.ground_truth_path = ground_truth_path

        self.base_url = base_url.rstrip("/")

    async def run_benchmark(self) -> BenchmarkReport:
        """Run all test cases from ground_truth.yaml and compute metrics."""
        if not self.ground_truth_path.exists():
            raise FileNotFoundError(f"Ground truth configuration not found at: {self.ground_truth_path}")

        with open(self.ground_truth_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        endpoints = data.get("endpoints", [])
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        report = BenchmarkReport(timestamp=timestamp, base_url=self.base_url)

        # Initialize metrics for all modules
        for mod_name in MODULE_MAP.keys():
            report.module_metrics[mod_name] = BenchmarkMetric(name=mod_name)

        client = HttpClient(verify_ssl=False)
        await client.start()

        try:
            for ep in endpoints:
                test_id = ep.get("id", "unknown")
                mod_name = ep.get("module")
                target_path = ep.get("path")
                ep_type = ep.get("type", "vulnerable")
                is_safe = (ep_type == "safe")
                expected: List[str] = ep.get("expected_findings", [])
                forbidden: List[str] = ep.get("forbidden_findings", [])

                if mod_name not in MODULE_MAP:
                    continue

                module_cls = MODULE_MAP[mod_name]
                module_instance = module_cls()

                full_url = f"{self.base_url}{target_path}"
                target = ScanTarget.from_url(full_url)

                result: ModuleResult = await module_instance.run(target, client)
                actual_finding_ids = [f.id for f in result.findings]

                metric = report.module_metrics[mod_name]

                # Evaluate TP, FP, FN
                actual_set = set(actual_finding_ids)
                expected_set = set(expected)
                forbidden_set = set(forbidden)

                if is_safe:
                    # Safe endpoint: any finding detected is a False Positive
                    tp = 0
                    fp = len(actual_set)
                    fn = 0
                    tn = 1 if len(actual_set) == 0 else 0
                    passed = (fp == 0)
                else:
                    # Vulnerable endpoint:
                    # True Positive: Expected finding was detected
                    tp = len(actual_set.intersection(expected_set))
                    # False Positive: Finding was in forbidden set or unexpected
                    unexpected = actual_set - expected_set
                    fp = len(actual_set.intersection(forbidden_set)) + (1 if unexpected and not expected_set else 0)
                    # False Negative: Expected finding was missed
                    fn = len(expected_set - actual_set)
                    tn = 0
                    passed = (tp > 0 and fn == 0 and fp == 0)

                metric.tp += tp
                metric.fp += fp
                metric.fn += fn
                metric.tn += tn

                report.test_cases.append(
                    TestCaseResult(
                        test_id=test_id,
                        module=mod_name,
                        target_path=target_path,
                        is_safe=is_safe,
                        expected_findings=expected,
                        actual_findings=actual_finding_ids,
                        tp_count=tp,
                        fp_count=fp,
                        fn_count=fn,
                        passed=passed,
                    )
                )
        finally:
            await client.close()

        return report
