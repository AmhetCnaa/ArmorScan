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
import shutil
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urljoin
import yaml

from armorscan.core.client import HttpClient
from armorscan.core.crawler import WebCrawler
from armorscan.core.models import Finding, ModuleResult, ScanTarget
from armorscan.core.runner import ScanRunner
from armorscan.modules.base import BaseModule
from armorscan.modules.authz_check import AuthzCheckModule
from armorscan.modules.cookies import CookieHygieneModule
from armorscan.modules.cors import CorsAndMethodModule
from armorscan.modules.error_leak import ErrorLeakModule
from armorscan.modules.exposure import ExposureAuditModule
from armorscan.modules.headers import SecurityHeadersModule
from armorscan.modules.jwt_audit import JwtAuditModule
from armorscan.modules.multi_step import MultiStepLogicModule
from armorscan.modules.ratelimit import RateLimitModule
from armorscan.modules.redirect import OpenRedirectModule
from armorscan.modules.reflection import InputReflectionModule
from armorscan.modules.secret_leak import SecretLeakModule
from armorscan.modules.tls_ssl import TlsSslModule

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
    "multi_step": MultiStepLogicModule,
    "tls": TlsSslModule,
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
            if m.tp == 0 and m.fp == 0 and m.fn == 0:
                status = "N/A"
                prec_str = "-"
                rec_str = "-"
                f1_str = "-"
            else:
                status = "✅ PASS" if (m.precision >= 0.90 and m.recall >= 0.90) else "⚠️ WARN"
                prec_str = f"{m.precision:.1%}"
                rec_str = f"{m.recall:.1%}"
                f1_str = f"{m.f1_score:.3f}"
            lines.append(
                f"| `{mod_name}` | {m.tp} | {m.fp} | {m.fn} | "
                f"{prec_str} | {rec_str} | {f1_str} | {status} |"
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


class RealWorldBenchmarkProfile:
    """Configuration profile defining ground truth for external benchmark targets."""

    def __init__(
        self,
        name: str,
        target_id: str,
        version: str,
        description: str,
        default_url: str,
        health_check_path: str,
        docker_service: str,
        docker_image: str,
        expected_vulnerabilities: List[Dict[str, Any]],
        forbidden_false_positives: List[Dict[str, Any]],
    ):
        self.name = name
        self.target_id = target_id
        self.version = version
        self.description = description
        self.default_url = default_url
        self.health_check_path = health_check_path
        self.docker_service = docker_service
        self.docker_image = docker_image
        self.expected_vulnerabilities = expected_vulnerabilities
        self.forbidden_false_positives = forbidden_false_positives

    @classmethod
    def load(cls, profile_path: Union[str, Path]) -> RealWorldBenchmarkProfile:
        p = Path(profile_path)
        if not p.exists():
            raise FileNotFoundError(f"Benchmark profile not found: {p}")
        with open(p, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(
            name=data.get("name", "Unknown Target"),
            target_id=data.get("target_id", "unknown"),
            version=data.get("version", "latest"),
            description=data.get("description", ""),
            default_url=data.get("default_url", "http://127.0.0.1:3000"),
            health_check_path=data.get("health_check_path", "/"),
            docker_service=data.get("docker_service", ""),
            docker_image=data.get("docker_image", ""),
            expected_vulnerabilities=data.get("expected_vulnerabilities", []),
            forbidden_false_positives=data.get("forbidden_false_positives", []),
        )


@dataclass
class RealWorldBenchmarkReport:
    """Benchmark report generated from scanning a real-world target like Juice Shop or DVWA."""

    profile: RealWorldBenchmarkProfile
    base_url: str
    timestamp: str
    scan_duration_seconds: float
    routes_discovered: int
    forms_discovered: int
    tp_findings: List[str] = field(default_factory=list)
    fp_findings: List[str] = field(default_factory=list)
    fn_findings: List[str] = field(default_factory=list)
    novel_findings: List[str] = field(default_factory=list)
    all_findings: List[Finding] = field(default_factory=list)

    @property
    def precision(self) -> float:
        total = len(self.tp_findings) + len(self.fp_findings)
        return (len(self.tp_findings) / total) if total > 0 else 1.0

    @property
    def recall(self) -> float:
        total = len(self.tp_findings) + len(self.fn_findings)
        return (len(self.tp_findings) / total) if total > 0 else 1.0

    @property
    def f1_score(self) -> float:
        p = self.precision
        r = self.recall
        return (2 * p * r / (p + r)) if (p + r) > 0 else 0.0

    def to_markdown_report(self) -> str:
        """Render a detailed GitHub-Flavored Markdown report."""
        lines = [
            f"# 🛡️ ArmorScan Real-World Benchmark: {self.profile.name}",
            "",
            f"> **Target Architecture:** {self.profile.description}  ",
            f"> **Target Base URL:** `{self.base_url}`  ",
            f"> **Execution Timestamp:** {self.timestamp}  ",
            f"> **Duration:** {self.scan_duration_seconds:.2f}s  ",
            (
                f"> **Docker Service:** `{self.profile.docker_service}` (`{self.profile.docker_image}`)  "
                if shutil.which("docker")
                else "> **Execution Environment:** Node.js 24 Native Process (`127.0.0.1:3000` - Docker unavailable in this environment)  "
            ),
            "",
            "## 📊 Benchmark Summary Metrics",
            "",
            "| Metric | Value | Target Goal | Status |",
            "| :--- | :---: | :---: | :---: |",
            f"| **Precision** | **{self.precision:.1%}** | ≥ 90.0% | {'✅ PASS' if self.precision >= 0.9 else '⚠️ WARN'} |",
            f"| **Recall (Coverage)** | **{self.recall:.1%}** | ≥ 80.0% | {'✅ PASS' if self.recall >= 0.8 else '⚠️ WARN'} |",
            f"| **F1-Score** | **{self.f1_score:.3f}** | ≥ 0.850 | {'✅ PASS' if self.f1_score >= 0.85 else '⚠️ WARN'} |",
            f"| **True Positives (Detected)** | {len(self.tp_findings)} | - | ✅ |",
            f"| **False Positives (Suppressed)** | {len(self.fp_findings)} | 0 | {'✅ 0 FP' if len(self.fp_findings) == 0 else '❌ FP Detected'} |",
            f"| **False Negatives (Missed)** | {len(self.fn_findings)} | 0 | {'✅' if len(self.fn_findings) == 0 else '⚠️ Needs Tuning'} |",
            f"| **Discovered Routes** | {self.routes_discovered} | - | 🌐 |",
            f"| **Discovered Forms** | {self.forms_discovered} | - | 📝 |",
            "",
            "## 🎯 Expected Vulnerabilities Matrix",
            "",
            "| Finding ID | Module | Severity | Expected Description | Detected? |",
            "| :--- | :--- | :---: | :--- | :---: |",
        ]

        expected_map = {v.get("id"): v for v in self.profile.expected_vulnerabilities}
        for exp_id, exp_meta in expected_map.items():
            is_detected = exp_id in self.tp_findings
            detected_badge = "✅ YES" if is_detected else "❌ MISSED"
            mod = exp_meta.get("module", "-")
            sev = exp_meta.get("severity", "-")
            desc = exp_meta.get("description", "")
            lines.append(f"| `{exp_id}` | `{mod}` | {sev} | {desc} | {detected_badge} |")

        lines.extend([
            "",
            "## 🛡️ False Positive Resilience Verification",
            "",
            "| Checked Finding ID | Module | Resilience Requirement | Result |",
            "| :--- | :--- | :--- | :---: |",
        ])

        for fp_meta in self.profile.forbidden_false_positives:
            fp_id = fp_meta.get("id")
            mod = fp_meta.get("module", "-")
            reason = fp_meta.get("reason", "")
            triggered = fp_id in self.fp_findings
            res_status = "❌ FALSE POSITIVE" if triggered else "✅ CLEAN (Zero FP)"
            lines.append(f"| `{fp_id}` | `{mod}` | {reason} | {res_status} |")

        if self.novel_findings:
            lines.extend([
                "",
                "## 💡 Additional Real-World Findings Discovered",
                "",
                "| Finding ID | Severity | Confidence | Title |",
                "| :--- | :---: | :---: | :--- |",
            ])
            for finding in self.all_findings:
                if finding.id in self.novel_findings:
                    lines.append(f"| `{finding.id}` | {finding.severity.value} | {finding.confidence.value} | {finding.title} |")

        return "\n".join(lines) + "\n"

    def save_markdown(self, output_path: Union[str, Path]) -> None:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.to_markdown_report(), encoding="utf-8")


class RealWorldBenchmarkRunner:
    """Executes ArmorScan against a live or simulated real-world target."""

    def __init__(
        self,
        profile_path: Union[str, Path],
        base_url: Optional[str] = None,
    ):
        self.profile = RealWorldBenchmarkProfile.load(profile_path)
        self.base_url = (base_url or self.profile.default_url).rstrip("/")

    async def check_health(self, client: HttpClient) -> Tuple[bool, Optional[str]]:
        """Verify target service is accessible before executing scan."""
        health_url = urljoin(self.base_url + "/", self.profile.health_check_path.lstrip("/"))
        try:
            resp = await client.get(health_url)
            if resp.error:
                err_msg = (
                    f"Cannot connect to target '{self.profile.name}' at {self.base_url}.\n"
                    f"Error: {resp.error}\n"
                    f"Make sure the benchmark container is running via:\n"
                    f"  docker compose -f benchmark/docker-compose.yml up -d {self.profile.docker_service}"
                )
                return False, err_msg
            if resp.status_code in (200, 301, 302, 304, 401, 403):
                return True, None
            return False, f"Target returned unexpected HTTP {resp.status_code} on health check {health_url}"
        except Exception as e:
            err_msg = (
                f"Cannot connect to target '{self.profile.name}' at {self.base_url}.\n"
                f"Make sure the benchmark container is running via:\n"
                f"  docker compose -f benchmark/docker-compose.yml up -d {self.profile.docker_service}"
            )
            return False, err_msg

    async def run_benchmark(
        self,
        enable_crawler: bool = True,
        custom_schema: Optional[str] = None,
        client: Optional[HttpClient] = None,
    ) -> RealWorldBenchmarkReport:
        """Run complete benchmark against the real-world application."""
        start_time = time.monotonic()
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        target = ScanTarget.from_url(self.base_url)
        close_client = False
        if client is None:
            client = HttpClient(verify_ssl=False)
            await client.start()
            close_client = True

        try:
            # 1. Health check
            is_healthy, health_err = await self.check_health(client)
            if not is_healthy:
                raise ConnectionError(health_err)

            # 2. Web Crawling & Endpoint Discovery
            routes_count = 1
            forms_count = 0
            if enable_crawler:
                crawler = WebCrawler(max_depth=2, max_pages=15)
                crawl_res = await crawler.crawl(target, client, custom_schema_path=custom_schema)
                routes_count = len(crawl_res.discovered_paths)
                forms_count = len(crawl_res.forms)

            # 3. Instantiate modules and execute scan
            modules = [cls() for cls in MODULE_MAP.values()]
            runner = ScanRunner(modules=modules, verify_ssl=False, concurrency=5)
            scan_result = await runner.scan(target)

            all_findings = scan_result.all_findings
            detected_ids = {f.id for f in all_findings}

            expected_ids = {v.get("id") for v in self.profile.expected_vulnerabilities if v.get("id")}
            forbidden_ids = {v.get("id") for v in self.profile.forbidden_false_positives if v.get("id")}

            tp_findings = sorted(list(detected_ids.intersection(expected_ids)))
            fp_findings = sorted(list(detected_ids.intersection(forbidden_ids)))
            fn_findings = sorted(list(expected_ids - detected_ids))
            novel_findings = sorted(list(detected_ids - expected_ids - forbidden_ids))

            duration = time.monotonic() - start_time

            return RealWorldBenchmarkReport(
                profile=self.profile,
                base_url=self.base_url,
                timestamp=timestamp,
                scan_duration_seconds=duration,
                routes_discovered=routes_count,
                forms_discovered=forms_count,
                tp_findings=tp_findings,
                fp_findings=fp_findings,
                fn_findings=fn_findings,
                novel_findings=novel_findings,
                all_findings=all_findings,
            )

        finally:
            if close_client:
                await client.close()

