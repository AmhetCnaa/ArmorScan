"""
Scan Runner and Orchestrator for ArmorScan.
Coordinates concurrent execution of security modules and aggregates results.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import time
from typing import Callable, List, Optional

from armorscan.core.client import HttpClient
from armorscan.core.models import Confidence, Finding, ModuleResult, ScanResult, ScanTarget
from armorscan.core.scoring import ScoringEngine
from armorscan.core.suppression import SuppressionEngine
from armorscan.modules.base import BaseModule


class ScanRunner:
    """Orchestrates security modules, handles timeouts, and compiles scan results."""

    def __init__(
        self,
        modules: Optional[List[BaseModule]] = None,
        verify_ssl: bool = True,
        timeout: float = 10.0,
        concurrency: int = 5,
        suppression_engine: Optional[SuppressionEngine] = None,
    ):
        self.modules: List[BaseModule] = modules or []
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.concurrency = concurrency
        self.suppression_engine = suppression_engine or SuppressionEngine.find_and_load()

    @staticmethod
    def deduplicate_findings(modules: List[ModuleResult]) -> None:
        """
        Deduplicates identical findings produced across multiple crawled pages.
        Groups duplicate findings by (finding.id, finding.title) and merges their affected_urls.
        """
        for mod in modules:
            if not mod.findings:
                continue

            deduped: dict[str, Finding] = {}
            for finding in mod.findings:
                key = f"{finding.id}:{finding.title}"
                if key not in deduped:
                    if not finding.affected_urls and finding.evidence:
                        finding.affected_urls = []
                    deduped[key] = finding
                else:
                    existing = deduped[key]
                    for u in finding.affected_urls:
                        if u not in existing.affected_urls:
                            existing.affected_urls.append(u)
                    # Keep confirmed confidence if any duplicate was confirmed
                    if finding.confidence == Confidence.CONFIRMED:
                        existing.confidence = Confidence.CONFIRMED

            mod.findings = list(deduped.values())

    async def scan(
        self,
        target: ScanTarget,
        on_module_start: Optional[Callable[[BaseModule], None]] = None,
        on_module_complete: Optional[Callable[[BaseModule, ModuleResult], None]] = None,
    ) -> ScanResult:
        """
        Execute all registered security audit modules against the given target.
        """
        started_at = datetime.now(timezone.utc)
        start_mono = time.monotonic()

        async with HttpClient.for_target(target, verify_ssl=self.verify_ssl) as client:
            semaphore = asyncio.Semaphore(self.concurrency)

            async def _run_single(mod: BaseModule) -> ModuleResult:
                if on_module_start:
                    on_module_start(mod)
                async with semaphore:
                    result = await mod.execute(target, client)
                if on_module_complete:
                    on_module_complete(mod, result)
                return result

            # Run all active modules
            tasks = [_run_single(mod) for mod in self.modules if mod.enabled]
            module_results = await asyncio.gather(*tasks)

        completed_at = datetime.now(timezone.utc)
        duration = round(time.monotonic() - start_mono, 3)

        # 1. Deduplicate identical findings
        self.deduplicate_findings(module_results)

        # 2. Apply .armorscanignore suppressions
        for mod in module_results:
            self.suppression_engine.apply_to_findings(mod.findings, target.raw_url)

        # 3. Calculate score & summary (ignoring suppressed findings)
        summary = ScoringEngine.calculate_summary(module_results)

        return ScanResult(
            target=target,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            summary=summary,
            modules=module_results,
        )
