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
from armorscan.core.models import ModuleResult, ScanResult, ScanTarget
from armorscan.core.scoring import ScoringEngine
from armorscan.modules.base import BaseModule


class ScanRunner:
    """Orchestrates security modules, handles timeouts, and compiles scan results."""

    def __init__(
        self,
        modules: Optional[List[BaseModule]] = None,
        verify_ssl: bool = True,
        timeout: float = 10.0,
        concurrency: int = 5,
    ):
        self.modules: List[BaseModule] = modules or []
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.concurrency = concurrency

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

        summary = ScoringEngine.calculate_summary(module_results)

        return ScanResult(
            target=target,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            summary=summary,
            modules=module_results,
        )
