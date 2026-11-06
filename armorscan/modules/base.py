"""
Base module definition for ArmorScan plugins.
All security audit modules inherit from BaseModule.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import time
from typing import List, Optional

from armorscan.core.client import HttpClient
from armorscan.core.models import Finding, ModuleResult, ScanTarget


class BaseModule(ABC):
    """Abstract base class for all ArmorScan security checking modules."""

    name: str = "base"
    display_name: str = "Base Security Module"
    description: str = "Abstract security module"
    enabled: bool = True

    async def execute(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        """
        Execute the module with timing instrumentation and safe exception handling.
        """
        start_time = time.monotonic()
        try:
            result = await self.run(target, client)
            result.duration_seconds = round(time.monotonic() - start_time, 3)
            return result
        except Exception as e:
            duration = round(time.monotonic() - start_time, 3)
            return ModuleResult(
                module_name=self.name,
                display_name=self.display_name,
                duration_seconds=duration,
                findings=[],
                passed_checks=[],
                error=f"{type(e).__name__}: {str(e)}",
            )

    @abstractmethod
    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        """Core audit logic to be implemented by each module."""
        raise NotImplementedError
