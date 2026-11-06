"""
Tests for ScanRunner orchestrator.
"""

import pytest
from armorscan.core.client import HttpClient
from armorscan.core.models import Finding, ModuleResult, ScanTarget, Severity
from armorscan.core.runner import ScanRunner
from armorscan.modules.base import BaseModule


class MockPassingModule(BaseModule):
    name = "mock_pass"
    display_name = "Mock Passing Module"

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=[],
            passed_checks=["mock_check_1", "mock_check_2"],
        )


class MockFailingModule(BaseModule):
    name = "mock_fail"
    display_name = "Mock Failing Module"

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        finding = Finding(
            id="MOCK_ERR",
            title="Mock Error",
            description="Mock vulnerability",
            severity=Severity.HIGH,
            module=self.name,
            impact="Mock impact",
        )
        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=[finding],
            passed_checks=[],
        )


@pytest.mark.asyncio
async def test_scan_runner_orchestration():
    target = ScanTarget.from_url("http://127.0.0.1:9999")
    runner = ScanRunner(modules=[MockPassingModule(), MockFailingModule()], concurrency=2)

    started_events = []
    completed_events = []

    result = await runner.scan(
        target=target,
        on_module_start=lambda m: started_events.append(m.name),
        on_module_complete=lambda m, res: completed_events.append(m.name),
    )

    assert len(started_events) == 2
    assert len(completed_events) == 2
    assert len(result.modules) == 2
    assert result.summary.high_count == 1
    assert result.summary.score == 85  # 100 - 15
    assert len(result.all_findings) == 1
    assert result.duration_seconds >= 0
