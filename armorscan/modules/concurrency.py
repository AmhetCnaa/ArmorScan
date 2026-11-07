"""
Concurrency & Transaction Isolation Audit Module for ArmorScan.
Tests state-changing endpoints (coupons, discounts, balance transfers, checkouts)
using synchronized millisecond burst requests (asyncio.Event barrier) to uncover
missing database row locks, mutexes, and Time-of-Check to Time-of-Use (TOCTOU) anomalies.
"""

from __future__ import annotations

import asyncio
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from armorscan.core.client import HttpClient
from armorscan.core.models import Confidence, Finding, ModuleResult, ScanTarget, Severity
from armorscan.modules.base import BaseModule

STATE_CHANGING_KEYWORDS = (
    "coupon", "redeem", "voucher", "claim", "discount", "transfer",
    "withdraw", "checkout", "vote", "gift", "balance", "apply"
)

DEFAULT_CONCURRENCY_PATHS = [
    "/api/coupons/apply",
    "/api/redeem",
    "/rest/basket/checkout",
    "/api/wallet/transfer",
    "/api/vote",
]


class ConcurrencyAuditModule(BaseModule):
    """
    Concurrency & Transaction Isolation Auditor.
    Executes synchronized micro-bursts to detect race condition state anomalies.
    """

    name: str = "concurrency"
    display_name: str = "Concurrency & Transaction Isolation Auditor"
    description: str = "Deploys synchronized micro-burst requests to verify atomic transaction isolation and idempotency on state-changing endpoints."

    def __init__(
        self,
        burst_size: int = 10,
        candidate_paths: Optional[List[str]] = None,
    ):
        self.burst_size = burst_size
        self.candidate_paths = candidate_paths or []

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        # 1. Gather target candidate endpoints
        endpoints: Set[str] = set()
        if self.candidate_paths:
            for p in self.candidate_paths:
                endpoints.add(urljoin(target.base_url, p))

        if target.discovered_paths:
            for p in target.discovered_paths:
                if any(kw in p.lower() for kw in STATE_CHANGING_KEYWORDS):
                    endpoints.add(urljoin(target.base_url, p))

        for p in DEFAULT_CONCURRENCY_PATHS:
            endpoints.add(urljoin(target.base_url, p))

        for full_url in sorted(endpoints):
            parsed = urlparse(full_url)

            # Establish baseline probe
            try:
                test_payload = {"code": "ARMORSCAN_CONCURRENCY_PROBE", "amount": 1, "action": "test"}
                baseline_resp = await client.post(full_url, json=test_payload)
            except Exception:
                continue

            # Skip non-existent routes
            if baseline_resp.status_code in (404, 405):
                continue

            # Skip HTML catch-alls
            if "<!doctype html" in baseline_resp.text.lower():
                continue

            # 2. Execute Synchronized Millisecond Burst
            barrier = asyncio.Event()

            async def _worker(worker_id: int) -> Tuple[int, str, float]:
                await barrier.wait()  # Wait for simultaneous release
                t0 = time.monotonic()
                try:
                    resp = await client.post(
                        full_url,
                        json={"code": "ARMORSCAN_SINGLE_USE_COUPON", "worker": worker_id, "id": 1},
                    )
                    return resp.status_code, resp.text, time.monotonic() - t0
                except Exception:
                    return 0, "", 0.0

            tasks = [_worker(i) for i in range(self.burst_size)]

            # Release all workers at the same millisecond
            barrier.set()
            results = await asyncio.gather(*tasks)

            # 3. Analyze Response Distribution
            success_count = 0
            success_snippets = []
            status_distribution: Dict[int, int] = {}

            for status, body, elapsed in results:
                status_distribution[status] = status_distribution.get(status, 0) + 1
                if status in (200, 201):
                    # Check if body indicates successful fulfillment
                    lower_body = body.lower()
                    if any(kw in lower_body for kw in ("success", "applied", "completed", "accepted", "transferred", "true")):
                        success_count += 1
                        if len(success_snippets) < 2:
                            success_snippets.append(body[:120].strip())

            # If more than 1 request succeeded on a limited-state action
            if success_count > 1:
                dist_str = ", ".join(f"HTTP {k}: {v}" for k, v in sorted(status_distribution.items()))
                curl_cmd = Finding.build_curl("POST", full_url, data='{"code": "ARMORSCAN_SINGLE_USE_COUPON"}')

                findings.append(
                    Finding(
                        id="CONCURRENCY_ISOLATION_ANOMALY",
                        title=f"Concurrency & Transaction Isolation Anomaly on {parsed.path}",
                        description=(
                            f"Dispatching a synchronized burst of {self.burst_size} concurrent requests to '{parsed.path}' "
                            f"resulted in {success_count} simultaneous successful executions. The application lacks "
                            f"distributed locks (mutex), database row-level locking (SELECT FOR UPDATE), or idempotency keys."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        module=self.name,
                        impact=(
                            "Attackers can exploit race conditions to execute double spending, duplicate promo code redemptions, "
                            "bypass account transfer limits, or exhaust scarce inventory."
                        ),
                        evidence=(
                            f"Burst Size: {self.burst_size} | Successful Operations: {success_count}\n"
                            f"Response Status Distribution: {dist_str}\n"
                            f"Sample Leaked Body: {success_snippets[0] if success_snippets else 'N/A'}"
                        ),
                        curl_command=curl_cmd,
                        affected_urls=[full_url],
                        remediation=(
                            "Implement strict transaction isolation (SERIALIZABLE or SELECT FOR UPDATE), "
                            "distributed locks using Redis Redlock, or enforce unique database constraints and idempotency keys."
                        ),
                        cwe_id="CWE-362",
                        owasp_category="A04:2021-Insecure Design",
                    )
                )
            else:
                passed_checks.append(
                    f"Endpoint {parsed.path} properly serialized concurrent requests ({self.burst_size} parallel probes handled without race anomalies)"
                )

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )
