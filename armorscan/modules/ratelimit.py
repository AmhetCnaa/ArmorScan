"""
Rate Limiting & DoS Resilience Audit Module for ArmorScan.
Executes non-destructive, bounded concurrent bursts to verify HTTP 429 throttling
and inspects standard and vendor RateLimit headers.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set
import httpx

from armorscan.core.client import HttpClient, HttpResponse
from armorscan.core.models import Finding, ModuleResult, ScanTarget, Severity
from armorscan.modules.base import BaseModule
from armorscan.remediations.templates import get_rate_limit_remediations

RATE_LIMIT_HEADERS = [
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "retry-after",
]


class RateLimitModule(BaseModule):
    """Audits targets for rate limiting defenses and anti-brute-force controls."""

    name: str = "ratelimit"
    display_name: str = "Rate Limiting & DoS Resilience Audit"
    description: str = "Tests for HTTP 429 throttling and inspects RateLimit headers using a controlled burst."

    def __init__(self, burst_count: int = 18, concurrency: int = 10):
        self.burst_count = burst_count
        self.concurrency = concurrency

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        url = target.raw_url
        probe_urls = [url] * self.burst_count

        # Execute safe, bounded concurrent burst
        responses = await client.burst_requests(probe_urls, concurrency=self.concurrency)

        status_counts: Dict[int, int] = {}
        detected_headers: Dict[str, str] = {}
        throttled_count = 0

        for r in responses:
            if not r.ok and not r.headers:
                continue

            status = r.status_code
            status_counts[status] = status_counts.get(status, 0) + 1

            if status in (429, 503):
                throttled_count += 1

            # Check for RateLimit headers
            for header_name in RATE_LIMIT_HEADERS:
                val = r.headers.get(header_name)
                if val:
                    detected_headers[header_name] = val

        # Evaluate Results
        if throttled_count > 0:
            passed_checks.append(f"rate-limiting-enforced ({throttled_count}/{len(responses)} requests throttled with HTTP 429/503)")
        elif detected_headers:
            header_summary = ", ".join(f"{k}: {v}" for k, v in list(detected_headers.items())[:3])
            passed_checks.append(f"rate-limiting-headers-active ({header_summary})")
        else:
            success_count = status_counts.get(200, 0)
            total_valid = sum(status_counts.values())

            findings.append(
                Finding(
                    id="MISSING_RATE_LIMITING",
                    title="Missing Rate Limiting & DoS Throttling Defenses",
                    description=(
                        f"The target processed {total_valid} rapid concurrent requests without triggering "
                        "HTTP 429 (Too Many Requests) and without returning any RateLimit-* or X-RateLimit-* headers."
                    ),
                    severity=Severity.MEDIUM,
                    module=self.name,
                    impact=(
                        "Automated attack exposure: Lack of request throttling allows attackers to perform "
                        "credential brute-forcing, password spraying, automated data scraping, and Layer-7 resource exhaustion."
                    ),
                    evidence=(
                        f"Burst test sent {self.burst_count} concurrent requests.\n"
                        f"Response statuses: {status_counts}\n"
                        "Rate-limiting headers: None detected"
                    ),
                    remediation="Deploy rate-limiting middleware or configure reverse-proxy throttling (e.g. Nginx limit_req, express-rate-limit, slowapi).",
                    remediation_snippets=get_rate_limit_remediations(),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/429",
                    ],
                    cwe_id="CWE-770",
                    owasp_category="A04:2021-Insecure Design",
                )
            )

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )
