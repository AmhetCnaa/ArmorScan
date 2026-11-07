"""
API Fuzzing & Anomaly Crash Detection Module for ArmorScan.
Tests parameter boundaries, type confusion, and numeric/string extremes using
safe, non-destructive payloads to detect unhandled exceptions (HTTP 500) and
resource exhaustion lag anomalies.
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from armorscan.core.client import HttpClient, HttpResponse
from armorscan.core.models import Confidence, Finding, ModuleResult, ScanTarget, Severity
from armorscan.modules.base import BaseModule

# Safe, non-destructive fuzz vectors
NUMERIC_PAYLOADS = [
    ("MAX_INT64", "9223372036854775807"),
    ("MIN_INT64", "-9223372036854775808"),
    ("NEGATIVE_ONE", "-1"),
    ("FLOAT_EPSILON", "0.0000001"),
    ("NAN_NOTATION", "NaN"),
]

STRING_PAYLOADS = [
    ("BUFFER_1K", "A" * 1024),
    ("UNICODE_RTL", "\u202Earmorscan_fuzz\u202C"),
    ("NULL_BYTE_ENC", "%00canary"),
    ("EMPTY_STRING", ""),
]

JSON_TYPE_PAYLOADS = [
    ("EMPTY_OBJECT", {}),
    ("EMPTY_ARRAY", []),
    ("NULL_VALUE", None),
]

DEFAULT_FUZZ_PATHS = [
    "/api/search?q=test",
    "/api/products?id=1",
    "/api/users?page=1",
    "/rest/products/search?q=apple",
]


class ApiFuzzerModule(BaseModule):
    """
    Non-destructive API Fuzzing & Crash Anomaly Detector.
    Probes input boundaries to uncover unhandled 500 exceptions and CPU lag.
    """

    name: str = "fuzzer"
    display_name: str = "API Fuzzing & Anomaly Crash Detector"
    description: str = "Probes parameters with extreme numerical bounds, long buffers, and type mutations to identify 500 errors and resource lag."

    def __init__(self, target_endpoints: Optional[List[str]] = None):
        self.target_endpoints = target_endpoints or []

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        # Gather endpoints to fuzz
        candidate_urls: Set[str] = set()

        # If target URL itself has query parameters, fuzz it
        parsed_target = urlparse(target.raw_url)
        if parsed_target.query:
            candidate_urls.add(target.raw_url)

        if self.target_endpoints:
            for ep in self.target_endpoints:
                candidate_urls.add(urljoin(target.base_url, ep))

        if target.discovered_paths:
            for p in target.discovered_paths:
                if "?" in p:
                    candidate_urls.add(urljoin(target.base_url, p))

        # Add sensible default candidate paths
        for p in DEFAULT_FUZZ_PATHS:
            candidate_urls.add(urljoin(target.base_url, p))

        for full_url in sorted(candidate_urls):
            parsed = urlparse(full_url)
            qs = parse_qs(parsed.query)

            if not qs:
                continue

            # 1. Establish Baseline Performance
            try:
                t0 = time.monotonic()
                baseline_resp = await client.get(full_url)
                baseline_time = max(0.01, time.monotonic() - t0)
            except Exception:
                continue

            # 0 FP Rule: If baseline itself returns 500 or fails, do not report fuzz anomaly
            if baseline_resp.status_code >= 500:
                continue

            # Fuzz each query parameter
            for param_name, values in qs.items():
                orig_val = values[0] if values else ""
                is_numeric = orig_val.lstrip("-").isdigit()

                payloads_to_test = list(NUMERIC_PAYLOADS if is_numeric else STRING_PAYLOADS)
                # Also test a few boundary values from both
                if is_numeric:
                    payloads_to_test.append(("BUFFER_1K", "A" * 1024))
                else:
                    payloads_to_test.append(("MAX_INT64", "9223372036854775807"))

                for payload_type, payload_val in payloads_to_test:
                    fuzz_qs = dict(qs)
                    fuzz_qs[param_name] = [str(payload_val)]
                    new_query = urlencode(fuzz_qs, doseq=True)
                    fuzz_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        new_query,
                        parsed.fragment,
                    ))

                    try:
                        t_fuzz_start = time.monotonic()
                        fuzz_resp = await client.get(fuzz_url)
                        fuzz_elapsed = time.monotonic() - t_fuzz_start

                        # Anomaly 1: Unhandled Server Exception (HTTP 500/502/503)
                        if fuzz_resp.status_code in (500, 502, 503):
                            curl_cmd = Finding.build_curl("GET", fuzz_url)
                            req_snippet = f"GET {parsed.path}?{new_query} HTTP/1.1\nHost: {target.host}"
                            resp_snippet = fuzz_resp.text[:300].strip()

                            findings.append(
                                Finding(
                                    id="UNHANDLED_EXCEPTION_500_ANOMALY",
                                    title=f"Unhandled Server Exception (HTTP {fuzz_resp.status_code}) during Input Fuzzing on '{param_name}'",
                                    description=(
                                        f"Mutating parameter '{param_name}' with fuzz vector [{payload_type}] "
                                        f"triggered an unhandled internal exception (HTTP {fuzz_resp.status_code}) on {parsed.path}."
                                    ),
                                    severity=Severity.HIGH,
                                    confidence=Confidence.CONFIRMED,
                                    module=self.name,
                                    impact=(
                                        "Unhandled exceptions can crash worker threads, lead to Denial of Service (DoS), "
                                        "or expose underlying database schemas, stack traces, and internal environment details."
                                    ),
                                    evidence=(
                                        f"Baseline status was HTTP {baseline_resp.status_code} ({baseline_time:.2f}s). "
                                        f"Fuzzing with '{payload_type}' returned HTTP {fuzz_resp.status_code}. "
                                        f"Response preview: {resp_snippet[:150]}"
                                    ),
                                    curl_command=curl_cmd,
                                    request_snippet=req_snippet,
                                    response_snippet=resp_snippet,
                                    affected_urls=[fuzz_url],
                                    remediation=(
                                        "Implement strict input validation, type coercion schemas (e.g. Pydantic/Zod), "
                                        "and catch unexpected exceptions in global controller error handlers."
                                    ),
                                    cwe_id="CWE-755",
                                    owasp_category="A04:2021-Insecure Design",
                                )
                            )
                            # Once a 500 crash is found on this param, stop testing this param to avoid spam
                            break

                        # Anomaly 2: Resource Exhaustion / Severe Latency Lag (>10x baseline and > 2.0s)
                        if fuzz_elapsed > (10 * baseline_time) and fuzz_elapsed > 2.0:
                            findings.append(
                                Finding(
                                    id="POTENTIAL_RESOURCE_EXHAUSTION_LAG",
                                    title=f"Potential Resource Exhaustion / CPU Spike Anomaly on '{param_name}'",
                                    description=(
                                        f"Mutating parameter '{param_name}' with fuzz vector [{payload_type}] "
                                        f"caused response latency to spike from {baseline_time:.2f}s to {fuzz_elapsed:.2f}s (>10x degradation)."
                                    ),
                                    severity=Severity.MEDIUM,
                                    confidence=Confidence.TENTATIVE,
                                    module=self.name,
                                    impact=(
                                        "Algorithmic complexity vulnerabilities (ReDoS, expensive unindexed DB queries) "
                                        "can allow unauthenticated attackers to exhaust server CPU and memory with few requests."
                                    ),
                                    evidence=(
                                        f"Baseline elapsed: {baseline_time:.2f}s. Fuzz elapsed: {fuzz_elapsed:.2f}s "
                                        f"using vector [{payload_type}]."
                                    ),
                                    affected_urls=[fuzz_url],
                                    remediation=(
                                        "Enforce strict length limits on string inputs, use timeouts on regex operations, "
                                        "and paginate or index database queries."
                                    ),
                                    cwe_id="CWE-400",
                                    owasp_category="A04:2021-Insecure Design",
                                )
                            )
                            break

                        passed_checks.append(
                            f"Parameter '{param_name}' on {parsed.path} handled [{payload_type}] cleanly (HTTP {fuzz_resp.status_code})"
                        )

                    except Exception:
                        continue

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )
