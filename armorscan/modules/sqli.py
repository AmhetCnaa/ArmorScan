"""
Safe Boolean SQL Injection Indication Module for ArmorScan.
Performs strictly non-destructive response differential analysis (1=1 vs 1=2)
without data exfiltration, destructive payloads, or time delays.
Findings are strictly marked as Confidence.TENTATIVE.
"""

from __future__ import annotations

import difflib
from typing import List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from armorscan.core.client import HttpClient, HttpResponse
from armorscan.core.models import Confidence, Finding, ModuleResult, ScanTarget, Severity
from armorscan.modules.base import BaseModule


# Benign boolean test pairs: (true_payload, false_payload)
BOOLEAN_PAIRS = [
    # Pair 1: Quotes and parens for complex expressions (e.g. Products search)
    ("')) OR 1=1--", "')) AND 1=2--"),
    # Pair 2: Standard single-quote string literal
    ("' AND '1'='1", "' AND '1'='2"),
    # Pair 3: Numeric / bare literal
    (" AND 1=1", " AND 1=2"),
]

# Second-pass confirmation pairs: (true_payload_2, false_payload_2)
CONFIRMATION_PAIRS = [
    ("')) OR 2=2--", "')) AND 2=3--"),
    ("' AND '2'='2", "' AND '2'='3"),
    (" AND 2=2", " AND 2=3"),
]


class SqliIndicationModule(BaseModule):
    """
    Audits parameters for SQL Injection indications using benign boolean differentials.
    Compares server responses between boolean TRUE and boolean FALSE conditions.
    """

    name: str = "sqli"
    display_name: str = "SQL Injection Boolean Differential Auditor"
    description: str = "Probes parameters for boolean response divergence (1=1 vs 1=2) without data exfiltration."

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        parsed_url = urlparse(target.raw_url)
        query_params = parse_qs(parsed_url.query)

        # Candidate URLs to test: target raw_url + known common search/filter paths if testing base URL
        targets_to_evaluate: List[Tuple[str, str, str]] = []  # (full_url, param_name, param_val)

        if query_params:
            for p_name, p_vals in query_params.items():
                val = p_vals[0] if p_vals else "1"
                targets_to_evaluate.append((target.raw_url, p_name, val))
        else:
            # Common REST API search endpoints if scanning on root/base
            search_paths = [
                "/rest/products/search?q=apple",
                "/api/Products?name=apple",
                "/search?q=test",
            ]
            for sp in search_paths:
                full_sp = f"{target.base_url.rstrip('/')}{sp}"
                sp_parsed = urlparse(full_sp)
                sp_qs = parse_qs(sp_parsed.query)
                for sp_name, sp_vals in sp_qs.items():
                    targets_to_evaluate.append((full_sp, sp_name, sp_vals[0] if sp_vals else "test"))

        tested_params: Set[str] = set()

        for test_url, param_name, base_val in targets_to_evaluate:
            param_key = f"{test_url}:{param_name}"
            if param_key in tested_params:
                continue
            tested_params.add(param_key)

            # Baseline request
            resp_base = await client.get(test_url)
            if not resp_base.ok:
                continue

            for i, (true_suffix, false_suffix) in enumerate(BOOLEAN_PAIRS):
                url_true = self._build_param_url(test_url, param_name, base_val + true_suffix)
                url_false = self._build_param_url(test_url, param_name, base_val + false_suffix)

                resp_true = await client.get(url_true)
                resp_false = await client.get(url_false)

                if not resp_true.ok or not resp_false.ok:
                    continue

                # Analyze differential
                is_diff, diff_reason = self._is_boolean_differential(
                    resp_base, resp_true, resp_false
                )

                if is_diff:
                    # Pass 2: Confirm with alternative numbers (2=2 vs 2=3) to prevent false positives
                    c_true_suffix, c_false_suffix = CONFIRMATION_PAIRS[i]
                    c_url_true = self._build_param_url(test_url, param_name, base_val + c_true_suffix)
                    c_url_false = self._build_param_url(test_url, param_name, base_val + c_false_suffix)

                    c_resp_true = await client.get(c_url_true)
                    c_resp_false = await client.get(c_url_false)

                    c_is_diff, _ = self._is_boolean_differential(
                        resp_base, c_resp_true, c_resp_false
                    )

                    if c_is_diff:
                        # Confirmed boolean response differential
                        safe_evidence = (
                            f"Parameter '{param_name}' evaluated on {urlparse(test_url).path}. "
                            f"{diff_reason}. "
                            f"Validated across two independent canary iterations (1=1 vs 1=2 and 2=2 vs 2=3)."
                        )
                        curl_repro = (
                            f"# Reproduce benign response differential:\n"
                            f"curl -s '{url_true}' | wc -c   # TRUE condition\n"
                            f"curl -s '{url_false}' | wc -c  # FALSE condition"
                        )

                        findings.append(
                            Finding(
                                id="SQLI_BOOLEAN_DIFFERENCE_SUSPECTED",
                                title=f"Suspected SQL Injection via Boolean Response Differential in '{param_name}'",
                                description=(
                                    f"The application responds with significantly different content length or structure "
                                    f"when injecting benign boolean TRUE (1=1) versus FALSE (1=2) logic into parameter '{param_name}'. "
                                    "No data extraction, stacked queries, or time delays were performed."
                                ),
                                severity=Severity.HIGH,
                                confidence=Confidence.TENTATIVE,
                                module=self.name,
                                impact=(
                                    "May allow unauthorized database querying, authentication bypass, or data exposure "
                                    "if user input is concatenated directly into backend SQL queries."
                                ),
                                evidence=safe_evidence,
                                curl_command=curl_repro,
                                remediation=(
                                    "Use parameterized queries (prepared statements) or an ORM with automatic parameter binding. "
                                    "Never concatenate raw user input into SQL commands."
                                ),
                                cwe_id="CWE-89",
                                owasp_category="A03:2021-Injection",
                            )
                        )
                        break

            if not any(f.id == "SQLI_BOOLEAN_DIFFERENCE_SUSPECTED" for f in findings):
                passed_checks.append(f"sqli-boolean-clean-{param_name}")

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )

    def _is_boolean_differential(
        self,
        base_resp: HttpResponse,
        true_resp: HttpResponse,
        false_resp: HttpResponse,
    ) -> Tuple[bool, str]:
        """
        Evaluate if true_resp and false_resp demonstrate consistent boolean behavior.
        TRUE response should match or return content; FALSE response should return empty/different content.
        """
        # If response codes differ (e.g. 200 vs 404/500/400)
        if true_resp.status_code == 200 and false_resp.status_code != 200:
            return True, f"TRUE condition returned HTTP 200 while FALSE condition returned HTTP {false_resp.status_code}"

        len_true = len(true_resp.text)
        len_false = len(false_resp.text)
        diff_bytes = abs(len_true - len_false)

        # Case 1: JSON response where FALSE condition returns empty list or data: []
        if "data" in false_resp.text:
            if '"data":[]' in false_resp.text or '"data": []' in false_resp.text:
                if len_true > len_false + 50:
                    return True, f"TRUE condition returned {len_true} bytes of records while FALSE condition returned empty data array ({len_false} bytes)"

        # Case 2: Significant length difference
        if len_true > 200 and diff_bytes > 150:
            # Check similarity ratio
            similarity = difflib.SequenceMatcher(None, true_resp.text[:500], false_resp.text[:500]).ratio()
            if similarity < 0.70:
                return True, f"Significant length and structural divergence (TRUE: {len_true}B vs FALSE: {len_false}B, diff: {diff_bytes}B)"

        return False, ""

    def _build_param_url(self, base_url: str, param_name: str, new_val: str) -> str:
        """Inject new parameter value into URL query string."""
        parsed = urlparse(base_url)
        qs = parse_qs(parsed.query)
        qs[param_name] = [new_val]
        new_query = urlencode(qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
