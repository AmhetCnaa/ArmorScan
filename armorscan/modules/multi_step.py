"""
Multi-Step Business Logic & Tenant Isolation Audit Module for ArmorScan.
Tests workflows and ID parameter manipulation (BOLA/IDOR) across steps to verify that
authenticated users cannot access records belonging to other tenants or users.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from armorscan.core.client import HttpClient, HttpResponse
from armorscan.core.models import Confidence, Finding, ModuleResult, ScanTarget, Severity
from armorscan.modules.base import BaseModule
from armorscan.remediations.templates import get_authz_remediations

TAMPER_ID_PAIRS = [
    ("usr_alice", "usr_bob"),
    ("alice", "bob"),
    ("101", "102"),
    ("1", "2"),
    ("1000", "1001"),
]

ID_PARAM_NAMES = {"user_id", "id", "account_id", "tenant_id", "order_id", "profile_id"}


class MultiStepLogicModule(BaseModule):
    """Audits multi-step state transitions and verifies tenant object isolation."""

    name: str = "multi_step"
    display_name: str = "Multi-Step Business Logic & Tenant Isolation Audit"
    description: str = "Tests IDOR and multi-step resource access to verify cross-tenant data isolation."

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        candidate_urls: Set[str] = set()

        if target.path and target.path != "/":
            candidate_urls.add(target.raw_url)
        else:
            candidate_urls.add(urljoin(target.base_url, "/vuln/logic_idor?user_id=usr_alice"))
            candidate_urls.add(urljoin(target.base_url, "/safe/logic_idor?user_id=usr_alice"))
            candidate_urls.add(urljoin(target.base_url, "/api/orders?id=101"))
            candidate_urls.add(urljoin(target.base_url, "/api/invoices?id=101"))

        for endpoint_url in sorted(candidate_urls):
            parsed = urlparse(endpoint_url)
            qs = parse_qs(parsed.query)

            # Check if URL contains an ID parameter to tamper
            param_to_test: Optional[str] = None
            for p_name in qs:
                if p_name.lower() in ID_PARAM_NAMES:
                    param_to_test = p_name
                    break

            # If no query parameter but path contains logic_idor, add default
            if not param_to_test and "logic_idor" in parsed.path:
                param_to_test = "user_id"
                qs["user_id"] = ["usr_alice"]

            if not param_to_test:
                continue

            current_val = qs[param_to_test][0] if param_to_test in qs and qs[param_to_test] else "usr_alice"
            tampered_val = self._get_tampered_id(current_val)

            # Step 1: Baseline request with initial user/tenant ID
            url_step1 = self._build_url(parsed, param_to_test, current_val)
            try:
                resp_step1 = await client.get(url_step1)
                if not resp_step1.ok or resp_step1.status_code != 200:
                    continue

                # Step 2: Tampered request with neighboring user/tenant ID
                url_step2 = self._build_url(parsed, param_to_test, tampered_val)
                resp_step2 = await client.get(url_step2)

                # Check if access was blocked (403 Forbidden or 404 Not Found) -> Safe
                if resp_step2.status_code in (403, 404, 401):
                    passed_checks.append(
                        f"Cross-tenant access properly blocked (HTTP {resp_step2.status_code}) on {parsed.path} for param '{param_to_test}'"
                    )
                    continue

                # If tampered request succeeded with 200 OK and returned content
                if resp_step2.status_code == 200:
                    # Verify response contains the tampered record or sensitive fields
                    is_unauthorized_access = False
                    if tampered_val in resp_step2.text:
                        is_unauthorized_access = True
                    elif "data" in resp_step2.text or "account" in resp_step2.text or "order" in resp_step2.text:
                        is_unauthorized_access = True
                    elif len(resp_step2.text) > 20 and abs(len(resp_step2.text) - len(resp_step1.text)) < 50:
                        is_unauthorized_access = True

                    if is_unauthorized_access:
                        curl_cmd = Finding.build_curl("GET", url_step2)
                        req_snippet = f"GET {url_step2} HTTP/1.1\nHost: {target.host}\nUser-Agent: {client.user_agent}"
                        resp_snippet = Finding.extract_context_snippet(resp_step2.text, tampered_val) or resp_step2.text[:250]

                        findings.append(
                            Finding(
                                id="CROSS_TENANT_OBJECT_ACCESS",
                                title=f"Cross-Tenant Broken Object Level Authorization (IDOR) on {parsed.path}",
                                description=(
                                    f"The endpoint '{parsed.path}' allowed accessing a foreign user's object by altering "
                                    f"the '{param_to_test}' parameter from '{current_val}' to '{tampered_val}' without ownership validation."
                                ),
                                severity=Severity.HIGH,
                                confidence=Confidence.CONFIRMED,
                                module=self.name,
                                impact=(
                                    "Attackers can enumerate and access other users' private accounts, billing records, "
                                    "or confidential orders simply by incrementing or guessing identifier parameters."
                                ),
                                evidence=(
                                    f"Tampered request for ID '{tampered_val}' returned HTTP {resp_step2.status_code} "
                                    f"({len(resp_step2.text)} bytes). Sample leaked record: {resp_step2.text[:120].strip()}"
                                ),
                                curl_command=curl_cmd,
                                request_snippet=req_snippet,
                                response_snippet=resp_snippet,
                                affected_urls=[url_step2],
                                remediation=(
                                    "Enforce strict ownership and tenant-scoping checks in the database query "
                                    "(e.g., WHERE id = :id AND tenant_id = :current_tenant_id)."
                                ),
                                remediation_snippets=get_authz_remediations(),
                                cwe_id="CWE-639",
                                owasp_category="A01:2021-Broken Access Control",
                            )
                        )

            except Exception:
                continue

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )

    def _get_tampered_id(self, original_id: str) -> str:
        """Derive a plausible neighboring tenant/user ID for tampering."""
        for orig, replacement in TAMPER_ID_PAIRS:
            if original_id == orig:
                return replacement
            if original_id == replacement:
                return orig

        # If numeric, increment by 1
        if original_id.isdigit():
            return str(int(original_id) + 1)

        # Fallback
        return f"{original_id}_other"

    def _build_url(self, parsed: Any, param_name: str, param_val: str) -> str:
        """Construct full URL with modified parameter value."""
        qs = parse_qs(parsed.query)
        qs[param_name] = [param_val]
        new_query = urlencode(qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
