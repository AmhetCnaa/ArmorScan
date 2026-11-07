"""
Open Redirect & Unvalidated Navigation Audit Module for ArmorScan.
Tests authentication and navigation parameters for unvalidated external redirects
that can be weaponized in phishing and credential-harvesting campaigns.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from armorscan.core.client import HttpClient, HttpResponse
from armorscan.core.models import Confidence, Finding, ModuleResult, ScanTarget, Severity
from armorscan.modules.base import BaseModule
from armorscan.remediations.templates import get_open_redirect_remediations

REDIRECT_PARAMS = [
    "next",
    "redirect",
    "redirect_uri",
    "return",
    "url",
    "to",
    "goto",
    "dest",
    "target",
    "continue",
    "forward",
    "r",
]

TEST_EXTERNAL_URL = "https://example.com/armorscan-test"
TEST_PROTOCOL_RELATIVE = "//example.com/armorscan-test"
TEST_ALLOWLIST_BYPASS = "https://example.com/armorscan-test?p=https://github.com/juice-shop/juice-shop"


class OpenRedirectModule(BaseModule):
    """Audits targets for unvalidated external redirection vulnerabilities."""

    name: str = "redirect"
    display_name: str = "Open Redirect & Navigation Security"
    description: str = "Probes redirection parameters to detect unvalidated external URL redirects."

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        parsed_url = urlparse(target.raw_url)
        existing_params = parse_qs(parsed_url.query)

        # Test existing query parameters first
        tested_params: Set[str] = set()
        for p in existing_params.keys():
            if p.lower() in REDIRECT_PARAMS:
                tested_params.add(p)
                await self._test_param_redirect(target, client, p, findings, passed_checks)

        # If none in current URL, probe top candidate parameters
        if not tested_params:
            for p in REDIRECT_PARAMS[:4]:
                await self._test_param_redirect(target, client, p, findings, passed_checks)
            # Also check dedicated /redirect?to= endpoint if scanning root
            if parsed_url.path in ("/", "") and not findings:
                redirect_target = ScanTarget.from_url(f"{target.base_url}/redirect")
                await self._test_param_redirect(redirect_target, client, "to", findings, passed_checks)

        if not findings and passed_checks:
            passed_checks.append("no-open-redirect-detected")

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )

    async def _test_param_redirect(
        self,
        target: ScanTarget,
        client: HttpClient,
        param_name: str,
        findings: List[Finding],
        passed_checks: List[str],
    ) -> None:
        for payload in (TEST_EXTERNAL_URL, TEST_PROTOCOL_RELATIVE, TEST_ALLOWLIST_BYPASS):
            probe_url = self._build_probe_url(target.raw_url, param_name, payload)
            # Crucial: follow_redirects=False to inspect the raw Location header
            resp = await client.get(probe_url, follow_redirects=False)

            if not resp.ok:
                continue

            status = resp.status_code
            location = resp.headers.get("location", "").strip()

            # 1. Check HTTP 3xx Location header
            if status in (301, 302, 303, 307, 308) and location:
                if location.startswith(TEST_EXTERNAL_URL) or location.startswith(TEST_PROTOCOL_RELATIVE) or "example.com/armorscan-test" in location:
                    curl_cmd = Finding.build_curl("GET", probe_url)
                    req_snippet = f"GET {probe_url} HTTP/1.1\nHost: {target.host}\nUser-Agent: {client.user_agent}"
                    resp_snippet = f"HTTP/1.1 {status} Found\nLocation: {location}\nContent-Length: {len(resp.text)}"
                    findings.append(
                        Finding(
                            id="OPEN_REDIRECT_UNVALIDATED",
                            title=f"High Risk: Unvalidated Open Redirect via Parameter '{param_name}'",
                            description=(
                                f"The target allows external redirection to '{location}' when parameter "
                                f"'{param_name}' is manipulated with arbitrary external URLs."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.CONFIRMED,
                            module=self.name,
                            impact=(
                                "Phishing & Credential Theft: Attackers craft trusted-looking links on your domain "
                                f"(e.g. {target.base_url}/login?{param_name}=https://evil.com) that redirect unsuspecting "
                                "users to rogue phishing pages, stealing session tokens and credentials."
                            ),
                            evidence=f"GET {probe_url} -> HTTP {status} Location: {location}",
                            curl_command=curl_cmd,
                            request_snippet=req_snippet,
                            response_snippet=resp_snippet,
                            affected_urls=[target.raw_url],
                            remediation="Validate redirect destinations against an explicit whitelist or enforce relative paths (/...).",
                            remediation_snippets=get_open_redirect_remediations(),
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
                            cwe_id="CWE-601",
                            owasp_category="A01:2021-Broken Access Control",
                        )
                    )
                    return  # Found on this param, move to next

            # 2. Check HTML Meta Refresh or JS location redirection
            if resp.status_code == 200 and resp.text:
                if re.search(r"""<meta\s+http-equiv=["']refresh["']\s+content=["'][^"']*example\.com/armorscan-test""", resp.text, re.IGNORECASE):
                    curl_cmd = Finding.build_curl("GET", probe_url)
                    req_snippet = f"GET {probe_url} HTTP/1.1\nHost: {target.host}\nUser-Agent: {client.user_agent}"
                    context_snippet = Finding.extract_context_snippet(resp.text, "example.com/armorscan-test")
                    findings.append(
                        Finding(
                            id="CLIENT_SIDE_OPEN_REDIRECT",
                            title=f"Client-Side Open Redirect via Meta Refresh ({param_name})",
                            description=f"HTML page executes a client-side redirect to an untrusted external URL via '{param_name}'.",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CONFIRMED,
                            module=self.name,
                            impact="Phishing & credential theft through client-side HTML redirect injection.",
                            evidence=f"Meta refresh redirect to example.com detected in response.",
                            curl_command=curl_cmd,
                            request_snippet=req_snippet,
                            response_snippet=context_snippet,
                            affected_urls=[target.raw_url],
                            remediation="Do not render untrusted URLs in meta refresh tags.",
                            remediation_snippets=get_open_redirect_remediations(),
                            cwe_id="CWE-601",
                        )
                    )
                    return

        passed_checks.append(f"param-{param_name}:redirect-safe")

    def _build_probe_url(self, raw_url: str, param: str, value: str) -> str:
        parsed = urlparse(raw_url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
