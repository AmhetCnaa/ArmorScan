"""
Broken Object Level Authorization (BOLA) & Authentication Gate Audit Module for ArmorScan.
Tests candidate private and sensitive endpoints with and without authentication credentials
to detect missing authorization gates and unprotected data exposures.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from armorscan.core.client import HttpClient, HttpResponse
from armorscan.core.models import Confidence, Finding, ModuleResult, ScanTarget, Severity
from armorscan.modules.base import BaseModule
from armorscan.remediations.templates import get_authz_remediations

PRIVATE_CANDIDATE_PATHS = [
    "/vuln/idor",
    "/safe/idor",
    "/api/me",
    "/api/user/profile",
    "/api/account",
    "/api/v1/user",
    "/dashboard/profile",
    "/rest/admin/application-configuration",
]

SENSITIVE_BODY_PATTERNS = [
    re.compile(r"""["'](?:user_id|username|email|role|balance|private_notes|account_number|credit_card|ctfKey|cookieSecret)["']\s*:""", re.IGNORECASE),
    re.compile(r"""\b(?:billing_administrator|confidential account data|internal audit record)\b""", re.IGNORECASE),
]


class AuthzCheckModule(BaseModule):
    """Audits endpoints for missing authentication gates and BOLA/IDOR vulnerabilities."""

    name: str = "authz_check"
    display_name: str = "Authorization & Authentication Gate Audit"
    description: str = "Probes private endpoints to verify that authentication gates are strictly enforced."

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        # 1. Collect candidate endpoints to audit
        candidate_urls: Set[str] = set()

        # If scan target points to a specific endpoint, only test that targeted endpoint
        if target.path and target.path != "/":
            candidate_urls.add(target.raw_url)
        else:
            # Root site audit: probe common candidate private routes
            for path in PRIVATE_CANDIDATE_PATHS:
                candidate_urls.add(urljoin(target.base_url, path))

        # 2. Probe candidate endpoints
        for endpoint_url in sorted(candidate_urls):
            path_part = urlparse(endpoint_url).path

            try:
                # Send authenticated request
                resp_auth = await client.get(endpoint_url)

                # If authenticated request is completely not found (404), skip
                if resp_auth.status_code == 404:
                    continue

                # Send unauthenticated request (no auth headers, no session cookies, don't follow redirect)
                resp_unauth = await client.get_unauthenticated(endpoint_url, follow_redirects=False)

                # Case 1: Unauthenticated request is rejected (401 / 403) -> PASS
                if resp_unauth.status_code in (401, 403):
                    passed_checks.append(
                        f"Authentication gate properly enforced (HTTP {resp_unauth.status_code}) on {path_part}"
                    )
                    continue

                # Case 2: Unauthenticated request redirects to login page -> PASS
                if resp_unauth.status_code in (301, 302, 303, 307, 308):
                    loc = resp_unauth.headers.get("location", "").lower()
                    if any(term in loc for term in ("login", "auth", "signin")):
                        passed_checks.append(
                            f"Unauthenticated request safely redirected to login ({loc}) on {path_part}"
                        )
                        continue

                # Case 3: Unauthenticated request returns HTTP 200 OK -> Investigate for Missing Auth Gate
                if resp_unauth.status_code == 200:
                    is_html = self._is_html(resp_unauth)
                    is_sensitive = self._is_sensitive_response(resp_unauth.text, path_part, is_html=is_html)

                    # Length similarity only applies to JSON/API responses, not static SPA HTML shells
                    length_similar = (
                        not is_html
                        and resp_auth.status_code == 200
                        and abs(len(resp_auth.text) - len(resp_unauth.text)) < 50
                        and len(resp_unauth.text) > 30
                    )

                    if is_sensitive or (length_similar and "idor" in path_part.lower()):
                        sample_match = self._find_sample_pattern(resp_unauth.text)
                        context_snippet = (
                            Finding.extract_context_snippet(resp_unauth.text, sample_match)
                            if sample_match
                            else resp_unauth.text[:250]
                        )
                        curl_cmd = Finding.build_curl("GET", endpoint_url)
                        req_snippet = f"GET {endpoint_url} HTTP/1.1\nHost: {target.host}\nUser-Agent: {client.user_agent}"

                        findings.append(
                            Finding(
                                id="MISSING_AUTHENTICATION_GATE",
                                title=f"Missing Authentication Gate on Sensitive Endpoint: {path_part}",
                                description=(
                                    f"The sensitive endpoint '{path_part}' returned HTTP 200 OK with private user/account data "
                                    f"when accessed without any authentication headers or session cookies."
                                ),
                                severity=Severity.CRITICAL,
                                confidence=Confidence.CONFIRMED,
                                module=self.name,
                                impact=(
                                    "Unauthenticated external attackers can access confidential user accounts, private profile data, "
                                    "or administrative endpoints without authentication (Broken Object Level Authorization / BOLA)."
                                ),
                                evidence=(
                                    f"Unauthenticated HTTP 200 response ({len(resp_unauth.text)} bytes). "
                                    f"Response excerpt: {resp_unauth.text[:120].strip()}"
                                ),
                                curl_command=curl_cmd,
                                request_snippet=req_snippet,
                                response_snippet=context_snippet,
                                affected_urls=[endpoint_url],
                                remediation=(
                                    "Enforce mandatory server-side authentication middleware/guards on all private API routes "
                                    "before processing requests."
                                ),
                                remediation_snippets=get_authz_remediations(),
                                cwe_id="CWE-306",
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

    def _is_html(self, resp: HttpResponse) -> bool:
        ct = resp.headers.get("content-type", "").lower()
        if "text/html" in ct:
            return True
        t = resp.text.strip().lower()
        return t.startswith("<!doctype html") or t.startswith("<html")

    def _is_sensitive_response(self, text: str, path: str, is_html: bool = False) -> bool:
        """Check if response body exhibits clear attributes of private user or account data."""
        if is_html:
            # HTML pages (like SPA shells) only qualify if explicit sensitive patterns match
            return any(pat.search(text) for pat in SENSITIVE_BODY_PATTERNS)

        if any(pat.search(text) for pat in SENSITIVE_BODY_PATTERNS):
            return True

        # Endpoints explicitly named idor/profile/admin returning JSON with keys
        if any(keyword in path.lower() for keyword in ("idor", "profile", "account", "me", "admin")):
            if "{" in text and any(k in text for k in ("user", "email", "id", "role", "config", "server", "securityQuestions")):
                return True

        return False

    def _find_sample_pattern(self, text: str) -> str:
        """Find a sample matching substring for context snippet extraction."""
        for pat in SENSITIVE_BODY_PATTERNS:
            m = pat.search(text)
            if m:
                return m.group(0)
        for term in ("username", "user_id", "email", "balance", "role", "user"):
            if term in text:
                return term
        return ""
