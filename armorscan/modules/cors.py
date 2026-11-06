"""
CORS Configuration & HTTP Method Security Audit Module for ArmorScan.
Audits Cross-Origin Resource Sharing vulnerabilities (Arbitrary Origin Reflection,
Null Origin Trust, Regex Bypasses, Wildcard with Credentials) and dangerous HTTP methods (TRACE/XST, PUT, DELETE).
"""

from __future__ import annotations

from typing import Dict, List, Optional
import httpx

from armorscan.core.client import HttpClient, HttpResponse
from armorscan.core.models import Finding, ModuleResult, ScanTarget, Severity
from armorscan.modules.base import BaseModule
from armorscan.remediations.templates import (
    get_cors_remediations,
    get_method_security_remediations,
)


class CorsAndMethodModule(BaseModule):
    """Audits targets for CORS misconfigurations and risky HTTP verbs."""

    name: str = "cors"
    display_name: str = "CORS & HTTP Method Security Audit"
    description: str = "Tests for arbitrary origin reflection, null origin trust, and TRACE/XST method enablement."

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        # 1. Test CORS Scenarios
        await self._audit_cors(target, client, findings, passed_checks)

        # 2. Test HTTP Methods (OPTIONS, TRACE)
        await self._audit_http_methods(target, client, findings, passed_checks)

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )

    async def _audit_cors(
        self,
        target: ScanTarget,
        client: HttpClient,
        findings: List[Finding],
        passed_checks: List[str],
    ) -> None:
        evil_origin = "https://evil-attacker.com"
        null_origin = "null"
        post_bypass_origin = f"https://{target.host}.attacker.com"
        pre_bypass_origin = f"https://attacker{target.host}"

        # Probe concurrently with various Origin headers
        test_cases = [
            ("evil", evil_origin),
            ("null", null_origin),
            ("post_bypass", post_bypass_origin),
            ("pre_bypass", pre_bypass_origin),
        ]

        responses: Dict[str, HttpResponse] = {}
        for label, origin in test_cases:
            resp = await client.get(target.raw_url, headers={"Origin": origin})
            responses[label] = resp

        # Also get baseline response without custom Origin
        base_resp = await client.get(target.raw_url)

        # 1.1 Check Wildcard with Credentials conflict on baseline or responses
        acao_base = base_resp.headers.get("access-control-allow-origin", "").strip()
        acac_base = base_resp.headers.get("access-control-allow-credentials", "").strip().lower()

        if acao_base == "*" and acac_base == "true":
            findings.append(
                Finding(
                    id="CORS_WILDCARD_CREDENTIALS_CONFLICT",
                    title="Critical CORS Misconfiguration: Wildcard '*' with Credentials 'true'",
                    description=(
                        "The server configured 'Access-Control-Allow-Origin: *' alongside "
                        "'Access-Control-Allow-Credentials: true'. This violates the W3C/WHATWG CORS specification "
                        "and exposes credentials across origins."
                    ),
                    severity=Severity.HIGH,
                    module=self.name,
                    impact="Violates browser security model and permits unauthorized cross-origin data access.",
                    evidence="Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true",
                    remediation="Never use '*' when credentials are required. Explicitly whitelist trusted origins.",
                    remediation_snippets=get_cors_remediations(),
                    references=["https://portswigger.net/web-security/cors"],
                    cwe_id="CWE-942",
                    owasp_category="A01:2021-Broken Access Control",
                )
            )

        # 1.2 Test Arbitrary Origin Reflection
        resp_evil = responses.get("evil")
        if resp_evil and resp_evil.ok:
            acao = resp_evil.headers.get("access-control-allow-origin", "").strip()
            acac = resp_evil.headers.get("access-control-allow-credentials", "").strip().lower()

            if acao == evil_origin:
                if acac == "true":
                    findings.append(
                        Finding(
                            id="CORS_ARBITRARY_ORIGIN_WITH_CREDENTIALS",
                            title="Critical Vulnerability: Arbitrary CORS Origin Reflection with Credentials",
                            description=(
                                f"The server dynamically mirrored the untrusted attacker origin '{evil_origin}' "
                                "in the Access-Control-Allow-Origin header while enabling Access-Control-Allow-Credentials: true."
                            ),
                            severity=Severity.CRITICAL,
                            module=self.name,
                            impact=(
                                "Severe Cross-Origin Data Theft: Attackers can host a malicious webpage that executes "
                                "authenticated XMLHttpRequests/fetch to this application, reading private user profiles, "
                                "confidential financial data, and sensitive tokens."
                            ),
                            evidence=(
                                f"Request Origin: {evil_origin}\n"
                                f"Response Access-Control-Allow-Origin: {acao}\n"
                                f"Response Access-Control-Allow-Credentials: {acac}"
                            ),
                            remediation="Implement an explicit origin whitelist instead of dynamically reflecting the Origin header.",
                            remediation_snippets=get_cors_remediations(),
                            references=[
                                "https://portswigger.net/web-security/cors",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html",
                            ],
                            cwe_id="CWE-942",
                            owasp_category="A01:2021-Broken Access Control",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            id="CORS_ARBITRARY_ORIGIN_REFLECTION",
                            title="Insecure CORS: Arbitrary Origin Reflection (Uncredentialed)",
                            description=(
                                f"The server reflected the untrusted origin '{evil_origin}' without credentials."
                            ),
                            severity=Severity.MEDIUM,
                            module=self.name,
                            impact="Permits external websites to read unauthenticated API responses.",
                            evidence=f"Reflected Access-Control-Allow-Origin: {acao}",
                            remediation="Restrict Access-Control-Allow-Origin to trusted domains.",
                            remediation_snippets=get_cors_remediations(),
                            cwe_id="CWE-942",
                        )
                    )

        # 1.3 Test Null Origin Trust
        resp_null = responses.get("null")
        if resp_null and resp_null.ok:
            acao = resp_null.headers.get("access-control-allow-origin", "").strip()
            acac = resp_null.headers.get("access-control-allow-credentials", "").strip().lower()

            if acao == "null":
                severity = Severity.HIGH if acac == "true" else Severity.MEDIUM
                findings.append(
                    Finding(
                        id="CORS_TRUST_NULL_ORIGIN_CREDENTIALS" if acac == "true" else "CORS_TRUST_NULL_ORIGIN",
                        title="Dangerous CORS Configuration: Trusting 'null' Origin",
                        description=(
                            "The server responded with 'Access-Control-Allow-Origin: null'. "
                            "Attackers can leverage sandboxed <iframe> (sandbox='allow-scripts') or local file contexts "
                            "to send requests with an Origin of 'null' and bypass origin restrictions."
                        ),
                        severity=severity,
                        module=self.name,
                        impact="Cross-origin attack bypass: Enables malicious sandboxed frames to access application resources.",
                        evidence=f"Request Origin: null -> Access-Control-Allow-Origin: {acao}, Credentials: {acac or 'false'}",
                        remediation="Do not whitelist 'null' as a valid origin. Use explicit domain whitelists.",
                        remediation_snippets=get_cors_remediations(),
                        cwe_id="CWE-942",
                    )
                )

        # 1.4 Test Regex Bypasses (Post-domain and Pre-domain)
        for label, origin in (("post_bypass", post_bypass_origin), ("pre_bypass", pre_bypass_origin)):
            resp_bypass = responses.get(label)
            if resp_bypass and resp_bypass.ok:
                acao = resp_bypass.headers.get("access-control-allow-origin", "").strip()
                if acao == origin:
                    findings.append(
                        Finding(
                            id="CORS_REGEX_BYPASS_ORIGIN",
                            title=f"CORS Origin Validation Flaw (Flawed Domain Regex / Substring Match)",
                            description=(
                                f"The server allowed origin '{origin}' because its validation logic "
                                f"likely uses an unanchored regex or substring search for '{target.host}'."
                            ),
                            severity=Severity.HIGH,
                            module=self.name,
                            impact="Attackers can register domains matching the regex to bypass all CORS protections.",
                            evidence=f"Accepted Origin: {origin}",
                            remediation="Anchor domain regexes strictly with '^https://(www\\.)?domain\\.com$' or use an array whitelist.",
                            remediation_snippets=get_cors_remediations(),
                            cwe_id="CWE-942",
                        )
                    )

        if not any(f.id.startswith("CORS_") for f in findings):
            passed_checks.append("cors-origin-secure")

    async def _audit_http_methods(
        self,
        target: ScanTarget,
        client: HttpClient,
        findings: List[Finding],
        passed_checks: List[str],
    ) -> None:
        # Test TRACE method (Cross-Site Tracing / XST)
        trace_resp = await client.trace(target.raw_url)

        if trace_resp.ok and trace_resp.status_code == 200:
            content_type = trace_resp.headers.get("content-type", "").lower()
            text = trace_resp.text
            # If server echoes back the request (message/http or contains TRACE request headers)
            if "message/http" in content_type or "TRACE" in text or "User-Agent" in text:
                findings.append(
                    Finding(
                        id="HTTP_TRACE_METHOD_ENABLED",
                        title="Dangerous HTTP TRACE Method Enabled (Cross-Site Tracing / XST Risk)",
                        description=(
                            "The web server responds to HTTP TRACE requests by echoing back incoming headers. "
                            "This permits Cross-Site Tracing (XST) attacks."
                        ),
                        severity=Severity.MEDIUM,
                        module=self.name,
                        impact=(
                            "Bypasses HttpOnly cookie protections: An attacker executing XSS can issue a TRACE request "
                            "via fetch/XMLHttpRequest and read the echoed headers, which contain HttpOnly session cookies."
                        ),
                        evidence=f"HTTP 200 OK received for TRACE request. Content-Type: {content_type}",
                        remediation="Disable the TRACE HTTP method in your web server (e.g. 'TraceEnable Off' in Apache).",
                        remediation_snippets=get_method_security_remediations(),
                        references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
                        cwe_id="CWE-16",
                        owasp_category="A05:2021-Security Misconfiguration",
                    )
                )
            else:
                passed_checks.append("http-trace-disabled")
        else:
            passed_checks.append("http-trace-disabled")

        # Test OPTIONS method to inspect allowed verbs
        options_resp = await client.options(target.raw_url)
        if options_resp.ok:
            allow_header = options_resp.headers.get("allow") or options_resp.headers.get("access-control-allow-methods")
            if allow_header:
                methods = [m.strip().upper() for m in allow_header.split(",")]
                if "TRACE" in methods:
                    if not any(f.id == "HTTP_TRACE_METHOD_ENABLED" for f in findings):
                        findings.append(
                            Finding(
                                id="HTTP_TRACE_ADVERTISED",
                                title="HTTP TRACE Method Advertised in OPTIONS Header",
                                description=f"The server advertises TRACE in 'Allow: {allow_header}'.",
                                severity=Severity.LOW,
                                module=self.name,
                                impact="Indicates TRACE method support is enabled on the server.",
                                evidence=f"Allow: {allow_header}",
                                remediation="Disable TRACE in web server configuration.",
                                remediation_snippets=get_method_security_remediations(),
                                cwe_id="CWE-16",
                            )
                        )
                passed_checks.append(f"options-methods-audited ({', '.join(methods[:5])})")
