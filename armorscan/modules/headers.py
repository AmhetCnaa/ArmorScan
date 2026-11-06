"""
Security Headers Audit Module for ArmorScan.
Deeply inspects HTTP response headers (HSTS, CSP, XFO, XCTO, Referrer, Permissions, Server tokens)
and attaches production-ready remediation code snippets for Nginx, Express, and FastAPI.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional
import httpx

from armorscan.core.client import HttpClient, HttpResponse
from armorscan.core.models import Finding, ModuleResult, ScanTarget, Severity
from armorscan.modules.base import BaseModule
from armorscan.remediations.templates import (
    get_csp_remediations,
    get_hsts_remediations,
    get_permissions_policy_remediations,
    get_referrer_policy_remediations,
    get_server_masking_remediations,
    get_x_content_type_options_remediations,
    get_x_frame_options_remediations,
)

MIN_HSTS_MAX_AGE = 31536000  # 1 year in seconds


class SecurityHeadersModule(BaseModule):
    """Audits HTTP response headers for missing or misconfigured security controls."""

    name: str = "headers"
    display_name: str = "Security Headers Audit"
    description: str = "Inspects HSTS, CSP, Clickjacking, MIME-sniffing, and Information Disclosure."

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        # Send GET request to target base/path
        resp = await client.get(target.raw_url)
        if not resp.ok and not resp.headers:
            return ModuleResult(
                module_name=self.name,
                display_name=self.display_name,
                findings=[],
                passed_checks=[],
                error=resp.error or "Failed to connect to target URL.",
            )

        headers = resp.headers

        # 1. Strict-Transport-Security (HSTS)
        self._check_hsts(headers, target, findings, passed_checks)

        # 2. Content-Security-Policy (CSP)
        self._check_csp(headers, findings, passed_checks)

        # 3. X-Frame-Options
        self._check_x_frame_options(headers, findings, passed_checks)

        # 4. X-Content-Type-Options
        self._check_x_content_type_options(headers, findings, passed_checks)

        # 5. Referrer-Policy
        self._check_referrer_policy(headers, findings, passed_checks)

        # 6. Permissions-Policy
        self._check_permissions_policy(headers, findings, passed_checks)

        # 7. Information Disclosure (Server, X-Powered-By)
        self._check_information_disclosure(headers, findings, passed_checks)

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )

    def _check_hsts(
        self,
        headers: httpx.Headers,
        target: ScanTarget,
        findings: List[Finding],
        passed_checks: List[str],
    ) -> None:
        hsts_value = headers.get("strict-transport-security")

        if not target.is_https:
            if hsts_value:
                findings.append(
                    Finding(
                        id="HSTS_ON_HTTP",
                        title="HSTS Sent Over Insecure HTTP",
                        description="Strict-Transport-Security header was delivered over unencrypted HTTP.",
                        severity=Severity.INFO,
                        module=self.name,
                        impact="Browsers ignore HSTS headers received over HTTP as per RFC 6797 §7.2.",
                        evidence=f"Strict-Transport-Security: {hsts_value}",
                        remediation="Deliver HSTS strictly over HTTPS connections.",
                        remediation_snippets=get_hsts_remediations(),
                        cwe_id="CWE-319",
                        owasp_category="A02:2021-Cryptographic Failures",
                    )
                )
            return

        if not hsts_value:
            findings.append(
                Finding(
                    id="MISSING_HSTS",
                    title="Missing Strict-Transport-Security (HSTS) Header",
                    description=(
                        "The server did not return a Strict-Transport-Security header. "
                        "Without HSTS, initial connections may fall back to plain HTTP, enabling SSL stripping."
                    ),
                    severity=Severity.MEDIUM,
                    module=self.name,
                    impact="Enables Man-in-the-Middle (MitM) attackers to strip TLS encryption via downgrade attacks.",
                    evidence="Strict-Transport-Security header is absent.",
                    remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
                    remediation_snippets=get_hsts_remediations(),
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
                    cwe_id="CWE-319",
                    owasp_category="A02:2021-Cryptographic Failures",
                )
            )
            return

        # Parse HSTS components
        max_age_match = re.search(r"max-age=(\d+)", hsts_value, re.IGNORECASE)
        include_subdomains = "includesubdomains" in hsts_value.lower()
        preload = "preload" in hsts_value.lower()

        if not max_age_match:
            findings.append(
                Finding(
                    id="MALFORMED_HSTS",
                    title="Malformed HSTS Header",
                    description="Strict-Transport-Security header is missing a valid 'max-age' directive.",
                    severity=Severity.MEDIUM,
                    module=self.name,
                    impact="Browsers will fail to enforce HTTPS pinning.",
                    evidence=f"Strict-Transport-Security: {hsts_value}",
                    remediation="Specify a valid max-age directive, e.g., max-age=31536000.",
                    remediation_snippets=get_hsts_remediations(),
                    cwe_id="CWE-319",
                )
            )
            return

        max_age = int(max_age_match.group(1))

        if max_age == 0:
            findings.append(
                Finding(
                    id="HSTS_DISABLED_ZERO_MAX_AGE",
                    title="HSTS Disabled via max-age=0",
                    description="The Strict-Transport-Security header specifies max-age=0, actively disabling HSTS pinning.",
                    severity=Severity.HIGH,
                    module=self.name,
                    impact="Completely disables browser-side HTTPS enforcement for returning users.",
                    evidence=f"Strict-Transport-Security: {hsts_value}",
                    remediation="Set max-age to at least 31536000 seconds (1 year).",
                    remediation_snippets=get_hsts_remediations(),
                    cwe_id="CWE-319",
                )
            )
        elif max_age < MIN_HSTS_MAX_AGE:
            findings.append(
                Finding(
                    id="WEAK_HSTS_MAX_AGE",
                    title=f"Short HSTS max-age Duration ({max_age}s < 31536000s)",
                    description=(
                        f"The HSTS max-age duration is {max_age} seconds. "
                        "Industry best practices and browser preload lists require at least 1 year (31,536,000s)."
                    ),
                    severity=Severity.LOW,
                    module=self.name,
                    impact="Users are vulnerable to MitM attacks if they visit infrequently.",
                    evidence=f"Strict-Transport-Security: {hsts_value}",
                    remediation="Increase max-age to 31536000.",
                    remediation_snippets=get_hsts_remediations(),
                    cwe_id="CWE-319",
                )
            )

        if not include_subdomains:
            findings.append(
                Finding(
                    id="HSTS_MISSING_SUBDOMAINS",
                    title="HSTS Header Missing 'includeSubDomains' Directive",
                    description="Subdomains under this host are not protected by HSTS.",
                    severity=Severity.LOW,
                    module=self.name,
                    impact="Subdomains could be intercepted or spoofed over plain HTTP.",
                    evidence=f"Strict-Transport-Security: {hsts_value}",
                    remediation="Append 'includeSubDomains' to the HSTS header.",
                    remediation_snippets=get_hsts_remediations(),
                    cwe_id="CWE-319",
                )
            )

        if not findings or all(f.module != self.name or "HSTS" not in f.id for f in findings):
            passed_checks.append("hsts")

    def _check_csp(
        self,
        headers: httpx.Headers,
        findings: List[Finding],
        passed_checks: List[str],
    ) -> None:
        csp_value = headers.get("content-security-policy")
        report_only = headers.get("content-security-policy-report-only")

        if not csp_value:
            if report_only:
                findings.append(
                    Finding(
                        id="CSP_REPORT_ONLY",
                        title="Content-Security-Policy In Report-Only Mode",
                        description=(
                            "Content-Security-Policy-Report-Only is configured, but no enforcing "
                            "Content-Security-Policy header is active. Browser does not block violations."
                        ),
                        severity=Severity.LOW,
                        module=self.name,
                        impact="XSS and malicious resources are detected and logged, but NOT blocked.",
                        evidence=f"Content-Security-Policy-Report-Only: {report_only[:120]}...",
                        remediation="Promote the policy to 'Content-Security-Policy' once verified.",
                        remediation_snippets=get_csp_remediations(),
                        cwe_id="CWE-1021",
                        owasp_category="A05:2021-Security Misconfiguration",
                    )
                )
            else:
                findings.append(
                    Finding(
                        id="MISSING_CSP",
                        title="Missing Content-Security-Policy (CSP) Header",
                        description=(
                            "The server did not send a Content-Security-Policy header. "
                            "CSP restricts the sources from which scripts, images, and other assets can load."
                        ),
                        severity=Severity.HIGH,
                        module=self.name,
                        impact="Significantly increases exposure to Cross-Site Scripting (XSS) and data exfiltration.",
                        evidence="Content-Security-Policy header is absent.",
                        remediation="Define a strict Content-Security-Policy starting with 'default-src 'self''.",
                        remediation_snippets=get_csp_remediations(),
                        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
                        cwe_id="CWE-79",
                        owasp_category="A03:2021-Injection",
                    )
                )
            return

        # Deep inspection of CSP directives
        directives = [d.strip() for d in csp_value.split(";") if d.strip()]
        directive_map: Dict[str, List[str]] = {}
        for d in directives:
            parts = d.split()
            if parts:
                name = parts[0].lower()
                values = [v.lower() for v in parts[1:]]
                directive_map[name] = values

        script_or_default = directive_map.get("script-src", directive_map.get("default-src", []))

        # Check for 'unsafe-inline' in script-src / default-src
        if "'unsafe-inline'" in script_or_default:
            findings.append(
                Finding(
                    id="CSP_UNSAFE_INLINE",
                    title="CSP Contains Dangerous 'unsafe-inline' Directive",
                    description=(
                        "The Content-Security-Policy permits 'unsafe-inline' execution for scripts. "
                        "This negates the primary XSS mitigation provided by CSP."
                    ),
                    severity=Severity.HIGH,
                    module=self.name,
                    impact="Attackers can inject and execute arbitrary inline JavaScript via XSS vulnerabilities.",
                    evidence=f"Directive: {' '.join(script_or_default)}",
                    remediation="Remove 'unsafe-inline'. Use cryptographic nonces (nonce-...) or SHA-256 hashes.",
                    remediation_snippets=get_csp_remediations(),
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"],
                    cwe_id="CWE-79",
                    owasp_category="A03:2021-Injection",
                )
            )

        # Check for 'unsafe-eval' in script-src / default-src
        if "'unsafe-eval'" in script_or_default:
            findings.append(
                Finding(
                    id="CSP_UNSAFE_EVAL",
                    title="CSP Contains 'unsafe-eval' Directive",
                    description=(
                        "The Content-Security-Policy allows 'unsafe-eval', enabling dynamic code evaluation "
                        "using eval(), setTimeout(string), or Function()."
                    ),
                    severity=Severity.MEDIUM,
                    module=self.name,
                    impact="Enables dynamic code injection attacks if untrusted strings reach evaluation sinks.",
                    evidence=f"Directive: {' '.join(script_or_default)}",
                    remediation="Refactor code to avoid eval() and remove 'unsafe-eval' from script-src.",
                    remediation_snippets=get_csp_remediations(),
                    cwe_id="CWE-95",
                    owasp_category="A03:2021-Injection",
                )
            )

        # Check for wildcard '*' in script-src / default-src
        if "*" in script_or_default:
            findings.append(
                Finding(
                    id="CSP_WILDCARD_SOURCE",
                    title="CSP Uses Wildcard '*' in Script/Default Directives",
                    description="Allowing scripts from any origin (*) completely undermines CSP protections.",
                    severity=Severity.HIGH,
                    module=self.name,
                    impact="Allows loading scripts hosted on any arbitrary external domain.",
                    evidence=f"Directive: {' '.join(script_or_default)}",
                    remediation="Restrict script sources to 'self' and explicit trusted CDNs.",
                    remediation_snippets=get_csp_remediations(),
                    cwe_id="CWE-79",
                )
            )

        if not any(f.id.startswith("CSP_") for f in findings):
            passed_checks.append("csp")

    def _check_x_frame_options(
        self,
        headers: httpx.Headers,
        findings: List[Finding],
        passed_checks: List[str],
    ) -> None:
        xfo = headers.get("x-frame-options")
        csp = headers.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower()

        if not xfo:
            if not has_frame_ancestors:
                findings.append(
                    Finding(
                        id="MISSING_X_FRAME_OPTIONS",
                        title="Missing Anti-Clickjacking Protection (X-Frame-Options)",
                        description=(
                            "The server did not return an X-Frame-Options or CSP 'frame-ancestors' header. "
                            "This allows other websites to embed this application inside an <iframe>."
                        ),
                        severity=Severity.MEDIUM,
                        module=self.name,
                        impact="Vulnerable to Clickjacking (UI Redress Attack), tricking users into unintentional clicks.",
                        evidence="Neither X-Frame-Options nor frame-ancestors directive present.",
                        remediation="Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
                        remediation_snippets=get_x_frame_options_remediations(),
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"],
                        cwe_id="CWE-1021",
                        owasp_category="A05:2021-Security Misconfiguration",
                    )
                )
            else:
                passed_checks.append("x-frame-options (via CSP frame-ancestors)")
            return

        normalized = xfo.strip().upper()
        if normalized not in ("DENY", "SAMEORIGIN"):
            findings.append(
                Finding(
                    id="INVALID_X_FRAME_OPTIONS",
                    title="Deprecated or Invalid X-Frame-Options Header",
                    description=(
                        f"X-Frame-Options header value '{xfo}' is invalid or deprecated. "
                        "Modern browsers ignore ALLOW-FROM directives."
                    ),
                    severity=Severity.LOW,
                    module=self.name,
                    impact="Browser fallback may leave the page vulnerable to embedding.",
                    evidence=f"X-Frame-Options: {xfo}",
                    remediation="Use 'DENY' or 'SAMEORIGIN', or transition to CSP 'frame-ancestors'.",
                    remediation_snippets=get_x_frame_options_remediations(),
                    cwe_id="CWE-1021",
                )
            )
        else:
            passed_checks.append("x-frame-options")

    def _check_x_content_type_options(
        self,
        headers: httpx.Headers,
        findings: List[Finding],
        passed_checks: List[str],
    ) -> None:
        xcto = headers.get("x-content-type-options")
        if not xcto or xcto.strip().lower() != "nosniff":
            findings.append(
                Finding(
                    id="MISSING_X_CONTENT_TYPE_OPTIONS",
                    title="Missing X-Content-Type-Options Header",
                    description=(
                        "The server did not send 'X-Content-Type-Options: nosniff'. "
                        "Without this, browsers may attempt MIME-type sniffing."
                    ),
                    severity=Severity.LOW,
                    module=self.name,
                    impact="Enables MIME confusion attacks where non-executable files (e.g., images) are executed as scripts.",
                    evidence=f"X-Content-Type-Options: {xcto or 'absent'}",
                    remediation="Add 'X-Content-Type-Options: nosniff' header.",
                    remediation_snippets=get_x_content_type_options_remediations(),
                    cwe_id="CWE-79",
                    owasp_category="A05:2021-Security Misconfiguration",
                )
            )
        else:
            passed_checks.append("x-content-type-options")

    def _check_referrer_policy(
        self,
        headers: httpx.Headers,
        findings: List[Finding],
        passed_checks: List[str],
    ) -> None:
        ref_policy = headers.get("referrer-policy")
        if not ref_policy:
            findings.append(
                Finding(
                    id="MISSING_REFERRER_POLICY",
                    title="Missing Referrer-Policy Header",
                    description=(
                        "The server does not specify a Referrer-Policy header. "
                        "Sensitive tokens or user IDs in query parameters may leak in the Referer header to external sites."
                    ),
                    severity=Severity.LOW,
                    module=self.name,
                    impact="Information disclosure: Full URLs with query parameters may leak to third-party domains.",
                    evidence="Referrer-Policy header is absent.",
                    remediation="Set 'Referrer-Policy: strict-origin-when-cross-origin'.",
                    remediation_snippets=get_referrer_policy_remediations(),
                    cwe_id="CWE-200",
                    owasp_category="A01:2021-Broken Access Control",
                )
            )
        elif "unsafe-url" in ref_policy.lower():
            findings.append(
                Finding(
                    id="UNSAFE_REFERRER_POLICY",
                    title="Insecure Referrer-Policy ('unsafe-url')",
                    description="The server explicitly sends full path and query strings to all origins via 'unsafe-url'.",
                    severity=Severity.MEDIUM,
                    module=self.name,
                    impact="High probability of leaking sensitive URL parameters to third-party trackers or external links.",
                    evidence=f"Referrer-Policy: {ref_policy}",
                    remediation="Replace 'unsafe-url' with 'strict-origin-when-cross-origin' or 'no-referrer'.",
                    remediation_snippets=get_referrer_policy_remediations(),
                    cwe_id="CWE-200",
                )
            )
        else:
            passed_checks.append("referrer-policy")

    def _check_permissions_policy(
        self,
        headers: httpx.Headers,
        findings: List[Finding],
        passed_checks: List[str],
    ) -> None:
        perm_policy = headers.get("permissions-policy") or headers.get("feature-policy")
        if not perm_policy:
            findings.append(
                Finding(
                    id="MISSING_PERMISSIONS_POLICY",
                    title="Missing Permissions-Policy Header",
                    description=(
                        "The server did not send a Permissions-Policy header to restrict powerful browser features "
                        "(e.g., camera, microphone, geolocation)."
                    ),
                    severity=Severity.LOW,
                    module=self.name,
                    impact="Embedded iframes and third-party scripts may request access to sensitive device APIs.",
                    evidence="Permissions-Policy header is absent.",
                    remediation="Add 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
                    remediation_snippets=get_permissions_policy_remediations(),
                    cwe_id="CWE-693",
                )
            )
        else:
            passed_checks.append("permissions-policy")

    def _check_information_disclosure(
        self,
        headers: httpx.Headers,
        findings: List[Finding],
        passed_checks: List[str],
    ) -> None:
        server = headers.get("server")
        powered_by = headers.get("x-powered-by")
        aspnet_ver = headers.get("x-aspnet-version") or headers.get("x-aspnetmvc-version")

        if server and any(char.isdigit() for char in server):
            findings.append(
                Finding(
                    id="SERVER_VERSION_DISCLOSURE",
                    title=f"Server Version Disclosed ({server})",
                    description="The 'Server' header exposes detailed software and version information.",
                    severity=Severity.LOW,
                    module=self.name,
                    impact="Assists attackers in fingerprinting known CVEs for the specific server version.",
                    evidence=f"Server: {server}",
                    remediation="Disable server version tokens (e.g. 'server_tokens off;' in Nginx).",
                    remediation_snippets=get_server_masking_remediations(),
                    cwe_id="CWE-200",
                    owasp_category="A05:2021-Security Misconfiguration",
                )
            )
        elif not server:
            passed_checks.append("server-banner-masked")

        if powered_by:
            findings.append(
                Finding(
                    id="X_POWERED_BY_DISCLOSURE",
                    title=f"Technology Fingerprint Disclosed ({powered_by})",
                    description="The 'X-Powered-By' header leaks backend framework identity (e.g. Express, PHP).",
                    severity=Severity.LOW,
                    module=self.name,
                    impact="Aids targeted attacks against framework-specific vulnerabilities.",
                    evidence=f"X-Powered-By: {powered_by}",
                    remediation="Remove the X-Powered-By header (e.g. app.disable('x-powered-by') in Express).",
                    remediation_snippets=get_server_masking_remediations(),
                    cwe_id="CWE-200",
                )
            )

        if aspnet_ver:
            findings.append(
                Finding(
                    id="ASPNET_VERSION_DISCLOSURE",
                    title=f"ASP.NET Version Disclosed ({aspnet_ver})",
                    description="The server leaks internal ASP.NET version numbers.",
                    severity=Severity.LOW,
                    module=self.name,
                    impact="Facilitates targeted .NET exploitation.",
                    evidence=f"ASP.NET Header: {aspnet_ver}",
                    remediation="Set enableVersionHeader='false' in web.config.",
                    remediation_snippets=get_server_masking_remediations(),
                    cwe_id="CWE-200",
                )
            )
