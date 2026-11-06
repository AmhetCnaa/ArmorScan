"""
Cookie Hygiene & Session Security Audit Module for ArmorScan.
Audits response Set-Cookie headers for HttpOnly, Secure, SameSite, and modern cookie prefixes (__Host-, __Secure-).
Uses heuristic analysis to detect sensitive session/auth tokens and escalate severity accordingly.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional
import httpx

from armorscan.core.client import HttpClient
from armorscan.core.models import Finding, ModuleResult, ScanTarget, Severity
from armorscan.modules.base import BaseModule
from armorscan.remediations.templates import (
    get_cookie_hygiene_remediations,
    get_cookie_prefix_remediations,
)

SENSITIVE_COOKIE_PATTERNS = [
    r"session",
    r"sess",
    r"sid",
    r"token",
    r"jwt",
    r"auth",
    r"id_token",
    r"access_token",
    r"refresh_token",
    r"phpsessid",
    r"jsessionid",
    r"aspsessionid",
    r"asp\.net_sessionid",
    r"connect\.sid",
    r"laravel_session",
    r"remember",
    r"user_session",
    r"account",
]

SENSITIVE_REGEX = re.compile("|".join(SENSITIVE_COOKIE_PATTERNS), re.IGNORECASE)


class ParsedCookie:
    """Represents a parsed Set-Cookie header line."""

    def __init__(self, raw: str):
        self.raw = raw
        self.name: str = ""
        self.value: str = ""
        self.secure: bool = False
        self.httponly: bool = False
        self.samesite: Optional[str] = None
        self.domain: Optional[str] = None
        self.path: Optional[str] = None
        self.max_age: Optional[int] = None
        self._parse()

    def _parse(self) -> None:
        parts = [p.strip() for p in self.raw.split(";") if p.strip()]
        if not parts:
            return

        # First part is name=value
        first = parts[0]
        if "=" in first:
            self.name, self.value = first.split("=", 1)
        else:
            self.name = first
            self.value = ""

        # Remaining parts are attributes
        for part in parts[1:]:
            lower = part.lower()
            if lower == "secure":
                self.secure = True
            elif lower == "httponly":
                self.httponly = True
            elif lower.startswith("samesite="):
                self.samesite = part.split("=", 1)[1].strip().lower()
            elif lower.startswith("domain="):
                self.domain = part.split("=", 1)[1].strip()
            elif lower.startswith("path="):
                self.path = part.split("=", 1)[1].strip()
            elif lower.startswith("max-age="):
                try:
                    self.max_age = int(part.split("=", 1)[1].strip())
                except ValueError:
                    pass

    @property
    def is_sensitive(self) -> bool:
        """Heuristically identify if this cookie contains authentication or session state."""
        return bool(SENSITIVE_REGEX.search(self.name))

    @property
    def has_host_prefix(self) -> bool:
        return self.name.startswith("__Host-")

    @property
    def has_secure_prefix(self) -> bool:
        return self.name.startswith("__Secure-")


class CookieHygieneModule(BaseModule):
    """Audits HTTP cookies for missing security flags, dangerous SameSite configurations, and prefix standards."""

    name: str = "cookies"
    display_name: str = "Cookie Hygiene & Session Security"
    description: str = "Inspects Set-Cookie flags (HttpOnly, Secure, SameSite, and __Host-/__Secure- prefixes)."

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        # Send GET request to target
        resp = await client.get(target.raw_url)
        if not resp.ok and not resp.headers:
            return ModuleResult(
                module_name=self.name,
                display_name=self.display_name,
                findings=[],
                passed_checks=[],
                error=resp.error or "Failed to connect to target URL.",
            )

        # Extract all Set-Cookie headers
        raw_cookie_headers = resp.headers.get_list("set-cookie")

        # If no cookies found on initial page, check common auth entrypoint paths like /login or /api/auth
        if not raw_cookie_headers:
            for probe_path in ("/login", "/api/auth", "/auth/login"):
                probe_url = f"{target.base_url}{probe_path}"
                probe_resp = await client.get(probe_url)
                if probe_resp.ok and probe_resp.headers.get_list("set-cookie"):
                    raw_cookie_headers = probe_resp.headers.get_list("set-cookie")
                    break

        if not raw_cookie_headers:
            passed_checks.append("no-cookies-set-on-target")
            return ModuleResult(
                module_name=self.name,
                display_name=self.display_name,
                findings=[],
                passed_checks=passed_checks,
            )

        for raw_header in raw_cookie_headers:
            cookie = ParsedCookie(raw_header)
            self._audit_cookie(cookie, target, findings, passed_checks)

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )

    def _audit_cookie(
        self,
        cookie: ParsedCookie,
        target: ScanTarget,
        findings: List[Finding],
        passed_checks: List[str],
    ) -> None:
        cookie_label = f"Cookie '{cookie.name}'"
        is_sensitive = cookie.is_sensitive

        # 1. HttpOnly Check
        if not cookie.httponly:
            if is_sensitive:
                findings.append(
                    Finding(
                        id="COOKIE_MISSING_HTTPONLY_SESSION",
                        title=f"{cookie_label}: Sensitive Session Cookie Missing 'HttpOnly'",
                        description=(
                            f"The cookie '{cookie.name}' appears to be a sensitive session/authentication "
                            "token but does not have the 'HttpOnly' flag enabled."
                        ),
                        severity=Severity.HIGH,
                        module=self.name,
                        impact=(
                            "Critical XSS exposure: In the event of any Cross-Site Scripting vulnerability, "
                            "an attacker can access document.cookie to steal this session token and execute Session Hijacking."
                        ),
                        evidence=f"Set-Cookie: {cookie.raw}",
                        remediation="Set the 'HttpOnly' flag in the server Set-Cookie configuration.",
                        remediation_snippets=get_cookie_hygiene_remediations(),
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"],
                        cwe_id="CWE-1004",
                        owasp_category="A01:2021-Broken Access Control",
                    )
                )
            else:
                findings.append(
                    Finding(
                        id="COOKIE_MISSING_HTTPONLY",
                        title=f"{cookie_label}: Missing 'HttpOnly' Flag",
                        description=f"Cookie '{cookie.name}' is accessible to client-side JavaScript via document.cookie.",
                        severity=Severity.LOW,
                        module=self.name,
                        impact="Allows client-side scripts to read or modify the cookie value.",
                        evidence=f"Set-Cookie: {cookie.raw}",
                        remediation="Add the 'HttpOnly' attribute if the cookie is not required by client-side JS.",
                        remediation_snippets=get_cookie_hygiene_remediations(),
                        cwe_id="CWE-1004",
                    )
                )
        else:
            passed_checks.append(f"{cookie.name}:httponly-enabled")

        # 2. Secure Flag Check
        if not cookie.secure:
            if target.is_https or is_sensitive:
                severity = Severity.HIGH if is_sensitive else Severity.MEDIUM
                findings.append(
                    Finding(
                        id="COOKIE_MISSING_SECURE_SESSION" if is_sensitive else "COOKIE_MISSING_SECURE",
                        title=f"{cookie_label}: Missing 'Secure' Flag",
                        description=(
                            f"The cookie '{cookie.name}' was issued without the 'Secure' attribute. "
                            "Browsers will transmit this cookie in unencrypted plain HTTP requests."
                        ),
                        severity=severity,
                        module=self.name,
                        impact=(
                            "Vulnerable to Man-in-the-Middle (MitM) eavesdropping and SSL-stripping attacks. "
                            "Network observers can capture this token when an insecure HTTP request is issued."
                        ),
                        evidence=f"Set-Cookie: {cookie.raw}",
                        remediation="Add the 'Secure' flag so the browser only transmits this cookie over HTTPS.",
                        remediation_snippets=get_cookie_hygiene_remediations(),
                        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies"],
                        cwe_id="CWE-614",
                        owasp_category="A02:2021-Cryptographic Failures",
                    )
                )
        else:
            passed_checks.append(f"{cookie.name}:secure-enabled")

        # 3. SameSite Attribute Check
        if cookie.samesite is None:
            findings.append(
                Finding(
                    id="COOKIE_MISSING_SAMESITE",
                    title=f"{cookie_label}: Missing 'SameSite' Attribute",
                    description=(
                        f"The cookie '{cookie.name}' does not specify a 'SameSite' attribute. "
                        "Without SameSite=Lax or SameSite=Strict, the cookie is prone to Cross-Site Request Forgery (CSRF)."
                    ),
                    severity=Severity.MEDIUM if is_sensitive else Severity.LOW,
                    module=self.name,
                    impact="Enables cross-origin requests to send this cookie, increasing exposure to CSRF attacks.",
                    evidence=f"Set-Cookie: {cookie.raw}",
                    remediation="Add 'SameSite=Lax' (recommended default) or 'SameSite=Strict' to the cookie.",
                    remediation_snippets=get_cookie_hygiene_remediations(),
                    cwe_id="CWE-1275",
                    owasp_category="A01:2021-Broken Access Control",
                )
            )
        elif cookie.samesite == "none":
            if not cookie.secure:
                findings.append(
                    Finding(
                        id="COOKIE_SAMESITE_NONE_INSECURE",
                        title=f"{cookie_label}: 'SameSite=None' Without 'Secure' Attribute (Rejected by Browsers)",
                        description=(
                            f"Cookie '{cookie.name}' sets 'SameSite=None' but lacks the 'Secure' flag. "
                            "Modern browsers strictly drop/reject this cookie."
                        ),
                        severity=Severity.HIGH,
                        module=self.name,
                        impact="Browser rejects the cookie entirely, breaking authentication and session persistence.",
                        evidence=f"Set-Cookie: {cookie.raw}",
                        remediation="Ensure 'Secure' is always set whenever 'SameSite=None' is used.",
                        remediation_snippets=get_cookie_hygiene_remediations(),
                        cwe_id="CWE-1275",
                    )
                )
            else:
                findings.append(
                    Finding(
                        id="COOKIE_SAMESITE_NONE_PERMISSIVE",
                        title=f"{cookie_label}: Permissive 'SameSite=None' Policy",
                        description=(
                            f"Cookie '{cookie.name}' sets 'SameSite=None', allowing it to be sent across third-party contexts."
                        ),
                        severity=Severity.LOW,
                        module=self.name,
                        impact="Allows third-party sites to initiate authenticated requests (CSRF risk if no anti-CSRF token).",
                        evidence=f"Set-Cookie: {cookie.raw}",
                        remediation="Unless cross-domain embedding is explicitly required, switch to SameSite=Lax.",
                        remediation_snippets=get_cookie_hygiene_remediations(),
                        cwe_id="CWE-1275",
                    )
                )
        elif cookie.samesite in ("lax", "strict"):
            passed_checks.append(f"{cookie.name}:samesite-{cookie.samesite}")

        # 4. Cookie Prefix Standard (__Host- and __Secure-)
        if cookie.has_host_prefix:
            # __Host- rules: Must be Secure, must NOT have Domain, must have Path=/
            if not cookie.secure:
                findings.append(
                    Finding(
                        id="INVALID_HOST_COOKIE_PREFIX_NO_SECURE",
                        title=f"{cookie_label}: Invalid '__Host-' Prefix (Missing Secure Flag)",
                        description="__Host- cookies must have the 'Secure' attribute set; otherwise browsers reject them.",
                        severity=Severity.HIGH,
                        module=self.name,
                        impact="Browsers conforming to RFC 6265bis will reject this cookie.",
                        evidence=f"Set-Cookie: {cookie.raw}",
                        remediation="Add the 'Secure' attribute to the cookie.",
                        remediation_snippets=get_cookie_prefix_remediations(),
                        cwe_id="CWE-1275",
                    )
                )
            if cookie.domain:
                findings.append(
                    Finding(
                        id="INVALID_HOST_COOKIE_PREFIX_DOMAIN",
                        title=f"{cookie_label}: Invalid '__Host-' Prefix (Domain Attribute Present)",
                        description="__Host- cookies must NOT specify a Domain attribute, binding them strictly to the origin host.",
                        severity=Severity.HIGH,
                        module=self.name,
                        impact="Browsers will reject this cookie.",
                        evidence=f"Set-Cookie: {cookie.raw}",
                        remediation="Remove the Domain attribute from the __Host- cookie.",
                        remediation_snippets=get_cookie_prefix_remediations(),
                        cwe_id="CWE-1275",
                    )
                )
            if cookie.path != "/":
                findings.append(
                    Finding(
                        id="INVALID_HOST_COOKIE_PREFIX_PATH",
                        title=f"{cookie_label}: Invalid '__Host-' Prefix (Path Is Not '/')",
                        description="__Host- cookies must specify 'Path=/'.",
                        severity=Severity.MEDIUM,
                        module=self.name,
                        impact="Browsers will reject this cookie.",
                        evidence=f"Set-Cookie: {cookie.raw}",
                        remediation="Set 'Path=/' on the __Host- cookie.",
                        remediation_snippets=get_cookie_prefix_remediations(),
                        cwe_id="CWE-1275",
                    )
                )
            if cookie.secure and not cookie.domain and cookie.path == "/":
                passed_checks.append(f"{cookie.name}:valid-host-prefix")

        elif cookie.has_secure_prefix:
            if not cookie.secure:
                findings.append(
                    Finding(
                        id="INVALID_SECURE_COOKIE_PREFIX",
                        title=f"{cookie_label}: Invalid '__Secure-' Prefix (Missing Secure Flag)",
                        description="__Secure- cookies must have the 'Secure' flag set.",
                        severity=Severity.HIGH,
                        module=self.name,
                        impact="Browsers will reject this cookie.",
                        evidence=f"Set-Cookie: {cookie.raw}",
                        remediation="Add the 'Secure' attribute to the __Secure- cookie.",
                        remediation_snippets=get_cookie_prefix_remediations(),
                        cwe_id="CWE-1275",
                    )
                )
            else:
                passed_checks.append(f"{cookie.name}:valid-secure-prefix")

        elif is_sensitive and target.is_https:
            # Sensitive cookie without modern prefix: report as best-practice recommendation
            findings.append(
                Finding(
                    id="COOKIE_PREFIX_RECOMMENDED",
                    title=f"{cookie_label}: Sensitive Session Cookie Not Using '__Host-' Prefix",
                    description=(
                        f"The sensitive cookie '{cookie.name}' does not use the '__Host-' prefix standard. "
                        "The '__Host-' prefix locks cookies to the exact host, preventing subdomain cookie injection attacks."
                    ),
                    severity=Severity.INFO,
                    module=self.name,
                    impact="Subdomains compromised by attackers could overwrite or shadow this cookie for the root domain.",
                    evidence=f"Set-Cookie: {cookie.raw}",
                    remediation=f"Rename cookie '{cookie.name}' to '__Host-{cookie.name}', ensure Secure, Path=/, and omit Domain.",
                    remediation_snippets=get_cookie_prefix_remediations(),
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#cookie_prefixes"],
                    cwe_id="CWE-614",
                )
            )
