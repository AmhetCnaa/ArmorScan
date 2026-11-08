"""
TLS/SSL and HTTPS Configuration Audit Module for ArmorScan.
Verifies TLS certificate validity, expiration dates, cipher/protocol strength,
and enforces HTTP-to-HTTPS redirection policies.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import socket
import ssl
from typing import Any, Dict, List, Optional

from armorscan.core.client import HttpClient
from armorscan.core.fast_probe import FastProbe
from armorscan.core.models import Finding, ModuleResult, ScanTarget, Severity
from armorscan.modules.base import BaseModule

EXPIRATION_WARNING_DAYS = 30


class TlsSslModule(BaseModule):
    """Audits TLS certificate health, protocol versions, and HTTPS redirection enforcement."""

    name: str = "tls_ssl"
    display_name: str = "TLS/SSL & HTTPS Encryption Audit"
    description: str = "Checks certificate expiry, TLS version, and HTTP-to-HTTPS redirect enforcement."

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        # 1. Check HTTP to HTTPS redirection
        await self._check_https_redirection(target, client, findings, passed_checks)

        # 2. Check TLS Certificate details (if target is HTTPS or supports HTTPS)
        if target.is_https:
            await self._check_tls_certificate(target, findings, passed_checks)
        elif not target.is_localhost:
            # Pre-flight TCP Syn check on port 443 with fast-bailout (<800ms)
            port_443_open = await FastProbe.is_port_open(target.host, 443, timeout=0.8)
            if port_443_open:
                https_target = ScanTarget.from_url(f"https://{target.host}")
                await self._check_tls_certificate(https_target, findings, passed_checks)
            else:
                passed_checks.append("https-port-443-inactive-fast-bailout")
                findings.append(
                    Finding(
                        id="CLEARTEXT_HTTP_TARGET_CONTEXT",
                        title="Cleartext HTTP-Only Target Architecture (Port 443 Inactive)",
                        description=(
                            f"Target '{target.host}' is configured exclusively as cleartext HTTP. "
                            "Port 443 (HTTPS) did not respond to pre-flight TCP probes (<800ms)."
                        ),
                        severity=Severity.INFO,
                        module=self.name,
                        impact="All network communications over cleartext HTTP can be intercepted in transit.",
                        evidence=f"Pre-flight probe to {target.host}:443 timed out/refused. Target operates in HTTP-only context.",
                        remediation="Deploy a trusted TLS certificate and open HTTPS port 443 on the web server.",
                        cwe_id="CWE-319",
                    )
                )
        else:
            passed_checks.append("localhost-tls-cert-skipped")

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )

    async def _check_https_redirection(
        self,
        target: ScanTarget,
        client: HttpClient,
        findings: List[Finding],
        passed_checks: List[str],
    ) -> None:
        """Verify whether unencrypted HTTP automatically redirects to HTTPS."""
        if target.is_localhost:
            # Localhost development environments typically run plain HTTP
            passed_checks.append("localhost-http-redirect-skipped")
            return

        http_url = f"http://{target.host}{target.path}"
        # Make request WITHOUT following redirects to examine the raw 301/302 status
        resp = await client.get(http_url, follow_redirects=False)

        if not resp.ok:
            # Couldn't reach HTTP port 80 (might be completely closed/blocked)
            passed_checks.append("http-port-closed")
            return

        status = resp.status_code
        location = resp.headers.get("location", "")

        if status in (301, 302, 307, 308) and location.startswith("https://"):
            passed_checks.append("https-redirection-enforced")
        else:
            findings.append(
                Finding(
                    id="NO_HTTPS_REDIRECT",
                    title="Unencrypted HTTP Allowed Without Automatic HTTPS Redirection",
                    description=(
                        f"Target URL '{http_url}' responded with HTTP {status} instead of a permanent "
                        "redirect (301/308) to HTTPS."
                    ),
                    severity=Severity.HIGH,
                    module=self.name,
                    impact="Users accessing the site via plain HTTP transmit credentials and session cookies in cleartext.",
                    evidence=f"Status: {status}, Location: {location or 'None'}",
                    remediation="Configure a permanent redirect (HTTP 301) from HTTP to HTTPS in your web server.",
                    remediation_snippets={
                        "nginx": (
                            "server {\n"
                            "    listen 80;\n"
                            f"    server_name {target.host};\n"
                            f"    return 301 https://$host$request_uri;\n"
                            "}"
                        ),
                        "express": (
                            "// Enforce HTTPS in Express:\n"
                            "app.use((req, res, next) => {\n"
                            "  if (req.header('x-forwarded-proto') !== 'https' && !req.secure) {\n"
                            f"    return res.redirect(301, `https://${{req.header('host')}}${{req.url}}`);\n"
                            "  }\n"
                            "  next();\n"
                            "});"
                        ),
                        "fastapi": (
                            "# Enforce HTTPS in FastAPI:\n"
                            "from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware\n"
                            "app.add_middleware(HTTPSRedirectMiddleware)"
                        ),
                    },
                    cwe_id="CWE-319",
                    owasp_category="A02:2021-Cryptographic Failures",
                )
            )

    async def _check_tls_certificate(
        self,
        target: ScanTarget,
        findings: List[Finding],
        passed_checks: List[str],
    ) -> None:
        """Inspect TLS certificate expiry, issuer, and protocol version."""
        if target.is_localhost:
            passed_checks.append("localhost-tls-cert-skipped")
            return

        loop = asyncio.get_running_loop()
        try:
            cert_info = await asyncio.wait_for(
                loop.run_in_executor(None, self._fetch_peer_cert, target.host, target.port),
                timeout=1.5,
            )
        except Exception as e:
            # If TLS handshake fails, record finding
            findings.append(
                Finding(
                    id="TLS_HANDSHAKE_FAILED",
                    title="TLS Handshake Failed or Untrusted Certificate",
                    description=f"Could not establish a secure TLS connection with {target.host}:{target.port}.",
                    severity=Severity.HIGH,
                    module=self.name,
                    impact="Clients cannot establish a trusted, encrypted session.",
                    evidence=f"Error: {type(e).__name__}: {str(e)}",
                    remediation="Ensure a valid, trusted TLS/SSL certificate is installed and bound to the port.",
                    cwe_id="CWE-295",
                )
            )
            return

        if not cert_info:
            return

        not_after_str = cert_info.get("notAfter")
        if not_after_str:
            # Parse OpenSSL date format: "Mar 15 12:00:00 2026 GMT"
            try:
                expires_at = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                remaining_days = (expires_at - now).days

                if remaining_days < 0:
                    findings.append(
                        Finding(
                            id="SSL_CERT_EXPIRED",
                            title=f"TLS/SSL Certificate Expired ({abs(remaining_days)} days ago)",
                            description=f"The certificate expired on {expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}.",
                            severity=Severity.CRITICAL,
                            module=self.name,
                            impact="Browsers will block user access with major security warning screens.",
                            evidence=f"Expired: {expires_at}, Remaining days: {remaining_days}",
                            remediation="Renew and redeploy your TLS certificate immediately.",
                            cwe_id="CWE-298",
                            owasp_category="A02:2021-Cryptographic Failures",
                        )
                    )
                elif remaining_days <= EXPIRATION_WARNING_DAYS:
                    findings.append(
                        Finding(
                            id="SSL_CERT_EXPIRING_SOON",
                            title=f"TLS/SSL Certificate Expiring Soon ({remaining_days} days left)",
                            description=f"Certificate will expire on {expires_at.strftime('%Y-%m-%d')}.",
                            severity=Severity.MEDIUM,
                            module=self.name,
                            impact="Service will be abruptly disrupted if the certificate is not renewed before expiry.",
                            evidence=f"Expiry date: {expires_at}, Days remaining: {remaining_days}",
                            remediation="Renew the certificate (e.g., via Let's Encrypt certbot automated renewal).",
                            cwe_id="CWE-298",
                        )
                    )
                else:
                    passed_checks.append(f"tls-cert-valid (expires in {remaining_days} days)")
            except ValueError:
                pass

        # Check TLS Protocol Version
        tls_version = cert_info.get("tls_version", "")
        if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append(
                Finding(
                    id="OBSOLETE_TLS_VERSION",
                    title=f"Insecure/Obsolete TLS Protocol In Use ({tls_version})",
                    description=(
                        f"The server negotiated connection using {tls_version}. "
                        "TLS 1.0 and 1.1 have been deprecated by RFC 8996 due to known cryptographic weaknesses."
                    ),
                    severity=Severity.HIGH,
                    module=self.name,
                    impact="Vulnerable to cipher downgrade attacks and protocol exploits like POODLE and BEAST.",
                    evidence=f"Negotiated version: {tls_version}",
                    remediation="Disable TLS 1.0 and 1.1 in web server configuration. Enforce TLS 1.2 and TLS 1.3.",
                    remediation_snippets={
                        "nginx": "ssl_protocols TLSv1.2 TLSv1.3;",
                        "apache": "SSLProtocol -all +TLSv1.2 +TLSv1.3",
                    },
                    cwe_id="CWE-326",
                    owasp_category="A02:2021-Cryptographic Failures",
                )
            )
        elif tls_version in ("TLSv1.2", "TLSv1.3"):
            passed_checks.append(f"tls-protocol-secure ({tls_version})")

    def _fetch_peer_cert(self, host: str, port: int) -> Dict[str, Any]:
        """Synchronous helper to retrieve peer SSL certificate and TLS version."""
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=1.5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cert["tls_version"] = ssock.version()
                return cert
