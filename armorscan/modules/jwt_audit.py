"""
JWT Client Security & Lifecycle Audit Module for ArmorScan.
Detects JWT tokens in cookies, headers, and responses to audit cryptographic algorithms
(alg: none bypass), expiration policies, and sensitive data leakage in unencrypted payloads.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from armorscan.core.client import HttpClient, HttpResponse
from armorscan.core.models import Confidence, Finding, ModuleResult, ScanTarget, Severity
from armorscan.modules.base import BaseModule
from armorscan.remediations.templates import get_jwt_audit_remediations

JWT_REGEX = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*")
SENSITIVE_PAYLOAD_KEYS = {"password", "passwd", "secret", "private_key", "ssn", "api_key", "card_number"}
MAX_RECOMMENDED_LIFETIME_SECONDS = 30 * 86400  # 30 days


class JwtAuditModule(BaseModule):
    """Audits targets for weak or misconfigured JSON Web Tokens."""

    name: str = "jwt_audit"
    display_name: str = "JWT Client Security & Lifecycle Audit"
    description: str = "Inspects detected JWTs for 'alg: none', missing expirations, and credential leaks."

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        # 1. Fetch target baseline
        resp = await client.get(target.raw_url)
        if not resp.ok and not resp.headers:
            return ModuleResult(
                module_name=self.name,
                display_name=self.display_name,
                findings=[],
                passed_checks=["target-not-reachable"],
            )

        collected_jwts: Set[str] = set()

        # Check Set-Cookie headers
        for sc in resp.headers.get_list("set-cookie"):
            for match in JWT_REGEX.findall(sc):
                collected_jwts.add(match)

        # Check response body
        if resp.text:
            for match in JWT_REGEX.findall(resp.text):
                collected_jwts.add(match)

        # Check probe paths if none found on root (e.g. /api/auth, /login)
        if not collected_jwts:
            for probe_path in ("/api/auth/token", "/api/token", "/auth/login"):
                probe_url = f"{target.base_url}{probe_path}"
                probe_resp = await client.get(probe_url)
                if probe_resp.ok and probe_resp.text:
                    for match in JWT_REGEX.findall(probe_resp.text):
                        collected_jwts.add(match)
                for sc in probe_resp.headers.get_list("set-cookie"):
                    for match in JWT_REGEX.findall(sc):
                        collected_jwts.add(match)
                if collected_jwts:
                    break

        if not collected_jwts:
            passed_checks.append("no-jwt-tokens-detected")
            return ModuleResult(
                module_name=self.name,
                display_name=self.display_name,
                findings=[],
                passed_checks=passed_checks,
            )

        for raw_jwt in collected_jwts:
            self._audit_jwt(raw_jwt, target, findings, passed_checks)

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )

    def _audit_jwt(self, raw_jwt: str, target: ScanTarget, findings: List[Finding], passed_checks: List[str]) -> None:
        parts = raw_jwt.split(".")
        if len(parts) < 2:
            return

        header = self._decode_segment(parts[0])
        payload = self._decode_segment(parts[1])

        if not header or not payload:
            return

        curl_cmd = Finding.build_curl("GET", target.raw_url)

        # 1. Check 'alg: none' algorithm bypass
        alg = str(header.get("alg", "")).lower()
        if alg == "none":
            findings.append(
                Finding(
                    id="JWT_INSECURE_ALGORITHM_NONE",
                    title="Critical Vulnerability: JWT Configured With Insecure 'alg: none'",
                    description=(
                        "The discovered JSON Web Token explicitly specifies 'alg: none' in its header. "
                        "This allows attackers to strip cryptographic signatures and forge arbitrary authentication claims."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    module=self.name,
                    impact="Complete Authentication Bypass: Attackers can impersonate any user, including administrators.",
                    evidence=f"JWT Header: {json.dumps(header)}",
                    curl_command=curl_cmd,
                    affected_urls=[target.raw_url],
                    remediation="Reject tokens with 'alg: none' and enforce strong cryptographic algorithms (RS256, Ed25519, HS256).",
                    remediation_snippets=get_jwt_audit_remediations(),
                    references=["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
                    cwe_id="CWE-347",
                    owasp_category="A02:2021-Cryptographic Failures",
                )
            )
        elif alg in ("hs256", "rs256", "es256", "eddsa"):
            passed_checks.append(f"jwt-alg-valid ({alg})")

        # 2. Check expiration (exp claim)
        exp = payload.get("exp")
        now = time.time()

        if exp is None:
            findings.append(
                Finding(
                    id="JWT_MISSING_EXPIRATION",
                    title="Missing Expiration Claim ('exp') in JWT",
                    description="The JWT payload does not define an 'exp' claim, making the token valid indefinitely.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    module=self.name,
                    impact="Token Persistence: If the token is leaked or intercepted, it remains valid indefinitely.",
                    evidence=f"Payload keys: {', '.join(payload.keys())}",
                    curl_command=curl_cmd,
                    affected_urls=[target.raw_url],
                    remediation="Always set an 'exp' expiration claim with a short lifespan (15 to 60 minutes).",
                    remediation_snippets=get_jwt_audit_remediations(),
                    cwe_id="CWE-613",
                    owasp_category="A07:2021-Identification and Authentication Failures",
                )
            )
        elif isinstance(exp, (int, float)):
            remaining = exp - now
            if remaining > MAX_RECOMMENDED_LIFETIME_SECONDS:
                days = int(remaining // 86400)
                findings.append(
                    Finding(
                        id="JWT_EXCESSIVE_EXPIRATION",
                        title=f"Excessive JWT Expiration Lifetime ({days} days remaining)",
                        description=f"JWT token has an unusually long lifetime of {days} days before expiring.",
                        severity=Severity.LOW,
                        confidence=Confidence.FIRM,
                        module=self.name,
                        impact="Widened vulnerability window if the user's browser or device is compromised.",
                        evidence=f"exp timestamp: {exp} (approx {days} days)",
                        curl_command=curl_cmd,
                        affected_urls=[target.raw_url],
                        remediation="Shorten access token lifetime and use rotating refresh tokens for session renewal.",
                        remediation_snippets=get_jwt_audit_remediations(),
                        cwe_id="CWE-613",
                    )
                )
            else:
                passed_checks.append("jwt-exp-claim-enforced")

        # 3. Check Sensitive Plaintext Data in Payload
        payload_keys = set(str(k).lower() for k in payload.keys())
        exposed_keys = payload_keys.intersection(SENSITIVE_PAYLOAD_KEYS)

        if exposed_keys:
            findings.append(
                Finding(
                    id="JWT_SENSITIVE_DATA_IN_PAYLOAD",
                    title=f"Sensitive Credentials in Plaintext JWT Payload ({', '.join(exposed_keys)})",
                    description=(
                        f"The JWT payload contains sensitive credential fields: {', '.join(exposed_keys)}. "
                        "JWT payloads are merely base64-encoded, NOT encrypted, and visible to anyone inspecting the token."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    module=self.name,
                    impact="Credential Leakage: Exposes cleartext passwords or internal secrets to client-side scripts and network logs.",
                    evidence=f"Disclosed payload keys: {', '.join(exposed_keys)}",
                    curl_command=curl_cmd,
                    affected_urls=[target.raw_url],
                    remediation="Never store passwords, secrets, or private keys inside JWT claims.",
                    remediation_snippets=get_jwt_audit_remediations(),
                    cwe_id="CWE-312",
                    owasp_category="A02:2021-Cryptographic Failures",
                )
            )

    def _decode_segment(self, segment: str) -> Optional[Dict[str, Any]]:
        """Decode base64url segment into JSON dict."""
        try:
            # Re-add required base64 padding
            padded = segment + "=" * ((4 - len(segment) % 4) % 4)
            decoded_bytes = base64.urlsafe_b64decode(padded)
            return json.loads(decoded_bytes.decode("utf-8", errors="ignore"))
        except Exception:
            return None
