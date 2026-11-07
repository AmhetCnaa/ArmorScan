"""
Server-Side Request Forgery (SSRF) Indication Module for ArmorScan (modules/ssrf_check.py).
Audits URL-accepting parameters (?url=, ?webhook=, ?callback=, ?uri=, ?avatar=)
using harmless loopback and link-local canary probes to detect unvalidated outbound requests.
"""

from __future__ import annotations

from typing import List, Set
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from armorscan.core.client import HttpClient
from armorscan.core.models import (
    Confidence,
    Finding,
    ModuleResult,
    ScanTarget,
    Severity,
)
from armorscan.modules.base import BaseModule

SSRF_PARAM_NAMES = {
    "url",
    "uri",
    "webhook",
    "callback",
    "avatar",
    "image_url",
    "imageurl",
    "fetch",
    "proxy",
    "endpoint",
    "source",
}

SSRF_INDICATORS = [
    ("ECONNREFUSED", "Server attempted outbound TCP connection (Node/Linux ECONNREFUSED leaked)"),
    ("Connection refused", "Server attempted outbound TCP connection (Connection refused error leaked)"),
    ("169.254.169.254", "Cloud instance metadata address reflected from server outbound client"),
    ("ami-id", "AWS EC2 instance metadata leaked via SSRF"),
    ("instance-id", "Cloud instance metadata leaked via SSRF"),
    ("computeMetadata", "Google Cloud metadata leaked via SSRF"),
    ("ClientConnectorError", "Python aiohttp/httpx outbound connection error leaked"),
    ("urllib.error.URLError", "Python urllib outbound connection error leaked"),
]

SAFE_LOOPBACK_PROBES = [
    "http://127.0.0.1:80/armorscan-ssrf-check",
    "http://169.254.169.254/latest/meta-data/",
]


class SsrfCheckModule(BaseModule):
    """
    Audits URL and webhook parameters for unvalidated outbound server-side requests (SSRF)
    using harmless local loopback and metadata probe targets.
    """

    @property
    def name(self) -> str:
        return "ssrf_check"

    @property
    def display_name(self) -> str:
        return "Server-Side Request Forgery (SSRF) Auditor"

    @property
    def description(self) -> str:
        return (
            "Audits URL, webhook, and proxy parameters for unvalidated outbound server requests "
            "using non-destructive loopback and metadata indicators."
        )

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        parsed = urlparse(target.raw_url)
        qs = parse_qs(parsed.query)
        candidate_params: Set[str] = set()

        for p in qs:
            if p.lower() in SSRF_PARAM_NAMES:
                candidate_params.add(p)

        if not candidate_params and any(k in parsed.path.lower() for k in ("proxy", "fetch", "webhook", "ssrf", "url")):
            candidate_params.add("url")

        for param in sorted(candidate_params):
            baseline_url = self._build_url(parsed, param, "https://example.invalid/safe")
            base_resp = await client.get(baseline_url)

            for probe_target in SAFE_LOOPBACK_PROBES:
                test_url = self._build_url(parsed, param, probe_target)
                resp = await client.get(test_url)
                if not resp.ok and resp.status_code == 0:
                    continue

                if base_resp.ok and resp.text == base_resp.text:
                    continue

                for sig, reason in SSRF_INDICATORS:
                    if sig in resp.text and (not base_resp.ok or sig not in base_resp.text):
                        curl_cmd = Finding.build_curl("GET", test_url)
                        findings.append(
                            Finding(
                                id="SSRF_UNVALIDATED_OUTBOUND_REQUEST",
                                title=f"Unvalidated Outbound Server Request (SSRF) in '{param}'",
                                description=(
                                    f"Supplying internal loopback/metadata address '{probe_target}' in parameter '{param}' "
                                    f"triggered an outbound server connection indicator: {reason}."
                                ),
                                severity=Severity.HIGH,
                                confidence=Confidence.FIRM,
                                module=self.name,
                                impact=(
                                    "Server-Side Request Forgery (SSRF) allows attackers to scan internal VPC networks, "
                                    "query cloud instance metadata (169.254.169.254) for IAM credentials, or interact "
                                    "with unauthenticated internal services (Redis, Consul, Kubelet)."
                                ),
                                evidence=f"Parameter '{param}={probe_target}' matched indicator '{sig}' ({reason}).",
                                curl_command=curl_cmd,
                                request_snippet=f"GET {test_url} HTTP/1.1\nHost: {target.host}",
                                response_snippet=Finding.extract_context_snippet(resp.text, sig) or resp.text[:250],
                                affected_urls=[test_url],
                                remediation=(
                                    "Validate and parse user-supplied URLs against a strict domain allowlist. Resolve DNS "
                                    "and block all private/loopback IPv4/IPv6 ranges (RFC 1918, 127.0.0.0/8, 169.254.0.0/16, ::1)."
                                ),
                                remediation_snippets={
                                    "express": "// Block private/loopback IP ranges before fetching:\nconst ipaddr = require('ipaddr.js');\n// Resolve hostname and verify ipaddr.parse(ip).range() === 'unicast'",
                                    "fastapi": "import ipaddress, socket\nip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))\nif ip.is_private or ip.is_loopback or ip.is_link_local:\n    raise HTTPException(403, 'Internal target forbidden')",
                                },
                                cwe_id="CWE-918",
                                owasp_category="A10:2021-Server-Side Request Forgery (SSRF)",
                                references=[
                                    "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                                ],
                            )
                        )
                        break

        if not findings:
            passed_checks.append("no-ssrf-outbound-indicators-detected")

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )

    @staticmethod
    def _build_url(parsed, param: str, value: str) -> str:
        qs = parse_qs(parsed.query)
        qs[param] = [value]
        new_query = urlencode(qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
