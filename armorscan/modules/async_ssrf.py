"""
Asynchronous Outbound Callback & Blind SSRF Audit Module for ArmorScan.
Coordinates with LocalCallbackVerifier to inject ephemeral verification tokens
into webhook, callback, and URL parameters to confirm unvalidated outbound requests.
"""

from __future__ import annotations

import asyncio
from typing import Dict, List, Optional, Set
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from armorscan.core.callback_verifier import LocalCallbackVerifier
from armorscan.core.client import HttpClient
from armorscan.core.models import Confidence, Finding, ModuleResult, ScanTarget, Severity
from armorscan.modules.base import BaseModule

CALLBACK_PARAM_NAMES = {
    "url", "webhook", "webhook_url", "callback", "callback_url", "dest",
    "destination", "feed", "target", "redirect_uri", "endpoint", "fetch_url"
}

DEFAULT_WEBHOOK_PATHS = [
    "/api/webhook",
    "/api/webhooks",
    "/api/subscribe",
    "/api/notify",
    "/api/callbacks",
    "/rest/import",
    "/api/url-preview",
]


class AsyncSsrfModule(BaseModule):
    """
    Asynchronous Outbound Callback & Blind SSRF Verifier.
    Launches an ephemeral local listener to confirm unvalidated outbound server connections.
    """

    name: str = "async_ssrf"
    display_name: str = "Asynchronous Outbound Callback & Blind SSRF Verifier"
    description: str = "Probes webhook and URL parameters with ephemeral local tokens to confirm unvalidated outbound HTTP calls."

    def __init__(self, verifier: Optional[LocalCallbackVerifier] = None):
        self._external_verifier = verifier

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        # Use external verifier if passed, otherwise launch an ephemeral one
        verifier = self._external_verifier or LocalCallbackVerifier()
        own_verifier = self._external_verifier is None

        if own_verifier:
            await verifier.start()

        try:
            # 1. Gather target endpoints
            candidate_urls: Set[str] = set()

            parsed_target = urlparse(target.raw_url)
            if parsed_target.query:
                candidate_urls.add(target.raw_url)

            if target.discovered_paths:
                for p in target.discovered_paths:
                    if any(kw in p.lower() for kw in ("webhook", "callback", "subscribe", "notify", "fetch", "preview")):
                        candidate_urls.add(urljoin(target.base_url, p))
                    elif "?" in p:
                        candidate_urls.add(urljoin(target.base_url, p))

            for p in DEFAULT_WEBHOOK_PATHS:
                candidate_urls.add(urljoin(target.base_url, p))

            # 2. Iterate and test candidate parameters
            for full_url in sorted(candidate_urls):
                parsed = urlparse(full_url)
                qs = parse_qs(parsed.query)

                # Test A: Query parameters
                for param_name in list(qs.keys()):
                    if param_name.lower() in CALLBACK_PARAM_NAMES or "url" in param_name.lower():
                        token, callback_url = verifier.register_probe(parsed.path, param_name)

                        tampered_qs = dict(qs)
                        tampered_qs[param_name] = [callback_url]
                        test_url = urlunparse((
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            parsed.params,
                            urlencode(tampered_qs, doseq=True),
                            parsed.fragment,
                        ))

                        try:
                            await client.get(test_url)
                        except Exception:
                            pass

                # Test B: JSON webhook endpoints
                if any(kw in parsed.path.lower() for kw in ("webhook", "callback", "subscribe", "notify", "import")):
                    token, callback_url = verifier.register_probe(parsed.path, "json_body_url")
                    try:
                        await client.post(
                            full_url,
                            json={"url": callback_url, "webhook_url": callback_url, "callback": callback_url},
                        )
                    except Exception:
                        pass

            # 3. Wait briefly for asynchronous callbacks
            await verifier.wait_for_callbacks(timeout=0.4)

            # 4. Analyze intercepted events
            for ev in verifier.captured_events:
                finding_url = urljoin(target.base_url, ev.endpoint)
                curl_cmd = Finding.build_curl("POST", finding_url, data=f'{{"url": "{verifier.base_url}/verify/{ev.token}"}}')

                findings.append(
                    Finding(
                        id="UNVALIDATED_ASYNC_OUTBOUND_CALLBACK",
                        title=f"Unvalidated Asynchronous Outbound Callback (Blind SSRF) on {ev.endpoint}",
                        description=(
                            f"The endpoint '{ev.endpoint}' triggered an asynchronous outbound connection "
                            f"to the user-controlled parameter '{ev.parameter}' without strict IP allowlisting or URL validation."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        module=self.name,
                        impact=(
                            "Unvalidated outbound callbacks allow attackers to pivot into the internal network, "
                            "probe internal microservices, or access cloud metadata services (e.g. AWS 169.254.169.254)."
                        ),
                        evidence=(
                            f"Backend worker triggered HTTP {ev.method} callback to verification URL "
                            f"from {ev.client_address} (Token: {ev.token})."
                        ),
                        curl_command=curl_cmd,
                        affected_urls=[finding_url],
                        remediation=(
                            "Validate outbound destination URLs against a strict domain whitelist, disallow internal IP ranges "
                            "(127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254), "
                            "and enforce an isolated egress proxy for webhook dispatch."
                        ),
                        cwe_id="CWE-918",
                        owasp_category="A10:2021-Server-Side Request Forgery (SSRF)",
                    )
                )

            if not findings:
                passed_checks.append("All tested webhook and callback endpoints safely rejected or did not trigger unvalidated local callbacks.")

        finally:
            if own_verifier:
                await verifier.stop()

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )
