"""
WebSocket & GraphQL Protocol Resilience Audit Module for ArmorScan.
Tests WebSocket endpoints for missing Origin validation (Cross-Site WebSocket Hijacking - CSWSH)
and GraphQL endpoints for unbounded batching / alias amplification attacks.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from armorscan.core.client import HttpClient
from armorscan.core.models import Confidence, Finding, ModuleResult, ScanTarget, Severity
from armorscan.modules.base import BaseModule

DEFAULT_WS_PATHS = ["/ws", "/socket.io/", "/chat", "/cable", "/graphql/ws", "/notifications"]
DEFAULT_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql"]

# Multi-alias amplification payload
ALIAS_QUERY = """
query AliasAmplificationProbe {
  a1: __typename
  a2: __typename
  a3: __typename
  a4: __typename
  a5: __typename
  a6: __typename
  a7: __typename
  a8: __typename
  a9: __typename
  a10: __typename
}
""".strip()


class ProtocolsResilienceModule(BaseModule):
    """
    WebSocket & GraphQL Protocol Resilience Auditor.
    Audits transport-level origin validation and query complexity batch limits.
    """

    name: str = "protocols"
    display_name: str = "WebSocket & GraphQL Protocol Resilience Auditor"
    description: str = "Evaluates WebSocket handshake origin validation and GraphQL query alias batching limits."

    def __init__(
        self,
        candidate_ws_paths: Optional[List[str]] = None,
        candidate_graphql_paths: Optional[List[str]] = None,
    ):
        self.candidate_ws_paths = candidate_ws_paths or []
        self.candidate_graphql_paths = candidate_graphql_paths or []

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        # 1. Audit WebSocket Origin Validation
        await self._audit_websocket_origin(target, client, findings, passed_checks)

        # 2. Audit GraphQL Unbounded Batching
        await self._audit_graphql_batching(target, client, findings, passed_checks)

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )

    async def _audit_websocket_origin(
        self,
        target: ScanTarget,
        client: HttpClient,
        findings: List[Finding],
        passed_checks: List[str],
    ) -> None:
        """Check if WebSocket upgrade rejects untrusted cross-origin requests."""
        ws_endpoints: Set[str] = set()
        for p in self.candidate_ws_paths or DEFAULT_WS_PATHS:
            ws_endpoints.add(urljoin(target.base_url, p))

        if target.discovered_paths:
            for p in target.discovered_paths:
                if any(kw in p.lower() for kw in ("ws", "socket", "chat", "cable")):
                    ws_endpoints.add(urljoin(target.base_url, p))

        untrusted_origin = "https://untrusted-attacker-origin.evil.com"
        ws_headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
            "Origin": untrusted_origin,
        }

        for full_url in sorted(ws_endpoints):
            parsed = urlparse(full_url)
            try:
                resp = await client.get(full_url, headers=ws_headers)
                # If server accepts the upgrade with 101 Switching Protocols without checking Origin
                if resp.status_code == 101:
                    curl_cmd = (
                        f"curl -i -N -H 'Upgrade: websocket' -H 'Connection: Upgrade' "
                        f"-H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Version: 13' "
                        f"-H 'Origin: {untrusted_origin}' '{full_url}'"
                    )
                    findings.append(
                        Finding(
                            id="WEBSOCKET_MISSING_ORIGIN_VALIDATION",
                            title=f"WebSocket Missing Origin Validation (CSWSH Risk) on {parsed.path}",
                            description=(
                                f"The WebSocket endpoint at '{parsed.path}' completed an HTTP 101 Switching Protocols "
                                f"handshake despite receiving an untrusted cross-origin Origin header ('{untrusted_origin}')."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.CONFIRMED,
                            module=self.name,
                            impact=(
                                "Enables Cross-Site WebSocket Hijacking (CSWSH). If users authenticate via ambient cookies, "
                                "a malicious web page can initiate duplex WebSocket connections and steal sensitive real-time data."
                            ),
                            evidence=(
                                f"Handshake with Origin '{untrusted_origin}' returned HTTP 101 Switching Protocols. "
                                f"Response Headers: {dict(resp.headers)}"
                            ),
                            curl_command=curl_cmd,
                            affected_urls=[full_url],
                            remediation=(
                                "Validate the 'Origin' request header during the WebSocket HTTP Upgrade handshake and reject "
                                "any origins not explicitly listed in your server's trusted domain whitelist with HTTP 403 Forbidden."
                            ),
                            cwe_id="CWE-1385",
                            owasp_category="A01:2021-Broken Access Control",
                        )
                    )
                elif resp.status_code in (401, 403, 400):
                    passed_checks.append(
                        f"WebSocket endpoint {parsed.path} safely rejected untrusted cross-origin handshake (HTTP {resp.status_code})"
                    )
            except Exception:
                continue

    async def _audit_graphql_batching(
        self,
        target: ScanTarget,
        client: HttpClient,
        findings: List[Finding],
        passed_checks: List[str],
    ) -> None:
        """Check if GraphQL endpoint enforces alias limits or batch request caps."""
        gql_endpoints: Set[str] = set()
        for p in self.candidate_graphql_paths or DEFAULT_GRAPHQL_PATHS:
            gql_endpoints.add(urljoin(target.base_url, p))

        if target.discovered_paths:
            for p in target.discovered_paths:
                if "graphql" in p.lower():
                    gql_endpoints.add(urljoin(target.base_url, p))

        for full_url in sorted(gql_endpoints):
            parsed = urlparse(full_url)
            try:
                # 1. Test multi-alias amplification
                resp = await client.post(full_url, json={"query": ALIAS_QUERY})
                if resp.status_code == 200:
                    try:
                        import json
                        data = json.loads(resp.text)
                    except Exception:
                        data = None

                    if isinstance(data, dict) and "data" in data and isinstance(data["data"], dict):
                        ret_keys = list(data["data"].keys())
                        # If all 10 aliases were executed without restriction
                        if len(ret_keys) >= 10 and all(k.startswith("a") for k in ret_keys):
                            curl_cmd = Finding.build_curl("POST", full_url, data='{"query": "query { a1: __typename ... a10: __typename }"}')
                            findings.append(
                                Finding(
                                    id="GRAPHQL_UNBOUNDED_BATCHING",
                                    title=f"Unbounded GraphQL Query Batching / Alias Amplification on {parsed.path}",
                                    description=(
                                        f"The GraphQL endpoint '{parsed.path}' allowed executing 10 simultaneous field aliases "
                                        f"in a single HTTP query without enforcing query complexity or alias limits."
                                    ),
                                    severity=Severity.MEDIUM,
                                    confidence=Confidence.CONFIRMED,
                                    module=self.name,
                                    impact=(
                                        "Attackers can bypass rate limits, brute-force OTP tokens/passwords, or trigger "
                                        "backend resource exhaustion (Denial of Service) by packing hundreds of queries into one request."
                                    ),
                                    evidence=(
                                        f"Single HTTP POST returned HTTP 200 OK with {len(ret_keys)} simultaneously resolved aliases: "
                                        f"{ret_keys[:5]}..."
                                    ),
                                    curl_command=curl_cmd,
                                    affected_urls=[full_url],
                                    remediation=(
                                        "Configure query depth and alias limits (e.g. graphql-armor, max_aliases=5), "
                                        "and disable batch array queries in production."
                                    ),
                                    cwe_id="CWE-770",
                                    owasp_category="A04:2021-Insecure Design",
                                )
                            )
                elif resp.status_code in (400, 429):
                    passed_checks.append(
                        f"GraphQL endpoint {parsed.path} properly enforced query complexity or batch limits (HTTP {resp.status_code})"
                    )
            except Exception:
                continue
