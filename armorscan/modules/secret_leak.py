"""
DOM & Client-Side Secret Hunter Module for ArmorScan.
Scans HTML source code and client-side JavaScript bundles to identify hardcoded API keys,
cloud credentials (AWS, OpenAI, GitHub, Stripe, Slack), and internal staging URLs.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from armorscan.core.client import HttpClient, HttpResponse
from armorscan.core.models import Confidence, Finding, ModuleResult, ScanTarget, Severity
from armorscan.modules.base import BaseModule
from armorscan.remediations.templates import get_secret_leak_remediations

SECRET_RULES = [
    {
        "id": "OPENAI_API_KEY_LEAK",
        "name": "OpenAI Secret API Key",
        "pattern": re.compile(r"\b(sk-[A-Za-z0-9]{20,}|sk-proj-[A-Za-z0-9_-]{20,})\b"),
        "severity": Severity.CRITICAL,
        "impact": "Unrestricted OpenAI API usage, unauthorized LLM consumption, and data leakage.",
    },
    {
        "id": "AWS_ACCESS_KEY_LEAK",
        "name": "AWS Access Key ID",
        "pattern": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "severity": Severity.HIGH,
        "impact": "Exposes AWS account identity and enables automated credential spraying against AWS IAM.",
    },
    {
        "id": "GITHUB_PAT_LEAK",
        "name": "GitHub Personal Access Token",
        "pattern": re.compile(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{30,})\b"),
        "severity": Severity.CRITICAL,
        "impact": "Source code repository takeover, private commits access, and unauthorized CI/CD manipulation.",
    },
    {
        "id": "STRIPE_SECRET_KEY_LEAK",
        "name": "Stripe Live Secret Key",
        "pattern": re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b"),
        "severity": Severity.CRITICAL,
        "impact": "Complete payment gateway compromise: Allows unauthorized refunds, customer PII theft, and card tampering.",
    },
    {
        "id": "SLACK_WEBHOOK_LEAK",
        "name": "Slack Incoming Webhook URL",
        "pattern": re.compile(r"(https://hooks\.slack\.com/services/T[0-9A-Za-z]{6,}/B[0-9A-Za-z]{6,}/[0-9A-Za-z]{18,})"),
        "severity": Severity.HIGH,
        "impact": "Enables attackers to post malicious messages, phishing links, and spoof notifications in internal Slack channels.",
    },
    {
        "id": "GOOGLE_API_KEY_LEAK",
        "name": "Google Cloud / Maps API Key",
        "pattern": re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        "severity": Severity.MEDIUM,
        "impact": "Potential quota exhaustion and unauthorized consumption of Google Cloud APIs.",
    },
    {
        "id": "INTERNAL_IP_DISCLOSURE",
        "name": "Internal RFC 1918 Private IP Address",
        "pattern": re.compile(r"\b(https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/[^\s\"'<>]+)?)\b"),
        "severity": Severity.LOW,
        "impact": "Internal network topology disclosure: Leaks staging IPs or private microservice routing addresses.",
    },
]

SCRIPT_SRC_REGEX = re.compile(r"""<script\b[^>]*src=["']([^"']+\.js[^"']*)["']""", re.IGNORECASE)


class SecretLeakModule(BaseModule):
    """Audits HTML and client-side JavaScript assets for hardcoded secrets and credentials."""

    name: str = "secret_leak"
    display_name: str = "DOM & Client-Side Secret Hunter"
    description: str = "Scans HTML source and linked JS bundles for exposed API keys and credentials."

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        # 1. Fetch main HTML document
        resp = await client.get(target.raw_url)
        if not resp.ok or not resp.text:
            return ModuleResult(
                module_name=self.name,
                display_name=self.display_name,
                findings=[],
                passed_checks=["target-not-reachable"],
            )

        html_text = resp.text
        # Scan HTML body
        self._scan_content_for_secrets(html_text, target, target.raw_url, "HTML Document", findings, client)

        # 2. Extract and fetch up to 4 client-side JS bundles
        js_urls = self._extract_js_urls(target, html_text)
        for js_url in js_urls[:4]:
            js_resp = await client.get(js_url)
            if js_resp.ok and js_resp.text:
                self._scan_content_for_secrets(js_resp.text, target, js_url, f"JavaScript Bundle ({js_url})", findings, client)

        if not findings:
            passed_checks.append("no-hardcoded-secrets-in-client-assets")

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )

    def _extract_js_urls(self, target: ScanTarget, html_text: str) -> List[str]:
        """Extract same-origin or relative JavaScript URLs from script tags."""
        urls: List[str] = []
        target_host = target.host.lower()

        for match in SCRIPT_SRC_REGEX.finditer(html_text):
            src = match.group(1).strip()
            full_url = urljoin(target.raw_url, src)
            parsed = urlparse(full_url)
            # Only include same-origin JS files to avoid crawling third-party trackers
            if parsed.hostname and parsed.hostname.lower() == target_host:
                urls.append(full_url)

        return urls

    def _scan_content_for_secrets(
        self,
        content: str,
        target: ScanTarget,
        asset_url: str,
        source_label: str,
        findings: List[Finding],
        client: HttpClient,
    ) -> None:
        """Scan text using compiled secret rules with masked context snippet."""
        for rule in SECRET_RULES:
            rule_id = rule["id"]
            pattern: re.Pattern = rule["pattern"]

            # If finding with this ID is already reported, avoid duplicates
            if any(f.id == rule_id for f in findings):
                continue

            matches = pattern.findall(content)
            if matches:
                sample_match = matches[0]
                masked_match = self._mask_secret(sample_match)

                # Safe masked context snippet
                raw_snippet = Finding.extract_context_snippet(content, sample_match)
                masked_snippet = raw_snippet.replace(sample_match, masked_match)

                curl_cmd = Finding.build_curl("GET", asset_url)
                req_snippet = f"GET {asset_url} HTTP/1.1\nHost: {target.host}\nUser-Agent: {client.user_agent}"

                findings.append(
                    Finding(
                        id=rule_id,
                        title=f"{rule['name']} Disclosed in {source_label.split('(')[0].strip()}",
                        description=(
                            f"A hardcoded credential ({rule['name']}) was detected inside publicly delivered client assets "
                            f"from {source_label}."
                        ),
                        severity=rule["severity"],
                        confidence=Confidence.CONFIRMED,
                        module=self.name,
                        impact=rule["impact"],
                        evidence=f"Matched secret (masked): {masked_match}",
                        curl_command=curl_cmd,
                        request_snippet=req_snippet,
                        response_snippet=masked_snippet,
                        affected_urls=[asset_url],
                        remediation="Revoke the exposed key immediately and move all secret credentials to server-side environment variables.",
                        remediation_snippets=get_secret_leak_remediations(),
                        cwe_id="CWE-798",
                        owasp_category="A07:2021-Identification and Authentication Failures",
                    )
                )

    def _mask_secret(self, secret: str) -> str:
        """Safely mask secret for evidence output."""
        if len(secret) <= 8:
            return "****"
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]
