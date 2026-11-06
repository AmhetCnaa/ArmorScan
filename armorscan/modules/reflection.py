"""
Input Reflection & Context Analysis Module for ArmorScan.
Tests input parameters for unencoded reflection and identifies injection contexts
(Raw HTML, Script block, or Tag Attribute) to uncover potential XSS vectors.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
import uuid

from armorscan.core.client import HttpClient, HttpResponse
from armorscan.core.models import Finding, ModuleResult, ScanTarget, Severity
from armorscan.modules.base import BaseModule
from armorscan.remediations.templates import get_reflection_remediations

DEFAULT_TEST_PARAMS = ["q", "search", "name", "keyword", "query"]


class InputReflectionModule(BaseModule):
    """Audits targets for unencoded user input reflection and HTML/Script context escapes."""

    name: str = "reflection"
    display_name: str = "Input Reflection & Context Analysis"
    description: str = "Probes parameters for unescaped HTML, script block, and tag attribute reflection."

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        # Determine parameters to test
        parsed_url = urlparse(target.raw_url)
        existing_params = parse_qs(parsed_url.query)

        params_to_test: Set[str] = set(existing_params.keys())
        if not params_to_test:
            params_to_test = set(DEFAULT_TEST_PARAMS[:3])  # Test common params if none present

        for param in sorted(list(params_to_test)):
            await self._audit_param_reflection(target, client, param, findings, passed_checks)

        if not findings and passed_checks:
            passed_checks.append("no-unencoded-input-reflection-detected")

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )

    async def _audit_param_reflection(
        self,
        target: ScanTarget,
        client: HttpClient,
        param_name: str,
        findings: List[Finding],
        passed_checks: List[str],
    ) -> None:
        canary_id = uuid.uuid4().hex[:6]
        # Canary payload with special characters: quotes and angle brackets
        canary_payload = f"armorscan{canary_id}\"<'probe>"
        # Verbatim unencoded marker
        unescaped_marker = f"armorscan{canary_id}\"<'probe>"
        unescaped_tag_marker = f"<'probe>"

        test_url = self._build_probe_url(target.raw_url, param_name, canary_payload)
        resp = await client.get(test_url)

        if not resp.ok or not resp.text:
            return

        text = resp.text

        # If canary is not reflected at all, parameter is not reflected
        if f"armorscan{canary_id}" not in text:
            passed_checks.append(f"param-{param_name}:not-reflected")
            return

        # Check if properly HTML-encoded (e.g. &lt; or &#39; or &#60;)
        is_encoded = (
            f"&lt;&#39;probe&gt;" in text
            or f"&lt;&apos;probe&gt;" in text
            or f"&lt;'probe&gt;" in text
            or f"&#60;" in text
            or f"&quot;&lt;" in text
        )

        # Check if unescaped angle brackets or quotes are reflected
        if unescaped_marker in text or unescaped_tag_marker in text:
            context = self._analyze_reflection_context(text, f"armorscan{canary_id}")

            if context == "script":
                findings.append(
                    Finding(
                        id="SCRIPT_CONTEXT_INPUT_REFLECTION",
                        title=f"High Risk: Input Reflected Directly Inside <script> Block ({param_name})",
                        description=(
                            f"Parameter '{param_name}' is reflected without sanitization directly inside a "
                            "<script> block. Attackers can execute arbitrary JavaScript in the user's browser."
                        ),
                        severity=Severity.HIGH,
                        module=self.name,
                        impact="Direct XSS execution: Bypasses standard HTML tag filtering and executes in script context.",
                        evidence=f"Reflected in <script> tag: ...{canary_payload}...",
                        remediation="Never reflect untrusted inputs directly inside script tags. Use JSON serialization with unicode escapes.",
                        remediation_snippets=get_reflection_remediations(),
                        cwe_id="CWE-79",
                        owasp_category="A03:2021-Injection",
                    )
                )
            elif context == "attribute":
                findings.append(
                    Finding(
                        id="ATTRIBUTE_CONTEXT_INPUT_REFLECTION",
                        title=f"Input Reflected Inside HTML Tag Attribute Without Escaping ({param_name})",
                        description=(
                            f"Parameter '{param_name}' is reflected inside an HTML attribute with unescaped quotes. "
                            "Attackers can break out of the attribute and inject event handlers (e.g., onload, onmouseover)."
                        ),
                        severity=Severity.MEDIUM,
                        module=self.name,
                        impact="Attribute breakout XSS: Enables event handler injection or javascript: URI execution.",
                        evidence=f"Reflected in attribute context: ...{canary_payload}...",
                        remediation="HTML-attribute-encode untrusted inputs (encode quotes, ampersands, angle brackets).",
                        remediation_snippets=get_reflection_remediations(),
                        cwe_id="CWE-79",
                        owasp_category="A03:2021-Injection",
                    )
                )
            else:
                findings.append(
                    Finding(
                        id="UNENCODED_HTML_INPUT_REFLECTION",
                        title=f"High Risk: Unencoded Input Reflection in HTML Body ({param_name})",
                        description=(
                            f"Parameter '{param_name}' was reflected in the HTML response body with raw, unencoded "
                            "angle brackets (< >) and quotation marks (\")."
                        ),
                        severity=Severity.HIGH,
                        module=self.name,
                        impact="Cross-Site Scripting (XSS): Enables attackers to inject arbitrary HTML tags and scripts.",
                        evidence=f"Unencoded reflection found for '{param_name}': {canary_payload}",
                        remediation="Apply context-aware HTML entity encoding on all user-supplied outputs.",
                        remediation_snippets=get_reflection_remediations(),
                        cwe_id="CWE-79",
                        owasp_category="A03:2021-Injection",
                    )
                )
        elif is_encoded:
            passed_checks.append(f"param-{param_name}:safely-html-encoded")

    def _build_probe_url(self, raw_url: str, param: str, value: str) -> str:
        parsed = urlparse(raw_url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    def _analyze_reflection_context(self, html_text: str, token: str) -> str:
        """Heuristically identify whether token resides in a <script> block, an attribute, or body."""
        idx = html_text.find(token)
        if idx == -1:
            return "body"

        # Check for <script> context: find last <script or </script before token
        prefix = html_text[:idx].lower()
        last_script_open = prefix.rfind("<script")
        last_script_close = prefix.rfind("</script")

        if last_script_open > last_script_close:
            return "script"

        # Check for attribute context: inside a tag <tag attr="...token..."
        last_tag_open = prefix.rfind("<")
        last_tag_close = prefix.rfind(">")
        if last_tag_open > last_tag_close:
            return "attribute"

        return "body"
