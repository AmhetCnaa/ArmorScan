"""
Error-Based Information & Database Leakage Audit Module for ArmorScan.
Tests endpoints with unexpected input types to detect unhandled exceptions,
raw database errors, and exposed server stack traces.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from armorscan.core.client import HttpClient, HttpResponse
from armorscan.core.models import Finding, ModuleResult, ScanTarget, Severity
from armorscan.modules.base import BaseModule
from armorscan.remediations.templates import get_error_leak_remediations

DB_ERROR_PATTERNS = [
    (r"SQL syntax.*MySQL", "MySQL"),
    (r"syntax error near", "Generic SQL"),
    (r"unclosed quotation mark after the character string", "MSSQL"),
    (r"ORA-[0-9]{4,5}", "Oracle DB"),
    (r"PostgreSQL query failed", "PostgreSQL"),
    (r"psycopg2\.errors\.", "PostgreSQL / psycopg2"),
    (r"sqlite3\.OperationalError", "SQLite"),
    (r"Mongo(?:Server)?Error", "MongoDB"),
    (r"com\.mysql\.jdbc\.exceptions", "MySQL JDBC"),
]

STACK_TRACE_PATTERNS = [
    (r"Traceback \(most recent call last\):", "Python Traceback"),
    (r"Django Version:\s*[0-9.]+", "Django Debug Page"),
    (r"at (?:Function\.Module\._load|Object\.<anonymous>|next) \([^)]+\.js:[0-9]+:[0-9]+\)", "Node.js Stack Trace"),
    (r"java\.lang\.[A-Za-z]+Exception", "Java Exception"),
    (r"at org\.springframework\.", "Spring Framework Trace"),
    (r"Fatal error: Uncaught [A-Za-z]+Exception in /[^:]+:[0-9]+", "PHP Fatal Error"),
]

ERROR_PROBES = ["'", "\"", "[]", "9999999999"]


class ErrorLeakModule(BaseModule):
    """Audits targets for database error disclosure and unhandled stack traces."""

    name: str = "error_leak"
    display_name: str = "Error-Based Info & Database Leakage Audit"
    description: str = "Probes parameters to detect exposed database errors and raw stack traces."

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        parsed_url = urlparse(target.raw_url)
        existing_params = parse_qs(parsed_url.query)

        # Baseline check on root first
        base_resp = await client.get(target.raw_url)
        if base_resp.ok and base_resp.text:
            self._scan_text_for_leaks(base_resp.text, "Baseline Target URL", findings, passed_checks)

        # Probe parameters
        params_to_test = list(existing_params.keys()) if existing_params else ["id", "user", "page"]

        for param in params_to_test[:3]:
            for probe in ERROR_PROBES:
                probe_url = self._build_probe_url(target.raw_url, param, probe)
                resp = await client.get(probe_url)
                if resp.ok and resp.text:
                    if self._scan_text_for_leaks(resp.text, f"Param '{param}' with probe '{probe}'", findings, passed_checks):
                        break  # Found leak for this param, stop probing other probes for it

        if not findings and passed_checks:
            passed_checks.append("no-stack-traces-or-db-errors-disclosed")

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )

    def _scan_text_for_leaks(
        self,
        text: str,
        source_label: str,
        findings: List[Finding],
        passed_checks: List[str],
    ) -> bool:
        """Scan response text against DB and stack trace signatures."""
        leak_found = False

        # 1. Database Error Check
        for pattern, db_name in DB_ERROR_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                evidence_snippet = text[max(0, match.start() - 30) : min(len(text), match.end() + 80)].strip()
                findings.append(
                    Finding(
                        id="DATABASE_ERROR_DISCLOSURE",
                        title=f"High Risk: Database Error Disclosed ({db_name})",
                        description=(
                            f"The application returned a raw database error message from {db_name} "
                            f"triggered by: {source_label}."
                        ),
                        severity=Severity.HIGH,
                        module=self.name,
                        impact=(
                            "Schema Reconnaissance & SQLi: Raw database errors expose internal column/table names "
                            "and serve as immediate proof of SQL injection or improper query handling."
                        ),
                        evidence=f"Matched {db_name} pattern: '{evidence_snippet}'",
                        remediation="Catch all database exceptions and return generic opaque error messages.",
                        remediation_snippets=get_error_leak_remediations(),
                        cwe_id="CWE-209",
                        owasp_category="A05:2021-Security Misconfiguration",
                    )
                )
                leak_found = True
                break

        # 2. Stack Trace / Debugger Check
        for pattern, trace_name in STACK_TRACE_PATTERNS:
            match = re.search(pattern, text)
            if match:
                evidence_snippet = text[max(0, match.start() - 20) : min(len(text), match.end() + 100)].strip()
                findings.append(
                    Finding(
                        id="STACK_TRACE_DISCLOSURE",
                        title=f"High Risk: Detailed Stack Trace Disclosed ({trace_name})",
                        description=(
                            f"The server leaked an internal application stack trace ({trace_name}) "
                            f"triggered by: {source_label}."
                        ),
                        severity=Severity.HIGH,
                        module=self.name,
                        impact=(
                            "Information Disclosure: Reveals backend source file paths, third-party library versions, "
                            "and application call flows, assisting targeted exploitation."
                        ),
                        evidence=f"Matched trace signature: '{evidence_snippet}'",
                        remediation="Disable DEBUG mode in production and configure global generic error handling.",
                        remediation_snippets=get_error_leak_remediations(),
                        cwe_id="CWE-209",
                        owasp_category="A05:2021-Security Misconfiguration",
                    )
                )
                leak_found = True
                break

        if not leak_found:
            passed_checks.append(f"{source_label}:clean")

        return leak_found

    def _build_probe_url(self, raw_url: str, param: str, value: str) -> str:
        parsed = urlparse(raw_url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
