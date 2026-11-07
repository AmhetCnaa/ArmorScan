"""
Core data models for ArmorScan.
Defines findings, severities, scan results, and configuration structures.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def color(self) -> str:
        """Return Rich color tag corresponding to the severity."""
        return {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "blue",
        }[self]

    @property
    def score_penalty(self) -> int:
        """Penalty points subtracted from 100 per finding."""
        return {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }[self]


class Grade(str, Enum):
    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"

    @classmethod
    def from_score(cls, score: int) -> Grade:
        if score >= 95:
            return cls.A_PLUS
        elif score >= 85:
            return cls.A
        elif score >= 70:
            return cls.B
        elif score >= 55:
            return cls.C
        elif score >= 40:
            return cls.D
        return cls.F

    @property
    def color(self) -> str:
        return {
            Grade.A_PLUS: "bold green",
            Grade.A: "green",
            Grade.B: "bold yellow",
            Grade.C: "yellow",
            Grade.D: "bold red",
            Grade.F: "bold red on white",
        }[self]


class Confidence(str, Enum):
    CONFIRMED = "confirmed"  # Verified by dynamic multi-pass probe or exact canary match
    FIRM = "firm"            # High confidence behavioral or structured evidence
    TENTATIVE = "tentative"  # Heuristic, signature-only, or unverified response

    @property
    def color(self) -> str:
        return {
            Confidence.CONFIRMED: "bold green",
            Confidence.FIRM: "cyan",
            Confidence.TENTATIVE: "yellow",
        }[self]


class Finding(BaseModel):
    """Represents an individual security finding/vulnerability detected during a scan."""
    id: str = Field(..., description="Unique machine-friendly identifier, e.g., 'MISSING_HSTS'")
    title: str = Field(..., description="Short human-readable finding title")
    description: str = Field(..., description="Detailed explanation of the issue")
    severity: Severity = Field(..., description="Finding severity level")
    module: str = Field(..., description="Name of the module that produced this finding")
    impact: str = Field(..., description="Security impact / exploit risk explanation")
    evidence: Optional[str] = Field(default=None, description="Actual evidence from the response (e.g. headers, URL)")
    confidence: Confidence = Field(default=Confidence.FIRM, description="Finding confidence rating (confirmed, firm, tentative)")
    curl_command: Optional[str] = Field(default=None, description="Ready-to-use curl command to reproduce the finding")
    request_snippet: Optional[str] = Field(default=None, description="Full HTTP request representation (method, URL, headers)")
    response_snippet: Optional[str] = Field(default=None, description="HTTP response snippet (matching lines with ±2 lines of context)")
    affected_urls: List[str] = Field(default_factory=list, description="List of all affected URLs where this finding applies")
    is_suppressed: bool = Field(default=False, description="Whether this finding is suppressed via .armorscanignore")
    suppression_reason: Optional[str] = Field(default=None, description="Reason why this finding was suppressed")
    remediation: Optional[str] = Field(default=None, description="General fix guidance")
    remediation_snippets: Dict[str, str] = Field(
        default_factory=dict,
        description="Framework-specific fix code snippets (nginx, express, fastapi, etc.)",
    )
    references: List[str] = Field(default_factory=list, description="Useful links to OWASP, MDN, CWE")
    cwe_id: Optional[str] = Field(default=None, description="CWE identifier (e.g. 'CWE-693')")
    owasp_category: Optional[str] = Field(default=None, description="OWASP Top 10 category")

    @staticmethod
    def build_curl(
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[str] = None,
    ) -> str:
        """Construct a standardized, copy-pasteable curl reproduction command."""
        cmd_parts = [f"curl -i -s -k -X {method.upper()} '{url}'"]
        if headers:
            for k, v in headers.items():
                if k.lower() in ("host", "user-agent", "origin", "cookie", "referer", "content-type", "authorization"):
                    val_str = str(v)
                    if k.lower() == "authorization" and len(val_str) > 16:
                        val_str = f"{val_str[:12]}...[REDACTED]"
                    cmd_parts.append(f"-H '{k}: {val_str}'")
        if data:
            cmd_parts.append(f"--data '{data}'")
        return " \\\n  ".join(cmd_parts)

    @staticmethod
    def extract_context_snippet(full_text: str, match_str: str, context_lines: int = 2) -> str:
        """Extract matching lines with ±context_lines around match_str."""
        if not full_text or not match_str:
            return ""
        lines = full_text.splitlines()
        for idx, line in enumerate(lines):
            if match_str in line:
                start = max(0, idx - context_lines)
                end = min(len(lines), idx + context_lines + 1)
                snippet_lines = []
                for i in range(start, end):
                    prefix = ">> " if i == idx else "   "
                    snippet_lines.append(f"{prefix}{lines[i]}")
                return "\n".join(snippet_lines)
        return match_str[:250]


class ModuleResult(BaseModel):
    """Result of running a single scanner module."""
    module_name: str
    display_name: str
    duration_seconds: float = 0.0
    findings: List[Finding] = Field(default_factory=list)
    passed_checks: List[str] = Field(default_factory=list)
    error: Optional[str] = None

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0


class ScanTarget(BaseModel):
    """Structured information about the target URL being audited."""
    raw_url: str
    scheme: str
    host: str
    port: int
    path: str
    is_https: bool
    is_localhost: bool
    discovered_paths: List[str] = Field(default_factory=list)

    @classmethod
    def from_url(cls, url: str) -> ScanTarget:
        """Parse, validate and normalize a target URL."""
        cleaned = url.strip()
        if "://" in cleaned:
            scheme = cleaned.split("://", 1)[0].lower()
            if scheme not in ("http", "https"):
                raise ValueError(f"Unsupported URL scheme: '{scheme}'. Use http:// or https://")
        else:
            # Auto-prefix: default to http for localhost/127.0.0.1, https for others
            host_part = cleaned.split("/")[0].split(":")[0].lower()
            if host_part in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
                cleaned = "http://" + cleaned
            else:
                cleaned = "https://" + cleaned

        parsed = urlparse(cleaned)
        scheme = parsed.scheme.lower()
        host = parsed.hostname or ""
        if not host:
            raise ValueError(f"Invalid target URL: {url} (missing host)")

        default_port = 443 if scheme == "https" else 80
        port = parsed.port or default_port
        path = parsed.path if parsed.path else "/"

        is_local = host in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or host.endswith(".local") or host.endswith(".internal")

        return cls(
            raw_url=cleaned,
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            is_https=(scheme == "https"),
            is_localhost=is_local,
        )

    @property
    def base_url(self) -> str:
        """Return base URL without query parameters or trailing slash in path."""
        port_part = ""
        if (self.scheme == "https" and self.port != 443) or (self.scheme == "http" and self.port != 80):
            port_part = f":{self.port}"
        return f"{self.scheme}://{self.host}{port_part}"


class ScanSummary(BaseModel):
    """Overall summary statistics and score for a completed scan."""
    total_checks: int = 0
    passed_checks: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    suppressed_count: int = 0
    score: int = 100
    grade: Grade = Grade.A_PLUS


class ScanResult(BaseModel):
    """Complete container for a full ArmorScan execution."""
    target: ScanTarget
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    summary: ScanSummary = Field(default_factory=ScanSummary)
    modules: List[ModuleResult] = Field(default_factory=list)
    meta: Dict[str, Any] = Field(default_factory=dict)

    @property
    def all_findings(self) -> List[Finding]:
        """Aggregate all findings across all modules."""
        findings: List[Finding] = []
        for mod in self.modules:
            findings.extend(mod.findings)
        return findings
