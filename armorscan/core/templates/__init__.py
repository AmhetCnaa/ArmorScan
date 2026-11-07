"""
Nuclei-Style YAML Template Engine for ArmorScan (core/templates/__init__.py).
Allows security researchers and community contributors to define declarative
YAML security checks with HTTP requests, status/word/regex/header matchers,
and AND/OR boolean conditions without writing Python code.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urljoin

import yaml
from pydantic import BaseModel, Field

from armorscan.core.client import HttpClient, HttpResponse
from armorscan.core.models import (
    Confidence,
    Finding,
    ModuleResult,
    ScanTarget,
    Severity,
)
from armorscan.modules.base import BaseModule


class TemplateInfo(BaseModel):
    """Metadata block of a security template."""

    name: str
    severity: str = "MEDIUM"
    description: str = ""
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    remediation: Optional[str] = None
    confidence: str = "firm"
    references: List[str] = Field(default_factory=list)


class TemplateMatcher(BaseModel):
    """Matcher rule within a template request."""

    type: str = Field(..., description="status, word, words, regex, or header")
    status: List[int] = Field(default_factory=list)
    words: List[str] = Field(default_factory=list)
    regex: List[str] = Field(default_factory=list)
    part: str = Field(default="body", description="body, header, or all")
    condition: str = Field(default="or", description="and / or")
    negative: bool = Field(default=False, description="Invert match result if True")


class TemplateRequest(BaseModel):
    """HTTP Request definition in a template."""

    method: str = "GET"
    path: List[str] = Field(default_factory=lambda: ["/"])
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    matchers_condition: str = Field(default="and", alias="matchers-condition")
    matchers: List[TemplateMatcher] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


class SecurityTemplate(BaseModel):
    """Top-level Nuclei-style YAML template representation."""

    id: str
    info: TemplateInfo
    requests: List[TemplateRequest] = Field(default_factory=list)


class TemplateEngine(BaseModule):
    """
    Loads and executes Nuclei-style YAML security templates against a ScanTarget.
    Includes built-in SPA catch-all false-positive protection.
    """

    def __init__(self, template_paths: Optional[List[Union[str, Path]]] = None):
        self.template_paths = template_paths or [self.default_templates_dir()]
        self.templates: List[SecurityTemplate] = self.load_templates(self.template_paths)

    @staticmethod
    def default_templates_dir() -> Path:
        return Path(__file__).resolve().parent.parent.parent / "templates"

    @property
    def name(self) -> str:
        return "templates"

    @property
    def display_name(self) -> str:
        return "Nuclei-Style YAML Template Engine"

    @property
    def description(self) -> str:
        return "Executes declarative YAML community security templates with multi-condition matchers."

    @classmethod
    def load_templates(cls, paths: List[Union[str, Path]]) -> List[SecurityTemplate]:
        loaded: List[SecurityTemplate] = []
        seen_ids = set()

        for p in paths:
            path_obj = Path(p)
            if not path_obj.exists():
                continue

            yaml_files = [path_obj] if path_obj.is_file() else sorted(
                list(path_obj.rglob("*.yaml")) + list(path_obj.rglob("*.yml"))
            )
            for yf in yaml_files:
                try:
                    raw = yaml.safe_load(yf.read_text(encoding="utf-8"))
                    if isinstance(raw, dict) and "id" in raw and "info" in raw:
                        tmpl = SecurityTemplate.model_validate(raw)
                        if tmpl.id not in seen_ids:
                            seen_ids.add(tmpl.id)
                            loaded.append(tmpl)
                except Exception:
                    continue
        return loaded

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        if not self.templates:
            return ModuleResult(
                module_name=self.name,
                display_name=self.display_name,
                findings=[],
                passed_checks=["no-templates-loaded"],
            )

        # Fetch 404/SPA canary baseline to eliminate SPA catch-all false positives
        canary_url = urljoin(target.base_url, "/armorscan-template-canary-404")
        canary_resp = await client.get(canary_url)

        for tmpl in self.templates:
            matched_finding = await self._execute_template(tmpl, target, client, canary_resp)
            if matched_finding:
                findings.append(matched_finding)
            else:
                passed_checks.append(f"template-clean:{tmpl.id}")

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )

    async def _execute_template(
        self,
        tmpl: SecurityTemplate,
        target: ScanTarget,
        client: HttpClient,
        canary_resp: HttpResponse,
    ) -> Optional[Finding]:
        for req_def in tmpl.requests:
            for raw_path in req_def.path:
                clean_path = raw_path.replace("{{BaseURL}}", "").strip()
                if not clean_path.startswith("/"):
                    clean_path = "/" + clean_path
                full_url = urljoin(target.base_url, clean_path)

                method = req_def.method.upper()
                try:
                    if method == "GET":
                        resp = await client.get(full_url, headers=req_def.headers or None)
                    elif method == "POST":
                        resp = await client.post(
                            full_url,
                            headers=req_def.headers or None,
                            content=req_def.body,
                        )
                    else:
                        resp = await client.request(
                            method,
                            full_url,
                            headers=req_def.headers or None,
                            content=req_def.body,
                        )
                except Exception:
                    continue

                if not resp.ok and resp.status_code == 0:
                    continue

                # SPA catch-all resilience: if response is identical to 404 canary HTML, skip
                if (
                    canary_resp.ok
                    and canary_resp.status_code == 200
                    and resp.status_code == 200
                    and "text/html" in resp.headers.get("content-type", "").lower()
                    and abs(len(resp.text) - len(canary_resp.text)) < 40
                ):
                    continue

                if self._evaluate_request_matchers(req_def, resp):
                    sev_str = tmpl.info.severity.upper()
                    sev = Severity[sev_str] if sev_str in Severity.__members__ else Severity.MEDIUM
                    conf_str = tmpl.info.confidence.lower()
                    conf = (
                        Confidence(conf_str)
                        if conf_str in [c.value for c in Confidence]
                        else Confidence.FIRM
                    )
                    curl_cmd = Finding.build_curl(method, full_url, headers=req_def.headers, data=req_def.body)
                    return Finding(
                        id=tmpl.id.upper().replace("-", "_"),
                        title=tmpl.info.name,
                        description=tmpl.info.description or f"Matched security template '{tmpl.id}' at {full_url}.",
                        severity=sev,
                        confidence=conf,
                        module=self.name,
                        impact=f"Template rule '{tmpl.id}' verified an exposed service or vulnerability condition.",
                        evidence=f"Matched template '{tmpl.id}' on {method} {full_url} (HTTP {resp.status_code}, {len(resp.text)} bytes)",
                        curl_command=curl_cmd,
                        request_snippet=f"{method} {full_url} HTTP/1.1\nHost: {target.host}",
                        response_snippet=resp.text[:250],
                        affected_urls=[full_url],
                        remediation=tmpl.info.remediation or "Restrict public access or apply vendor security patch.",
                        cwe_id=tmpl.info.cwe or "CWE-200",
                        owasp_category=tmpl.info.owasp or "A05:2021-Security Misconfiguration",
                        references=tmpl.info.references,
                    )
        return None

    def _evaluate_request_matchers(self, req_def: TemplateRequest, resp: HttpResponse) -> bool:
        if not req_def.matchers:
            return False

        results: List[bool] = []
        for m in req_def.matchers:
            res = self._evaluate_single_matcher(m, resp)
            if m.negative:
                res = not res
            results.append(res)

        if req_def.matchers_condition.lower() == "or":
            return any(results)
        return all(results)

    @staticmethod
    def _evaluate_single_matcher(matcher: TemplateMatcher, resp: HttpResponse) -> bool:
        mtype = matcher.type.lower()
        cond = matcher.condition.lower()

        if mtype == "status":
            return resp.status_code in matcher.status

        # Determine target text to inspect
        if matcher.part.lower() == "header":
            haystack = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        elif matcher.part.lower() == "all":
            hdrs = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            haystack = f"{hdrs}\n\n{resp.text}"
        else:
            haystack = resp.text or ""

        if mtype in ("word", "words"):
            if not matcher.words:
                return False
            matches = [w in haystack for w in matcher.words]
            return all(matches) if cond == "and" else any(matches)

        if mtype == "regex":
            if not matcher.regex:
                return False
            matches = [bool(re.search(rx, haystack, re.IGNORECASE | re.MULTILINE)) for rx in matcher.regex]
            return all(matches) if cond == "and" else any(matches)

        return False
