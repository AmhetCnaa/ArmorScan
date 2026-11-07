"""
NoSQL Injection Indication Module for ArmorScan (modules/nosqli.py).
Tests JSON body endpoints and NoSQL query paths using harmless boolean/operator
differentials ($ne, $gt, || true) without modifying or deleting data.
All findings are marked strictly as Confidence.TENTATIVE.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from armorscan.core.client import HttpClient, HttpResponse
from armorscan.core.models import (
    Confidence,
    Finding,
    ModuleResult,
    ScanTarget,
    Severity,
)
from armorscan.modules.base import BaseModule


class NoSqliIndicationModule(BaseModule):
    """
    Audits endpoints for NoSQL Injection behavioral differentials.
    Uses non-destructive JSON operator payloads ({"$ne": null}, {"$gt": ""}) and
    read-only NoSQL expression comparisons to detect unvalidated query operators.
    """

    @property
    def name(self) -> str:
        return "nosqli"

    @property
    def display_name(self) -> str:
        return "NoSQL Injection Differential Auditor"

    @property
    def description(self) -> str:
        return (
            "Audits JSON and document-store endpoints using non-destructive NoSQL "
            "operator differentials ($ne, $gt, boolean expressions) with tentative confidence."
        )

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        # 1. JSON Operator Differential on Authentication Endpoints (Strictly non-mutating)
        json_candidates: List[Tuple[str, Dict[str, object], Dict[str, object]]] = [
            (
                urljoin(target.base_url, "/rest/user/login"),
                {"email": "armorscan_nonexistent_user@example.invalid", "password": "InvalidPassword123!"},
                {"email": {"$gt": ""}, "password": "InvalidPassword123!"},
            ),
            (
                urljoin(target.base_url, "/api/login"),
                {"username": "armorscan_nonexistent", "password": "InvalidPassword123!"},
                {"username": {"$ne": None}, "password": {"$ne": None}},
            ),
        ]

        if target.path and target.path not in ("/", "") and "login" in target.path.lower():
            target_full = target.raw_url
            json_candidates.insert(
                0,
                (
                    target_full,
                    {"id": "armorscan_baseline_000", "email": "armorscan@example.invalid"},
                    {"id": {"$ne": None}, "email": {"$gt": ""}},
                ),
            )

        for endpoint_url, baseline_json, operator_json in json_candidates:
            try:
                base_resp = await client.post(endpoint_url, json=baseline_json)
                if not base_resp.ok:
                    continue

                op_resp = await client.post(endpoint_url, json=operator_json)
                if not op_resp.ok:
                    continue

                # Skip HTML catch-all responses
                if self._is_html(base_resp) and self._is_html(op_resp):
                    continue

                # Detect authentication bypass (e.g. baseline 401/403 -> operator 200 with token/data)
                if base_resp.status_code in (401, 403, 400) and op_resp.status_code == 200:
                    if any(k in op_resp.text.lower() for k in ("token", "authentication", "success", "data", "user")):
                        curl_cmd = Finding.build_curl(
                            "POST",
                            endpoint_url,
                            headers={"Content-Type": "application/json"},
                            data='{"email": {"$gt": ""}, "password": "..."}',
                        )
                        findings.append(
                            Finding(
                                id="NOSQLI_OPERATOR_INJECTION_SUSPECTED",
                                title=f"Suspected NoSQL Operator Injection on {urlparse(endpoint_url).path}",
                                description=(
                                    f"The endpoint '{urlparse(endpoint_url).path}' exhibited an authentication or query "
                                    f"differential when supplied with a MongoDB/NoSQL comparison operator (`$gt` / `$ne`). "
                                    f"Baseline request returned HTTP {base_resp.status_code}, whereas the operator payload "
                                    f"returned HTTP 200 with structured application records."
                                ),
                                severity=Severity.HIGH,
                                confidence=Confidence.TENTATIVE,
                                module=self.name,
                                impact=(
                                    "Attackers can inject NoSQL query operators ($ne, $gt, $regex, $where) into JSON request bodies "
                                    "to bypass authentication controls or enumerate unauthorized document records."
                                ),
                                evidence=(
                                    f"Baseline status: HTTP {base_resp.status_code} ({len(base_resp.text)} bytes) | "
                                    f"Operator payload status: HTTP {op_resp.status_code} ({len(op_resp.text)} bytes)"
                                ),
                                curl_command=curl_cmd,
                                request_snippet=f"POST {endpoint_url} HTTP/1.1\nContent-Type: application/json\n\n{operator_json}",
                                response_snippet=op_resp.text[:250],
                                affected_urls=[endpoint_url],
                                remediation=(
                                    "Validate that user-supplied fields in JSON payloads are primitive types (strings/integers) "
                                    "and reject nested objects or keys starting with '$' (e.g., using express-mongo-sanitize or strict Pydantic/Zod schemas)."
                                ),
                                remediation_snippets={
                                    "express": "const mongoSanitize = require('express-mongo-sanitize');\napp.use(mongoSanitize());",
                                    "fastapi": "# Use strict Pydantic string types to reject dict operators:\nclass LoginInput(BaseModel):\n    email: str\n    password: str",
                                },
                                cwe_id="CWE-943",
                                owasp_category="A03:2021-Injection",
                                references=[
                                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
                                    "https://cwe.mitre.org/data/definitions/943.html",
                                ],
                            )
                        )
            except Exception:
                continue

        # 2. Read-Only NoSQL Expression Differential on URL Path/Query Endpoints (e.g. /rest/track-order/:id)
        path_candidates = [
            (
                urljoin(target.base_url, "/rest/track-order/99998888"),
                urljoin(target.base_url, "/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27"),
                urljoin(target.base_url, "/rest/track-order/%27%20%26%26%20false%20%26%26%20%27"),
            ),
        ]

        for base_url, true_url, false_url in path_candidates:
            try:
                resp_base = await client.get(base_url)
                resp_true = await client.get(true_url)
                resp_false = await client.get(false_url)

                if not (resp_base.ok and resp_true.ok and resp_false.ok):
                    continue
                if self._is_html(resp_true) or self._is_html(resp_base):
                    continue

                # Check if TRUE condition dumps multiple records while FALSE / baseline returns minimal fallback
                if (
                    resp_true.status_code == 200
                    and len(resp_true.text) > len(resp_base.text) + 150
                    and len(resp_true.text) > len(resp_false.text) + 150
                    and '"data":[' in resp_true.text.replace(" ", "")
                    and len(resp_false.text) < len(resp_base.text) + 50
                ):
                    curl_cmd = Finding.build_curl("GET", true_url)
                    findings.append(
                        Finding(
                            id="NOSQLI_OPERATOR_INJECTION_SUSPECTED",
                            title="Suspected NoSQL Expression Injection via Boolean Differential on /rest/track-order",
                            description=(
                                "The document lookup endpoint '/rest/track-order' exhibited a stark response differential "
                                "between a boolean TRUE NoSQL expression (`' || true || '`) and a boolean FALSE expression "
                                "(`' && false && '`). The TRUE condition returned multiple order documents whereas FALSE returned an empty list."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.TENTATIVE,
                            module=self.name,
                            impact=(
                                "Unvalidated string concatenation inside MongoDB/MarsDB `$where` or query evaluators allows "
                                "attackers to bypass filter predicates and access all records in the collection."
                            ),
                            evidence=(
                                f"Baseline length: {len(resp_base.text)}B | "
                                f"Boolean TRUE (`|| true`) length: {len(resp_true.text)}B | "
                                f"Boolean FALSE (`&& false`) length: {len(resp_false.text)}B"
                            ),
                            curl_command=curl_cmd,
                            request_snippet=f"GET {true_url} HTTP/1.1\nHost: {target.host}",
                            response_snippet=resp_true.text[:250],
                            affected_urls=[true_url],
                            remediation=(
                                "Avoid evaluating user input inside JavaScript-backed `$where` clauses. "
                                "Use parameterized field equality queries (`db.orders.find({ orderId: String(id) })`)."
                            ),
                            remediation_snippets={
                                "express": "// Avoid $where string concatenation:\n// BAD: db.orders.find({ $where: `this.orderId === '${req.params.id}'` })\n// GOOD:\ndb.orders.find({ orderId: String(req.params.id) });",
                            },
                            cwe_id="CWE-943",
                            owasp_category="A03:2021-Injection",
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
                                "https://cwe.mitre.org/data/definitions/943.html",
                            ],
                        )
                    )
            except Exception:
                continue

        if not findings:
            passed_checks.append("no-nosqli-operator-differential-detected")

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )

    @staticmethod
    def _is_html(resp: HttpResponse) -> bool:
        ctype = resp.headers.get("content-type", "").lower()
        return "text/html" in ctype or "<!doctype html" in resp.text[:200].lower()
