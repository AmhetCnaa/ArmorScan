"""
GraphQL Introspection & Schema Disclosure Module for ArmorScan (modules/graphql.py).
Audits discovered or standard GraphQL endpoints (/graphql, /api/graphql, /v1/graphql)
by executing a harmless standard __schema introspection query.
"""

from __future__ import annotations

import json
from typing import List
from urllib.parse import urljoin

from armorscan.core.client import HttpClient
from armorscan.core.models import (
    Confidence,
    Finding,
    ModuleResult,
    ScanTarget,
    Severity,
)
from armorscan.modules.base import BaseModule

GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql")
INTROSPECTION_PAYLOAD = {"query": "{ __schema { types { name } } }"}


class GraphqlAuditModule(BaseModule):
    """
    Audits GraphQL endpoints for unauthenticated schema introspection disclosure.
    """

    @property
    def name(self) -> str:
        return "graphql"

    @property
    def display_name(self) -> str:
        return "GraphQL Introspection & Schema Auditor"

    @property
    def description(self) -> str:
        return (
            "Audits GraphQL endpoints (/graphql, /api/graphql) for unrestricted "
            "__schema introspection disclosure."
        )

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        candidates = [urljoin(target.base_url, p) for p in GRAPHQL_PATHS]
        if target.path and "graphql" in target.path.lower():
            if target.raw_url not in candidates:
                candidates.insert(0, target.raw_url)

        for gql_url in candidates:
            try:
                resp = await client.post(
                    gql_url,
                    json=INTROSPECTION_PAYLOAD,
                    headers={"Content-Type": "application/json"},
                )
                if not resp.ok or resp.status_code != 200:
                    continue

                ctype = resp.headers.get("content-type", "").lower()
                if "text/html" in ctype or "<!doctype html" in resp.text[:200].lower():
                    continue

                data = json.loads(resp.text)
                if isinstance(data, dict) and "data" in data and isinstance(data["data"], dict):
                    schema = data["data"].get("__schema")
                    if isinstance(schema, dict) and "types" in schema and isinstance(schema["types"], list):
                        type_names = [
                            t.get("name")
                            for t in schema["types"]
                            if isinstance(t, dict) and t.get("name") and not str(t.get("name")).startswith("__")
                        ]
                        curl_cmd = Finding.build_curl(
                            "POST",
                            gql_url,
                            headers={"Content-Type": "application/json"},
                            data=json.dumps(INTROSPECTION_PAYLOAD),
                        )
                        findings.append(
                            Finding(
                                id="GRAPHQL_INTROSPECTION_ENABLED",
                                title="GraphQL Schema Introspection Enabled in Production",
                                description=(
                                    f"The GraphQL endpoint at '{gql_url}' responded to an unauthenticated `__schema` "
                                    f"introspection query, exposing {len(schema['types'])} schema types "
                                    f"(including custom types: {', '.join(type_names[:6]) or 'Query'})."
                                ),
                                severity=Severity.MEDIUM,
                                confidence=Confidence.CONFIRMED,
                                module=self.name,
                                impact=(
                                    "Publicly enabled GraphQL introspection allows attackers to map the entire backend "
                                    "data model, discover hidden mutations, internal fields, and administrative queries."
                                ),
                                evidence=(
                                    f"Endpoint: {gql_url} | Total types exposed: {len(schema['types'])} | "
                                    f"Sample types: {', '.join(type_names[:8])}"
                                ),
                                curl_command=curl_cmd,
                                request_snippet=f"POST {gql_url} HTTP/1.1\nContent-Type: application/json\n\n{json.dumps(INTROSPECTION_PAYLOAD)}",
                                response_snippet=resp.text[:250],
                                affected_urls=[gql_url],
                                remediation=(
                                    "Disable GraphQL schema introspection in production environments unless explicitly "
                                    "required for public developer APIs."
                                ),
                                remediation_snippets={
                                    "express": "// Apollo Server: Disable introspection in production\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  introspection: process.env.NODE_ENV !== 'production',\n});",
                                    "fastapi": "# Strawberry GraphQL: Disable introspection via validation rules\nfrom graphql.validation import NoSchemaIntrospectionCustomRule",
                                },
                                cwe_id="CWE-200",
                                owasp_category="A05:2021-Security Misconfiguration",
                                references=[
                                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
                                    "https://cwe.mitre.org/data/definitions/200.html",
                                ],
                            )
                        )
                        break
            except Exception:
                continue

        if not findings:
            passed_checks.append("graphql-introspection-disabled-or-not-present")

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )
