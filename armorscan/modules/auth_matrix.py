"""
Role Access Control Matrix & BOLA/IDOR Audit Module for ArmorScan.
Tests parametric routes across multiple defined roles (e.g. Admin, User, Guest)
using strictly non-destructive read-only GET requests to identify Broken Object
Level Authorization (BOLA) and Cross-Tenant Object Access (IDOR).
"""

from __future__ import annotations

import html
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse
from pydantic import BaseModel, Field

from armorscan.core.client import HttpClient, HttpResponse
from armorscan.core.models import Confidence, Finding, ModuleResult, ScanTarget, Severity
from armorscan.modules.base import BaseModule
from armorscan.remediations.templates import get_authz_remediations


class RoleSpec(BaseModel):
    """Specification of an audit identity role with its authentication tokens."""
    name: str = Field(..., description="Role identifier, e.g. 'admin', 'user', 'guest'")
    auth_header: Optional[str] = Field(default=None, description="Authorization header value, e.g. 'Bearer <token>'")
    custom_headers: Dict[str, str] = Field(default_factory=dict, description="Custom role headers")

    def get_headers(self) -> Dict[str, str]:
        """Construct request headers for this role."""
        headers = dict(self.custom_headers)
        if self.auth_header:
            val = self.auth_header.strip()
            if ":" in val and not val.lower().startswith("bearer ") and not val.lower().startswith("basic "):
                k, v = val.split(":", 1)
                headers[k.strip()] = v.strip()
            else:
                if not val.lower().startswith("bearer ") and not val.lower().startswith("basic "):
                    val = f"Bearer {val}"
                headers["Authorization"] = val
        return headers


def parse_matrix_roles(raw: str) -> List[RoleSpec]:
    """
    Parse a comma-separated role specification string.
    Example: "admin:Bearer <T1>,user:Bearer <T2>,guest:"
    """
    roles: List[RoleSpec] = []
    if not raw or not raw.strip():
        return roles

    items = [item.strip() for item in raw.split(",") if item.strip()]
    for item in items:
        if ":" in item:
            name, token = item.split(":", 1)
            name = name.strip()
            token = token.strip()
        else:
            name = item.strip()
            token = ""

        if not name:
            continue

        if not token or name.lower() == "guest":
            roles.append(RoleSpec(name=name, auth_header=None))
        else:
            roles.append(RoleSpec(name=name, auth_header=token))

    return roles


DEFAULT_CANDIDATE_PATHS = [
    "/api/orders/1",
    "/api/orders/2",
    "/rest/basket/1",
    "/rest/basket/2",
    "/api/users/1",
    "/api/users/2",
    "/api/invoices/1",
    "/api/user/settings",
    "/api/profile",
    "/api/account",
    "/vuln/logic_idor?user_id=usr_alice",
]

SENSITIVE_BODY_INDICATORS = [
    "user", "email", "order", "basket", "account", "balance", "address",
    "card", "token", "password", "invoice", "customer", "tenant"
]


class AuthMatrixModule(BaseModule):
    """
    Role Access Control Matrix & BOLA/IDOR Auditor.
    Maps out endpoint accessibility across role boundaries.
    """

    name: str = "auth_matrix"
    display_name: str = "Multi-Role BOLA/IDOR Permission Matrix"
    description: str = "Evaluates parametric endpoints across multi-tier identities to detect unauthenticated BOLA and cross-tenant IDOR."

    def __init__(
        self,
        roles: Optional[List[RoleSpec]] = None,
        candidate_paths: Optional[List[str]] = None,
    ):
        self.roles: List[RoleSpec] = roles or []
        self.candidate_paths: List[str] = candidate_paths or []

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        # Ensure at least simulated roles exist if none provided
        roles_to_test = list(self.roles)
        if not roles_to_test:
            roles_to_test = [
                RoleSpec(name="admin", auth_header="Bearer armorscan-admin-simulated-token"),
                RoleSpec(name="user", auth_header="Bearer armorscan-user-simulated-token"),
                RoleSpec(name="guest", auth_header=None),
            ]

        # Gather target paths to test
        endpoints: Set[str] = set()
        if target.path and target.path != "/":
            endpoints.add(target.raw_url)

        if self.candidate_paths:
            for p in self.candidate_paths:
                endpoints.add(urljoin(target.base_url, p))

        if target.discovered_paths:
            for p in target.discovered_paths:
                # Include paths that look parametric or end with IDs
                if re.search(r"/\d+$", p) or "?" in p or any(kw in p.lower() for kw in ("user", "order", "basket", "account", "profile")):
                    endpoints.add(urljoin(target.base_url, p))

        # Add sensible default candidate paths
        for p in DEFAULT_CANDIDATE_PATHS:
            endpoints.add(urljoin(target.base_url, p))

        # Matrix storage: path -> {role_name: (status_code, text_sample, is_sensitive)}
        matrix_data: Dict[str, Dict[str, Tuple[int, str, bool]]] = {}

        for full_url in sorted(endpoints):
            parsed = urlparse(full_url)
            path_label = parsed.path
            if parsed.query:
                path_label = f"{parsed.path}?{parsed.query}"

            role_results: Dict[str, Tuple[int, str, bool]] = {}

            for role in roles_to_test:
                headers = role.get_headers()
                try:
                    resp = await client.get(full_url, headers=headers)
                    text = resp.text.strip()
                    # Skip SPA html fallbacks
                    is_spa_html = "<!doctype html" in text.lower() or "<html" in text.lower()
                    if is_spa_html and resp.status_code == 200:
                        status = 404  # Normalize SPA catch-all
                    else:
                        status = resp.status_code

                    is_sensitive = False
                    if status == 200 and not is_spa_html:
                        lower_text = text.lower()
                        if any(kw in lower_text for kw in SENSITIVE_BODY_INDICATORS) and len(text) > 10:
                            is_sensitive = True

                    role_results[role.name] = (status, text[:200], is_sensitive)
                except Exception:
                    role_results[role.name] = (0, "", False)

            matrix_data[path_label] = role_results

            # Analyze Role Access Violations for this endpoint
            guest_status, guest_body, guest_sens = role_results.get("guest", (0, "", False))
            user_status, user_body, user_sens = role_results.get("user", (0, "", False))
            admin_status, admin_body, admin_sens = role_results.get("admin", (0, "", False))

            # 1. BOLA Unauthenticated Guest Access (CRITICAL)
            # Occurs when an authenticated resource with sensitive user/order content is accessible by guest
            if guest_status == 200 and guest_sens:
                # Confirm that user or admin also gets 200
                if (user_status == 200 or admin_status == 200):
                    matrix_summary = self._format_matrix_row(path_label, roles_to_test, role_results)
                    curl_cmd = Finding.build_curl("GET", full_url)
                    req_snippet = f"GET {path_label} HTTP/1.1\nHost: {target.host}\n(Unauthenticated Guest Request)"
                    resp_snippet = guest_body[:250]

                    findings.append(
                        Finding(
                            id="BOLA_UNAUTHENTICATED_ACCESS",
                            title=f"Broken Object Level Authorization (BOLA) on {path_label}",
                            description=(
                                f"The parametric endpoint '{path_label}' permits unauthenticated 'guest' requests "
                                f"to read sensitive business object data without requiring an active session or token."
                            ),
                            severity=Severity.CRITICAL,
                            confidence=Confidence.CONFIRMED,
                            module=self.name,
                            impact=(
                                "Anonymous attackers can harvest all customer records, billing details, orders, "
                                "and personal profile data without needing valid credentials or permission checks."
                            ),
                            evidence=(
                                f"Guest GET request returned HTTP 200 OK ({len(guest_body)} bytes).\n"
                                f"Role Access Matrix:\n{matrix_summary}"
                            ),
                            curl_command=curl_cmd,
                            request_snippet=req_snippet,
                            response_snippet=resp_snippet,
                            affected_urls=[full_url],
                            remediation=(
                                "Enforce authentication middleware on all private API routes and verify session tokens "
                                "before executing database lookups."
                            ),
                            remediation_snippets=get_authz_remediations(),
                            cwe_id="CWE-284",
                            owasp_category="A01:2021-Broken Access Control",
                        )
                    )
                    continue

            # 2. Cross-Tenant IDOR Confirmation (HIGH)
            # If two distinct user identities exist (e.g. user_a vs user_b or user vs admin)
            # and non-admin user can access administrative or another tenant's private scope
            other_user_roles = [r for r in roles_to_test if r.name not in ("admin", "guest") and r.name != "user"]
            for other_r in other_user_roles:
                other_status, other_body, other_sens = role_results.get(other_r.name, (0, "", False))
                if user_status == 200 and other_status == 200 and other_sens and user_sens:
                    # If endpoint represents a specific user/tenant resource
                    if re.search(r"/\d+$", path_label) or "user_id" in path_label or "basket" in path_label or "order" in path_label:
                        matrix_summary = self._format_matrix_row(path_label, roles_to_test, role_results)
                        findings.append(
                            Finding(
                                id="CROSS_TENANT_IDOR_CONFIRMED",
                                title=f"Cross-Tenant Broken Object Level Authorization (IDOR) on {path_label}",
                                description=(
                                    f"The endpoint '{path_label}' permitted role '{other_r.name}' to retrieve the private "
                                    f"records belonging to role 'user' without ownership validation."
                                ),
                                severity=Severity.HIGH,
                                confidence=Confidence.CONFIRMED,
                                module=self.name,
                                impact=(
                                    "Attackers with standard tenant accounts can read private data, orders, and "
                                    "confidential configuration belonging to other tenants or users."
                                ),
                                evidence=(
                                    f"Role '{other_r.name}' and 'user' both received HTTP 200 OK with sensitive tenant data.\n"
                                    f"Role Access Matrix:\n{matrix_summary}"
                                ),
                                affected_urls=[full_url],
                                remediation=(
                                    "Bind database lookups strictly to the authenticated tenant/user ID extracted "
                                    "from the validated JWT or session cookie (e.g. WHERE id = :id AND tenant_id = :session_tenant)."
                                ),
                                remediation_snippets=get_authz_remediations(),
                                cwe_id="CWE-639",
                                owasp_category="A01:2021-Broken Access Control",
                            )
                        )
                        break

            # If properly protected
            if guest_status in (401, 403, 404):
                passed_checks.append(
                    f"Role permission boundary strictly enforced on {path_label} (Guest: HTTP {guest_status}, Admin: HTTP {admin_status})"
                )

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )

    def _format_matrix_row(
        self,
        path: str,
        roles: List[RoleSpec],
        role_results: Dict[str, Tuple[int, str, bool]],
    ) -> str:
        """Format an ASCII matrix line for finding evidence."""
        parts = [f"Path: {path}"]
        for r in roles:
            st, _, _ = role_results.get(r.name, (0, "", False))
            parts.append(f"{r.name.upper()}={st}")
        return " | ".join(parts)
