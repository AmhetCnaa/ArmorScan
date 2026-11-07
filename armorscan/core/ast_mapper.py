"""
Static AST & Source Code Route Mapper for ArmorScan.
Parses application source code (FastAPI, Flask, Django, Express.js) using Python AST
and pattern matchers to discover undocumented shadow routes, parameter schemas,
and endpoints lacking authentication middleware.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Union
from pydantic import BaseModel, Field

from armorscan.core.models import Confidence, Finding, Severity


class EndpointParam(BaseModel):
    """Specification of a parameter discovered from route definitions."""
    name: str = Field(..., description="Parameter name")
    param_type: str = Field(default="string", description="Type annotation or inferred type")
    is_required: bool = Field(default=True, description="Whether parameter is mandatory")
    location: str = Field(default="query", description="Location: query, path, body, header")


class DiscoveredEndpoint(BaseModel):
    """Structured API endpoint parsed directly from application source code."""
    method: str = Field(..., description="HTTP method (GET, POST, PUT, DELETE, etc.)")
    path: str = Field(..., description="Route URL path")
    source_file: str = Field(..., description="Path to source file where endpoint is declared")
    line_number: int = Field(default=1, description="Line number of declaration")
    framework: str = Field(..., description="FastAPI, Flask, Django, or Express")
    parameters: List[EndpointParam] = Field(default_factory=list, description="Expected parameters")
    is_protected: bool = Field(default=True, description="Whether route has authentication middleware/dependencies")
    auth_mechanisms: List[str] = Field(default_factory=list, description="Names of identified auth guards")


class AstMappingResult(BaseModel):
    """Aggregation of static route discovery across an entire source code tree."""
    endpoints: List[DiscoveredEndpoint] = Field(default_factory=list)
    unprotected_shadow_routes: List[DiscoveredEndpoint] = Field(default_factory=list)
    scanned_files_count: int = 0


# Sensitive route patterns that should never be left unauthenticated
SENSITIVE_PATH_PATTERNS = re.compile(
    r"/(admin|api/v\d+/users?|api/v\d+/orders?|internal|debug|settings|config|billing|dashboard|management)",
    re.IGNORECASE,
)

AUTH_GUARD_KEYWORDS = {
    "depends", "security", "login_required", "permission_required", "authmiddleware",
    "requireauth", "verifytoken", "passport.authenticate", "jwt_required", "authenticated",
    "authguard", "checkauth", "has_permission", "auth"
}


class AstSourceMapper:
    """
    Static Code Route Discovery & Security Guard Auditor.
    Parses application repositories without executing untrusted code.
    """

    def scan_directory(self, root_dir: Union[str, Path]) -> AstMappingResult:
        """Scan a repository directory recursively for supported framework route declarations."""
        base_path = Path(root_dir)
        if not base_path.exists() or not base_path.is_dir():
            raise ValueError(f"Source directory '{root_dir}' does not exist or is not a directory.")

        all_endpoints: List[DiscoveredEndpoint] = []
        scanned_count = 0

        # Skip vendor and virtual environment directories
        ignore_dirs = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build", ".pytest_cache"}

        for current_root, dirs, files in os.walk(base_path):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for file_name in files:
                file_path = Path(current_root) / file_name
                rel_path = str(file_path.relative_to(base_path))

                if file_name.endswith(".py"):
                    scanned_count += 1
                    all_endpoints.extend(self._parse_python_file(file_path, rel_path))
                elif file_name.endswith((".js", ".ts", ".mjs", ".cjs")):
                    scanned_count += 1
                    all_endpoints.extend(self._parse_javascript_file(file_path, rel_path))

        unprotected = [
            ep for ep in all_endpoints
            if not ep.is_protected and SENSITIVE_PATH_PATTERNS.search(ep.path)
        ]

        return AstMappingResult(
            endpoints=all_endpoints,
            unprotected_shadow_routes=unprotected,
            scanned_files_count=scanned_count,
        )

    def _parse_python_file(self, file_path: Path, rel_path: str) -> List[DiscoveredEndpoint]:
        """Parse Python source files using standard ast library."""
        endpoints: List[DiscoveredEndpoint] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=str(file_path))
        except Exception:
            return endpoints

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    ep = self._extract_fastapi_or_flask_endpoint(node, decorator, rel_path)
                    if ep:
                        endpoints.append(ep)

        # Also inspect Django urls.py patterns if applicable
        if "urls.py" in rel_path.lower():
            endpoints.extend(self._extract_django_urls(tree, rel_path))

        return endpoints

    def _extract_fastapi_or_flask_endpoint(
        self,
        func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
        decorator: ast.expr,
        rel_path: str,
    ) -> Optional[DiscoveredEndpoint]:
        """Extract FastAPI (@app.get, @router.post) or Flask (@app.route) route declarations."""
        if not isinstance(decorator, ast.Call):
            return None

        # Resolve decorator function name: app.get, router.post, etc.
        attr_name = ""
        if isinstance(decorator.func, ast.Attribute):
            attr_name = decorator.func.attr.lower()
        elif isinstance(decorator.func, ast.Name):
            attr_name = decorator.func.id.lower()

        http_methods = {"get", "post", "put", "delete", "patch", "options", "head"}
        framework = "FastAPI"
        method = "GET"

        if attr_name in http_methods:
            method = attr_name.upper()
        elif attr_name == "route":
            framework = "Flask"
            method = "GET"
            # Check methods kwarg in @app.route("/path", methods=["POST"])
            for kw in decorator.keywords:
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                    methods = [ast.literal_eval(elt).upper() for elt in kw.value.elts if isinstance(elt, ast.Constant)]
                    if methods:
                        method = methods[0]
        else:
            return None

        # Route path is typically the first argument
        route_path = ""
        if decorator.args and isinstance(decorator.args[0], ast.Constant):
            route_path = str(decorator.args[0].value)
        elif decorator.keywords:
            for kw in decorator.keywords:
                if kw.arg in ("path", "rule") and isinstance(kw.value, ast.Constant):
                    route_path = str(kw.value.value)

        if not route_path or not route_path.startswith("/"):
            return None

        # Parameter extraction from function signature
        params: List[EndpointParam] = []
        auth_guards: List[str] = []

        # Check decorator keywords for dependencies=[Depends(...)]
        for kw in decorator.keywords:
            if kw.arg == "dependencies":
                auth_guards.append("decorator_dependencies")

        for arg in func_node.args.args:
            p_name = arg.arg
            if p_name in ("self", "cls", "request", "req", "response", "res"):
                continue

            # Check if parameter has Depends(...)
            type_str = "string"
            is_auth = False
            if arg.annotation:
                ann_str = ast.unparse(arg.annotation) if hasattr(ast, "unparse") else ""
                type_str = ann_str or "string"
                if any(kw in ann_str.lower() for kw in AUTH_GUARD_KEYWORDS):
                    is_auth = True
                    auth_guards.append(ann_str)

            if not is_auth:
                loc = "path" if f"{{{p_name}}}" in route_path or f":{p_name}" in route_path else "query"
                params.append(EndpointParam(name=p_name, param_type=type_str, location=loc))

        # Check other decorators on the function (e.g. @login_required)
        for other_dec in func_node.decorator_list:
            dec_text = ast.unparse(other_dec).lower() if hasattr(ast, "unparse") else ""
            if any(kw in dec_text for kw in AUTH_GUARD_KEYWORDS):
                auth_guards.append(dec_text)

        is_protected = len(auth_guards) > 0

        return DiscoveredEndpoint(
            method=method,
            path=route_path,
            source_file=rel_path,
            line_number=func_node.lineno,
            framework=framework,
            parameters=params,
            is_protected=is_protected,
            auth_mechanisms=auth_guards,
        )

    def _extract_django_urls(self, tree: ast.AST, rel_path: str) -> List[DiscoveredEndpoint]:
        """Extract path('route', views.func) from Django urls.py."""
        endpoints: List[DiscoveredEndpoint] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("path", "re_path"):
                if node.args and isinstance(node.args[0], ast.Constant):
                    route = str(node.args[0].value)
                    if not route.startswith("/"):
                        route = f"/{route}"
                    endpoints.append(
                        DiscoveredEndpoint(
                            method="GET",
                            path=route,
                            source_file=rel_path,
                            line_number=node.lineno,
                            framework="Django",
                            is_protected=False,  # Checked at view level
                        )
                    )
        return endpoints

    def _parse_javascript_file(self, file_path: Path, rel_path: str) -> List[DiscoveredEndpoint]:
        """Parse Express.js routes using pattern matching."""
        endpoints: List[DiscoveredEndpoint] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return endpoints

        # Pattern: (app|router).(get|post|put|delete|patch)\(\s*['"`](/[^'"`]*)['"`](.*)
        express_pattern = re.compile(
            r"(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['\"](/[^'\"]*)['\"]([^\)]*)\)",
            re.MULTILINE,
        )

        for line_idx, line in enumerate(content.splitlines(), start=1):
            match = express_pattern.search(line)
            if match:
                method = match.group(1).upper()
                route_path = match.group(2)
                args_rest = match.group(3).lower()

                # Check if middleware arguments contain auth keywords
                has_auth = any(kw in args_rest for kw in AUTH_GUARD_KEYWORDS)
                auth_list = ["auth_middleware"] if has_auth else []

                # Extract path parameters e.g. /users/:id
                params: List[EndpointParam] = []
                for p_match in re.finditer(r":([a-zA-Z0-9_]+)", route_path):
                    params.append(EndpointParam(name=p_match.group(1), location="path"))

                endpoints.append(
                    DiscoveredEndpoint(
                        method=method,
                        path=route_path,
                        source_file=rel_path,
                        line_number=line_idx,
                        framework="Express",
                        parameters=params,
                        is_protected=has_auth,
                        auth_mechanisms=auth_list,
                    )
                )

        return endpoints

    @staticmethod
    def generate_findings(result: AstMappingResult, base_url: str = "") -> List[Finding]:
        """Transform discovered unprotected shadow routes into standardized findings."""
        findings: List[Finding] = []
        for ep in result.unprotected_shadow_routes:
            sev = Severity.HIGH if SENSITIVE_PATH_PATTERNS.search(ep.path) else Severity.MEDIUM
            full_url = f"{base_url.rstrip('/')}{ep.path}" if base_url else ep.path

            findings.append(
                Finding(
                    id="SHADOW_API_UNPROTECTED_ROUTE",
                    title=f"Unprotected Shadow API Route in Source Code ({ep.method} {ep.path})",
                    description=(
                        f"Static code AST analysis of '{ep.source_file}:{ep.line_number}' identified that "
                        f"endpoint '{ep.method} {ep.path}' has no authentication guards or middleware configured."
                    ),
                    severity=sev,
                    confidence=Confidence.CONFIRMED,
                    module="ast_mapper",
                    impact=(
                        "Shadow or undocumented endpoints left without authentication allow unauthorized "
                        "access to business data, internal administrative functions, or state-changing operations."
                    ),
                    evidence=(
                        f"Framework: {ep.framework} | Source File: {ep.source_file}:{ep.line_number}\n"
                        f"Method: {ep.method} | Path: {ep.path}\n"
                        f"Discovered Parameters: {[p.name for p in ep.parameters]}"
                    ),
                    affected_urls=[full_url],
                    remediation=(
                        "Attach standard authentication middleware or dependency injection guards to the route "
                        "(e.g., Depends(get_current_user) in FastAPI or authMiddleware in Express)."
                    ),
                    cwe_id="CWE-306",
                    owasp_category="A01:2021-Broken Access Control",
                )
            )

        return findings
