"""
API Schema-Driven Parsing & GraphQL Introspection Engine for ArmorScan.
Parses OpenAPI 3.x, Swagger 2.0, and probes GraphQL endpoints to extract
all application routes, HTTP methods, and input parameters for comprehensive scanning.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urljoin, urlparse
from pydantic import BaseModel, Field
import yaml

from armorscan.core.client import HttpClient, HttpResponse


COMMON_OPENAPI_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/api-docs/",
    "/api-docs/swagger.json",
    "/api-docs/swagger-ui-init.js",
    "/api/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/docs/openapi.json",
]

COMMON_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
]

GRAPHQL_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
      }
    }
  }
}
"""


class ApiParameter(BaseModel):
    """Parameter definition extracted from an API schema."""
    name: str
    location: str = "query"  # query, path, header, body, formData
    param_type: str = "string"
    required: bool = False
    default: Optional[Any] = None


class ApiEndpoint(BaseModel):
    """Fully structured API route definition extracted from OpenAPI or GraphQL."""
    path: str
    method: str = "GET"
    summary: Optional[str] = None
    parameters: List[ApiParameter] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    is_graphql: bool = False

    @property
    def query_parameters(self) -> List[ApiParameter]:
        return [p for p in self.parameters if p.location == "query"]

    @property
    def path_parameters(self) -> List[ApiParameter]:
        return [p for p in self.parameters if p.location == "path"]

    @property
    def body_parameters(self) -> List[ApiParameter]:
        return [p for p in self.parameters if p.location in ("body", "formData")]

    def build_test_url(self, base_url: str) -> str:
        """
        Build a concrete test URL, replacing path parameters ({id} -> 1)
        and appending sample query parameters (?q=test).
        """
        resolved_path = self.path
        for p in self.path_parameters:
            sample_val = "1" if p.param_type in ("integer", "number") else "test_val"
            resolved_path = resolved_path.replace(f"{{{p.name}}}", sample_val)

        full_url = urljoin(base_url, resolved_path)

        query_parts = []
        for p in self.query_parameters:
            sample_val = "1" if p.param_type in ("integer", "number") else "test"
            query_parts.append(f"{p.name}={sample_val}")

        if query_parts and "?" not in full_url:
            full_url = f"{full_url}?{'&'.join(query_parts)}"

        return full_url


class OpenApiParser:
    """Parses OpenAPI 3.x and Swagger 2.0 schemas from string, file, or remote URL."""

    @classmethod
    def parse_content(cls, content: str) -> List[ApiEndpoint]:
        """Parse raw JSON or YAML schema content into ApiEndpoint objects."""
        if not content:
            return []

        data: Optional[Dict[str, Any]] = None
        # 1. Try JSON
        try:
            data = json.loads(content)
        except Exception:
            # 2. Try YAML
            try:
                data = yaml.safe_load(content)
            except Exception:
                return []

        if not isinstance(data, dict) or "paths" not in data:
            return []

        endpoints: List[ApiEndpoint] = []
        paths_dict = data.get("paths", {})

        for path, path_item in paths_dict.items():
            if not isinstance(path_item, dict):
                continue

            # Path-level parameters
            path_level_params = path_item.get("parameters", [])

            for method in ("get", "post", "put", "delete", "patch", "options", "head"):
                if method not in path_item:
                    continue

                op = path_item[method]
                if not isinstance(op, dict):
                    continue

                summary = op.get("summary") or op.get("operationId")
                tags = op.get("tags", [])
                raw_params = list(path_level_params) + op.get("parameters", [])

                extracted_params: List[ApiParameter] = []
                for p in raw_params:
                    if isinstance(p, dict) and "name" in p:
                        schema = p.get("schema", {})
                        p_type = schema.get("type", p.get("type", "string")) if isinstance(schema, dict) else "string"
                        extracted_params.append(
                            ApiParameter(
                                name=str(p["name"]),
                                location=str(p.get("in", "query")),
                                param_type=str(p_type),
                                required=bool(p.get("required", False)),
                                default=p.get("default"),
                            )
                        )

                # Extract OpenAPI 3.x requestBody properties
                request_body = op.get("requestBody", {})
                if isinstance(request_body, dict):
                    content_map = request_body.get("content", {})
                    for media_type, media_obj in content_map.items():
                        if isinstance(media_obj, dict):
                            body_schema = media_obj.get("schema", {})
                            if isinstance(body_schema, dict):
                                properties = body_schema.get("properties", {})
                                for prop_name, prop_data in properties.items():
                                    prop_type = prop_data.get("type", "string") if isinstance(prop_data, dict) else "string"
                                    extracted_params.append(
                                        ApiParameter(
                                            name=str(prop_name),
                                            location="body",
                                            param_type=str(prop_type),
                                            required=prop_name in body_schema.get("required", []),
                                        )
                                    )

                endpoints.append(
                    ApiEndpoint(
                        path=path,
                        method=method.upper(),
                        summary=summary,
                        parameters=extracted_params,
                        tags=tags,
                    )
                )

        return endpoints

    @classmethod
    def parse_file(cls, file_path: Union[str, Path]) -> List[ApiEndpoint]:
        """Read and parse local schema file."""
        p = Path(file_path)
        if not p.exists():
            return []
        try:
            content = p.read_text(encoding="utf-8")
            return cls.parse_content(content)
        except Exception:
            return []

    @classmethod
    async def discover_and_parse(
        cls,
        client: HttpClient,
        base_url: str,
        custom_schema_path: Optional[str] = None,
    ) -> Tuple[Optional[str], List[ApiEndpoint]]:
        """
        Auto-discover or fetch OpenAPI specification from target.
        Returns (discovered_schema_url, list_of_endpoints).
        """
        # If custom schema path/URL provided
        if custom_schema_path:
            # Check if it's a local file
            local_p = Path(custom_schema_path)
            if local_p.exists():
                endpoints = cls.parse_file(local_p)
                if endpoints:
                    return str(local_p), endpoints

            # Otherwise attempt remote fetch
            target_url = urljoin(base_url, custom_schema_path)
            resp = await client.get(target_url)
            if resp.ok and len(resp.text) > 20:
                endpoints = cls.parse_content(resp.text)
                if endpoints:
                    return target_url, endpoints

        # Auto-probe common schema paths concurrently
        async def _probe_schema_path(path: str) -> Tuple[Optional[str], List[ApiEndpoint]]:
            target_url = urljoin(base_url, path)
            try:
                resp = await client.get(target_url, timeout=1.5)
                if resp.ok and resp.status_code == 200:
                    # Case 1: Direct JSON or YAML
                    if "paths" in resp.text or "swagger" in resp.text or "openapi" in resp.text:
                        endpoints = cls.parse_content(resp.text)
                        if endpoints:
                            return target_url, endpoints

                    # Case 2: Swagger UI HTML or swagger-ui-init.js
                    if "swagger-ui" in resp.text.lower() or "<title>swagger ui" in resp.text.lower():
                        init_url = urljoin(target_url, "swagger-ui-init.js")
                        init_resp = await client.get(init_url, timeout=1.5)
                        if init_resp.ok and ("swaggerDoc" in init_resp.text or "openapi" in init_resp.text):
                            doc = cls._extract_swagger_doc_from_js(init_resp.text)
                            if doc:
                                endpoints = cls.parse_content(json.dumps(doc))
                                if endpoints:
                                    return init_url, endpoints
            except Exception:
                pass
            return None, []

        import asyncio
        probe_results = await asyncio.gather(*[_probe_schema_path(p) for p in COMMON_OPENAPI_PATHS])
        for found_url, found_eps in probe_results:
            if found_url and found_eps:
                return found_url, found_eps

        return None, []

    @classmethod
    def _extract_swagger_doc_from_js(cls, text: str) -> Optional[Dict[str, Any]]:
        """Extract swaggerDoc JSON object from swagger-ui-init.js."""
        idx = text.find('"swaggerDoc":')
        if idx == -1:
            idx = text.find("'swaggerDoc':")
        if idx == -1:
            return None
        brace_start = text.find("{", idx)
        if brace_start == -1:
            return None
        cnt = 0
        end = brace_start
        for i in range(brace_start, len(text)):
            if text[i] == "{":
                cnt += 1
            elif text[i] == "}":
                cnt -= 1
                if cnt == 0:
                    end = i + 1
                    break
        try:
            return json.loads(text[brace_start:end])
        except Exception:
            return None


class GraphQLAuditor:
    """Probes GraphQL endpoints to verify introspection policies and extract operations."""

    @classmethod
    async def audit_graphql(
        cls,
        client: HttpClient,
        base_url: str,
        path: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], List[ApiEndpoint]]:
        """
        Probe GraphQL endpoint with standard introspection query.
        Returns (introspection_enabled, graphql_url, extracted_endpoints).
        """
        candidate_paths = [path] if path else COMMON_GRAPHQL_PATHS

        async def _probe_gql(candidate: str) -> Tuple[bool, Optional[str], List[ApiEndpoint]]:
            if not candidate:
                return False, None, []
            gql_url = urljoin(base_url, candidate)
            try:
                resp = await client.post(
                    gql_url,
                    json={"query": GRAPHQL_INTROSPECTION_QUERY},
                    headers={"Content-Type": "application/json"},
                    timeout=1.5,
                )
                if resp.ok and resp.status_code == 200 and "__schema" in resp.text:
                    endpoints = cls._extract_graphql_operations(resp.text, candidate)
                    return True, gql_url, endpoints
            except Exception:
                pass
            return False, None, []

        import asyncio
        results = await asyncio.gather(*[_probe_gql(c) for c in candidate_paths if c])
        for active, g_url, eps in results:
            if active:
                return True, g_url, eps

        return False, None, []

    @classmethod
    def _extract_graphql_operations(cls, response_text: str, path: str) -> List[ApiEndpoint]:
        """Extract query and mutation operation names from introspection response."""
        endpoints: List[ApiEndpoint] = []
        try:
            data = json.loads(response_text)
            schema = data.get("data", {}).get("__schema", {})
            types = schema.get("types", [])

            for t in types:
                if not isinstance(t, dict):
                    continue
                type_name = t.get("name", "")
                # Find root Query and Mutation types
                if type_name in ("Query", "Mutation", "RootQuery", "RootMutation"):
                    for field in t.get("fields", []) or []:
                        field_name = field.get("name")
                        if field_name and not field_name.startswith("__"):
                            endpoints.append(
                                ApiEndpoint(
                                    path=f"{path}#{type_name.lower()}:{field_name}",
                                    method="POST",
                                    summary=f"GraphQL {type_name}: {field_name}",
                                    is_graphql=True,
                                    tags=["GraphQL", type_name],
                                )
                            )
        except Exception:
            pass

        return endpoints
