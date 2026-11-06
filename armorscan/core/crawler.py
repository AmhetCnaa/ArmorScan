"""
Smart Web Crawler & Link Spider for ArmorScan.
Performs scoped, breadth-first discovery of internal endpoints, routes, and forms
within same-origin boundaries to power comprehensive multi-page audits.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from pydantic import BaseModel, Field

from armorscan.core.client import HttpClient
from armorscan.core.models import ScanTarget
from armorscan.core.schema import ApiEndpoint, GraphQLAuditor, OpenApiParser

# Media and asset extensions to ignore during web crawl
IGNORED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".webm", ".mp3", ".wav", ".avi",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dmg", ".apk",
}

HREF_REGEX = re.compile(r"""(?:href|action|src)=["']([^"'#\s>]+)["']""", re.IGNORECASE)
FORM_BLOCK_REGEX = re.compile(r"""<form\b([^>]*)>(.*?)</form>""", re.IGNORECASE | re.DOTALL)
INPUT_REGEX = re.compile(r"""<input\b([^>]*)>""", re.IGNORECASE)
ATTR_REGEX = re.compile(r"""([a-zA-Z_0-9-]+)\s*=\s*["']([^"']*)["']""")

CSRF_PARAMETER_NAMES = {
    "csrf", "csrf_token", "_csrf", "authenticity_token",
    "_token", "csrfmiddlewaretoken", "antiforgery", "xsrf_token",
}


class DiscoveredForm(BaseModel):
    """Information about an HTML form detected during crawl."""
    page_url: str
    action_url: str
    method: str = "GET"
    parameters: List[str] = Field(default_factory=list, description="Fuzzable input parameter names")
    inputs: List[Dict[str, str]] = Field(default_factory=list, description="Detailed input field metadata")


class CrawlResult(BaseModel):
    """Aggregated results from an automated target crawl."""
    base_url: str
    discovered_urls: List[str] = Field(default_factory=list)
    discovered_paths: List[str] = Field(default_factory=list)
    pages_crawled: int = 0
    forms: List[DiscoveredForm] = Field(default_factory=list)
    api_endpoints: List[ApiEndpoint] = Field(default_factory=list, description="Endpoints discovered via OpenAPI or GraphQL")
    discovered_parameters: Set[str] = Field(default_factory=set, description="All discovered fuzzable parameters")
    graphql_url: Optional[str] = None
    graphql_introspection_active: bool = False


class WebCrawler:
    """
    Asynchronous same-origin web crawler.
    Discovers application endpoints, API paths, and navigation routes.
    """

    def __init__(
        self,
        max_depth: int = 2,
        max_pages: int = 15,
        concurrency: int = 5,
    ):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = concurrency

    async def crawl(
        self,
        target: ScanTarget,
        client: HttpClient,
        custom_schema_path: Optional[str] = None,
    ) -> CrawlResult:
        """
        Execute scoped breadth-first search on the target application,
        combined with automated API schema discovery (OpenAPI/Swagger/GraphQL).
        """
        start_url = target.raw_url
        target_host = target.host.lower()
        target_scheme = target.scheme.lower()
        target_port = target.port

        visited: Set[str] = set()
        discovered_urls: Set[str] = {start_url}
        discovered_paths: Set[str] = {target.path or "/"}
        forms: List[DiscoveredForm] = []
        discovered_parameters: Set[str] = set()
        api_endpoints: List[ApiEndpoint] = []

        # 0. API Schema Discovery (OpenAPI / Swagger)
        schema_url, parsed_api = await OpenApiParser.discover_and_parse(
            client, target.base_url, custom_schema_path=custom_schema_path
        )
        if parsed_api:
            api_endpoints.extend(parsed_api)
            for ep in parsed_api:
                sample_url = ep.build_test_url(target.base_url)
                discovered_urls.add(sample_url)
                discovered_paths.add(ep.path)
                for p in ep.parameters:
                    if p.name.lower() not in CSRF_PARAMETER_NAMES:
                        discovered_parameters.add(p.name)

        # 0.1 GraphQL Introspection Probe
        gql_active, gql_url, gql_ops = await GraphQLAuditor.audit_graphql(client, target.base_url)
        if gql_ops:
            api_endpoints.extend(gql_ops)
            for op in gql_ops:
                discovered_paths.add(op.path)

        # Queue holds (url, current_depth)
        queue: List[Tuple[str, int]] = [(start_url, 0)]

        while queue and len(visited) < self.max_pages:
            current_url, depth = queue.pop(0)

            if current_url in visited or depth > self.max_depth:
                continue

            visited.add(current_url)

            # Fetch page content
            resp = await client.get(current_url)
            if not resp.ok or not resp.text:
                continue

            content_type = resp.headers.get("content-type", "").lower()
            if "text/html" not in content_type and not current_url.endswith("/"):
                # Non-HTML response, do not parse for links
                continue

            # Extract links and forms from HTML
            extracted_links, page_forms = self._parse_html(current_url, resp.text)
            forms.extend(page_forms)
            for f in page_forms:
                for p in f.parameters:
                    discovered_parameters.add(p)

            for link in extracted_links:
                normalized = self._normalize_link(current_url, link, target_scheme, target_host, target_port)
                if not normalized:
                    continue

                parsed = urlparse(normalized)
                path = parsed.path or "/"

                discovered_urls.add(normalized)
                discovered_paths.add(path)

                if normalized not in visited and (depth + 1) <= self.max_depth:
                    if len(visited) + len(queue) < self.max_pages * 2:
                        queue.append((normalized, depth + 1))

        return CrawlResult(
            base_url=target.base_url,
            discovered_urls=sorted(list(discovered_urls)),
            discovered_paths=sorted(list(discovered_paths)),
            pages_crawled=len(visited),
            forms=forms,
            api_endpoints=api_endpoints,
            discovered_parameters=discovered_parameters,
            graphql_url=gql_url,
            graphql_introspection_active=gql_active,
        )

    def _parse_html(self, page_url: str, html_text: str) -> Tuple[List[str], List[DiscoveredForm]]:
        """Extract links, forms, and input parameters using regular expressions."""
        links: List[str] = []
        forms: List[DiscoveredForm] = []

        # Find all href and action links
        for match in HREF_REGEX.finditer(html_text):
            link = match.group(1).strip()
            if link and not link.startswith(("javascript:", "mailto:", "tel:", "#")):
                links.append(link)

        # Find complete form blocks and extract input parameters
        for block_match in FORM_BLOCK_REGEX.finditer(html_text):
            form_tag_attrs = block_match.group(1)
            form_inner = block_match.group(2)

            # Extract action and method
            action_m = re.search(r"""action=["']([^"']*)["']""", form_tag_attrs, re.IGNORECASE)
            action = action_m.group(1).strip() if action_m else page_url
            full_action = urljoin(page_url, action)

            method_m = re.search(r"""method=["']([^"']*)["']""", form_tag_attrs, re.IGNORECASE)
            method = method_m.group(1).upper() if method_m else "GET"

            form_params: List[str] = []
            inputs_meta: List[Dict[str, str]] = []

            for input_match in INPUT_REGEX.finditer(form_inner):
                attrs = dict(ATTR_REGEX.findall(input_match.group(1)))
                name = attrs.get("name", "").strip()
                input_type = attrs.get("type", "text").strip().lower()

                if name and name.lower() not in CSRF_PARAMETER_NAMES:
                    form_params.append(name)
                    inputs_meta.append({"name": name, "type": input_type, "value": attrs.get("value", "")})

            forms.append(
                DiscoveredForm(
                    page_url=page_url,
                    action_url=full_action,
                    method=method,
                    parameters=form_params,
                    inputs=inputs_meta,
                )
            )

        # Fallback for unclosed <form> tags
        if not forms:
            for match in re.finditer(r"""<form\b[^>]*action=["']([^"']*)["'][^>]*>""", html_text, re.IGNORECASE):
                action = match.group(1).strip() or page_url
                full_action = urljoin(page_url, action)
                forms.append(DiscoveredForm(page_url=page_url, action_url=full_action))

        return links, forms

    def _normalize_link(
        self,
        base_url: str,
        raw_link: str,
        target_scheme: str,
        target_host: str,
        target_port: int,
    ) -> Optional[str]:
        """Validate same-origin scope and strip fragments/unneeded parameters."""
        try:
            full_url = urljoin(base_url, raw_link)
            parsed = urlparse(full_url)

            # Check scheme
            if parsed.scheme.lower() not in ("http", "https"):
                return None

            # Check same origin (host and port)
            parsed_host = parsed.hostname.lower() if parsed.hostname else ""
            if parsed_host != target_host:
                return None

            default_port = 443 if parsed.scheme.lower() == "https" else 80
            parsed_port = parsed.port or default_port
            if parsed_port != target_port:
                return None

            # Check ignored file extensions
            path_lower = parsed.path.lower()
            for ext in IGNORED_EXTENSIONS:
                if path_lower.endswith(ext):
                    return None

            # Reconstruct clean URL without fragment
            clean_url = f"{parsed.scheme}://{parsed_host}"
            if (parsed.scheme == "https" and parsed_port != 443) or (parsed.scheme == "http" and parsed_port != 80):
                clean_url += f":{parsed_port}"
            clean_url += parsed.path or "/"
            if parsed.query:
                clean_url += f"?{parsed.query}"

            return clean_url
        except Exception:
            return None
