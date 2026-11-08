"""
Deep Recursive Spider and Form/Parameter Extractor for ArmorScan.
Discovers endpoints, navigation trees, HTML form parameters, search queries,
and inputs with scoped same-origin crawling and strict loop prevention.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlparse

from pydantic import BaseModel, Field

from armorscan.core.client import HttpClient
from armorscan.core.models import ScanTarget

# Media and asset extensions to ignore during web crawl
IGNORED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".webm", ".mp3", ".wav", ".avi", ".mkv",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dmg", ".apk", ".iso",
}

# Link extraction regular expressions (support double-quoted, single-quoted, and unquoted attributes)
A_HREF_REGEX = re.compile(r"""<a\b[^>]*?\bhref\s*=\s*(?:"([^"#]+)"|'([^'#]+)'|([^\s>"'#]+))""", re.IGNORECASE)
AREA_HREF_REGEX = re.compile(r"""<area\b[^>]*?\bhref\s*=\s*(?:"([^"#]+)"|'([^'#]+)'|([^\s>"'#]+))""", re.IGNORECASE)
IFRAME_SRC_REGEX = re.compile(r"""<(?:iframe|frame)\b[^>]*?\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>"']+))""", re.IGNORECASE)
GENERIC_LINK_REGEX = re.compile(r"""(?:href|src|action)\s*=\s*(?:"([^"#\s>]+)"|'([^'#\s>]+)'|([^\s>"'#]+))""", re.IGNORECASE)

# Form parsing regular expressions
FORM_BLOCK_REGEX = re.compile(r"""<form\b([^>]*)>(.*?)</form>""", re.IGNORECASE | re.DOTALL)
INPUT_TAG_REGEX = re.compile(r"""<input\b([^>]*)>""", re.IGNORECASE)
TEXTAREA_TAG_REGEX = re.compile(r"""<textarea\b([^>]*)>""", re.IGNORECASE)
SELECT_TAG_REGEX = re.compile(r"""<select\b([^>]*)>""", re.IGNORECASE)
ATTR_REGEX = re.compile(r"""([a-zA-Z0-9_\-:]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.DOTALL)


class ExtractedInput(BaseModel):
    """Metadata for an individual form input or field."""
    name: str
    input_type: str = "text"
    value: Optional[str] = ""
    is_required: bool = False


class ExtractedForm(BaseModel):
    """HTML Form metadata including action target, method, and extractable parameters."""
    page_url: str
    action_url: str
    method: str = "GET"
    inputs: List[ExtractedInput] = Field(default_factory=list)
    parameter_names: List[str] = Field(default_factory=list)


class SpiderResult(BaseModel):
    """Aggregated output from a deep spider crawl."""
    base_url: str
    discovered_urls: List[str] = Field(default_factory=list)
    discovered_paths: List[str] = Field(default_factory=list)
    audit_routes: List[str] = Field(default_factory=list)
    pages_crawled: int = 0
    forms: List[ExtractedForm] = Field(default_factory=list)
    fuzzable_parameters: Set[str] = Field(default_factory=set)
    duration_seconds: float = 0.0


class DeepSpider:
    """
    High-performance recursive HTML spider and form extractor.
    Crawls links, forms, and parameterized query strings within the target scope.
    """

    def __init__(
        self,
        max_depth: int = 3,
        max_pages: int = 30,
        concurrency: int = 6,
    ):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = concurrency

    @staticmethod
    def _parse_tag_attrs(tag_attrs_str: str) -> Dict[str, str]:
        """Extract key-value attributes from raw HTML tag string."""
        attrs: Dict[str, str] = {}
        for match in ATTR_REGEX.finditer(tag_attrs_str):
            key = match.group(1).lower()
            val = match.group(2) if match.group(2) is not None else (
                match.group(3) if match.group(3) is not None else match.group(4)
            )
            attrs[key] = val or ""
        return attrs

    def extract_forms(self, page_url: str, html_text: str) -> List[ExtractedForm]:
        """Extract all HTML forms, input fields, and parameters from document."""
        forms: List[ExtractedForm] = []

        for form_match in FORM_BLOCK_REGEX.finditer(html_text):
            form_attrs_str = form_match.group(1)
            form_inner_html = form_match.group(2)

            f_attrs = self._parse_tag_attrs(form_attrs_str)
            raw_action = f_attrs.get("action", "").strip()
            method = f_attrs.get("method", "GET").strip().upper() or "GET"

            # Resolve relative action URL to absolute URL
            action_url = urljoin(page_url, raw_action) if raw_action else page_url

            inputs: List[ExtractedInput] = []
            param_names: List[str] = []

            # 1. Parse <input> tags
            for inp_match in INPUT_TAG_REGEX.finditer(form_inner_html):
                i_attrs = self._parse_tag_attrs(inp_match.group(1))
                name = i_attrs.get("name", "").strip()
                if not name:
                    continue
                inp_type = i_attrs.get("type", "text").strip().lower()
                val = i_attrs.get("value", "")
                is_req = "required" in i_attrs
                inputs.append(ExtractedInput(name=name, input_type=inp_type, value=val, is_required=is_req))
                if name not in param_names:
                    param_names.append(name)

            # 2. Parse <textarea> tags
            for txt_match in TEXTAREA_TAG_REGEX.finditer(form_inner_html):
                t_attrs = self._parse_tag_attrs(txt_match.group(1))
                name = t_attrs.get("name", "").strip()
                if name and name not in param_names:
                    inputs.append(ExtractedInput(name=name, input_type="textarea", value=""))
                    param_names.append(name)

            # 3. Parse <select> tags
            for sel_match in SELECT_TAG_REGEX.finditer(form_inner_html):
                s_attrs = self._parse_tag_attrs(sel_match.group(1))
                name = s_attrs.get("name", "").strip()
                if name and name not in param_names:
                    inputs.append(ExtractedInput(name=name, input_type="select", value=""))
                    param_names.append(name)

            forms.append(
                ExtractedForm(
                    page_url=page_url,
                    action_url=action_url,
                    method=method,
                    inputs=inputs,
                    parameter_names=param_names,
                )
            )

        return forms

    @staticmethod
    def _first_group(match: re.Match) -> str:
        for g in match.groups():
            if g is not None:
                return g.strip()
        return ""

    def extract_links(self, page_url: str, html_text: str) -> List[str]:
        """Extract all hyperlinked URLs from anchors, areas, and iframes."""
        raw_links: Set[str] = set()

        # Extract <a> hrefs
        for m in A_HREF_REGEX.finditer(html_text):
            val = self._first_group(m)
            if val and not val.startswith(("javascript:", "mailto:", "tel:", "#")):
                raw_links.add(val)

        # Extract <area> hrefs
        for m in AREA_HREF_REGEX.finditer(html_text):
            val = self._first_group(m)
            if val and not val.startswith(("javascript:", "mailto:", "tel:", "#")):
                raw_links.add(val)

        # Extract <iframe/frame> srcs
        for m in IFRAME_SRC_REGEX.finditer(html_text):
            val = self._first_group(m)
            if val and not val.startswith(("javascript:", "data:", "about:")):
                raw_links.add(val)

        # Fallback generic scanner
        for m in GENERIC_LINK_REGEX.finditer(html_text):
            val = self._first_group(m)
            if val and not val.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                raw_links.add(val)

        resolved_links: List[str] = []
        for r_link in raw_links:
            full_url = urljoin(page_url, r_link)
            resolved_links.append(full_url)

        return resolved_links

    def is_in_scope(
        self,
        url: str,
        target_scheme: str,
        target_host: str,
        target_port: int,
    ) -> bool:
        """Verify whether an extracted URL strictly belongs to the target domain."""
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return False

            parsed_host = parsed.hostname.lower() if parsed.hostname else ""
            if parsed_host != target_host:
                return False

            parsed_port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
            if parsed_port != target_port:
                return False

            # Ignore static assets (images, fonts, stylesheets)
            path_lower = parsed.path.lower()
            if any(path_lower.endswith(ext) for ext in IGNORED_EXTENSIONS):
                return False

            return True
        except Exception:
            return False

    async def crawl(self, target: ScanTarget, client: HttpClient) -> SpiderResult:
        """Execute deep recursive spider across target application."""
        start_time = time.monotonic()
        start_url = target.raw_url
        target_host = target.host.lower()
        target_scheme = target.scheme.lower()
        target_port = target.port

        visited: Set[str] = set()
        discovered_urls: Set[str] = {start_url}
        discovered_paths: Set[str] = {target.path or "/"}
        audit_routes: Set[str] = {target.path or "/"}
        all_forms: List[ExtractedForm] = []
        fuzzable_parameters: Set[str] = set()

        # Seed parameters from start URL query string if present
        start_parsed = urlparse(start_url)
        if start_parsed.query:
            audit_routes.add(f"{start_parsed.path or '/'}?{start_parsed.query}")
            for param in parse_qs(start_parsed.query):
                fuzzable_parameters.add(param)

        # Queue contains (url, depth)
        queue: List[Tuple[str, int]] = [(start_url, 0)]
        semaphore = asyncio.Semaphore(self.concurrency)

        while queue and len(visited) < self.max_pages:
            current_url, depth = queue.pop(0)

            if current_url in visited or depth > self.max_depth:
                continue

            visited.add(current_url)

            # Fetch page content
            async with semaphore:
                resp = await client.get(current_url)

            if not resp.ok or not resp.text:
                continue

            # Extract query parameters from URL itself
            parsed_current = urlparse(current_url)
            if parsed_current.query:
                for param in parse_qs(parsed_current.query):
                    fuzzable_parameters.add(param)

            # Extract forms and inputs
            page_forms = self.extract_forms(current_url, resp.text)
            all_forms.extend(page_forms)
            for f in page_forms:
                for p in f.parameter_names:
                    fuzzable_parameters.add(p)
                # If form action is in-scope, add action URL and synthetic query route
                if self.is_in_scope(f.action_url, target_scheme, target_host, target_port):
                    discovered_urls.add(f.action_url)
                    p_action = urlparse(f.action_url)
                    action_path = p_action.path or "/"
                    discovered_paths.add(action_path)
                    audit_routes.add(action_path)
                    if f.parameter_names:
                        sample_query = "&".join(f"{pn}=1" for pn in f.parameter_names[:4])
                        param_route = f"{action_path}?{sample_query}"
                        discovered_paths.add(param_route)
                        audit_routes.add(param_route)

            # Extract outgoing links
            links = self.extract_links(current_url, resp.text)
            for lk in links:
                if self.is_in_scope(lk, target_scheme, target_host, target_port):
                    discovered_urls.add(lk)
                    p_lk = urlparse(lk)
                    lk_path = p_lk.path or "/"
                    discovered_paths.add(lk_path)
                    audit_routes.add(lk_path)

                    if p_lk.query:
                        full_rel = f"{lk_path}?{p_lk.query}"
                        discovered_paths.add(full_rel)
                        audit_routes.add(full_rel)
                        for param in parse_qs(p_lk.query):
                            fuzzable_parameters.add(param)

                    if lk not in visited and (depth + 1) <= self.max_depth:
                        if len(visited) + len(queue) < self.max_pages * 2:
                            queue.append((lk, depth + 1))

        elapsed = round(time.monotonic() - start_time, 3)

        return SpiderResult(
            base_url=target.base_url,
            discovered_urls=sorted(list(discovered_urls)),
            discovered_paths=sorted(list(discovered_paths)),
            audit_routes=sorted(list(audit_routes)),
            pages_crawled=len(visited),
            forms=all_forms,
            fuzzable_parameters=fuzzable_parameters,
            duration_seconds=elapsed,
        )
