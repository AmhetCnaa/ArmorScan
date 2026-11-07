"""
Safe Path Traversal & Null-Byte File Access Auditor for ArmorScan (modules/traversal.py).
Audits file-serving and document parameters (/ftp, ?file=, ?doc=, ?page=, ?path=)
using non-destructive relative path probes and null-byte extension bypass checks.
"""

from __future__ import annotations

from typing import List, Set, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from armorscan.core.client import HttpClient, HttpResponse
from armorscan.core.models import (
    Confidence,
    Finding,
    ModuleResult,
    ScanTarget,
    Severity,
)
from armorscan.modules.base import BaseModule

FILE_PARAM_NAMES = {"file", "doc", "document", "page", "path", "template", "include", "filename"}

TRAVERSAL_SIGNATURES = [
    ("root:x:0:0:", "Unix /etc/passwd file content leaked"),
    ("[extensions]", "Windows win.ini file content leaked"),
    ('"dependencies"', "Node.js package.json configuration leaked via path/extension bypass"),
    ('"devDependencies"', "Node.js package.json devDependencies leaked via path/extension bypass"),
    ("Directory listing for", "Server directory listing exposed"),
    ("Index of /", "Server directory listing exposed"),
]


class PathTraversalModule(BaseModule):
    """
    Audits file and directory endpoints for Path Traversal (LFI) and Poison Null-Byte
    extension filter bypasses using strictly non-destructive read probes.
    """

    @property
    def name(self) -> str:
        return "traversal"

    @property
    def display_name(self) -> str:
        return "Path Traversal & File Inclusion Auditor"

    @property
    def description(self) -> str:
        return (
            "Detects Path Traversal (LFI), Poison Null-Byte filter bypasses, and exposed "
            "file directory listings using harmless relative path probes."
        )

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        # 1. Fetch SPA / 404 baseline to prevent false positives on catch-all routes
        canary_url = urljoin(target.base_url, "/armorscan-404-canary-traversal")
        canary_resp = await client.get(canary_url)
        canary_len = len(canary_resp.text) if canary_resp.ok else -1

        # 2. Check /ftp or /files directory & Poison Null-Byte bypass (e.g. /ftp/package.json.bak%2500.md)
        ftp_probes: List[Tuple[str, str, str]] = [
            (
                "/ftp/package.json.bak%2500.md",
                "/ftp/package.json.bak",
                "Poison Null-Byte (`%2500.md`) bypassed extension whitelist on `/ftp/package.json.bak`",
            ),
            (
                "/ftp/coupons_2013.md.bak%2500.md",
                "/ftp/coupons_2013.md.bak",
                "Poison Null-Byte (`%2500.md`) bypassed extension whitelist on `/ftp/coupons_2013.md.bak`",
            ),
        ]

        for bypass_path, direct_path, desc_reason in ftp_probes:
            bypass_url = urljoin(target.base_url, bypass_path)
            direct_url = urljoin(target.base_url, direct_path)
            try:
                resp_direct = await client.get(direct_url)
                resp_bypass = await client.get(bypass_url)

                if (
                    resp_bypass.ok
                    and resp_bypass.status_code == 200
                    and resp_direct.status_code in (403, 401, 400)
                    and not self._is_spa_fallback(resp_bypass, canary_len)
                ):
                    if '"name"' in resp_bypass.text or '"version"' in resp_bypass.text or len(resp_bypass.text) > 20:
                        curl_cmd = Finding.build_curl("GET", bypass_url)
                        findings.append(
                            Finding(
                                id="PATH_TRAVERSAL_DETECTED",
                                title=f"Restricted File Access via Poison Null-Byte / Traversal on {direct_path}",
                                description=(
                                    f"Direct access to '{direct_path}' was blocked with HTTP {resp_direct.status_code}, "
                                    f"but appending a URL-encoded null byte (`%2500.md`) at '{bypass_path}' bypassed "
                                    f"the file extension filter and returned HTTP 200 with restricted backup file contents."
                                ),
                                severity=Severity.HIGH,
                                confidence=Confidence.CONFIRMED,
                                module=self.name,
                                impact=(
                                    "Attackers can bypass file type restrictions and download sensitive backup files, "
                                    "source code archives, or configuration secrets from the server filesystem."
                                ),
                                evidence=(
                                    f"Direct GET {direct_path} -> HTTP {resp_direct.status_code} | "
                                    f"Bypass GET {bypass_path} -> HTTP 200 ({len(resp_bypass.text)} bytes)"
                                ),
                                curl_command=curl_cmd,
                                request_snippet=f"GET {bypass_url} HTTP/1.1\nHost: {target.host}",
                                response_snippet=resp_bypass.text[:250],
                                affected_urls=[bypass_url],
                                remediation=(
                                    "Reject file paths or parameters containing null bytes (`\\x00`, `%00`, `%2500`) or "
                                    "dot-dot segments (`..`). Resolve canonical paths using `path.resolve()` and enforce "
                                    "strict suffix validation on the normalized path."
                                ),
                                remediation_snippets={
                                    "express": "const path = require('path');\nif (fileParam.includes('\\0') || fileParam.includes('%00')) return res.status(400).send('Invalid path');\nconst safePath = path.resolve(BASE_DIR, fileParam);\nif (!safePath.startsWith(BASE_DIR)) return res.status(403).send('Forbidden');",
                                    "fastapi": "from pathlib import Path\nsafe_path = (BASE_DIR / filename).resolve()\nif not str(safe_path).startswith(str(BASE_DIR.resolve())):\n    raise HTTPException(status_code=403)",
                                },
                                cwe_id="CWE-22",
                                owasp_category="A01:2021-Broken Access Control",
                                references=[
                                    "https://owasp.org/www-community/attacks/Path_Traversal",
                                    "https://cwe.mitre.org/data/definitions/22.html",
                                ],
                            )
                        )
                        break
            except Exception:
                continue

        # 3. Query Parameter Relative Traversal Probes (?file=, ?doc=, ?page=, ?path=)
        parsed = urlparse(target.raw_url)
        qs = parse_qs(parsed.query)
        candidate_params: Set[str] = set()

        for p in qs:
            if p.lower() in FILE_PARAM_NAMES:
                candidate_params.add(p)

        # If target path looks like a file viewer or if query params exist
        if not candidate_params and any(k in parsed.path.lower() for k in ("file", "download", "view", "doc", "template")):
            candidate_params.add("file")

        traversal_payloads = [
            "../package.json",
            "..%2fpackage.json",
            "../../../../etc/passwd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
        ]

        for param in sorted(candidate_params):
            baseline_url = self._build_url(parsed, param, "index.html")
            base_resp = await client.get(baseline_url)

            for payload in traversal_payloads:
                test_url = self._build_url(parsed, param, payload)
                resp = await client.get(test_url)
                if not resp.ok or resp.status_code != 200:
                    continue
                if base_resp.ok and resp.text == base_resp.text:
                    continue
                if self._is_spa_fallback(resp, canary_len):
                    continue

                for sig, reason in TRAVERSAL_SIGNATURES:
                    if sig in resp.text and (not base_resp.ok or sig not in base_resp.text):
                        curl_cmd = Finding.build_curl("GET", test_url)
                        findings.append(
                            Finding(
                                id="PATH_TRAVERSAL_DETECTED",
                                title=f"Relative Path Traversal (LFI) in Parameter '{param}'",
                                description=(
                                    f"Supplying the relative traversal sequence '{payload}' in parameter '{param}' "
                                    f"disclosed internal filesystem content ({reason})."
                                ),
                                severity=Severity.HIGH,
                                confidence=Confidence.CONFIRMED,
                                module=self.name,
                                impact=(
                                    "Arbitrary local file read allows attackers to extract server configuration files, "
                                    "credentials, source code, and system user lists."
                                ),
                                evidence=f"Parameter '{param}={payload}' matched signature '{sig}' ({reason}).",
                                curl_command=curl_cmd,
                                request_snippet=f"GET {test_url} HTTP/1.1\nHost: {target.host}",
                                response_snippet=Finding.extract_context_snippet(resp.text, sig) or resp.text[:250],
                                affected_urls=[test_url],
                                remediation=(
                                    "Never pass raw user input directly to filesystem APIs. Map user inputs to an "
                                    "allowlist of known file identifiers, or verify canonical path confinement."
                                ),
                                remediation_snippets={
                                    "express": "const safePath = path.resolve( SAFE_ROOT, req.query.file );\nif (!safePath.startsWith(SAFE_ROOT)) return res.status(403).end();",
                                    "fastapi": "safe_path = (SAFE_ROOT / file).resolve()\nif not safe_path.is_relative_to(SAFE_ROOT):\n    raise HTTPException(403)",
                                },
                                cwe_id="CWE-22",
                                owasp_category="A01:2021-Broken Access Control",
                                references=[
                                    "https://owasp.org/www-community/attacks/Path_Traversal",
                                    "https://cwe.mitre.org/data/definitions/22.html",
                                ],
                            )
                        )
                        break

        if not findings:
            passed_checks.append("no-path-traversal-or-lfi-detected")

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )

    @staticmethod
    def _is_spa_fallback(resp: HttpResponse, canary_len: int) -> bool:
        ctype = resp.headers.get("content-type", "").lower()
        if "text/html" in ctype and ("<app-root" in resp.text.lower() or "<!doctype html" in resp.text[:200].lower()):
            if canary_len > 0 and abs(len(resp.text) - canary_len) < 60:
                return True
        return False

    @staticmethod
    def _build_url(parsed, param: str, value: str) -> str:
        qs = parse_qs(parsed.query)
        qs[param] = [value]
        new_query = urlencode(qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
