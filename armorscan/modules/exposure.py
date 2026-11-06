"""
Sensitive File & Information Disclosure Audit Module for ArmorScan.
Detects exposed files (.env, .git, .DS_Store, backups, openapi specs, robots.txt)
using Canary 404 baseline analysis and strict signature checks to eliminate false positives.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple
import httpx

from armorscan.core.client import HttpClient, HttpResponse
from armorscan.core.models import Finding, ModuleResult, ScanTarget, Severity
from armorscan.modules.base import BaseModule
from armorscan.remediations.templates import (
    get_dotfile_exposure_remediations,
    get_openapi_exposure_remediations,
)

# Common sensitive path keywords in robots.txt
ROBOTS_SENSITIVE_KEYWORDS = {
    "admin",
    "backup",
    "secret",
    "private",
    "internal",
    "panel",
    "dashboard",
    "portal",
    "config",
    "database",
    "db",
    "root",
}

ENV_KEY_PATTERNS = re.compile(
    r"(DB_|SECRET|KEY|PASS|PASSWORD|AUTH|TOKEN|AWS_|PORT=|DATABASE_|REDIS_|MAIL_|API_)",
    re.IGNORECASE,
)
ENV_LINE_PATTERN = re.compile(r"^[A-Z0-9_]{2,}\s*=\s*.+$", re.MULTILINE)


class ExposureAuditModule(BaseModule):
    """Audits targets for publicly exposed sensitive files with anti-false-positive validation."""

    name: str = "exposure"
    display_name: str = "Sensitive File & Information Disclosure Audit"
    description: str = "Scans for leaked .env, .git repositories, backups, and API specifications."

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        base_url = target.base_url

        # Step 1: Establish Canary 404 Baseline
        canary_token = uuid.uuid4().hex[:12]
        canary_url = f"{base_url}/armorscan-canary-404-{canary_token}"
        canary_resp = await client.get(canary_url)

        canary_status = canary_resp.status_code
        canary_body = canary_resp.text
        canary_len = len(canary_body)
        is_spa_catch_all = (canary_status == 200)

        # Step 2: Concurrently probe sensitive paths
        paths_to_probe = [
            "/.env",
            "/.git/HEAD",
            "/.git/config",
            "/.DS_Store",
            "/wp-config.php.bak",
            "/config.json",
            "/swagger.json",
            "/openapi.json",
            "/robots.txt",
        ]

        probe_urls = [f"{base_url}{p}" for p in paths_to_probe]
        responses = await client.burst_requests(probe_urls, concurrency=10)

        probe_map: Dict[str, HttpResponse] = {
            paths_to_probe[i]: responses[i] for i in range(len(paths_to_probe))
        }

        # Step 3: Signature and Content Validation

        # 3.1 Check /.env
        self._check_env_file(
            probe_map.get("/.env"),
            target,
            findings,
            passed_checks,
            is_spa_catch_all,
            canary_len,
        )

        # 3.2 Check /.git/HEAD and /.git/config
        self._check_git_repo(
            probe_map.get("/.git/HEAD"),
            probe_map.get("/.git/config"),
            target,
            findings,
            passed_checks,
            is_spa_catch_all,
        )

        # 3.3 Check /.DS_Store
        self._check_ds_store(
            probe_map.get("/.DS_Store"),
            target,
            findings,
            passed_checks,
        )

        # 3.4 Check /wp-config.php.bak
        self._check_backup_file(
            probe_map.get("/wp-config.php.bak"),
            target,
            findings,
            passed_checks,
        )

        # 3.5 Check /config.json
        self._check_config_json(
            probe_map.get("/config.json"),
            target,
            findings,
            passed_checks,
            is_spa_catch_all,
        )

        # 3.6 Check /swagger.json and /openapi.json
        self._check_openapi_specs(
            probe_map.get("/swagger.json"),
            probe_map.get("/openapi.json"),
            target,
            findings,
            passed_checks,
        )

        # 3.7 Check /robots.txt
        self._check_robots_txt(
            probe_map.get("/robots.txt"),
            target,
            findings,
            passed_checks,
        )

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )

    def _is_html(self, resp: HttpResponse) -> bool:
        """Check if response is HTML (indicating an SPA or custom 404 page)."""
        content_type = resp.headers.get("content-type", "").lower()
        if "text/html" in content_type:
            return True
        stripped = resp.text.strip().lower()
        return stripped.startswith("<!doctype html") or stripped.startswith("<html")

    def _check_env_file(
        self,
        resp: Optional[HttpResponse],
        target: ScanTarget,
        findings: List[Finding],
        passed_checks: List[str],
        is_spa: bool,
        canary_len: int,
    ) -> None:
        if not resp or not resp.ok or resp.status_code != 200:
            passed_checks.append("env-file-not-exposed")
            return

        # If it's HTML, it's virtually always a catch-all SPA or custom 404 page
        if self._is_html(resp):
            passed_checks.append("env-file-not-exposed (spa-404-bypassed)")
            return

        text = resp.text
        # Signature verification: must match line assignment pattern AND contain known secret keys
        has_assignments = bool(ENV_LINE_PATTERN.search(text))
        has_keywords = bool(ENV_KEY_PATTERNS.search(text))

        if has_assignments and has_keywords:
            # Mask sensitive values in evidence
            masked_lines = []
            for line in text.splitlines()[:5]:
                if "=" in line:
                    k, _ = line.split("=", 1)
                    masked_lines.append(f"{k.strip()}=[REDACTED]")
            evidence_snippet = "\n".join(masked_lines)

            findings.append(
                Finding(
                    id="EXPOSED_ENV_FILE",
                    title="Critical Exposure: Publicly Accessible .env File Detected",
                    description=(
                        f"Target URL '{target.base_url}/.env' is publicly accessible and contains "
                        "environment configuration variables with sensitive secrets."
                    ),
                    severity=Severity.CRITICAL,
                    module=self.name,
                    impact=(
                        "Catastrophic data breach: Attackers can extract database credentials, "
                        "API tokens, encryption keys, and third-party service secrets, leading to full server takeover."
                    ),
                    evidence=f"Sample extracted keys:\n{evidence_snippet}",
                    remediation="Configure web server to deny access to dotfiles or move .env outside web root.",
                    remediation_snippets=get_dotfile_exposure_remediations(),
                    references=["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"],
                    cwe_id="CWE-552",
                    owasp_category="A05:2021-Security Misconfiguration",
                )
            )
        else:
            passed_checks.append("env-file-not-exposed")

    def _check_git_repo(
        self,
        resp_head: Optional[HttpResponse],
        resp_config: Optional[HttpResponse],
        target: ScanTarget,
        findings: List[Finding],
        passed_checks: List[str],
        is_spa: bool,
    ) -> None:
        git_exposed = False
        evidence = ""

        # Check .git/HEAD
        if resp_head and resp_head.ok and resp_head.status_code == 200 and not self._is_html(resp_head):
            head_text = resp_head.text.strip()
            if head_text.startswith("ref: refs/heads/") or head_text.startswith("ref: refs/tags/") or (len(head_text) == 40 and re.match(r"^[0-9a-f]{40}$", head_text)):
                git_exposed = True
                evidence = f"/.git/HEAD: {head_text}"

        # Check .git/config
        if not git_exposed and resp_config and resp_config.ok and resp_config.status_code == 200 and not self._is_html(resp_config):
            config_text = resp_config.text
            if "[core]" in config_text and ("repositoryformatversion" in config_text or "filemode" in config_text):
                git_exposed = True
                evidence = "/.git/config: Valid git configuration file located."

        if git_exposed:
            findings.append(
                Finding(
                    id="EXPOSED_GIT_REPOSITORY",
                    title="Critical Exposure: Publicly Accessible .git Repository Detected",
                    description=(
                        f"The Git repository directory at '{target.base_url}/.git/' is publicly accessible. "
                        "Tools like git-dumper can reconstruct the entire application source code and commit history."
                    ),
                    severity=Severity.CRITICAL,
                    module=self.name,
                    impact=(
                        "Full source code compromise: Attackers can download complete project source code, "
                        "hardcoded credentials, proprietary business logic, and past commit diffs."
                    ),
                    evidence=evidence,
                    remediation="Deny public HTTP access to the .git directory in web server configuration.",
                    remediation_snippets=get_dotfile_exposure_remediations(),
                    references=["https://en.internetwache.org/dont-publicly-expose-git-directories-31-03-2015/"],
                    cwe_id="CWE-527",
                    owasp_category="A05:2021-Security Misconfiguration",
                )
            )
        else:
            passed_checks.append("git-repository-not-exposed")

    def _check_ds_store(
        self,
        resp: Optional[HttpResponse],
        target: ScanTarget,
        findings: List[Finding],
        passed_checks: List[str],
    ) -> None:
        if not resp or not resp.ok or resp.status_code != 200:
            passed_checks.append("ds-store-not-exposed")
            return

        content = resp.content
        # Apple .DS_Store binary signature: starts with 0x00 00 00 01 42 75 64 31 ("\x00\x00\x00\x01Bud1")
        if content.startswith(b"\x00\x00\x00\x01Bud1") or b"Bud1" in content[:16]:
            findings.append(
                Finding(
                    id="EXPOSED_DS_STORE",
                    title="Exposed macOS Metadata File (.DS_Store)",
                    description=(
                        f"The file '{target.base_url}/.DS_Store' is accessible. "
                        ".DS_Store files leak internal folder structures and file names created on macOS."
                    ),
                    severity=Severity.MEDIUM,
                    module=self.name,
                    impact="Directory enumeration: Discloses hidden files, staging folders, and backend directory layouts.",
                    evidence="Valid macOS Bud1 binary header detected.",
                    remediation="Add rule to block access to .DS_Store files and delete them from deployment bundles.",
                    remediation_snippets=get_dotfile_exposure_remediations(),
                    cwe_id="CWE-538",
                )
            )
        else:
            passed_checks.append("ds-store-not-exposed")

    def _check_backup_file(
        self,
        resp: Optional[HttpResponse],
        target: ScanTarget,
        findings: List[Finding],
        passed_checks: List[str],
    ) -> None:
        if not resp or not resp.ok or resp.status_code != 200:
            passed_checks.append("backup-files-not-exposed")
            return

        text = resp.text
        if "<?php" in text and ("DB_PASSWORD" in text or "DB_NAME" in text or "AUTH_KEY" in text):
            findings.append(
                Finding(
                    id="EXPOSED_BACKUP_CONFIG",
                    title="Critical Exposure: Publicly Accessible WordPress/PHP Backup File",
                    description=(
                        f"The backup file '{target.base_url}/wp-config.php.bak' was downloaded in cleartext. "
                        "Because it lacks the .php extension, the web server served it without PHP interpretation."
                    ),
                    severity=Severity.CRITICAL,
                    module=self.name,
                    impact="Database credentials and WordPress authentication salts exposed in plain text.",
                    evidence="Cleartext PHP configuration containing DB credentials detected.",
                    remediation="Remove backup files from the web root and configure web server to deny .bak extensions.",
                    remediation_snippets=get_dotfile_exposure_remediations(),
                    cwe_id="CWE-530",
                    owasp_category="A05:2021-Security Misconfiguration",
                )
            )
        else:
            passed_checks.append("backup-files-not-exposed")

    def _check_config_json(
        self,
        resp: Optional[HttpResponse],
        target: ScanTarget,
        findings: List[Finding],
        passed_checks: List[str],
        is_spa: bool,
    ) -> None:
        if not resp or not resp.ok or resp.status_code != 200 or self._is_html(resp):
            passed_checks.append("config-json-not-exposed")
            return

        try:
            data = json.loads(resp.text)
            if isinstance(data, dict):
                keys = set(str(k).lower() for k in data.keys())
                sensitive_keys = keys.intersection({"database", "db", "password", "secret", "apikey", "connectionstring", "auth"})
                if sensitive_keys:
                    findings.append(
                        Finding(
                            id="EXPOSED_CONFIG_JSON",
                            title="Sensitive Configuration File (config.json) Exposed",
                            description=f"Publicly accessible config.json containing sensitive parameters: {', '.join(sensitive_keys)}.",
                            severity=Severity.HIGH,
                            module=self.name,
                            impact="Leaks architectural configuration, internal hostnames, or authentication keys.",
                            evidence=f"Disclosed keys: {', '.join(sensitive_keys)}",
                            remediation="Do not place configuration files with credentials inside public web root.",
                            remediation_snippets=get_dotfile_exposure_remediations(),
                            cwe_id="CWE-552",
                        )
                    )
                    return
        except Exception:
            pass

        passed_checks.append("config-json-not-exposed")

    def _check_openapi_specs(
        self,
        resp_swagger: Optional[HttpResponse],
        resp_openapi: Optional[HttpResponse],
        target: ScanTarget,
        findings: List[Finding],
        passed_checks: List[str],
    ) -> None:
        found_spec = None
        evidence_url = ""

        for path, resp in (("/swagger.json", resp_swagger), ("/openapi.json", resp_openapi)):
            if resp and resp.ok and resp.status_code == 200 and not self._is_html(resp):
                try:
                    data = json.loads(resp.text)
                    if isinstance(data, dict) and ("openapi" in data or "swagger" in data) and "paths" in data:
                        found_spec = data
                        evidence_url = f"{target.base_url}{path}"
                        break
                except Exception:
                    pass

        if found_spec:
            endpoints_count = len(found_spec.get("paths", {}))
            findings.append(
                Finding(
                    id="EXPOSED_OPENAPI_SPEC",
                    title="Publicly Disclosed OpenAPI / Swagger API Specification",
                    description=(
                        f"An API schema document was discovered at '{evidence_url}' detailing {endpoints_count} API paths, "
                        "request schemas, and parameter models."
                    ),
                    severity=Severity.MEDIUM,
                    module=self.name,
                    impact=(
                        "Facilitates automated reconnaissance. Attackers can map all administrative, "
                        "internal, and undocumented endpoints without manual exploration."
                    ),
                    evidence=f"Found spec at {evidence_url} with {endpoints_count} routes mapped.",
                    remediation="Restrict OpenAPI/Swagger endpoints to internal networks or protect them behind authentication in production.",
                    remediation_snippets=get_openapi_exposure_remediations(),
                    cwe_id="CWE-200",
                )
            )
        else:
            passed_checks.append("openapi-spec-not-exposed")

    def _check_robots_txt(
        self,
        resp: Optional[HttpResponse],
        target: ScanTarget,
        findings: List[Finding],
        passed_checks: List[str],
    ) -> None:
        if not resp or not resp.ok or resp.status_code != 200 or self._is_html(resp):
            passed_checks.append("robots-txt-neutral")
            return

        text = resp.text
        if "user-agent:" not in text.lower():
            passed_checks.append("robots-txt-neutral")
            return

        disallowed_paths: List[str] = []
        sensitive_disallowed: List[str] = []

        for line in text.splitlines():
            line_clean = line.strip()
            if line_clean.lower().startswith("disallow:"):
                parts = line_clean.split(":", 1)
                if len(parts) > 1:
                    path = parts[1].strip()
                    if path and path != "/":
                        disallowed_paths.append(path)
                        path_lower = path.lower()
                        for kw in ROBOTS_SENSITIVE_KEYWORDS:
                            if kw in path_lower:
                                sensitive_disallowed.append(path)
                                break

        if sensitive_disallowed:
            unique_sensitive = sorted(list(set(sensitive_disallowed)))[:8]
            findings.append(
                Finding(
                    id="ROBOTS_TXT_SENSITIVE_PATHS",
                    title="Sensitive Admin/Internal Paths Disclosed in robots.txt",
                    description=(
                        f"The '/robots.txt' file explicitly advertises sensitive directory paths: "
                        f"{', '.join(unique_sensitive)}."
                    ),
                    severity=Severity.LOW,
                    module=self.name,
                    impact=(
                        "Security through obscurity failure: Disallow entries do not restrict access; "
                        "they serve as a roadmap for attackers seeking unlisted administrative portals."
                    ),
                    evidence=f"Disallowed paths found: {', '.join(unique_sensitive)}",
                    remediation="Remove sensitive URLs from robots.txt. Use proper authentication and IP whitelisting instead.",
                    cwe_id="CWE-200",
                )
            )
        else:
            passed_checks.append("robots-txt-clean")
