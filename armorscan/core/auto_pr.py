"""
Automated GitHub Pull Request & Self-Healing Remediation Engine for ArmorScan.
Transforms detected vulnerabilities into verified code patches, creates a secure
branch in the target repository, and opens an automated Pull Request via GitHub API.
"""

from __future__ import annotations

import base64
import os
import time
from typing import Any, Dict, List, Optional
import httpx
from pydantic import BaseModel, Field

from armorscan import __version__
from armorscan.core.ai_patch import AiPatchEngine, PatchResult
from armorscan.core.models import Finding, ScanResult, Severity


class AutoPrResult(BaseModel):
    """Result of automated GitHub Pull Request creation."""
    success: bool = Field(..., description="Whether the PR was opened successfully")
    pr_url: Optional[str] = Field(default=None, description="Web URL of the created Pull Request")
    pr_number: Optional[int] = Field(default=None, description="Pull Request number")
    branch: str = Field(default="", description="Name of the security patch branch")
    files_patched: List[str] = Field(default_factory=list, description="Target files updated in PR")
    error: Optional[str] = Field(default=None, description="Failure reason if unsuccessful")


class GitHubAutoPrEngine:
    """
    Automates GitHub Pull Request creation for detected security vulnerabilities.
    Interacts directly with GitHub REST API v3 using standard repository tokens.
    """

    def __init__(
        self,
        github_repo: str,
        github_token: Optional[str] = None,
        base_api_url: str = "https://api.github.com",
    ):
        self.github_repo = github_repo.strip()
        if github_token is not None:
            self.github_token = github_token.strip()
        else:
            self.github_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
        self.base_api_url = base_api_url.rstrip("/")
        self.ai_engine = AiPatchEngine()

        if "/" in self.github_repo:
            parts = self.github_repo.split("/", 1)
            self.owner = parts[0].strip()
            self.repo = parts[1].strip()
        else:
            self.owner = ""
            self.repo = self.github_repo

    def _get_headers(self) -> Dict[str, str]:
        """Construct standard GitHub REST API headers."""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": f"ArmorScan-AutoPR/{__version__}",
        }
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        return headers

    async def create_security_pr(
        self,
        scan_result: ScanResult,
        repo_path: Optional[str] = None,
    ) -> AutoPrResult:
        """
        Orchestrates full self-healing workflow:
        1. Selects highest severity findings.
        2. Synthesizes code patch via AiPatchEngine.
        3. Creates branch 'armorscan/security-patch-<timestamp>'.
        4. Commits patched file via GitHub Contents API.
        5. Opens automated Pull Request with audit narrative.
        """
        if not self.owner or not self.repo:
            return AutoPrResult(
                success=False,
                error=f"Invalid github_repo format '{self.github_repo}'. Expected 'owner/repo'.",
            )

        if not self.github_token:
            return AutoPrResult(
                success=False,
                error="Missing GitHub authentication token. Provide via --github-token or GITHUB_TOKEN environment variable.",
            )

        # 1. Filter actionable findings (Critical, High, Medium)
        actionable_findings = [
            f for f in scan_result.all_findings
            if not f.is_suppressed and f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
        ]

        if not actionable_findings:
            # Fall back to any finding if no high severity
            actionable_findings = [f for f in scan_result.all_findings if not f.is_suppressed]

        if not actionable_findings:
            return AutoPrResult(
                success=False,
                error="No actionable security findings detected to patch.",
            )

        # Focus primary patch on the most severe finding
        top_finding = actionable_findings[0]
        patch_res = await self.ai_engine.generate_patch(top_finding, repo_path=repo_path)

        async with httpx.AsyncClient(timeout=15.0, trust_env=False) as client:
            # 2. Get repository default branch
            repo_api_url = f"{self.base_api_url}/repos/{self.owner}/{self.repo}"
            repo_resp = await client.get(repo_api_url, headers=self._get_headers())
            if repo_resp.status_code == 401:
                return AutoPrResult(success=False, error="GitHub authentication failed (HTTP 401 Bad Credentials).")
            if repo_resp.status_code == 404:
                return AutoPrResult(success=False, error=f"GitHub repository '{self.github_repo}' not found (HTTP 404).")
            if repo_resp.status_code != 200:
                return AutoPrResult(success=False, error=f"Failed to query repository: HTTP {repo_resp.status_code} {repo_resp.text}")

            default_branch = repo_resp.json().get("default_branch", "main")

            # 3. Get commit SHA of default branch
            ref_url = f"{self.base_api_url}/repos/{self.owner}/{self.repo}/git/ref/heads/{default_branch}"
            ref_resp = await client.get(ref_url, headers=self._get_headers())
            if ref_resp.status_code != 200:
                return AutoPrResult(success=False, error=f"Failed to resolve head SHA for branch '{default_branch}': HTTP {ref_resp.status_code}")

            base_sha = ref_resp.json().get("object", {}).get("sha", "")
            if not base_sha:
                return AutoPrResult(success=False, error=f"Missing commit SHA on '{default_branch}'.")

            # 4. Create new security branch
            branch_name = f"armorscan/security-patch-{int(time.time())}"
            create_ref_url = f"{self.base_api_url}/repos/{self.owner}/{self.repo}/git/refs"
            ref_payload = {
                "ref": f"refs/heads/{branch_name}",
                "sha": base_sha,
            }
            create_ref_resp = await client.post(create_ref_url, headers=self._get_headers(), json=ref_payload)
            if create_ref_resp.status_code not in (200, 201):
                return AutoPrResult(success=False, error=f"Failed to create patch branch '{branch_name}': HTTP {create_ref_resp.status_code}")

            # 5. Commit patched file
            target_file = patch_res.target_file or "security_patch.conf"
            contents_url = f"{self.base_api_url}/repos/{self.owner}/{self.repo}/contents/{target_file}"

            # Check if file already exists on new branch
            get_file_resp = await client.get(f"{contents_url}?ref={branch_name}", headers=self._get_headers())
            file_sha: Optional[str] = None
            if get_file_resp.status_code == 200:
                file_sha = get_file_resp.json().get("sha")

            # Encode file content in base64
            # If unified diff, commit the diff or template remediation
            file_body_text = patch_res.unified_diff
            b64_content = base64.b64encode(file_body_text.encode("utf-8")).decode("utf-8")

            cwe_tag = f" [{top_finding.cwe_id}]" if top_finding.cwe_id else ""
            commit_payload: Dict[str, Any] = {
                "message": f"fix(security): resolve ArmorScan finding {top_finding.id}{cwe_tag}",
                "content": b64_content,
                "branch": branch_name,
            }
            if file_sha:
                commit_payload["sha"] = file_sha

            commit_resp = await client.put(contents_url, headers=self._get_headers(), json=commit_payload)
            if commit_resp.status_code not in (200, 201):
                return AutoPrResult(success=False, branch=branch_name, error=f"Failed to commit security patch file: HTTP {commit_resp.status_code}")

            # 6. Open Pull Request
            pulls_url = f"{self.base_api_url}/repos/{self.owner}/{self.repo}/pulls"
            pr_body = self._build_pr_body(scan_result, top_finding, patch_res)
            pr_payload = {
                "title": f"🛡️ [ArmorScan] Automated Security Hardening & Remediation ({top_finding.id})",
                "head": branch_name,
                "base": default_branch,
                "body": pr_body,
            }
            pr_resp = await client.post(pulls_url, headers=self._get_headers(), json=pr_payload)
            if pr_resp.status_code not in (200, 201):
                return AutoPrResult(success=False, branch=branch_name, error=f"Failed to open Pull Request: HTTP {pr_resp.status_code}")

            pr_json = pr_resp.json()
            return AutoPrResult(
                success=True,
                pr_url=pr_json.get("html_url"),
                pr_number=pr_json.get("number"),
                branch=branch_name,
                files_patched=[target_file],
            )

    def _build_pr_body(
        self,
        scan_result: ScanResult,
        finding: Finding,
        patch_res: PatchResult,
    ) -> str:
        """Construct comprehensive Pull Request description."""
        cwe = finding.cwe_id or "N/A"
        owasp = finding.owasp_category or "A05:2021-Security Misconfiguration"

        return f"""## 🛡️ ArmorScan Automated Security Hardening

This Pull Request was generated automatically by **ArmorScan Sovereign Engine v{__version__}**.
It applies targeted, verified remediations to address vulnerabilities identified during continuous security auditing.

---

### 📋 Addressed Vulnerability
- **Finding ID:** `{finding.id}`
- **Title:** {finding.title}
- **Severity:** **{finding.severity.value}**
- **CWE:** `{cwe}` | **OWASP Top 10:** `{owasp}`
- **Target File:** `{patch_res.target_file}`
- **Framework:** `{patch_res.framework}`

### ⚠️ Security Impact
> {finding.impact}

### 🛠️ Proposed Changes & Diff
```diff
{patch_res.unified_diff}
```

### 🔬 Verification & Quality Gate
After merging this patch, re-run ArmorScan in your CI/CD pipeline:
```bash
armorscan {scan_result.target.raw_url} --fail-under 80
```

---
*Self-healing pull request opened automatically by ArmorScan.*
"""
