"""
AI-Powered Vulnerability Storyteller & Automated Patch Generator (core/ai_patch.py).
Provides business impact analysis, executive summaries, and ready-to-apply unified
git diffs for discovered vulnerabilities.
Operates in dual-mode:
1. Offline / Deterministic Rule Engine (default, zero network or API keys required)
2. AI-Assisted Engine (Ollama local LLM, OpenAI, or Google Gemini when keys/services are available)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple

import httpx
from pydantic import BaseModel, Field

from armorscan.core.models import Finding, ScanResult


class FindingExplanation(BaseModel):
    """Executive narrative and risk analysis for a security finding."""

    finding_id: str
    title: str
    severity: str
    executive_summary: str
    business_impact: str
    technical_root_cause: str
    provider: str = Field(default="offline_rule_engine", description="offline_rule_engine, ollama, openai, or gemini")


class PatchResult(BaseModel):
    """Ready-to-apply unified git diff and code remediation."""

    finding_id: str
    target_file: str
    framework: str
    unified_diff: str
    remediation_advice: str
    provider: str = Field(default="offline_rule_engine")


# Deterministic offline explanations for core vulnerability categories
OFFLINE_EXPLANATIONS: Dict[str, Dict[str, str]] = {
    "CROSS_TENANT_OBJECT_ACCESS": {
        "summary": (
            "An unauthenticated or unprivileged user can read or modify another tenant's private "
            "data simply by altering an identifier in the request (Broken Object Level Authorization / IDOR)."
        ),
        "impact": (
            "Violates data privacy regulations (GDPR, CCPA, HIPAA), exposes confidential customer "
            "records to competitors, and damages corporate reputation."
        ),
        "root_cause": "The application controller fetches records by user-supplied ID without verifying ownership against session context.",
    },
    "DOM_XSS_SINK_TAINT_FLOW": {
        "summary": (
            "Untrusted URL parameters or input directly flow into browser DOM execution sinks "
            "(e.g., innerHTML, document.write) without sanitization."
        ),
        "impact": (
            "Attackers can hijack user sessions, steal authentication tokens, or perform unauthorized "
            "actions in the victim's browser."
        ),
        "root_cause": "Direct assignment of location.hash or search parameters into DOM elements without entity escaping or DOMPurify.",
    },
    "SQLI_BOOLEAN_DIFFERENCE_SUSPECTED": {
        "summary": (
            "The database query structure can be manipulated via input parameters, yielding different "
            "responses based on boolean logic."
        ),
        "impact": (
            "Allows full database dump, authentication bypass, data tampering, and potential server compromise."
        ),
        "root_cause": "Dynamic SQL concatenation instead of parameterized prepared statements.",
    },
    "NOSQLI_OPERATOR_INJECTION_SUSPECTED": {
        "summary": (
            "JSON payload input is passed directly to NoSQL queries, allowing query operators "
            "(e.g., $gt, $ne) to alter query logic."
        ),
        "impact": (
            "Attackers can bypass login screens or enumerate confidential documents without authorization."
        ),
        "root_cause": "Passing unvalidated request body objects directly into MongoDB/Sequelize search filters.",
    },
    "PATH_TRAVERSAL_DETECTED": {
        "summary": (
            "File handling endpoints fail to restrict relative path segments or null-bytes, allowing "
            "unauthorized reading of server files."
        ),
        "impact": (
            "Exposes application source code, configuration files containing credentials, and operating system files."
        ),
        "root_cause": "Resolving user-supplied filenames without enforcing an absolute sandbox root directory.",
    },
    "OPEN_REDIRECT_UNVALIDATED": {
        "summary": (
            "The application redirects users to arbitrary external URLs supplied in request query parameters."
        ),
        "impact": (
            "Facilitates highly convincing phishing attacks leveraging the trusted company domain name."
        ),
        "root_cause": "Setting the HTTP Location header directly from user input without an allowlist check.",
    },
    "DATABASE_ERROR_DISCLOSURE": {
        "summary": (
            "The server returns raw database error messages and stack traces to clients during unexpected conditions."
        ),
        "impact": (
            "Provides attackers with database engine version, table schemas, and internal query architecture."
        ),
        "root_cause": "Missing global exception handlers and unsuppressed debug/stack trace outputs in production.",
    },
    "JWT_MISSING_EXPIRATION": {
        "summary": (
            "Authentication JWT tokens lack an 'exp' claim, allowing tokens to remain valid indefinitely."
        ),
        "impact": (
            "Stolen or leaked tokens cannot naturally expire, enabling persistent unauthorized session hijacking."
        ),
        "root_cause": "Token creation routine omitted the standard 'exp' payload claim.",
    },
    "JWT_SENSITIVE_DATA_IN_PAYLOAD": {
        "summary": (
            "Authentication tokens contain sensitive attributes (passwords, salts, TOTP keys) in their base64 payload."
        ),
        "impact": (
            "Any client or network observer can decode and read plain credentials directly from the token string."
        ),
        "root_cause": "Encoding entire user database model objects into JWT claims instead of minimal identifier claims.",
    },
    "MISSING_AUTHENTICATION_GATE": {
        "summary": (
            "Administrative or private API endpoints do not enforce authentication middleware."
        ),
        "impact": (
            "Allows anonymous internet users to inspect internal configurations or invoke privileged operations."
        ),
        "root_cause": "Route definition was mounted outside the authenticated middleware router group.",
    },
    "MISSING_CSP": {
        "summary": (
            "The web server does not deliver a Content-Security-Policy (CSP) response header."
        ),
        "impact": (
            "Increases blast radius of Cross-Site Scripting (XSS) and allows unauthorized script injection."
        ),
        "root_cause": "HTTP security headers are not configured in web server reverse proxy or application middleware.",
    },
    "EXPOSED_PROMETHEUS_METRICS": {
        "summary": (
            "Prometheus internal performance metrics (/metrics) are publicly accessible without authentication."
        ),
        "impact": (
            "Leaks server CPU, memory, internal IP addresses, version details, and request traffic patterns."
        ),
        "root_cause": "Metrics endpoint is exposed on public interface without network firewall or auth barrier.",
    },
    "EXPOSED_ENV_FILE": {
        "summary": (
            "A sensitive environment file (.env) is directly accessible over HTTP."
        ),
        "impact": (
            "Exposes production database passwords, API secret keys, encryption salts, and third-party tokens."
        ),
        "root_cause": "Web server public document root includes dotfiles instead of serving only a designated public/ directory.",
    },
}

# Deterministic unified git diffs for core frameworks
OFFLINE_PATCH_TEMPLATES: Dict[str, Dict[str, Tuple[str, str, str]]] = {
    # finding_id -> {framework: (target_file, unified_diff, advice)}
    "CROSS_TENANT_OBJECT_ACCESS": {
        "express": (
            "routes/basket.js",
            """diff --git a/routes/basket.js b/routes/basket.js
--- a/routes/basket.js
+++ b/routes/basket.js
@@ -10,6 +10,10 @@ router.get('/basket/:id', async (req, res) => {
   const basket = await BasketModel.findByPk(req.params.id);
   if (!basket) return res.status(404).json({ error: 'Not found' });
+  // Enforce object-level tenant ownership check
+  if (basket.UserId !== req.user.id) {
+    return res.status(403).json({ error: 'Forbidden: Unauthorized object access' });
+  }
   return res.json(basket);
 });
""",
            "Enforce tenant ownership verification before returning or modifying the entity.",
        ),
        "fastapi": (
            "app/routers/basket.py",
            """diff --git a/app/routers/basket.py b/app/routers/basket.py
--- a/app/routers/basket.py
+++ b/app/routers/basket.py
@@ -15,5 +15,7 @@ async def get_basket(basket_id: int, current_user: User = Depends(get_current_u
     basket = await db.get(Basket, basket_id)
     if not basket:
         raise HTTPException(status_code=404, detail="Basket not found")
+    if basket.user_id != current_user.id:
+        raise HTTPException(status_code=403, detail="Forbidden: Access denied to foreign basket")
     return basket
""",
            "Verify that basket.user_id matches current_user.id from the authenticated token dependency.",
        ),
    },
    "OPEN_REDIRECT_UNVALIDATED": {
        "express": (
            "routes/redirect.js",
            """diff --git a/routes/redirect.js b/routes/redirect.js
--- a/routes/redirect.js
+++ b/routes/redirect.js
@@ -5,5 +5,8 @@ router.get('/redirect', (req, res) => {
   const target = req.query.to || req.query.url;
+  // Whitelist only relative paths starting with /
+  if (!target || !target.startsWith('/') || target.startsWith('//')) {
+    return res.status(400).send('Invalid redirect destination');
+  }
   return res.redirect(target);
 });
""",
            "Enforce relative paths or an explicit domain whitelist before issuing redirect responses.",
        ),
        "fastapi": (
            "app/routers/redirect.py",
            """diff --git a/app/routers/redirect.py b/app/routers/redirect.py
--- a/app/routers/redirect.py
+++ b/app/routers/redirect.py
@@ -8,4 +8,6 @@ from fastapi.responses import RedirectResponse
 @router.get("/redirect")
 def safe_redirect(to: str):
+    if not to.startswith("/") or to.startswith("//"):
+        raise HTTPException(status_code=400, detail="Invalid relative redirect target")
     return RedirectResponse(url=to)
""",
            "Reject external absolute URLs and protocol-relative URLs (//) in redirect destinations.",
        ),
    },
    "MISSING_CSP": {
        "nginx": (
            "nginx.conf",
            """diff --git a/nginx.conf b/nginx.conf
--- a/nginx.conf
+++ b/nginx.conf
@@ -20,4 +20,5 @@ server {
     listen 443 ssl http2;
     server_name example.com;
+    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self';" always;
 }
""",
            "Add a hardened Content-Security-Policy response header in the Nginx server block.",
        ),
        "express": (
            "app.js",
            """diff --git a/app.js b/app.js
--- a/app.js
+++ b/app.js
@@ -4,4 +4,11 @@ const express = require('express');
+const helmet = require('helmet');
 const app = express();
+app.use(helmet.contentSecurityPolicy({
+  directives: {
+    defaultSrc: ["'self'"],
+    scriptSrc: ["'self'"],
+    objectSrc: ["'none'"]
+  }
+}));
""",
            "Use helmet.contentSecurityPolicy middleware in Express to protect against XSS.",
        ),
    },
    "PATH_TRAVERSAL_DETECTED": {
        "express": (
            "routes/files.js",
            """diff --git a/routes/files.js b/routes/files.js
--- a/routes/files.js
+++ b/routes/files.js
@@ -1,6 +1,11 @@
 const path = require('path');
 const SAFE_DIR = path.resolve(__dirname, '../public/files');
 
 router.get('/file', (req, res) => {
-  const filename = req.query.file;
-  res.sendFile(path.join(SAFE_DIR, filename));
+  const rawFilename = (req.query.file || '').replace(/\\0/g, '');
+  const safePath = path.resolve(SAFE_DIR, rawFilename);
+  if (!safePath.startsWith(SAFE_DIR)) {
+    return res.status(403).send('Forbidden file path');
+  }
+  res.sendFile(safePath);
 });
""",
            "Strip null-bytes and ensure path.resolve() stays strictly inside the safe directory root.",
        ),
    },
    "MISSING_AUTHENTICATION_GATE": {
        "express": (
            "routes/admin.js",
            """diff --git a/routes/admin.js b/routes/admin.js
--- a/routes/admin.js
+++ b/routes/admin.js
@@ -3,3 +3,4 @@ const express = require('express');
+const { requireAuth, requireAdmin } = require('../middleware/auth');
 const router = express.Router();
+router.use(requireAuth, requireAdmin);
 router.get('/admin/application-configuration', (req, res) => {
""",
            "Apply authentication and role verification middleware before exposing administrative APIs.",
        ),
    },
}


class AiPatchEngine:
    """
    Orchestrates business impact explanations and code patches.
    Falls back gracefully to offline deterministic templates when no AI APIs are configured.
    """

    def __init__(self, model_provider: Optional[str] = None):
        self.explicit_provider = model_provider
        self.detected_provider = self._detect_provider()

    def _detect_provider(self) -> str:
        if self.explicit_provider:
            return self.explicit_provider
        if os.getenv("OPENAI_API_KEY"):
            return "openai"
        if os.getenv("GEMINI_API_KEY"):
            return "gemini"
        if os.getenv("OLLAMA_HOST") or os.getenv("OLLAMA_BASE_URL"):
            return "ollama"
        return "offline_rule_engine"

    async def explain(self, finding: Finding) -> FindingExplanation:
        """Generate executive summary and business impact explanation."""
        provider = self.detected_provider

        # Attempt online LLM explanation if configured
        if provider != "offline_rule_engine":
            try:
                llm_res = await self._call_llm_for_explanation(finding, provider)
                if llm_res:
                    return llm_res
            except Exception:
                pass  # Fall back to offline rules

        # Offline deterministic explanation
        rule_data = OFFLINE_EXPLANATIONS.get(
            finding.id,
            {
                "summary": f"Security finding '{finding.title}' was detected on {', '.join(finding.affected_urls[:2]) or 'target'}.",
                "impact": finding.impact or "Could allow unauthorized actions or information disclosure.",
                "root_cause": finding.description or "Improper input validation or missing security configuration.",
            },
        )

        return FindingExplanation(
            finding_id=finding.id,
            title=finding.title,
            severity=finding.severity.value,
            executive_summary=rule_data["summary"],
            business_impact=rule_data["impact"],
            technical_root_cause=rule_data["root_cause"],
            provider="offline_rule_engine",
        )

    async def generate_patch(
        self,
        finding: Finding,
        repo_path: Optional[str] = None,
        framework: Optional[str] = None,
    ) -> PatchResult:
        """Generate ready-to-apply unified git diff."""
        provider = self.detected_provider

        # Auto-detect framework from repo files if repo_path given
        selected_fw = framework or self._detect_repo_framework(repo_path)

        # Attempt online LLM patch if configured
        if provider != "offline_rule_engine":
            try:
                llm_patch = await self._call_llm_for_patch(finding, repo_path, selected_fw, provider)
                if llm_patch:
                    return llm_patch
            except Exception:
                pass  # Fall back to offline templates

        # Offline deterministic patch template
        fw_dict = OFFLINE_PATCH_TEMPLATES.get(finding.id, {})
        if selected_fw in fw_dict:
            target_file, diff, advice = fw_dict[selected_fw]
        elif fw_dict:
            # Use first available framework template
            first_fw = next(iter(fw_dict))
            target_file, diff, advice = fw_dict[first_fw]
            selected_fw = first_fw
        else:
            # Generic fallback diff
            target_file = "security_patch.diff"
            diff = f"""diff --git a/app.config b/app.config
--- a/app.config
+++ b/app.config
@@ -1,3 +1,5 @@
+# ArmorScan Automated Hardening Patch for {finding.id}
+# Title: {finding.title}
+# Remediation: {finding.remediation}
"""
            advice = finding.remediation or "Apply input sanitization and secure configuration."

        # If repo_path is provided, adjust file path if matching file exists
        if repo_path and target_file != "security_patch.diff":
            repo_file = Path(repo_path) / target_file
            if not repo_file.exists():
                # Attempt to find similar filename in repo
                matches = list(Path(repo_path).rglob(Path(target_file).name))
                if matches:
                    rel_path = str(matches[0].relative_to(Path(repo_path)))
                    diff = diff.replace(f"a/{target_file}", f"a/{rel_path}").replace(f"b/{target_file}", f"b/{rel_path}")
                    target_file = rel_path

        return PatchResult(
            finding_id=finding.id,
            target_file=target_file,
            framework=selected_fw,
            unified_diff=diff,
            remediation_advice=advice,
            provider="offline_rule_engine",
        )

    def _detect_repo_framework(self, repo_path: Optional[str]) -> str:
        if not repo_path or not Path(repo_path).exists():
            return "express"
        p = Path(repo_path)
        if (p / "package.json").exists():
            return "express"
        if (p / "requirements.txt").exists() or (p / "pyproject.toml").exists():
            return "fastapi"
        if (p / "nginx.conf").exists():
            return "nginx"
        return "express"

    async def _call_llm_for_explanation(self, finding: Finding, provider: str) -> Optional[FindingExplanation]:
        prompt = (
            f"You are a Senior AppSec Architect. Summarize this security vulnerability in 2 concise sentences for an executive, "
            f"then describe business impact and technical root cause in JSON format.\n"
            f"Finding: {finding.id} ({finding.title})\n"
            f"Severity: {finding.severity.value}\n"
            f"Evidence: {finding.evidence}\n"
            f"Description: {finding.description}\n"
            f'JSON format: {{"executive_summary": "...", "business_impact": "...", "technical_root_cause": "..."}}'
        )
        resp_json = await self._query_llm_json(prompt, provider)
        if resp_json and "executive_summary" in resp_json:
            return FindingExplanation(
                finding_id=finding.id,
                title=finding.title,
                severity=finding.severity.value,
                executive_summary=resp_json.get("executive_summary", ""),
                business_impact=resp_json.get("business_impact", ""),
                technical_root_cause=resp_json.get("technical_root_cause", ""),
                provider=provider,
            )
        return None

    async def _call_llm_for_patch(
        self,
        finding: Finding,
        repo_path: Optional[str],
        framework: str,
        provider: str,
    ) -> Optional[PatchResult]:
        prompt = (
            f"Generate a valid git unified diff patch to fix this vulnerability in {framework}.\n"
            f"Finding: {finding.id} ({finding.title})\n"
            f"Remediation: {finding.remediation}\n"
            f"Affected URL: {', '.join(finding.affected_urls)}\n"
            f'Return pure JSON: {{"target_file": "path/to/file", "unified_diff": "diff --git ...", "remediation_advice": "..."}}'
        )
        resp_json = await self._query_llm_json(prompt, provider)
        if resp_json and "unified_diff" in resp_json:
            return PatchResult(
                finding_id=finding.id,
                target_file=resp_json.get("target_file", "patch.diff"),
                framework=framework,
                unified_diff=resp_json.get("unified_diff", ""),
                remediation_advice=resp_json.get("remediation_advice", ""),
                provider=provider,
            )
        return None

    async def _query_llm_json(self, prompt: str, provider: str) -> Optional[Dict[str, Any]]:
        async with httpx.AsyncClient(timeout=10.0, trust_env=False) as client:
            if provider == "openai":
                api_key = os.getenv("OPENAI_API_KEY")
                resp = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                    json={
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "user", "content": prompt}],
                        "response_format": {"type": "json_object"},
                    },
                )
                if resp.status_code == 200:
                    content = resp.json()["choices"][0]["message"]["content"]
                    return json.loads(content)
            elif provider == "gemini":
                api_key = os.getenv("GEMINI_API_KEY")
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
                resp = await client.post(
                    url,
                    headers={"Content-Type": "application/json"},
                    json={"contents": [{"parts": [{"text": prompt}]}]},
                )
                if resp.status_code == 200:
                    text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
                    match = re.search(r"\{.*\}", text, re.DOTALL)
                    if match:
                        return json.loads(match.group(0))
            elif provider == "ollama":
                ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434") + "/api/generate"
                resp = await client.post(
                    ollama_url,
                    json={"model": os.getenv("OLLAMA_MODEL", "llama3"), "prompt": prompt, "stream": False, "format": "json"},
                )
                if resp.status_code == 200:
                    return json.loads(resp.json().get("response", "{}"))
        return None
