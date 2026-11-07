"""
Unit tests for AI Vulnerability Storyteller & Auto-Patch Generator (tests/test_ai_patch.py).
Validates offline deterministic rule-based explanations, business impact narratives,
unified git diff patch generation across frameworks, and LLM query parsing.
"""

from pathlib import Path
import pytest
import respx
import httpx

from armorscan.core.ai_patch import AiPatchEngine, FindingExplanation, PatchResult
from armorscan.core.models import Confidence, Finding, Severity


@pytest.fixture
def idor_finding() -> Finding:
    return Finding(
        id="CROSS_TENANT_OBJECT_ACCESS",
        title="Cross-Tenant Broken Object Level Authorization (BOLA / IDOR)",
        description="User A accessed User B's private basket at /rest/basket/1.",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        module="multi_step",
        impact="Allows unauthorized access to customer private data.",
        evidence="GET /rest/basket/1 returned HTTP 200 (749 bytes).",
        affected_urls=["http://127.0.0.1:3000/rest/basket/1"],
        remediation="Enforce object-level tenant ownership checks before returning entity.",
    )


@pytest.fixture
def xss_finding() -> Finding:
    return Finding(
        id="DOM_XSS_SINK_TAINT_FLOW",
        title="Client-Side DOM XSS Sink Taint Flow",
        description="URL parameter flowed into Element.innerHTML.",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        module="browser_dom",
        impact="Allows session hijacking and account takeover.",
        evidence="Taint traced from location.search to #search.innerHTML.",
        affected_urls=["http://127.0.0.1:3000/#/search?q=test"],
        remediation="Sanitize input or use textContent instead of innerHTML.",
    )


@pytest.mark.asyncio
async def test_offline_explanation_generation(idor_finding: Finding, xss_finding: Finding):
    engine = AiPatchEngine(model_provider="offline_rule_engine")

    # 1. IDOR finding explanation
    idor_expl = await engine.explain(idor_finding)
    assert isinstance(idor_expl, FindingExplanation)
    assert idor_expl.finding_id == "CROSS_TENANT_OBJECT_ACCESS"
    assert idor_expl.provider == "offline_rule_engine"
    assert "Broken Object Level Authorization" in idor_expl.executive_summary or "IDOR" in idor_expl.executive_summary
    assert "GDPR" in idor_expl.business_impact or "privacy" in idor_expl.business_impact

    # 2. DOM XSS finding explanation
    xss_expl = await engine.explain(xss_finding)
    assert xss_expl.finding_id == "DOM_XSS_SINK_TAINT_FLOW"
    assert "innerHTML" in xss_expl.executive_summary
    assert "hijack" in xss_expl.business_impact

    # 3. Fallback for custom / unknown finding
    custom_finding = Finding(
        id="CUSTOM_ANOMALY",
        title="Custom Server Anomaly",
        description="Unidentified error pattern observed.",
        severity=Severity.LOW,
        confidence=Confidence.TENTATIVE,
        module="custom",
        impact="Minimal operational impact.",
        affected_urls=["http://example.com/status"],
    )
    custom_expl = await engine.explain(custom_finding)
    assert custom_expl.finding_id == "CUSTOM_ANOMALY"
    assert "CUSTOM_ANOMALY" in custom_expl.executive_summary or "Custom Server Anomaly" in custom_expl.executive_summary


@pytest.mark.asyncio
async def test_offline_unified_diff_patch_generation(idor_finding: Finding, tmp_path: Path):
    engine = AiPatchEngine(model_provider="offline_rule_engine")

    # 1. Default Express patch
    patch_express = await engine.generate_patch(idor_finding, framework="express")
    assert isinstance(patch_express, PatchResult)
    assert patch_express.framework == "express"
    assert "diff --git" in patch_express.unified_diff
    assert "--- a/routes/basket.js" in patch_express.unified_diff
    assert "+++ b/routes/basket.js" in patch_express.unified_diff
    assert "+  if (basket.UserId !== req.user.id)" in patch_express.unified_diff

    # 2. FastAPI patch
    patch_fastapi = await engine.generate_patch(idor_finding, framework="fastapi")
    assert patch_fastapi.framework == "fastapi"
    assert "--- a/app/routers/basket.py" in patch_fastapi.unified_diff
    assert "+    if basket.user_id != current_user.id:" in patch_fastapi.unified_diff

    # 3. Contextual patch with existing repo file in tmp_path
    sub_dir = tmp_path / "src" / "routes"
    sub_dir.mkdir(parents=True)
    custom_basket_file = sub_dir / "basket.js"
    custom_basket_file.write_text("// existing basket handler\n", encoding="utf-8")

    patch_repo = await engine.generate_patch(idor_finding, repo_path=str(tmp_path), framework="express")
    assert "src/routes/basket.js" in patch_repo.target_file
    assert "src/routes/basket.js" in patch_repo.unified_diff


@pytest.mark.asyncio
async def test_llm_query_mock_integration(idor_finding: Finding):
    engine = AiPatchEngine(model_provider="openai")

    # Mock OpenAI API call
    fake_openai_resp = {
        "choices": [
            {
                "message": {
                    "content": (
                        '{"executive_summary": "Critical tenant data isolation failure.", '
                        '"business_impact": "Severe breach of confidential consumer records.", '
                        '"technical_root_cause": "Missing session user ownership check on basket model."}'
                    )
                }
            }
        ]
    }

    with respx.mock:
        respx.post("https://api.openai.com/v1/chat/completions").respond(
            status_code=200,
            json=fake_openai_resp,
        )

        expl = await engine._call_llm_for_explanation(idor_finding, "openai")
        assert expl is not None
        assert expl.provider == "openai"
        assert expl.executive_summary == "Critical tenant data isolation failure."
        assert "breach" in expl.business_impact
