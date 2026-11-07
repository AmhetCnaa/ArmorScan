"""
Unit and Mock Integration Tests for "Self-Healing AI" GitHub Pull Request Generator.
Verifies repository branch creation, patch file commit, automated Pull Request opening,
and error handling using respx.
"""

import pytest
import respx
import httpx

from armorscan.core.auto_pr import GitHubAutoPrEngine, AutoPrResult
from armorscan.core.models import Confidence, Finding, ModuleResult, ScanResult, ScanTarget, Severity


def create_mock_scan_result() -> ScanResult:
    target = ScanTarget.from_url("https://example.com")
    f = Finding(
        id="MISSING_HSTS",
        title="Missing Strict-Transport-Security (HSTS) Header",
        description="The host does not enforce HTTPS connections via HSTS.",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        module="headers",
        impact="Susceptible to SSL-stripping and active man-in-the-middle attacks.",
        cwe_id="CWE-319",
        owasp_category="A05:2021-Security Misconfiguration",
    )
    mod = ModuleResult(module_name="headers", display_name="Security Headers", findings=[f])
    return ScanResult(target=target, modules=[mod])


@pytest.mark.asyncio
async def test_auto_pr_successful_flow():
    scan_result = create_mock_scan_result()
    engine = GitHubAutoPrEngine(github_repo="AmhetCnaa/test-app", github_token="ghp_mock_token_12345")

    with respx.mock(base_url="https://api.github.com") as respx_mock:
        # 1. Get repo default branch
        respx_mock.get("/repos/AmhetCnaa/test-app").mock(
            return_value=httpx.Response(200, json={"default_branch": "main", "name": "test-app"})
        )
        # 2. Get head commit SHA
        respx_mock.get("/repos/AmhetCnaa/test-app/git/ref/heads/main").mock(
            return_value=httpx.Response(200, json={"object": {"sha": "9abc1234def5678"}})
        )
        # 3. Create patch branch
        respx_mock.post("/repos/AmhetCnaa/test-app/git/refs").mock(
            return_value=httpx.Response(201, json={"ref": "refs/heads/armorscan/security-patch-123"})
        )
        # 4. Check if file exists
        respx_mock.get(url__regex=r"/repos/AmhetCnaa/test-app/contents/.*").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        # 5. Commit patch file
        respx_mock.put(url__regex=r"/repos/AmhetCnaa/test-app/contents/.*").mock(
            return_value=httpx.Response(201, json={"content": {"name": "nginx.conf"}})
        )
        # 6. Open Pull Request
        respx_mock.post("/repos/AmhetCnaa/test-app/pulls").mock(
            return_value=httpx.Response(
                201,
                json={
                    "html_url": "https://github.com/AmhetCnaa/test-app/pull/101",
                    "number": 101,
                    "title": "🛡️ [ArmorScan] Automated Security Hardening",
                },
            )
        )

        result = await engine.create_security_pr(scan_result)

    assert result.success is True
    assert result.pr_url == "https://github.com/AmhetCnaa/test-app/pull/101"
    assert result.pr_number == 101
    assert "armorscan/security-patch-" in result.branch
    assert len(result.files_patched) > 0


@pytest.mark.asyncio
async def test_auto_pr_missing_token_or_invalid_repo():
    scan_result = create_mock_scan_result()

    # Missing token
    engine_no_token = GitHubAutoPrEngine(github_repo="AmhetCnaa/test-app", github_token="")
    res1 = await engine_no_token.create_security_pr(scan_result)
    assert res1.success is False
    assert "token" in res1.error.lower()

    # Invalid repo format
    engine_invalid_repo = GitHubAutoPrEngine(github_repo="invalid-single-name", github_token="ghp_123")
    res2 = await engine_invalid_repo.create_security_pr(scan_result)
    assert res2.success is False
    assert "owner/repo" in res2.error


@pytest.mark.asyncio
async def test_auto_pr_github_api_401_error():
    scan_result = create_mock_scan_result()
    engine = GitHubAutoPrEngine(github_repo="AmhetCnaa/test-app", github_token="invalid_token")

    with respx.mock(base_url="https://api.github.com") as respx_mock:
        respx_mock.get("/repos/AmhetCnaa/test-app").mock(
            return_value=httpx.Response(401, json={"message": "Bad credentials"})
        )
        result = await engine.create_security_pr(scan_result)

    assert result.success is False
    assert "401" in result.error
