"""
Unit tests for Sensitive File & Information Disclosure Audit Module (exposure.py).
"""

import pytest
import respx

from armorscan.core.client import HttpClient
from armorscan.core.models import ScanTarget, Severity
from armorscan.modules.exposure import ExposureAuditModule


@pytest.mark.asyncio
async def test_exposure_env_file_detected():
    module = ExposureAuditModule()
    target = ScanTarget.from_url("https://leaky-repo.dev")

    raw_env = (
        "APP_ENV=production\n"
        "PORT=8000\n"
        "DB_HOST=10.0.0.5\n"
        "DB_PASSWORD=ultra_secret_db_pass_123!\n"
        "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"
    )

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://leaky-repo.dev") as respx_mock:
            # Canary 404
            respx_mock.get(url__regex=r"/armorscan-canary-404-.*").respond(status_code=404)
            # .env file exposed
            respx_mock.get("/.env").respond(status_code=200, text=raw_env, headers={"Content-Type": "text/plain"})
            # Other probes return 404
            respx_mock.get("/.git/HEAD").respond(status_code=404)
            respx_mock.get("/.git/config").respond(status_code=404)
            respx_mock.get("/.DS_Store").respond(status_code=404)
            respx_mock.get("/wp-config.php.bak").respond(status_code=404)
            respx_mock.get("/config.json").respond(status_code=404)
            respx_mock.get("/swagger.json").respond(status_code=404)
            respx_mock.get("/openapi.json").respond(status_code=404)
            respx_mock.get("/robots.txt").respond(status_code=404)

            result = await module.execute(target, client)
            finding_ids = [f.id for f in result.findings]

            assert "EXPOSED_ENV_FILE" in finding_ids
            finding = next(f for f in result.findings if f.id == "EXPOSED_ENV_FILE")
            assert finding.severity == Severity.CRITICAL
            assert "[REDACTED]" in finding.evidence
            assert "nginx" in finding.remediation_snippets
            assert "apache" in finding.remediation_snippets


@pytest.mark.asyncio
async def test_exposure_git_head_detected():
    module = ExposureAuditModule()
    target = ScanTarget.from_url("https://exposed-git.dev")

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://exposed-git.dev") as respx_mock:
            respx_mock.get(url__regex=r"/armorscan-canary-404-.*").respond(status_code=404)
            respx_mock.get("/.env").respond(status_code=404)
            respx_mock.get("/.git/HEAD").respond(status_code=200, text="ref: refs/heads/main\n")
            respx_mock.get("/.git/config").respond(status_code=404)
            respx_mock.get("/.DS_Store").respond(status_code=404)
            respx_mock.get("/wp-config.php.bak").respond(status_code=404)
            respx_mock.get("/config.json").respond(status_code=404)
            respx_mock.get("/swagger.json").respond(status_code=404)
            respx_mock.get("/openapi.json").respond(status_code=404)
            respx_mock.get("/robots.txt").respond(status_code=404)

            result = await module.execute(target, client)
            finding_ids = [f.id for f in result.findings]

            assert "EXPOSED_GIT_REPOSITORY" in finding_ids
            finding = next(f for f in result.findings if f.id == "EXPOSED_GIT_REPOSITORY")
            assert finding.severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_exposure_spa_false_positive_elimination():
    """Verify that an SPA returning 200 HTML for everything triggers 0 false positives."""
    module = ExposureAuditModule()
    target = ScanTarget.from_url("https://react-spa.dev")

    spa_html = "<!DOCTYPE html><html><head><title>App</title></head><body><div id='root'></div></body></html>"

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://react-spa.dev") as respx_mock:
            # All URLs respond with 200 and HTML
            respx_mock.get(url__regex=r".*").respond(
                status_code=200,
                text=spa_html,
                headers={"Content-Type": "text/html; charset=utf-8"},
            )

            result = await module.execute(target, client)
            assert len(result.findings) == 0


@pytest.mark.asyncio
async def test_exposure_ds_store_binary_detected():
    module = ExposureAuditModule()
    target = ScanTarget.from_url("https://mac-user-site.dev")

    ds_store_bytes = b"\x00\x00\x00\x01Bud1\x00\x00\x10\x00\x00\x00\x08\x00"

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://mac-user-site.dev") as respx_mock:
            respx_mock.get(url__regex=r"/armorscan-canary-404-.*").respond(status_code=404)
            respx_mock.get("/.env").respond(status_code=404)
            respx_mock.get("/.git/HEAD").respond(status_code=404)
            respx_mock.get("/.git/config").respond(status_code=404)
            respx_mock.get("/.DS_Store").respond(status_code=200, content=ds_store_bytes)
            respx_mock.get("/wp-config.php.bak").respond(status_code=404)
            respx_mock.get("/config.json").respond(status_code=404)
            respx_mock.get("/swagger.json").respond(status_code=404)
            respx_mock.get("/openapi.json").respond(status_code=404)
            respx_mock.get("/robots.txt").respond(status_code=404)

            result = await module.execute(target, client)
            finding_ids = [f.id for f in result.findings]

            assert "EXPOSED_DS_STORE" in finding_ids
            finding = next(f for f in result.findings if f.id == "EXPOSED_DS_STORE")
            assert finding.severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_exposure_backup_wp_config():
    module = ExposureAuditModule()
    target = ScanTarget.from_url("https://old-wordpress.dev")

    raw_backup = "<?php\ndefine('DB_NAME', 'prod_wp');\ndefine('DB_PASSWORD', 'root12345');\n"

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://old-wordpress.dev") as respx_mock:
            respx_mock.get(url__regex=r"/armorscan-canary-404-.*").respond(status_code=404)
            respx_mock.get("/.env").respond(status_code=404)
            respx_mock.get("/.git/HEAD").respond(status_code=404)
            respx_mock.get("/.git/config").respond(status_code=404)
            respx_mock.get("/.DS_Store").respond(status_code=404)
            respx_mock.get("/wp-config.php.bak").respond(status_code=200, text=raw_backup)
            respx_mock.get("/config.json").respond(status_code=404)
            respx_mock.get("/swagger.json").respond(status_code=404)
            respx_mock.get("/openapi.json").respond(status_code=404)
            respx_mock.get("/robots.txt").respond(status_code=404)

            result = await module.execute(target, client)
            finding_ids = [f.id for f in result.findings]

            assert "EXPOSED_BACKUP_CONFIG" in finding_ids
            finding = next(f for f in result.findings if f.id == "EXPOSED_BACKUP_CONFIG")
            assert finding.severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_exposure_openapi_specs():
    module = ExposureAuditModule()
    target = ScanTarget.from_url("https://api-service.dev")

    spec_json = '{"openapi": "3.0.0", "info": {"title": "API"}, "paths": {"/users": {}, "/admin/reset": {}}}'

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://api-service.dev") as respx_mock:
            respx_mock.get(url__regex=r"/armorscan-canary-404-.*").respond(status_code=404)
            respx_mock.get("/.env").respond(status_code=404)
            respx_mock.get("/.git/HEAD").respond(status_code=404)
            respx_mock.get("/.git/config").respond(status_code=404)
            respx_mock.get("/.DS_Store").respond(status_code=404)
            respx_mock.get("/wp-config.php.bak").respond(status_code=404)
            respx_mock.get("/config.json").respond(status_code=404)
            respx_mock.get("/swagger.json").respond(status_code=404)
            respx_mock.get("/openapi.json").respond(status_code=200, text=spec_json)
            respx_mock.get("/robots.txt").respond(status_code=404)

            result = await module.execute(target, client)
            finding_ids = [f.id for f in result.findings]

            assert "EXPOSED_OPENAPI_SPEC" in finding_ids
            finding = next(f for f in result.findings if f.id == "EXPOSED_OPENAPI_SPEC")
            assert finding.severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_exposure_robots_txt_sensitive_paths():
    module = ExposureAuditModule()
    target = ScanTarget.from_url("https://e-commerce.dev")

    robots_content = (
        "User-agent: *\n"
        "Disallow: /admin-panel-secret/\n"
        "Disallow: /database-backups/\n"
        "Disallow: /search?\n"
    )

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://e-commerce.dev") as respx_mock:
            respx_mock.get(url__regex=r"/armorscan-canary-404-.*").respond(status_code=404)
            respx_mock.get("/.env").respond(status_code=404)
            respx_mock.get("/.git/HEAD").respond(status_code=404)
            respx_mock.get("/.git/config").respond(status_code=404)
            respx_mock.get("/.DS_Store").respond(status_code=404)
            respx_mock.get("/wp-config.php.bak").respond(status_code=404)
            respx_mock.get("/config.json").respond(status_code=404)
            respx_mock.get("/swagger.json").respond(status_code=404)
            respx_mock.get("/openapi.json").respond(status_code=404)
            respx_mock.get("/robots.txt").respond(status_code=200, text=robots_content)

            result = await module.execute(target, client)
            finding_ids = [f.id for f in result.findings]

            assert "ROBOTS_TXT_SENSITIVE_PATHS" in finding_ids
            finding = next(f for f in result.findings if f.id == "ROBOTS_TXT_SENSITIVE_PATHS")
            assert finding.severity == Severity.LOW
            assert "/admin-panel-secret/" in finding.evidence
            assert "/database-backups/" in finding.evidence
