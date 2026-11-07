"""
Unit and Integration tests for Real-World Target Benchmark Engine (test_real_world_benchmarks.py).
Validates OWASP Juice Shop and DVWA target profiles, SPA false-positive resilience,
and accuracy metrics using realistic simulated server fixtures.
"""

from pathlib import Path
import pytest
import respx

from armorscan.core.client import HttpClient
from armorscan.core.benchmark import (
    RealWorldBenchmarkProfile,
    RealWorldBenchmarkReport,
    RealWorldBenchmarkRunner,
)


def test_real_world_profiles_load_correctly():
    # 1. OWASP Juice Shop Profile
    js_profile = RealWorldBenchmarkProfile.load("benchmark/profiles/juice_shop.yaml")
    assert js_profile.target_id == "juice_shop"
    assert js_profile.name == "OWASP Juice Shop"
    assert "juice-shop" in js_profile.docker_service
    assert len(js_profile.expected_vulnerabilities) >= 4
    assert len(js_profile.forbidden_false_positives) >= 2
    forbidden_ids = [f["id"] for f in js_profile.forbidden_false_positives]
    assert "EXPOSED_ENV_FILE" in forbidden_ids
    assert "EXPOSED_GIT_REPOSITORY" in forbidden_ids

    # 2. DVWA Profile
    dvwa_profile = RealWorldBenchmarkProfile.load("benchmark/profiles/dvwa.yaml")
    assert dvwa_profile.target_id == "dvwa"
    assert "DVWA" in dvwa_profile.name
    assert "dvwa" in dvwa_profile.docker_service
    assert len(dvwa_profile.expected_vulnerabilities) >= 4

    # 3. Nonexistent profile raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        RealWorldBenchmarkProfile.load("benchmark/profiles/nonexistent.yaml")


@pytest.mark.asyncio
async def test_real_world_runner_health_check():
    runner = RealWorldBenchmarkRunner("benchmark/profiles/juice_shop.yaml", base_url="https://mock-health.dev")

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://mock-health.dev", assert_all_called=False) as respx_mock:
            # When online
            respx_mock.get("/").respond(status_code=200, text="OK")
            is_healthy, err = await runner.check_health(client)
            assert is_healthy is True
            assert err is None

        with respx.mock(base_url="https://mock-error.dev", assert_all_called=False) as respx_mock:
            # When server returns error status (502)
            respx_mock.get("/").respond(status_code=502)
            runner_502 = RealWorldBenchmarkRunner("benchmark/profiles/juice_shop.yaml", base_url="https://mock-error.dev")
            is_healthy_502, err_502 = await runner_502.check_health(client)
            assert is_healthy_502 is False
            assert "unexpected HTTP 502" in err_502

    # When offline / connection refused
    runner_offline = RealWorldBenchmarkRunner("benchmark/profiles/juice_shop.yaml", base_url="http://127.0.0.1:59999")
    async with HttpClient(proxy=None) as client:
        is_healthy_conn, err_conn = await runner_offline.check_health(client)
        assert is_healthy_conn is False
        assert "Cannot connect to target" in err_conn


@pytest.mark.asyncio
async def test_juice_shop_spa_benchmark_simulation():
    """
    Simulates OWASP Juice Shop's authentic response architecture:
    - Angular SPA root & catch-all index.html for nonexistent routes
    - Express server headers (X-Powered-By: Express)
    - CORS arbitrary origin reflection
    - Exposed Swagger / OpenAPI specification
    - Cookie without SameSite
    - Verifies that SPA 200 catch-all does NOT produce false positive .env or .git findings!
    """
    base_url = "https://mock-juiceshop.dev"
    runner = RealWorldBenchmarkRunner("benchmark/profiles/juice_shop.yaml", base_url=base_url)

    angular_index_html = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
</head>
<body>
  <app-root></app-root>
  <script src="main.js"></script>
</body>
</html>"""

    swagger_json = """{
  "swagger": "2.0",
  "info": {"title": "Juice Shop API", "version": "16.0.0"},
  "paths": {
    "/rest/user/login": {
      "post": {
        "summary": "User Login",
        "parameters": [{"name": "email", "in": "body", "required": true}]
      }
    }
  }
}"""

    common_headers = {
        "Content-Type": "text/html; charset=utf-8",
        "X-Powered-By": "Express",
        "Set-Cookie": "token=jwt_sample_12345; Path=/; HttpOnly",
    }

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url=base_url, assert_all_called=False) as respx_mock:
            # 1. Health check & root page
            respx_mock.get("/").respond(status_code=200, text=angular_index_html, headers=common_headers)

            # 2. SPA Catch-all: Any nonexistent path (canary, .env, .git/HEAD) returns the Angular HTML!
            respx_mock.get(url__regex=r".*/armorscan-canary-404-.*").respond(status_code=200, text=angular_index_html, headers=common_headers)
            respx_mock.get("/.env").respond(status_code=200, text=angular_index_html, headers=common_headers)
            respx_mock.get("/.git/HEAD").respond(status_code=200, text=angular_index_html, headers=common_headers)
            respx_mock.get("/.git/config").respond(status_code=200, text=angular_index_html, headers=common_headers)
            respx_mock.get("/.DS_Store").respond(status_code=200, text=angular_index_html, headers=common_headers)
            respx_mock.get("/wp-config.php.bak").respond(status_code=200, text=angular_index_html, headers=common_headers)
            respx_mock.get("/config.json").respond(status_code=200, text=angular_index_html, headers=common_headers)
            respx_mock.get("/robots.txt").respond(status_code=200, text=angular_index_html, headers=common_headers)

            # 3. Swagger / OpenAPI spec is exposed
            respx_mock.get("/swagger.json").respond(status_code=200, text=swagger_json, headers={"Content-Type": "application/json"})
            respx_mock.get("/openapi.json").respond(status_code=404)

            # 4. CORS preflight / reflection
            respx_mock.options("/").respond(
                status_code=200,
                headers={
                    "Access-Control-Allow-Origin": "https://evil-attacker.com",
                    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
                }
            )

            # Execute real-world benchmark runner
            report: RealWorldBenchmarkReport = await runner.run_benchmark(
                enable_crawler=False,
                client=client,
            )

            # --- Verification of Benchmark Metrics ---
            # False Positive check: Must NOT trigger EXPOSED_ENV_FILE or EXPOSED_GIT_REPOSITORY
            assert "EXPOSED_ENV_FILE" not in report.fp_findings, "False positive .env triggered on SPA HTML catch-all!"
            assert "EXPOSED_GIT_REPOSITORY" not in report.fp_findings, "False positive .git triggered on SPA HTML catch-all!"
            assert len(report.fp_findings) == 0

            # True Positives: Missing CSP, Express banner disclosure, Swagger exposed, Cookie missing SameSite
            assert "MISSING_CSP" in report.tp_findings
            assert "X_POWERED_BY_DISCLOSURE" in report.tp_findings
            assert "EXPOSED_OPENAPI_SPEC" in report.tp_findings
            assert "COOKIE_MISSING_SAMESITE" in report.tp_findings

            assert report.precision == 1.0, f"Expected 100% precision, got {report.precision:.2%}"
            assert report.recall >= 0.60, f"Expected good recall, got {report.recall:.2%}"

            # Markdown report generation verification
            md = report.to_markdown_report()
            assert "# 🛡️ ArmorScan Real-World Benchmark: OWASP Juice Shop" in md
            assert "EXPOSED_OPENAPI_SPEC" in md
            assert "CLEAN (Zero FP)" in md


@pytest.mark.asyncio
async def test_dvwa_benchmark_simulation():
    """
    Simulates DVWA's response architecture:
    - Apache 2.4 Server header banner
    - Reflected input without HTML encoding
    - Open redirect on redirection parameter
    - Missing CSP & HSTS
    - PHPSESSID missing SameSite
    """
    base_url = "https://mock-dvwa.dev"
    runner = RealWorldBenchmarkRunner("benchmark/profiles/dvwa.yaml", base_url=base_url)

    dvwa_login_html = """<!DOCTYPE html>
<html>
<head><title>Login :: Damn Vulnerable Web Application</title></head>
<body>
  <form action="login.php" method="post">
    <input type="text" name="username">
    <input type="password" name="password">
    <input type="submit" name="Login" value="Login">
  </form>
</body>
</html>"""

    apache_headers = {
        "Server": "Apache/2.4.25 (Debian)",
        "Set-Cookie": "PHPSESSID=d41d8cd98f00b204e9800998ecf8427e; path=/",
        "Content-Type": "text/html; charset=UTF-8",
    }

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url=base_url, assert_all_called=False) as respx_mock:
            # Health check & login
            respx_mock.get("/login.php").respond(status_code=200, text=dvwa_login_html, headers=apache_headers)
            respx_mock.get("/").respond(status_code=200, text=dvwa_login_html, headers=apache_headers)

            # Dotfiles return Apache 404
            respx_mock.get(url__regex=r".*/\.env.*").respond(status_code=404)
            respx_mock.get(url__regex=r".*/\.git/.*").respond(status_code=404)
            respx_mock.get(url__regex=r".*canary.*").respond(status_code=404)

            # Execute benchmark
            report: RealWorldBenchmarkReport = await runner.run_benchmark(
                enable_crawler=False,
                client=client,
            )

            # True Positives: Server banner leak, missing CSP, missing HSTS, cookie missing SameSite
            assert "SERVER_VERSION_DISCLOSURE" in report.tp_findings
            assert "MISSING_CSP" in report.tp_findings
            assert "MISSING_HSTS" in report.tp_findings
            assert "COOKIE_MISSING_SAMESITE" in report.tp_findings

            # Zero false positives
            assert len(report.fp_findings) == 0
            assert report.precision == 1.0
