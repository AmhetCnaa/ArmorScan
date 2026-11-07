"""Unit tests for Nuclei-Style YAML Template Engine (tests/test_templates.py)."""

import pytest
import respx
import httpx

from armorscan.core.client import HttpClient
from armorscan.core.models import ScanTarget, Severity
from armorscan.core.templates import TemplateEngine


def test_builtin_templates_load():
    engine = TemplateEngine()
    template_ids = [t.id for t in engine.templates]
    assert len(engine.templates) >= 25
    assert "exposed-prometheus-metrics" in template_ids
    assert "actuator-health" in template_ids
    assert "cve-admin-exposed" in template_ids
    assert "docker-api-exposed" in template_ids
    assert "cve-2021-41773" in template_ids
    assert "s3-bucket-public-listing" in template_ids
    assert "env-file-exposed" in template_ids


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_template_engine_prometheus_detected(respx_mock):
    target = ScanTarget.from_url("http://127.0.0.1:3000")
    client = HttpClient(verify_ssl=False, proxy=None)
    await client.start()

    respx_mock.get("http://127.0.0.1:3000/armorscan-template-canary-404").mock(
        return_value=httpx.Response(404, text="Not Found")
    )
    respx_mock.get("http://127.0.0.1:3000/metrics").mock(
        return_value=httpx.Response(
            200,
            text="# HELP juiceshop_orders_total Total orders\n# TYPE juiceshop_orders_total counter\njuiceshop_orders_total 42\n",
            headers={"Content-Type": "text/plain"},
        )
    )
    respx_mock.get(url__regex=r".*").mock(return_value=httpx.Response(404))

    engine = TemplateEngine()
    result = await engine.run(target, client)
    await client.close()

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.id == "EXPOSED_PROMETHEUS_METRICS"
    assert f.severity == Severity.MEDIUM
    assert f.cwe_id == "CWE-200"


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_template_engine_spa_catchall_resilience(respx_mock):
    target = ScanTarget.from_url("https://spa-app.example.com")
    client = HttpClient(verify_ssl=False, proxy=None)
    await client.start()

    spa_html = "<!doctype html><html><body><app-root></app-root></body></html>"
    respx_mock.get(url__regex=r".*").mock(
        return_value=httpx.Response(200, text=spa_html, headers={"Content-Type": "text/html"})
    )

    engine = TemplateEngine()
    result = await engine.run(target, client)
    await client.close()

    assert len(result.findings) == 0


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_custom_yaml_template_execution(respx_mock, tmp_path):
    custom_yaml = tmp_path / "custom-check.yaml"
    custom_yaml.write_text(
        """
id: custom-debug-header
info:
  name: Custom Debug Header Leak
  severity: HIGH
  cwe: CWE-200
  description: Custom header leak detected
requests:
  - method: GET
    path:
      - "{{BaseURL}}/debug"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: regex
        part: body
        regex:
          - "DEBUG_KEY=[A-Z0-9]+"
""",
        encoding="utf-8",
    )

    target = ScanTarget.from_url("https://custom.example.com")
    client = HttpClient(verify_ssl=False, proxy=None)
    await client.start()

    respx_mock.get("https://custom.example.com/armorscan-template-canary-404").mock(
        return_value=httpx.Response(404)
    )
    respx_mock.get("https://custom.example.com/debug").mock(
        return_value=httpx.Response(200, text="Config: DEBUG_KEY=SECRET999")
    )

    engine = TemplateEngine(template_paths=[custom_yaml])
    result = await engine.run(target, client)
    await client.close()

    assert len(result.findings) == 1
    assert result.findings[0].id == "CUSTOM_DEBUG_HEADER"
    assert result.findings[0].severity == Severity.HIGH
