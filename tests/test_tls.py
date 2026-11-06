"""
Unit tests for TLS/SSL and HTTPS Configuration Audit Module (tls_ssl.py).
"""

from unittest.mock import patch
import pytest
import respx

from armorscan.core.client import HttpClient
from armorscan.core.models import ScanTarget, Severity
from armorscan.modules.tls_ssl import TlsSslModule


@pytest.mark.asyncio
async def test_tls_no_https_redirect():
    module = TlsSslModule()
    target = ScanTarget.from_url("http://example-plain.com")

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="http://example-plain.com") as respx_mock:
            # Responds with 200 without redirect
            respx_mock.get("/").respond(status_code=200, text="Plain HTTP Content")

            with patch.object(module, "_fetch_peer_cert", side_effect=Exception("Connection refused")):
                result = await module.execute(target, client)

            finding_ids = [f.id for f in result.findings]
            assert "NO_HTTPS_REDIRECT" in finding_ids

            finding = next(f for f in result.findings if f.id == "NO_HTTPS_REDIRECT")
            assert finding.severity == Severity.HIGH
            assert "nginx" in finding.remediation_snippets
            assert "express" in finding.remediation_snippets
            assert "fastapi" in finding.remediation_snippets


@pytest.mark.asyncio
async def test_tls_proper_https_redirect():
    module = TlsSslModule()
    target = ScanTarget.from_url("http://redirecting-site.com")

    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="http://redirecting-site.com") as respx_mock:
            respx_mock.get("/").respond(
                status_code=301,
                headers={"Location": "https://redirecting-site.com/"},
            )

            with patch.object(module, "_fetch_peer_cert", side_effect=Exception("No port 443")):
                result = await module.execute(target, client)

            assert "https-redirection-enforced" in result.passed_checks
            assert not any(f.id == "NO_HTTPS_REDIRECT" for f in result.findings)


@pytest.mark.asyncio
async def test_tls_localhost_skipped():
    module = TlsSslModule()
    target = ScanTarget.from_url("http://localhost:3000")

    async with HttpClient(proxy=None) as client:
        result = await module.execute(target, client)
        assert "localhost-http-redirect-skipped" in result.passed_checks
        assert "localhost-tls-cert-skipped" in result.passed_checks
        assert len(result.findings) == 0


@pytest.mark.asyncio
async def test_tls_cert_expired():
    module = TlsSslModule()
    target = ScanTarget.from_url("https://expired-cert.com")

    mock_cert = {
        "notAfter": "Jan 01 00:00:00 2020 GMT",
        "tls_version": "TLSv1.3",
    }

    async with HttpClient(proxy=None) as client:
        with patch.object(module, "_fetch_peer_cert", return_value=mock_cert):
            result = await module.execute(target, client)

        finding_ids = [f.id for f in result.findings]
        assert "SSL_CERT_EXPIRED" in finding_ids
        expired_finding = next(f for f in result.findings if f.id == "SSL_CERT_EXPIRED")
        assert expired_finding.severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_tls_obsolete_version():
    module = TlsSslModule()
    target = ScanTarget.from_url("https://legacy-tls.com")

    mock_cert = {
        "notAfter": "Dec 31 23:59:59 2030 GMT",
        "tls_version": "TLSv1",
    }

    async with HttpClient(proxy=None) as client:
        with patch.object(module, "_fetch_peer_cert", return_value=mock_cert):
            result = await module.execute(target, client)

        finding_ids = [f.id for f in result.findings]
        assert "OBSOLETE_TLS_VERSION" in finding_ids
        finding = next(f for f in result.findings if f.id == "OBSOLETE_TLS_VERSION")
        assert finding.severity == Severity.HIGH
