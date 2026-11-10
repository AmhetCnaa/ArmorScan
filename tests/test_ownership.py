"""
Unit tests for Zero-Trust Domain Ownership Gate & PBKDF2-HMAC-SHA512 Master Key Verifier.
"""

import pytest
import respx

from armorscan.core.client import HttpClient
from armorscan.core.models import ScanTarget
from armorscan.core.ownership import OwnershipGate


def test_domain_challenge_generation_is_unique_per_domain():
    """Verify every domain receives a unique cryptographic verification token."""
    t1 = OwnershipGate.generate_domain_challenge("example.com", date_str="2026-11-10")
    t2 = OwnershipGate.generate_domain_challenge("bank.com", date_str="2026-11-10")
    t3 = OwnershipGate.generate_domain_challenge("example.com", date_str="2026-11-11")

    assert t1.startswith("armorscan-site-verification=")
    assert t2.startswith("armorscan-site-verification=")
    assert t1 != t2
    assert t1 != t3


def test_master_key_verification_rejects_invalid_keys():
    """Verify PBKDF2-HMAC-SHA512 verifier rejects empty and invalid keys."""
    assert OwnershipGate.verify_master_key("") is False
    assert OwnershipGate.verify_master_key("wrong-password-123") is False
    assert OwnershipGate.verify_master_key("AS-ROOT-invalid-token") is False


@pytest.mark.asyncio
async def test_localhost_is_always_authorized():
    """Verify localhost and 127.0.0.1 targets pass without external challenge."""
    target = ScanTarget.from_url("http://127.0.0.1:3000")
    async with HttpClient.for_target(target) as client:
        res = await OwnershipGate.verify_target_access(target, client)
        assert res.authorized is True
        assert res.mode == "localhost"


@pytest.mark.asyncio
async def test_external_domain_denied_without_proof():
    """Verify scanning an external website without ownership proof is blocked."""
    target = ScanTarget.from_url("https://unverified-external-site.com")
    with respx.mock(assert_all_called=False) as mock_http:
        mock_http.get("https://unverified-external-site.com/.well-known/armorscan-verify.txt").mock(
            return_value=respx.MockResponse(404, text="Not Found")
        )
        mock_http.get("https://unverified-external-site.com").mock(
            return_value=respx.MockResponse(200, text="<html><head><title>Hello</title></head></html>")
        )
        async with HttpClient.for_target(target) as client:
            res = await OwnershipGate.verify_target_access(target, client)
            assert res.authorized is False
            assert res.mode == "denied"


@pytest.mark.asyncio
async def test_external_domain_authorized_via_well_known_file():
    """Verify external domain is authorized when .well-known/armorscan-verify.txt contains the daily token."""
    target = ScanTarget.from_url("https://my-verified-app.com")
    expected_token = OwnershipGate.generate_domain_challenge("my-verified-app.com")

    with respx.mock(assert_all_called=False) as mock_http:
        mock_http.get("https://my-verified-app.com/.well-known/armorscan-verify.txt").mock(
            return_value=respx.MockResponse(200, text=f"{expected_token}\n")
        )
        async with HttpClient.for_target(target) as client:
            res = await OwnershipGate.verify_target_access(target, client)
            assert res.authorized is True
            assert res.mode == "well_known"


@pytest.mark.asyncio
async def test_external_domain_authorized_via_html_meta_tag():
    """Verify external domain is authorized when homepage contains <meta name='armorscan-verification'>."""
    target = ScanTarget.from_url("https://meta-verified-app.com")
    expected_token = OwnershipGate.generate_domain_challenge("meta-verified-app.com")

    with respx.mock(assert_all_called=False) as mock_http:
        mock_http.get("https://meta-verified-app.com/.well-known/armorscan-verify.txt").mock(
            return_value=respx.MockResponse(404)
        )
        mock_http.get("https://meta-verified-app.com").mock(
            return_value=respx.MockResponse(
                200,
                text=f'<html><head><meta name="armorscan-verification" content="{expected_token}"></head></html>',
            )
        )
        async with HttpClient.for_target(target) as client:
            res = await OwnershipGate.verify_target_access(target, client)
            assert res.authorized is True
            assert res.mode == "meta_tag"
