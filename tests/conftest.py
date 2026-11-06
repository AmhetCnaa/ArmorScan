"""
Pytest configuration and shared fixtures for ArmorScan.
"""

import pytest
from armorscan.core.client import HttpClient
from armorscan.core.models import ScanTarget


@pytest.fixture
def sample_target() -> ScanTarget:
    return ScanTarget.from_url("https://example.com/api/v1")


@pytest.fixture
def localhost_target() -> ScanTarget:
    return ScanTarget.from_url("http://localhost:8000/app")


@pytest.fixture
async def http_client():
    client = HttpClient(verify_ssl=False)
    await client.start()
    yield client
    await client.close()
