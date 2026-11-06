"""
Unit tests for Local Port & Database Sniffer (ports.py).
"""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from armorscan.core.models import Severity
from armorscan.modules.ports import LocalPortSniffer


@pytest.mark.asyncio
async def test_port_sniffer_closed_ports():
    sniffer = LocalPortSniffer(timeout=0.05)
    result = await sniffer._check_port("127.0.0.1", 59999)
    assert result.is_open is False
    assert result.finding is None


@pytest.mark.asyncio
async def test_port_sniffer_redis_unauthenticated():
    sniffer = LocalPortSniffer(timeout=0.1)

    mock_reader = AsyncMock()
    mock_reader.read.return_value = b"+PONG\r\n"
    mock_writer = MagicMock()
    mock_writer.drain = AsyncMock()
    mock_writer.wait_closed = AsyncMock()

    with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
        result = await sniffer._check_port("127.0.0.1", 6379)

    assert result.is_open is True
    assert result.finding is not None
    assert result.finding.id == "REDIS_UNAUTHENTICATED_OPEN"
    assert result.finding.severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_port_sniffer_dev_web_server():
    sniffer = LocalPortSniffer(timeout=0.1)

    mock_reader = AsyncMock()
    mock_writer = MagicMock()
    mock_writer.drain = AsyncMock()
    mock_writer.wait_closed = AsyncMock()

    with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
        result = await sniffer._check_port("127.0.0.1", 3000)

    assert result.is_open is True
    assert result.finding is not None
    assert result.finding.id == "DEV_WEB_SERVER_PORT_3000"
    assert result.finding.severity == Severity.INFO


@pytest.mark.asyncio
async def test_port_sniffer_scan_host():
    sniffer = LocalPortSniffer(timeout=0.1)

    mock_reader = AsyncMock()
    mock_reader.read.return_value = b""
    mock_writer = MagicMock()
    mock_writer.drain = AsyncMock()
    mock_writer.wait_closed = AsyncMock()

    with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
        res = await sniffer.scan_host("127.0.0.1", ports=[3000, 8000])

    assert res.scanned_ports == 2
    assert len(res.open_ports) == 2
