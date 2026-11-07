"""
Turbo Fast-Probe and Adaptive Socket Timeout Engine for ArmorScan.
Provides micro-timeout protection, pre-flight TCP SYN probing, and non-blocking
TLS inspection to eliminate multi-minute socket hangs and guarantee sub-5-second execution.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import socket
import ssl
from typing import Any, Dict, Optional, Tuple


class FastProbe:
    """High-performance pre-flight TCP and TLS prober with micro-timeouts."""

    DEFAULT_TCP_TIMEOUT = 0.8  # 800ms TCP connection check
    DEFAULT_TLS_TIMEOUT = 1.5  # 1500ms maximum TLS handshake timeout

    @staticmethod
    async def is_port_open(host: str, port: int = 443, timeout: float = DEFAULT_TCP_TIMEOUT) -> bool:
        """
        Non-blocking pre-flight TCP check.
        Returns True if a TCP socket can connect within the timeout, False otherwise.
        Guarantees fast bailout (< 800ms) when port 443 is closed or dropping packets.
        """
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except (asyncio.TimeoutError, OSError, ConnectionRefusedError, socket.gaierror):
            return False

    @classmethod
    async def probe_tls(
        cls,
        host: str,
        port: int = 443,
        tcp_timeout: float = DEFAULT_TCP_TIMEOUT,
        tls_timeout: float = DEFAULT_TLS_TIMEOUT,
    ) -> Optional[Dict[str, Any]]:
        """
        Inspect peer TLS certificate with fast-bailout protection.
        First validates TCP port availability in <= 800ms.
        If port is open, executes SSL handshake with <= 1500ms timeout.
        Returns certificate metadata dict or None if port is closed/unresponsive.
        """
        # Step 1: Pre-flight TCP check to avoid long blocking connect timeouts
        is_open = await cls.is_port_open(host, port, timeout=tcp_timeout)
        if not is_open:
            return None

        # Step 2: Non-blocking TLS handshake wrapped with asyncio.wait_for
        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, cls._sync_fetch_cert, host, port, tls_timeout),
                timeout=tls_timeout + 0.3,
            )
        except (asyncio.TimeoutError, Exception):
            return None

    @staticmethod
    def _sync_fetch_cert(host: str, port: int, timeout: float) -> Optional[Dict[str, Any]]:
        """Synchronous SSL socket wrapper with strict timeout."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    if cert is None:
                        return None
                    cert_dict = dict(cert)
                    cert_dict["tls_version"] = ssock.version()
                    return cert_dict
        except Exception:
            return None
