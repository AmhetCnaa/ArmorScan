"""
Local Port & Database Sniffer Module for ArmorScan.
Fast, non-destructive TCP port discovery for developer workstations and localhost environments.
Detects active development servers (3000, 5173, 8000, 8080) and flags unintentionally
exposed unauthenticated databases/caches (Redis, Mongo, Postgres, MySQL, Elasticsearch).
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from armorscan.core.models import Finding, Severity

KNOWN_SERVICES = {
    # Web & Application Servers
    3000: {"name": "Node.js / Express / React", "category": "web", "risk": "dev_server"},
    5173: {"name": "Vite Dev Server", "category": "web", "risk": "dev_server"},
    8000: {"name": "FastAPI / Django / Python", "category": "web", "risk": "dev_server"},
    8080: {"name": "Spring / Tomcat / HTTP Proxy", "category": "web", "risk": "dev_server"},
    4200: {"name": "Angular CLI", "category": "web", "risk": "dev_server"},
    5000: {"name": "Flask / ASP.NET", "category": "web", "risk": "dev_server"},
    8888: {"name": "Jupyter Notebook", "category": "web", "risk": "dev_server"},
    # Databases & Caching Stores
    6379: {"name": "Redis In-Memory Store", "category": "database", "risk": "high"},
    27017: {"name": "MongoDB Database", "category": "database", "risk": "high"},
    5432: {"name": "PostgreSQL Database", "category": "database", "risk": "medium"},
    3306: {"name": "MySQL / MariaDB Database", "category": "database", "risk": "medium"},
    9200: {"name": "Elasticsearch Engine", "category": "database", "risk": "high"},
    11211: {"name": "Memcached Cache", "category": "database", "risk": "medium"},
}


class PortScanResult(BaseModel):
    """Result of scanning a single port."""
    port: int
    service_name: str
    category: str
    is_open: bool
    banner: Optional[str] = None
    finding: Optional[Finding] = None


class DiscoveryResult(BaseModel):
    """Overall discovery report for a target host."""
    host: str
    scanned_ports: int
    open_ports: List[PortScanResult] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)


class LocalPortSniffer:
    """Fast concurrent port sniffer designed for localhost / staging audits."""

    def __init__(self, timeout: float = 0.25, concurrency: int = 15):
        self.timeout = timeout
        self.concurrency = concurrency

    async def scan_host(self, host: str = "127.0.0.1", ports: Optional[List[int]] = None) -> DiscoveryResult:
        """Scan specified or default ports on host."""
        target_ports = ports or sorted(list(KNOWN_SERVICES.keys()))
        semaphore = asyncio.Semaphore(self.concurrency)

        async def _probe(p: int) -> PortScanResult:
            async with semaphore:
                return await self._check_port(host, p)

        tasks = [_probe(p) for p in target_ports]
        results = await asyncio.gather(*tasks)

        open_ports = [r for r in results if r.is_open]
        findings = [r.finding for r in open_ports if r.finding is not None]

        return DiscoveryResult(
            host=host,
            scanned_ports=len(target_ports),
            open_ports=open_ports,
            findings=findings,
        )

    async def _check_port(self, host: str, port: int) -> PortScanResult:
        service_meta = KNOWN_SERVICES.get(port, {"name": f"Unknown Port {port}", "category": "custom", "risk": "low"})
        service_name = service_meta["name"]
        category = service_meta["category"]

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout,
            )
        except (OSError, asyncio.TimeoutError):
            return PortScanResult(
                port=port,
                service_name=service_name,
                category=category,
                is_open=False,
            )

        banner = None
        finding = None

        try:
            # Special probe for Redis (6379)
            if port == 6379:
                writer.write(b"PING\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(64), timeout=0.3)
                resp_text = resp.decode("utf-8", errors="ignore").strip()
                banner = resp_text

                if "+PONG" in resp_text:
                    finding = Finding(
                        id="REDIS_UNAUTHENTICATED_OPEN",
                        title=f"Critical Exposure: Redis Open Without Authentication on {host}:{port}",
                        description="Redis responded with +PONG to PING command without requiring AUTH password.",
                        severity=Severity.CRITICAL,
                        module="ports",
                        impact="Full server takeover risk: Unauthenticated Redis allows arbitrary file writes and RCE.",
                        evidence=f"Sent: PING -> Received: {resp_text}",
                        remediation="Set 'requirepass <strong-password>' in redis.conf and bind strictly to 127.0.0.1.",
                        cwe_id="CWE-306",
                        owasp_category="A01:2021-Broken Access Control",
                    )
                else:
                    finding = Finding(
                        id="REDIS_PORT_OPEN",
                        title=f"Redis Port {port} Accessible on {host}",
                        description=f"Redis database service detected on port {port}.",
                        severity=Severity.MEDIUM,
                        module="ports",
                        impact="Ensure Redis is bound strictly to local loopback and protected by firewall.",
                        evidence=f"Service active on {host}:{port}",
                        remediation="Ensure Redis is not exposed to public network interfaces (0.0.0.0).",
                        cwe_id="CWE-668",
                    )

            # Special probe for Elasticsearch (9200)
            elif port == 9200:
                writer.write(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(256), timeout=0.3)
                resp_text = resp.decode("utf-8", errors="ignore")
                banner = resp_text[:80]

                if "cluster_name" in resp_text:
                    finding = Finding(
                        id="ELASTICSEARCH_UNAUTHENTICATED",
                        title=f"High Risk: Elasticsearch Open Without Auth on {host}:{port}",
                        description="Elasticsearch cluster root responded without authentication.",
                        severity=Severity.HIGH,
                        module="ports",
                        impact="Attackers can index, search, and delete all cluster indices and documents.",
                        evidence=f"Exposed cluster info: {banner}",
                        remediation="Enable X-Pack security with authentication ('xpack.security.enabled: true').",
                        cwe_id="CWE-306",
                    )

            # Other databases (Mongo 27017, Postgres 5432, MySQL 3306)
            elif category == "database":
                finding = Finding(
                    id=f"{service_name.split()[0].upper()}_PORT_OPEN",
                    title=f"Database Port Open: {service_name} on {host}:{port}",
                    description=f"The database port for {service_name} is active on {host}:{port}.",
                    severity=Severity.MEDIUM,
                    module="ports",
                    impact="If exposed beyond localhost or mapped in Docker to 0.0.0.0, attackers can attempt brute-force attacks.",
                    evidence=f"TCP port {port} is open on {host}.",
                    remediation=f"Ensure {service_name} is protected by strong passwords and bound only to 127.0.0.1.",
                    cwe_id="CWE-668",
                )

            # Web servers (3000, 5173, 8000, 8080)
            elif category == "web":
                finding = Finding(
                    id=f"DEV_WEB_SERVER_PORT_{port}",
                    title=f"Active Development Server Detected: {service_name} (Port {port})",
                    description=f"Active web application listening on {host}:{port}.",
                    severity=Severity.INFO,
                    module="ports",
                    impact="Information disclosure: Verifies active web application service.",
                    evidence=f"Port {port} accepts TCP connections.",
                    remediation="Audit endpoints using 'armorscan http://localhost:{port}'.",
                    cwe_id="CWE-200",
                )

        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        return PortScanResult(
            port=port,
            service_name=service_name,
            category=category,
            is_open=True,
            banner=banner,
            finding=finding,
        )
