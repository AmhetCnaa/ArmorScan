"""
Lightweight HTTP Forward Proxy & Live Traffic Auditor for ArmorScan.
Enables passive background auditing of web and API traffic routed from
browsers, QA automation suites, and mobile applications.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import re
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from rich.console import Console

# Sensitive leak regexes for passive traffic inspection
KEY_PATTERNS = [
    ("OPENAI_KEY_LEAK", re.compile(r"sk-[a-zA-Z0-9_-]{20,}")),
    ("AWS_KEY_LEAK", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("JWT_IN_PARAM", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("ERROR_STACK_LEAK", re.compile(r"(Traceback \(most recent call last\)|SQLSTATE\[|SyntaxError: )", re.IGNORECASE)),
]


class ProxyFlow:
    """Represents a single intercepted HTTP request and response cycle."""

    def __init__(
        self,
        method: str,
        url: str,
        path: str,
        host: str,
        request_headers: Dict[str, str],
        request_body: bytes = b"",
    ):
        self.timestamp = datetime.now(timezone.utc)
        self.method = method
        self.url = url
        self.path = path
        self.host = host
        self.request_headers = request_headers
        self.request_body = request_body
        self.status_code: int = 0
        self.response_headers: Dict[str, str] = {}
        self.response_body: bytes = b""
        self.findings: List[str] = []

    @property
    def response_text(self) -> str:
        try:
            return self.response_body.decode("utf-8", errors="replace")
        except Exception:
            return ""


class HttpProxy:
    """
    Lightweight Asyncio HTTP Forward Proxy & Passive Auditor.
    Captures HTTP and HTTPS CONNECT traffic and audits routes live.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        auto_audit: bool = True,
        console: Optional[Console] = None,
        on_flow: Optional[Callable[[ProxyFlow], None]] = None,
    ):
        self.host = host
        self.port = port
        self.auto_audit = auto_audit
        self.console = console or Console()
        self.on_flow = on_flow
        self.captured_flows: List[ProxyFlow] = []
        self.audited_paths: Set[str] = set()
        self._server: Optional[asyncio.Server] = None
        self._running = False

    async def start(self) -> asyncio.Server:
        """Start the async proxy server listener."""
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        self._running = True
        return self._server

    async def stop(self) -> None:
        """Gracefully terminate the proxy server."""
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        """Dispatch incoming client connection."""
        try:
            line = await client_reader.readline()
            if not line:
                client_writer.close()
                await client_writer.wait_closed()
                return

            request_line = line.decode("utf-8", errors="replace").strip()
            parts = request_line.split(" ")
            if len(parts) < 2:
                client_writer.close()
                await client_writer.wait_closed()
                return

            method, raw_url = parts[0].upper(), parts[1]

            if method == "CONNECT":
                await self._handle_connect(raw_url, client_reader, client_writer)
            else:
                await self._handle_http(method, raw_url, parts[2] if len(parts) > 2 else "HTTP/1.1", client_reader, client_writer)
        except Exception:
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass

    async def _handle_connect(self, host_port: str, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        """Tunnel HTTPS connections via CONNECT method."""
        if ":" in host_port:
            target_host, target_port_s = host_port.split(":", 1)
            target_port = int(target_port_s)
        else:
            target_host = host_port
            target_port = 443

        flow = ProxyFlow(
            method="CONNECT",
            url=f"https://{host_port}",
            path="/",
            host=target_host,
            request_headers={},
        )
        flow.status_code = 200
        self.captured_flows.append(flow)
        if self.console and self.auto_audit:
            self.console.print(f"[dim][CONNECT][/dim] {target_host}:{target_port} -> [cyan]Tunnelling TLS[/cyan]")

        try:
            target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_writer.drain()

            async def pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter):
                try:
                    while self._running:
                        data = await r.read(8192)
                        if not data:
                            break
                        w.write(data)
                        await w.drain()
                except Exception:
                    pass
                finally:
                    try:
                        w.close()
                    except Exception:
                        pass

            await asyncio.gather(pipe(client_reader, target_writer), pipe(target_reader, client_writer))
        except Exception:
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await client_writer.drain()
            client_writer.close()
            await client_writer.wait_closed()

    async def _handle_http(
        self,
        method: str,
        raw_url: str,
        http_version: str,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """Handle standard HTTP forwarding and passive audit."""
        headers: Dict[str, str] = {}
        raw_headers_list: List[str] = []

        while True:
            line_bytes = await client_reader.readline()
            if not line_bytes or line_bytes == b"\r\n":
                break
            line_str = line_bytes.decode("utf-8", errors="replace").rstrip("\r\n")
            raw_headers_list.append(line_str)
            if ":" in line_str:
                k, v = line_str.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        # Parse target host and port
        host_header = headers.get("host", "")
        if raw_url.startswith("http://") or raw_url.startswith("https://"):
            parsed = urlparse(raw_url)
            target_host = parsed.hostname or host_header
            target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            request_path = parsed.path or "/"
            if parsed.query:
                request_path += f"?{parsed.query}"
        else:
            request_path = raw_url
            if ":" in host_header:
                target_host, port_s = host_header.split(":", 1)
                target_port = int(port_s)
            else:
                target_host = host_header
                target_port = 80

        if not target_host:
            client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\nMissing Host header")
            await client_writer.drain()
            client_writer.close()
            await client_writer.wait_closed()
            return

        # Read request body if Content-Length specified
        content_length = int(headers.get("content-length", 0))
        request_body = b""
        if content_length > 0:
            request_body = await client_reader.readexactly(content_length)

        flow = ProxyFlow(
            method=method,
            url=f"http://{target_host}:{target_port}{request_path}",
            path=request_path,
            host=target_host,
            request_headers=headers,
            request_body=request_body,
        )

        # Forward request to upstream server
        try:
            up_reader, up_writer = await asyncio.open_connection(target_host, target_port)

            # Reconstruct request line
            up_writer.write(f"{method} {request_path} {http_version}\r\n".encode("utf-8"))
            for h in raw_headers_list:
                up_writer.write(f"{h}\r\n".encode("utf-8"))
            up_writer.write(b"\r\n")
            if request_body:
                up_writer.write(request_body)
            await up_writer.drain()

            # Read response status line
            status_line_bytes = await up_reader.readline()
            if not status_line_bytes:
                up_writer.close()
                await up_writer.wait_closed()
                client_writer.close()
                await client_writer.wait_closed()
                return

            status_line = status_line_bytes.decode("utf-8", errors="replace").strip()
            st_parts = status_line.split(" ", 2)
            status_code = int(st_parts[1]) if len(st_parts) > 1 and st_parts[1].isdigit() else 200
            flow.status_code = status_code

            # Read response headers
            resp_headers: Dict[str, str] = {}
            raw_resp_headers: List[bytes] = [status_line_bytes]

            while True:
                h_line = await up_reader.readline()
                raw_resp_headers.append(h_line)
                if not h_line or h_line == b"\r\n":
                    break
                h_str = h_line.decode("utf-8", errors="replace").rstrip("\r\n")
                if ":" in h_str:
                    k, v = h_str.split(":", 1)
                    resp_headers[k.strip().lower()] = v.strip()

            flow.response_headers = resp_headers

            # Forward response headers to client
            for raw_h in raw_resp_headers:
                client_writer.write(raw_h)
            await client_writer.drain()

            # Read response body
            resp_content_length = int(resp_headers.get("content-length", -1))
            is_chunked = resp_headers.get("transfer-encoding", "").lower() == "chunked"

            resp_body_chunks = []
            if resp_content_length >= 0:
                body_bytes = await up_reader.readexactly(resp_content_length)
                client_writer.write(body_bytes)
                await client_writer.drain()
                resp_body_chunks.append(body_bytes)
            elif is_chunked:
                # Read chunks until 0\r\n\r\n
                while True:
                    chunk_header = await up_reader.readline()
                    client_writer.write(chunk_header)
                    await client_writer.drain()
                    chunk_size_str = chunk_header.strip().split(b";")[0]
                    try:
                        chunk_size = int(chunk_size_str, 16)
                    except ValueError:
                        break
                    if chunk_size == 0:
                        trailer = await up_reader.readline()
                        client_writer.write(trailer)
                        await client_writer.drain()
                        break
                    chunk_data = await up_reader.readexactly(chunk_size + 2)  # data + \r\n
                    client_writer.write(chunk_data)
                    await client_writer.drain()
                    resp_body_chunks.append(chunk_data[:-2])
            else:
                # Read until EOF
                while True:
                    data = await up_reader.read(4096)
                    if not data:
                        break
                    client_writer.write(data)
                    await client_writer.drain()
                    resp_body_chunks.append(data)

            flow.response_body = b"".join(resp_body_chunks)
            up_writer.close()
            await up_writer.wait_closed()

        except Exception as e:
            flow.status_code = 502
            client_writer.write(f"HTTP/1.1 502 Bad Gateway\r\n\r\n{e}".encode("utf-8"))
            await client_writer.drain()

        finally:
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass

        # Perform live passive audit
        if self.auto_audit:
            self._audit_flow(flow)

        self.captured_flows.append(flow)
        if self.on_flow:
            self.on_flow(flow)

    def _audit_flow(self, flow: ProxyFlow) -> None:
        """Run passive security audits on the captured flow."""
        findings = []

        # 1. Missing Security Headers
        resp_headers = flow.response_headers
        if "content-security-policy" not in resp_headers:
            findings.append("MISSING_CSP")
        if "strict-transport-security" not in resp_headers and "https" in flow.url:
            findings.append("MISSING_HSTS")
        if resp_headers.get("x-content-type-options", "").lower() != "nosniff":
            findings.append("MISSING_X_CONTENT_TYPE_OPTIONS")
        if "x-frame-options" not in resp_headers:
            findings.append("MISSING_X_FRAME_OPTIONS")

        # 2. Cookie Hygiene
        set_cookie = resp_headers.get("set-cookie", "")
        if set_cookie:
            sc_lower = set_cookie.lower()
            if "httponly" not in sc_lower:
                findings.append("COOKIE_MISSING_HTTPONLY")
            if "secure" not in sc_lower:
                findings.append("COOKIE_MISSING_SECURE")

        # 3. Sensitive Data In Body
        body_text = flow.response_text
        for rule_id, pat in KEY_PATTERNS:
            if pat.search(body_text) or pat.search(flow.url):
                findings.append(rule_id)

        flow.findings = findings

        # Console logging
        if self.console:
            status_color = "green" if flow.status_code < 400 else ("yellow" if flow.status_code < 500 else "red")
            if findings:
                finding_names = ", ".join(findings[:3]) + (f" +{len(findings)-3} more" if len(findings) > 3 else "")
                self.console.print(
                    f"[{status_color}][{flow.method} {flow.status_code}][/{status_color}] [bold]{flow.path}[/bold] -> "
                    f"🛡️ [bold red]{len(findings)} Finding(s):[/bold red] [yellow]{finding_names}[/yellow]"
                )
            else:
                self.console.print(
                    f"[dim][{flow.method} {flow.status_code}][/dim] {flow.path} -> [bold green]Clean[/bold green]"
                )
