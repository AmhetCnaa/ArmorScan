"""
Local Ephemeral Callback Verifier for Out-of-Band & Asynchronous SSRF Auditing.
Starts a safe, temporary HTTP server bound strictly to 127.0.0.1 during scan execution
to capture and confirm unvalidated asynchronous outbound network callbacks.
"""

from __future__ import annotations

import asyncio
import time
from typing import Dict, List, Optional, Tuple
import uuid
from pydantic import BaseModel, Field


class CallbackEvent(BaseModel):
    """Metadata of an intercepted outbound callback request."""
    token: str
    endpoint: str
    parameter: str
    client_address: str = ""
    method: str = "GET"
    timestamp: float = Field(default_factory=time.time)


class LocalCallbackVerifier:
    """
    Ephemeral HTTP Callback Listener.
    Listens strictly on 127.0.0.1 on an OS-assigned dynamic port to verify
    whether backend workers or webhook handlers trigger unvalidated outbound connections.
    """

    def __init__(self, host: str = "127.0.0.1"):
        self.host = host
        self.port: int = 0
        self._server: Optional[asyncio.Server] = None
        self._registered_probes: Dict[str, Tuple[str, str]] = {}  # token -> (endpoint, param)
        self.captured_events: List[CallbackEvent] = []
        self._running = False

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    async def start(self) -> str:
        """Start ephemeral callback listener on random free local port."""
        self._server = await asyncio.start_server(self._handle_request, self.host, 0)
        self.port = self._server.sockets[0].getsockname()[1]
        self._running = True
        return self.base_url

    async def stop(self) -> None:
        """Gracefully terminate callback listener."""
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    def register_probe(self, endpoint: str, parameter: str) -> Tuple[str, str]:
        """
        Generate a unique verification token and callback URL for a target parameter.
        Returns: (token, verification_url)
        """
        token = uuid.uuid4().hex[:12]
        self._registered_probes[token] = (endpoint, parameter)
        callback_url = f"{self.base_url}/verify/{token}"
        return token, callback_url

    def has_interaction(self, token: str) -> bool:
        """Check if a specific verification probe was triggered."""
        return any(ev.token == token for ev in self.captured_events)

    async def wait_for_callbacks(self, timeout: float = 0.3) -> List[CallbackEvent]:
        """Wait briefly for background workers to execute outbound callbacks."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.captured_events:
                break
            await asyncio.sleep(0.05)
        return list(self.captured_events)

    async def _handle_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle incoming HTTP probe connection."""
        try:
            line_bytes = await reader.readline()
            if not line_bytes:
                writer.close()
                await writer.wait_closed()
                return

            req_line = line_bytes.decode("utf-8", errors="replace").strip()
            parts = req_line.split(" ")
            method = parts[0].upper() if parts else "GET"
            path = parts[1] if len(parts) > 1 else "/"

            # Read remaining headers
            while True:
                h = await reader.readline()
                if not h or h == b"\r\n":
                    break

            peer = writer.get_extra_info("peername")
            client_ip = peer[0] if peer else "127.0.0.1"

            # Parse token from /verify/<token>
            if "/verify/" in path:
                token_candidate = path.split("/verify/", 1)[1].split("?")[0].strip("/")
                if token_candidate in self._registered_probes:
                    endpoint, param = self._registered_probes[token_candidate]
                    event = CallbackEvent(
                        token=token_candidate,
                        endpoint=endpoint,
                        parameter=param,
                        client_address=client_ip,
                        method=method,
                    )
                    self.captured_events.append(event)

            # Return benign 200 OK verification response
            resp = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Connection: close\r\n\r\n"
                b"ARMORSCAN_CALLBACK_VERIFIED\r\n"
            )
            writer.write(resp)
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
