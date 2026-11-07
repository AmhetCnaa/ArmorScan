"""
Async HTTP Client Engine for ArmorScan.
Built on httpx with HTTP/2 support, robust connection management,
resilient error handling, and safe concurrency control.
"""

from __future__ import annotations

import asyncio
import os
import ssl
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
# Sanitize NO_PROXY / no_proxy environment variables for httpx compatibility (prevent InvalidURL on [::1])
for _env_var in ("NO_PROXY", "no_proxy"):
    _val = os.environ.get(_env_var)
    if _val and "[::1]" in _val:
        os.environ[_env_var] = _val.replace("[::1]", "::1")

import httpx

from armorscan import __version__
from armorscan.core.auth import AuthConfig
from armorscan.core.models import ScanTarget

DEFAULT_USER_AGENT = (
    f"ArmorScan/{__version__} (+https://github.com/AmhetCnaa/ArmorScan; Security Scanner)"
)
DEFAULT_TIMEOUT = httpx.Timeout(connect=3.0, read=6.0, write=3.0, pool=3.0)
TURBO_TIMEOUT = httpx.Timeout(connect=1.5, read=3.0, write=1.5, pool=2.0)


class HttpResponse:
    """Wrapper around httpx.Response providing safe attributes and helpers."""

    def __init__(
        self,
        response: Optional[httpx.Response] = None,
        error: Optional[str] = None,
        elapsed: float = 0.0,
    ):
        self._raw = response
        self.error = error
        self.elapsed = elapsed

    @property
    def ok(self) -> bool:
        return self._raw is not None and self.error is None

    @property
    def status_code(self) -> int:
        return self._raw.status_code if self._raw else 0

    @property
    def headers(self) -> httpx.Headers:
        return self._raw.headers if self._raw else httpx.Headers()

    @property
    def text(self) -> str:
        if not self._raw:
            return ""
        try:
            return self._raw.text
        except Exception:
            return ""

    @property
    def content(self) -> bytes:
        return self._raw.content if self._raw else b""

    @property
    def url(self) -> str:
        return str(self._raw.url) if self._raw else ""

    @property
    def http_version(self) -> str:
        return self._raw.http_version if self._raw else ""

    @property
    def cookies(self) -> httpx.Cookies:
        return self._raw.cookies if self._raw else httpx.Cookies()

    @property
    def raw_response(self) -> Optional[httpx.Response]:
        return self._raw


class HttpClient:
    """
    Asynchronous HTTP client tailored for security auditing.
    Supports HTTP/2, custom headers, redirect inspection, and rate-limiting bursts.
    """

    def __init__(
        self,
        verify_ssl: Union[bool, ssl.SSLContext] = True,
        timeout: Optional[httpx.Timeout] = None,
        user_agent: str = DEFAULT_USER_AGENT,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        http2: bool = True,
        proxy: Optional[Union[str, bool]] = "auto",
        auth_config: Optional[AuthConfig] = None,
    ):
        if verify_ssl is True:
            ca_bundle = os.environ.get("SSL_CERT_FILE")
            if ca_bundle and os.path.exists(ca_bundle):
                ctx = ssl.create_default_context(cafile=ca_bundle)
                self.verify_ssl: Union[bool, ssl.SSLContext] = ctx
            else:
                self.verify_ssl = True
        else:
            self.verify_ssl = verify_ssl

        self.timeout = timeout or DEFAULT_TIMEOUT
        self.user_agent = user_agent
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.http2 = http2
        self.auth_config = auth_config

        # Resolve proxy
        if proxy == "auto":
            env_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
            self.proxy: Optional[str] = env_proxy
        elif isinstance(proxy, str):
            self.proxy = proxy
        else:
            self.proxy = None

        self._client: Optional[httpx.AsyncClient] = None
        self._unauth_client: Optional[httpx.AsyncClient] = None

    @classmethod
    def for_target(
        cls,
        target: ScanTarget,
        verify_ssl: bool = True,
        proxy: Optional[str] = "auto",
        auth_config: Optional[AuthConfig] = None,
        **kwargs,
    ) -> HttpClient:
        """Create a client configured appropriately for target (e.g. bypassing proxy for localhost)."""
        resolved_proxy: Optional[Union[str, bool]] = proxy
        if target.is_localhost:
            resolved_proxy = None
            verify_ssl = False  # Localhost often uses self-signed or HTTP

        return cls(verify_ssl=verify_ssl, proxy=resolved_proxy, auth_config=auth_config, **kwargs)

    async def __aenter__(self) -> HttpClient:
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def start(self) -> None:
        """Initialize the underlying httpx AsyncClients (authenticated and unauthenticated)."""
        if self._client is None or self._client.is_closed:
            base_headers = {
                "User-Agent": self.user_agent,
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
            }
            # Ensure localhost and 127.0.0.1 bypass proxy
            mounts = {
                "all://localhost": httpx.AsyncHTTPTransport(verify=self.verify_ssl),
                "all://127.0.0.1": httpx.AsyncHTTPTransport(verify=self.verify_ssl),
            }

            # 1. Authenticated client
            auth_headers = dict(base_headers)
            cookies = None
            if self.auth_config:
                auth_headers.update(self.auth_config.headers)
                if self.auth_config.cookies:
                    cookies = self.auth_config.cookies

            self._client = httpx.AsyncClient(
                verify=self.verify_ssl,
                timeout=self.timeout,
                headers=auth_headers,
                cookies=cookies,
                follow_redirects=self.follow_redirects,
                max_redirects=self.max_redirects,
                http2=self.http2,
                proxy=self.proxy,
                mounts=mounts,
                trust_env=False,
            )

            # 2. Dedicated unauthenticated client (no credentials, no auth cookies)
            self._unauth_client = httpx.AsyncClient(
                verify=self.verify_ssl,
                timeout=self.timeout,
                headers=base_headers,
                follow_redirects=self.follow_redirects,
                max_redirects=self.max_redirects,
                http2=self.http2,
                proxy=self.proxy,
                mounts=mounts,
                trust_env=False,
            )

    async def close(self) -> None:
        """Close the underlying httpx clients."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
        if self._unauth_client is not None and not self._unauth_client.is_closed:
            await self._unauth_client.aclose()
            self._unauth_client = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            raise RuntimeError("HttpClient is not started. Use 'async with client:' or call 'await client.start()'")
        return self._client

    @property
    def unauth_client(self) -> httpx.AsyncClient:
        if self._unauth_client is None or self._unauth_client.is_closed:
            raise RuntimeError("HttpClient is not started. Use 'async with client:' or call 'await client.start()'")
        return self._unauth_client

    async def request_unauthenticated(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        follow_redirects: Optional[bool] = None,
        timeout: Optional[Union[float, httpx.Timeout]] = None,
    ) -> HttpResponse:
        """Execute an HTTP request strictly without authentication headers or session cookies."""
        start_time = time.monotonic()
        try:
            req_kwargs: Dict[str, Any] = {}
            if headers:
                req_kwargs["headers"] = headers
            if params:
                req_kwargs["params"] = params
            if data:
                req_kwargs["data"] = data
            if json is not None:
                req_kwargs["json"] = json
            if follow_redirects is not None:
                req_kwargs["follow_redirects"] = follow_redirects
            if timeout is not None:
                req_kwargs["timeout"] = timeout

            raw = await self.unauth_client.request(method, url, **req_kwargs)
            elapsed = time.monotonic() - start_time
            return HttpResponse(response=raw, elapsed=elapsed)
        except Exception as e:
            return HttpResponse(error=f"Unauthenticated request error: {e}", elapsed=time.monotonic() - start_time)

    async def get_unauthenticated(self, url: str, **kwargs) -> HttpResponse:
        return await self.request_unauthenticated("GET", url, **kwargs)

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        follow_redirects: Optional[bool] = None,
        timeout: Optional[Union[float, httpx.Timeout]] = None,
    ) -> HttpResponse:
        """
        Execute an HTTP request safely, capturing any network or SSL errors.
        """
        start_time = time.monotonic()
        try:
            req_kwargs: Dict[str, Any] = {}
            if headers:
                req_kwargs["headers"] = headers
            if params:
                req_kwargs["params"] = params
            if data:
                req_kwargs["data"] = data
            if json is not None:
                req_kwargs["json"] = json
            if follow_redirects is not None:
                req_kwargs["follow_redirects"] = follow_redirects
            if timeout is not None:
                req_kwargs["timeout"] = timeout

            raw = await self.client.request(method, url, **req_kwargs)
            elapsed = time.monotonic() - start_time
            return HttpResponse(response=raw, elapsed=elapsed)

        except httpx.ConnectTimeout:
            return HttpResponse(error="Connection timed out", elapsed=time.monotonic() - start_time)
        except httpx.ReadTimeout:
            return HttpResponse(error="Read timed out", elapsed=time.monotonic() - start_time)
        except httpx.ConnectError as e:
            return HttpResponse(error=f"Connection error: {e}", elapsed=time.monotonic() - start_time)
        except httpx.HTTPStatusError as e:
            return HttpResponse(error=f"HTTP status error: {e}", elapsed=time.monotonic() - start_time)
        except httpx.RequestError as e:
            return HttpResponse(error=f"Request error: {e}", elapsed=time.monotonic() - start_time)
        except Exception as e:
            return HttpResponse(error=f"Unexpected error: {type(e).__name__}: {e}", elapsed=time.monotonic() - start_time)

    async def get(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("HEAD", url, **kwargs)

    async def post(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("POST", url, **kwargs)

    async def options(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("OPTIONS", url, **kwargs)

    async def trace(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("TRACE", url, **kwargs)

    async def burst_requests(
        self,
        urls: Sequence[Union[str, Tuple[str, str]]],
        concurrency: int = 15,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
    ) -> List[HttpResponse]:
        """
        Execute multiple requests concurrently with bounded concurrency.
        Accepts a list of URLs or (method, URL) tuples.
        Useful for rate-limiting resilience tests.
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def _bounded_req(item: Union[str, Tuple[str, str]]) -> HttpResponse:
            async with semaphore:
                if isinstance(item, tuple):
                    m, u = item
                else:
                    m, u = method, item
                return await self.request(m, u, headers=headers)

        tasks = [_bounded_req(item) for item in urls]
        return await asyncio.gather(*tasks)
