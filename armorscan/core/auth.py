"""
Authentication & Session Management Engine for ArmorScan.
Supports static tokens, session cookies, custom headers, session keep-alive checks,
and automated login macros.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin
from pydantic import BaseModel, Field


class AuthConfig(BaseModel):
    """
    Configuration container for authenticated scanning sessions.
    Carries static credentials, session verification rules, and login macro parameters.
    """

    headers: Dict[str, str] = Field(
        default_factory=dict,
        description="Static authentication headers injected into requests (e.g. Authorization, X-API-Key)",
    )
    cookies: Dict[str, str] = Field(
        default_factory=dict,
        description="Static session cookies injected into requests (e.g. session=xyz)",
    )
    check_url: Optional[str] = Field(
        default=None,
        description="Health-check endpoint to verify active session (e.g. /api/me)",
    )
    check_status: int = Field(
        default=200,
        description="Expected HTTP status code for an active session",
    )
    check_body: Optional[str] = Field(
        default=None,
        description="Expected substring in check response body",
    )
    login_url: Optional[str] = Field(
        default=None,
        description="Login endpoint URL for macro authentication",
    )
    login_body: Optional[str] = Field(
        default=None,
        description="Request body payload for login macro (JSON or form string)",
    )
    login_token_path: Optional[str] = Field(
        default=None,
        description="Dot-notation path to extract token from JSON response (e.g. 'data.token')",
    )

    @property
    def has_auth(self) -> bool:
        """Return True if any authentication credentials or login macro are defined."""
        return bool(self.headers or self.cookies or self.login_url)

    def add_header(self, header_str: str) -> None:
        """Parse 'Header-Name: Value' string and store in headers dictionary."""
        if ":" in header_str:
            key, val = header_str.split(":", 1)
            self.headers[key.strip()] = val.strip()

    def add_cookie(self, cookie_str: str) -> None:
        """Parse 'name=value' string and store in cookies dictionary."""
        if "=" in cookie_str:
            key, val = cookie_str.split("=", 1)
            self.cookies[key.strip()] = val.strip()

    def add_custom_header(self, header_str: str) -> None:
        """Alias for add_header."""
        self.add_header(header_str)

    @staticmethod
    def extract_token_from_json(data: Any, path: Optional[str] = None) -> Optional[str]:
        """
        Extract token string from nested JSON structure.
        Supports dot notation like 'data.token' or 'auth.access_token'.
        If path is not provided, searches common key conventions.
        """
        if not isinstance(data, (dict, list)):
            return None

        if path:
            curr = data
            for part in path.split("."):
                part = part.strip()
                if isinstance(curr, dict) and part in curr:
                    curr = curr[part]
                elif isinstance(curr, list) and part.isdigit() and int(part) < len(curr):
                    curr = curr[int(part)]
                else:
                    return None
            return str(curr) if curr is not None else None

        # Fallback: check standard convention keys
        if isinstance(data, dict):
            for candidate in ("token", "access_token", "jwt", "authToken", "id_token", "session_token"):
                if candidate in data:
                    return str(data[candidate])
            # Check one level deeper (e.g. {"data": {"token": "..."}})
            if "data" in data and isinstance(data["data"], dict):
                for candidate in ("token", "access_token", "jwt"):
                    if candidate in data["data"]:
                        return str(data["data"][candidate])

        return None

    async def perform_login(self, client: Any, base_url: str) -> Tuple[bool, Optional[str]]:
        """
        Execute automated login macro against login_url.
        Parses response, extracts bearer token or session cookie, and updates client headers/cookies.
        """
        if not self.login_url:
            return True, None

        target_url = urljoin(base_url, self.login_url)

        # Prepare request payload
        json_payload: Optional[Dict[str, Any]] = None
        data_payload: Optional[str] = None

        if self.login_body:
            trimmed = self.login_body.strip()
            if trimmed.startswith("{") and trimmed.endswith("}"):
                try:
                    json_payload = json.loads(trimmed)
                except Exception:
                    data_payload = trimmed
            else:
                data_payload = trimmed

        resp = await client.post(
            target_url,
            json=json_payload,
            data=data_payload,
            headers={"Content-Type": "application/json"} if json_payload is not None else None,
        )

        if not resp.ok or resp.status_code >= 400:
            return False, f"Login failed with status {resp.status_code}: {resp.text[:120]}"

        # 1. Capture response cookies
        if resp.cookies:
            for k, v in resp.cookies.items():
                self.cookies[k] = v
                if hasattr(client, "client") and client.client:
                    client.client.cookies.set(k, v)

        # 2. Extract token from response JSON
        token: Optional[str] = None
        try:
            resp_data = resp.raw_response.json() if resp.raw_response else None
            if resp_data:
                token = self.extract_token_from_json(resp_data, self.login_token_path)
        except Exception:
            token = None

        if token:
            bearer_header = f"Bearer {token}"
            self.headers["Authorization"] = bearer_header
            if hasattr(client, "client") and client.client:
                client.client.headers["Authorization"] = bearer_header
            return True, token

        return True, "Login completed without explicit token"

    async def verify_session(self, client: Any, base_url: str) -> Tuple[bool, Optional[str]]:
        """
        Verify that the active session is valid by querying check_url.
        """
        if not self.check_url:
            return True, None

        target_url = urljoin(base_url, self.check_url)
        resp = await client.get(target_url)

        if not resp.ok or resp.status_code != self.check_status:
            return (
                False,
                f"Session check failed: expected HTTP {self.check_status}, received HTTP {resp.status_code}",
            )

        if self.check_body and self.check_body not in resp.text:
            return (
                False,
                f"Session check failed: response body missing expected text '{self.check_body}'",
            )

        return True, "Session active and verified"
