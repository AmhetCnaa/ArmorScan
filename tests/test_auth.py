"""
Unit tests for ArmorScan Authentication & Session Management Engine (auth.py).
Tests static credential injection, login macros, session verification, and token extraction.
"""

from pathlib import Path
import httpx
import pytest
import respx

from armorscan.cli import build_parser
from armorscan.core.auth import AuthConfig
from armorscan.core.client import HttpClient
from armorscan.core.models import ScanTarget


def test_auth_config_parsing():
    config = AuthConfig()
    config.add_header("Authorization: Bearer test-token-123")
    config.add_cookie("session=user_sess_abc")
    config.add_custom_header("X-API-Key: custom_secret_key")

    assert config.has_auth is True
    assert config.headers["Authorization"] == "Bearer test-token-123"
    assert config.headers["X-API-Key"] == "custom_secret_key"
    assert config.cookies["session"] == "user_sess_abc"


def test_extract_token_from_json():
    # 1. Simple key
    assert AuthConfig.extract_token_from_json({"token": "xyz123"}) == "xyz123"
    assert AuthConfig.extract_token_from_json({"access_token": "abc999"}) == "abc999"

    # 2. Dot notation
    data = {"data": {"user": "admin", "token": "jwt_deep_token"}}
    assert AuthConfig.extract_token_from_json(data, "data.token") == "jwt_deep_token"

    # 3. List indexing in path
    list_data = {"auth": [{"id": 1, "key": "tok_one"}, {"id": 2, "key": "tok_two"}]}
    assert AuthConfig.extract_token_from_json(list_data, "auth.1.key") == "tok_two"

    # 4. Non-matching path
    assert AuthConfig.extract_token_from_json(data, "data.missing_key") is None


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_http_client_auth_and_unauth_isolation(respx_mock):
    auth_config = AuthConfig()
    auth_config.add_header("Authorization: Bearer valid_secret_token")
    auth_config.add_cookie("session=active_session_123")

    client = HttpClient(verify_ssl=False, auth_config=auth_config)
    await client.start()

    # Route that records headers
    captured_auth_headers = {}
    captured_unauth_headers = {}

    def auth_callback(request):
        nonlocal captured_auth_headers
        captured_auth_headers = dict(request.headers)
        return httpx.Response(200, text="Auth OK")

    def unauth_callback(request):
        nonlocal captured_unauth_headers
        captured_unauth_headers = dict(request.headers)
        return httpx.Response(200, text="Unauth OK")

    respx_mock.get("https://auth-test.dev/api/data").mock(side_effect=auth_callback)
    respx_mock.get("https://auth-test.dev/api/public").mock(side_effect=unauth_callback)

    # 1. Authenticated request
    resp_auth = await client.get("https://auth-test.dev/api/data")
    assert resp_auth.status_code == 200
    assert captured_auth_headers.get("authorization") == "Bearer valid_secret_token"
    assert "session=active_session_123" in captured_auth_headers.get("cookie", "")

    # 2. Unauthenticated request must NOT carry authorization or session cookie
    resp_unauth = await client.get_unauthenticated("https://auth-test.dev/api/public")
    assert resp_unauth.status_code == 200
    assert "authorization" not in captured_unauth_headers
    assert "session" not in captured_unauth_headers.get("cookie", "")

    await client.close()


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_login_macro_success(respx_mock):
    respx_mock.post("https://macro-target.dev/api/login").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"token": "extracted_jwt_macro_token_456"}},
            headers={"Set-Cookie": "sess=macro_sess_999; Path=/; HttpOnly"},
        )
    )

    auth_config = AuthConfig(
        login_url="/api/login",
        login_body='{"user": "alice", "pass": "secret"}',
        login_token_path="data.token",
    )

    client = HttpClient(verify_ssl=False, auth_config=auth_config)
    await client.start()

    success, msg = await auth_config.perform_login(client, "https://macro-target.dev")
    assert success is True
    assert msg == "extracted_jwt_macro_token_456"

    # Verify injected into auth_config and client
    assert auth_config.headers["Authorization"] == "Bearer extracted_jwt_macro_token_456"
    assert client.client.headers["Authorization"] == "Bearer extracted_jwt_macro_token_456"

    await client.close()


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_login_macro_failure(respx_mock):
    respx_mock.post("https://macro-target.dev/api/login").mock(
        return_value=httpx.Response(401, text="Invalid credentials")
    )

    auth_config = AuthConfig(
        login_url="/api/login",
        login_body='{"user": "alice", "pass": "wrong"}',
    )

    client = HttpClient(verify_ssl=False, auth_config=auth_config)
    await client.start()

    success, msg = await auth_config.perform_login(client, "https://macro-target.dev")
    assert success is False
    assert "Login failed with status 401" in msg

    await client.close()


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_session_verification_check(respx_mock):
    respx_mock.get("https://check-target.dev/api/me").mock(
        return_value=httpx.Response(200, json={"status": "active", "user": "alice"})
    )

    auth_config = AuthConfig(
        check_url="/api/me",
        check_status=200,
        check_body="alice",
    )

    client = HttpClient(verify_ssl=False, auth_config=auth_config)
    await client.start()

    ok, msg = await auth_config.verify_session(client, "https://check-target.dev")
    assert ok is True
    assert "Session active" in msg

    # Test failure: wrong body
    auth_config_mismatch = AuthConfig(
        check_url="/api/me",
        check_status=200,
        check_body="non_existent_string",
    )
    fail_ok, fail_msg = await auth_config_mismatch.verify_session(client, "https://check-target.dev")
    assert fail_ok is False
    assert "missing expected text" in fail_msg

    await client.close()


def test_cli_auth_flags_parsing():
    parser = build_parser()
    args = parser.parse_args([
        "https://target.com",
        "--auth-header", "Authorization: Bearer token123",
        "--auth-header", "X-Tenant-ID: tenant-42",
        "--auth-cookie", "session=abc",
        "--auth-custom-header", "X-Custom: val",
        "--auth-check-url", "/api/health",
        "--auth-check-status", "204",
        "--auth-check-body", "healthy",
        "--login-url", "/auth/login",
        "--login-body", '{"u":"a"}',
        "--login-token-path", "jwt",
    ])

    assert args.auth_header == ["Authorization: Bearer token123", "X-Tenant-ID: tenant-42"]
    assert args.auth_cookie == ["session=abc"]
    assert args.auth_custom_header == ["X-Custom: val"]
    assert args.auth_check_url == "/api/health"
    assert args.auth_check_status == 204
    assert args.auth_check_body == "healthy"
    assert args.login_url == "/auth/login"
    assert args.login_body == '{"u":"a"}'
    assert args.login_token_path == "jwt"
