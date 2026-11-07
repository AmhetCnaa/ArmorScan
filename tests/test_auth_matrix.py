"""
Unit and Integration Tests for Multi-Role BOLA/IDOR Permission Matrix Module.
Verifies parsing of role specs, detection of unauthenticated guest BOLA,
cross-tenant IDOR between distinct users, and clean 401/403 access control enforcement.
"""

import pytest
import respx
import httpx

from armorscan.core.client import HttpClient
from armorscan.core.models import Confidence, ScanTarget, Severity
from armorscan.modules.auth_matrix import (
    AuthMatrixModule,
    RoleSpec,
    parse_matrix_roles,
)


def test_parse_matrix_roles():
    raw = "admin:Bearer token_admin_123, user:token_user_456, guest:, auditor:X-Custom: 789"
    roles = parse_matrix_roles(raw)

    assert len(roles) == 4
    assert roles[0].name == "admin"
    assert roles[0].auth_header == "Bearer token_admin_123"
    assert roles[0].get_headers() == {"Authorization": "Bearer token_admin_123"}

    assert roles[1].name == "user"
    assert roles[1].get_headers() == {"Authorization": "Bearer token_user_456"}

    assert roles[2].name == "guest"
    assert roles[2].auth_header is None
    assert roles[2].get_headers() == {}

    assert roles[3].name == "auditor"


@pytest.mark.asyncio
async def test_auth_matrix_bola_unauthenticated_guest_detected():
    target = ScanTarget.from_url("http://test-server.local")

    roles = [
        RoleSpec(name="admin", auth_header="Bearer admin_token"),
        RoleSpec(name="user", auth_header="Bearer user_token"),
        RoleSpec(name="guest", auth_header=None),
    ]
    module = AuthMatrixModule(roles=roles, candidate_paths=["/api/orders/1"])

    with respx.mock(base_url="http://test-server.local") as respx_mock:
        # All roles (including unauthenticated guest) get 200 OK with sensitive order data
        respx_mock.get("/api/orders/1").mock(
            return_value=httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json={"order_id": 1, "user": "alice", "items": [{"id": 10, "name": "Secret Document"}], "total": 199.99},
            )
        )

        async with HttpClient.for_target(target) as client:
            result = await module.execute(target, client)

    assert result.has_findings
    bola_findings = [f for f in result.findings if f.id == "BOLA_UNAUTHENTICATED_ACCESS"]
    assert len(bola_findings) == 1
    f = bola_findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.confidence == Confidence.CONFIRMED
    assert "BOLA" in f.title
    assert "guest" in f.description.lower()
    assert "/api/orders/1" in f.affected_urls[0]


@pytest.mark.asyncio
async def test_auth_matrix_cross_tenant_idor_confirmed():
    target = ScanTarget.from_url("http://test-server.local")

    roles = [
        RoleSpec(name="admin", auth_header="Bearer admin_token"),
        RoleSpec(name="user", auth_header="Bearer user_a_token"),
        RoleSpec(name="user_b", auth_header="Bearer user_b_token"),
        RoleSpec(name="guest", auth_header=None),
    ]
    module = AuthMatrixModule(roles=roles, candidate_paths=["/rest/basket/1"])

    with respx.mock(base_url="http://test-server.local") as respx_mock:
        # Guest is blocked with 401
        respx_mock.get("/rest/basket/1", headers__contains={"Authorization": "Bearer admin_token"}).mock(
            return_value=httpx.Response(200, json={"basket": 1, "user": "alice", "items": []})
        )
        respx_mock.get("/rest/basket/1", headers__contains={"Authorization": "Bearer user_a_token"}).mock(
            return_value=httpx.Response(200, json={"basket": 1, "user": "alice", "items": []})
        )
        # user_b also gets 200 OK with user_a's basket -> Cross-tenant IDOR!
        respx_mock.get("/rest/basket/1", headers__contains={"Authorization": "Bearer user_b_token"}).mock(
            return_value=httpx.Response(200, json={"basket": 1, "user": "alice", "items": []})
        )
        respx_mock.get("/rest/basket/1").mock(
            return_value=httpx.Response(401, json={"error": "Authentication required"})
        )

        async with HttpClient.for_target(target) as client:
            result = await module.execute(target, client)

    assert result.has_findings
    idor_findings = [f for f in result.findings if f.id == "CROSS_TENANT_IDOR_CONFIRMED"]
    assert len(idor_findings) == 1
    f = idor_findings[0]
    assert f.severity == Severity.HIGH
    assert f.confidence == Confidence.CONFIRMED
    assert "user_b" in f.description


@pytest.mark.asyncio
async def test_auth_matrix_clean_endpoint_zero_fp():
    target = ScanTarget.from_url("http://test-server.local")

    roles = [
        RoleSpec(name="admin", auth_header="Bearer admin_token"),
        RoleSpec(name="user", auth_header="Bearer user_token"),
        RoleSpec(name="guest", auth_header=None),
    ]
    module = AuthMatrixModule(roles=roles, candidate_paths=["/api/user/settings"])

    with respx.mock(base_url="http://test-server.local") as respx_mock:
        respx_mock.get("/api/user/settings", headers__contains={"Authorization": "Bearer admin_token"}).mock(
            return_value=httpx.Response(200, json={"settings": "ok"})
        )
        respx_mock.get("/api/user/settings", headers__contains={"Authorization": "Bearer user_token"}).mock(
            return_value=httpx.Response(200, json={"settings": "ok"})
        )
        # Guest receives 401 Unauthorized
        respx_mock.get("/api/user/settings").mock(
            return_value=httpx.Response(401, json={"error": "Unauthorized"})
        )

        async with HttpClient.for_target(target) as client:
            result = await module.execute(target, client)

    assert not result.has_findings
    assert len(result.passed_checks) > 0
    assert any("strictly enforced" in ch for ch in result.passed_checks)
