"""
Unit and Integration Tests for WebSocket & GraphQL Protocol Resilience Auditor Module.
Tests Cross-Site WebSocket Hijacking (CSWSH) Origin validation bypass and
GraphQL multi-alias amplification / unbounded query batching detection.
"""

import pytest
import respx
import httpx

from armorscan.core.client import HttpClient
from armorscan.core.models import Confidence, ScanTarget, Severity
from armorscan.modules.protocols import ProtocolsResilienceModule


@pytest.mark.asyncio
async def test_websocket_missing_origin_validation_detected():
    target = ScanTarget.from_url("http://ws-test.local")
    module = ProtocolsResilienceModule(candidate_ws_paths=["/ws"])

    with respx.mock(base_url="http://ws-test.local", assert_all_called=False) as respx_mock:
        # Server accepts cross-origin handshake with 101 Switching Protocols without checking Origin
        respx_mock.get("/ws").mock(
            return_value=httpx.Response(
                101,
                headers={
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Accept": "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
                },
            )
        )

        async with HttpClient.for_target(target) as client:
            result = await module.execute(target, client)

    assert result.has_findings
    ws_findings = [f for f in result.findings if f.id == "WEBSOCKET_MISSING_ORIGIN_VALIDATION"]
    assert len(ws_findings) == 1
    f = ws_findings[0]
    assert f.severity == Severity.HIGH
    assert f.confidence == Confidence.CONFIRMED
    assert "CSWSH" in f.title or "Origin" in f.title
    assert "CWE-1385" in f.cwe_id


@pytest.mark.asyncio
async def test_websocket_safe_origin_rejection():
    target = ScanTarget.from_url("http://safe-ws.local")
    module = ProtocolsResilienceModule(candidate_ws_paths=["/ws"])

    with respx.mock(base_url="http://safe-ws.local", assert_all_called=False) as respx_mock:
        # Server strictly checks Origin header and rejects untrusted origin with 403 Forbidden
        respx_mock.get("/ws").mock(
            return_value=httpx.Response(403, text="Forbidden: Untrusted WebSocket Origin")
        )

        async with HttpClient.for_target(target) as client:
            result = await module.execute(target, client)

    assert not any(f.id == "WEBSOCKET_MISSING_ORIGIN_VALIDATION" for f in result.findings)
    assert len(result.passed_checks) > 0


@pytest.mark.asyncio
async def test_graphql_unbounded_batching_detected():
    target = ScanTarget.from_url("http://gql-test.local")
    module = ProtocolsResilienceModule(candidate_graphql_paths=["/graphql"])

    with respx.mock(base_url="http://gql-test.local", assert_all_called=False) as respx_mock:
        # Server executes all 10 aliases without complexity restriction
        aliases_data = {f"a{i}": "Query" for i in range(1, 11)}
        respx_mock.post("/graphql").mock(
            return_value=httpx.Response(200, json={"data": aliases_data})
        )

        async with HttpClient.for_target(target) as client:
            result = await module.execute(target, client)

    assert result.has_findings
    gql_findings = [f for f in result.findings if f.id == "GRAPHQL_UNBOUNDED_BATCHING"]
    assert len(gql_findings) == 1
    f = gql_findings[0]
    assert f.severity == Severity.MEDIUM
    assert f.confidence == Confidence.CONFIRMED
    assert "Alias Amplification" in f.title or "Batching" in f.title
    assert "CWE-770" in f.cwe_id


@pytest.mark.asyncio
async def test_graphql_safe_alias_restriction():
    target = ScanTarget.from_url("http://safe-gql.local")
    module = ProtocolsResilienceModule(candidate_graphql_paths=["/graphql"])

    with respx.mock(base_url="http://safe-gql.local", assert_all_called=False) as respx_mock:
        # Server blocks excessive aliases with 400 Bad Request
        respx_mock.post("/graphql").mock(
            return_value=httpx.Response(400, json={"errors": [{"message": "Max alias count exceeded"}]})
        )

        async with HttpClient.for_target(target) as client:
            result = await module.execute(target, client)

    assert not any(f.id == "GRAPHQL_UNBOUNDED_BATCHING" for f in result.findings)
    assert len(result.passed_checks) > 0
