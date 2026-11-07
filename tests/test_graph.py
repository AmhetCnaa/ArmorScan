"""
Unit tests for Attack Surface & Risk Topology Graph Generator (tests/test_graph.py).
Validates topology node construction, multi-tier layout coordinates, interactive SVG
component rendering, and HTML report integration.
"""

from datetime import datetime, timezone
import pytest

from armorscan.core.models import (
    Confidence,
    Finding,
    ScanResult,
    ScanSummary,
    ScanTarget,
    Severity,
)
from armorscan.reporters.graph import AttackSurfaceGraphBuilder
from armorscan.reporters.html import HtmlReporter


@pytest.fixture
def sample_scan_result() -> ScanResult:
    target = ScanTarget.from_url("http://127.0.0.1:3000")
    target.discovered_paths = ["/", "/rest/basket/1", "/ftp", "/metrics"]

    f1 = Finding(
        id="CROSS_TENANT_OBJECT_ACCESS",
        title="BOLA IDOR on Basket",
        description="User A read User B basket.",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        module="multi_step",
        impact="Unauthorized access to customer private data.",
        affected_urls=["http://127.0.0.1:3000/rest/basket/1"],
    )
    f2 = Finding(
        id="PATH_TRAVERSAL_DETECTED",
        title="Null-Byte Traversal",
        description="Read restricted file.",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        module="traversal",
        impact="Exposes application source code and backup files.",
        affected_urls=["http://127.0.0.1:3000/ftp/package.json.bak%2500.md"],
    )
    f3 = Finding(
        id="MISSING_CSP",
        title="Missing CSP Header",
        description="Header not found.",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        module="headers",
        impact="Increases risk of script injection and XSS.",
        affected_urls=["http://127.0.0.1:3000/"],
    )

    summary = ScanSummary(
        total_checks=25,
        passed_checks=22,
        critical_count=1,
        high_count=2,
        medium_count=0,
        low_count=0,
        info_count=0,
        score=45,
    )

    from armorscan.core.models import ModuleResult
    mod = ModuleResult(
        module_name="test_mod",
        display_name="Test Module",
        findings=[f1, f2, f3],
        passed_checks=[],
    )

    return ScanResult(
        target=target,
        started_at=datetime.now(timezone.utc),
        duration_seconds=1.2,
        modules=[mod],
        summary=summary,
    )


def test_attack_surface_graph_builder(sample_scan_result: ScanResult):
    nodes, links = AttackSurfaceGraphBuilder.build(sample_scan_result)

    # 1. Host Node
    host_node = next((n for n in nodes if n.node_type == "host"), None)
    assert host_node is not None
    assert host_node.label == "127.0.0.1"
    assert host_node.radius > 20.0
    assert host_node.x == 500.0 and host_node.y == 300.0

    # 2. Endpoint Nodes
    endpoint_nodes = [n for n in nodes if n.node_type == "endpoint"]
    assert len(endpoint_nodes) >= 3
    endpoint_labels = [n.label for n in endpoint_nodes]
    assert any("/rest/basket" in lbl for lbl in endpoint_labels)

    # 3. Finding Nodes
    finding_nodes = [n for n in nodes if n.node_type == "finding"]
    assert len(finding_nodes) == 3
    crit_node = next((n for n in finding_nodes if n.severity == "CRITICAL"), None)
    assert crit_node is not None
    assert crit_node.finding_id == "CROSS_TENANT_OBJECT_ACCESS"

    # 4. Links
    assert len(links) >= 6
    link_sources = {l.source_id for l in links}
    assert "node_host" in link_sources


def test_svg_component_and_html_integration(sample_scan_result: ScanResult):
    svg_html = AttackSurfaceGraphBuilder.render_svg_component(sample_scan_result)

    assert "attack-graph-container" in svg_html
    assert "Interactive Attack Surface & Risk Topology Map" in svg_html
    assert "<svg id=\"attackSurfaceSvg\"" in svg_html
    assert "onclick=\"focusFindingCard('CROSS_TENANT_OBJECT_ACCESS')\"" in svg_html
    assert "legend-dot" in svg_html

    # Verify complete HTML report embeds the graph
    full_html = HtmlReporter.generate(sample_scan_result)
    assert "attack-graph-container" in full_html
    assert "id=\"finding-card-CROSS_TENANT_OBJECT_ACCESS\"" in full_html
    assert "function focusFindingCard(findingId)" in full_html
    assert "highlight-pulse" in full_html


def test_role_matrix_grid_html_integration():
    target = ScanTarget.from_url("http://127.0.0.1:3000")
    bola_finding = Finding(
        id="BOLA_UNAUTHENTICATED_ACCESS",
        title="BOLA on Orders",
        description="Guest read order 1",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        module="auth_matrix",
        impact="Leak sensitive order data",
        affected_urls=["http://127.0.0.1:3000/api/orders/1"],
    )
    from armorscan.core.models import ModuleResult
    mod = ModuleResult(module_name="auth_matrix", display_name="Auth Matrix", findings=[bola_finding])
    scan_res = ScanResult(target=target, modules=[mod])

    full_html = HtmlReporter.generate(scan_res)
    assert "Role Access Control Matrix (BOLA / IDOR Verification)" in full_html
    assert "CRITICAL BOLA" in full_html
    assert "/api/orders/1" in full_html
    assert "200 OK" in full_html
