"""
Interactive Attack Surface & Risk Topology Graph Generator (reporters/graph.py).
Builds a zero-CDN, standalone SVG & Canvas interactive network topology map
illustrating Target Host -> Endpoints / Open Ports -> Security Vulnerability Nodes.
Supports interactive node clicks with smooth-scroll linking directly to finding cards.
"""

from __future__ import annotations

import html
import math
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlparse

from armorscan.core.models import Finding, ScanResult, Severity


class GraphNode:
    """Represents a node in the attack surface topology graph."""

    def __init__(
        self,
        node_id: str,
        label: str,
        node_type: str,  # "host", "endpoint", "port", "finding"
        severity: str = "INFO",
        finding_id: str = "",
        details: str = "",
    ):
        self.node_id = node_id
        self.label = label
        self.node_type = node_type
        self.severity = severity
        self.finding_id = finding_id
        self.details = details
        self.x: float = 0.0
        self.y: float = 0.0
        self.radius: float = 16.0


class GraphLink:
    """Represents an edge linking two nodes in the topology graph."""

    def __init__(self, source_id: str, target_id: str, edge_type: str = "route"):
        self.source_id = source_id
        self.target_id = target_id
        self.edge_type = edge_type


class AttackSurfaceGraphBuilder:
    """Constructs the interactive attack surface network topology."""

    SEV_COLORS = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#38bdf8",
        "INFO": "#94a3b8",
        "HOST": "#10b981",
        "ENDPOINT": "#6366f1",
        "PORT": "#a855f7",
    }

    @classmethod
    def build(cls, result: ScanResult) -> Tuple[List[GraphNode], List[GraphLink]]:
        nodes: Dict[str, GraphNode] = {}
        links: List[GraphLink] = []

        # 1. Central Host Node
        host_id = "node_host"
        host_label = result.target.host or "Target Host"
        nodes[host_id] = GraphNode(
            node_id=host_id,
            label=host_label,
            node_type="host",
            severity="HOST",
            details=f"Target URL: {result.target.raw_url}",
        )
        nodes[host_id].radius = 28.0

        # 2. Extract Endpoints & associate with Findings
        endpoint_nodes: Set[str] = set()
        routes_discovered = list(result.target.discovered_paths or ["/"])
        # Add affected URLs from findings
        for f in result.all_findings:
            for u in f.affected_urls:
                try:
                    p = urlparse(u).path or "/"
                    if p not in routes_discovered:
                        routes_discovered.append(p)
                except Exception:
                    pass

        # Limit displayed endpoints in graph to top 15 for optimal visual clarity
        capped_routes = routes_discovered[:15]
        for idx, route in enumerate(capped_routes):
            clean_route = route if len(route) <= 24 else route[:21] + "..."
            ep_id = f"ep_{idx}"
            endpoint_nodes.add(ep_id)
            nodes[ep_id] = GraphNode(
                node_id=ep_id,
                label=clean_route,
                node_type="endpoint",
                severity="ENDPOINT",
                details=f"Path: {route}",
            )
            nodes[ep_id].radius = 16.0
            links.append(GraphLink(source_id=host_id, target_id=ep_id, edge_type="route"))

        # 3. Add Port Nodes (if port discovery or non-default port)
        target_port = result.target.port
        if target_port and target_port not in (80, 443):
            port_id = f"port_{target_port}"
            nodes[port_id] = GraphNode(
                node_id=port_id,
                label=f":{target_port}",
                node_type="port",
                severity="PORT",
                details=f"Open Port: {target_port}",
            )
            nodes[port_id].radius = 18.0
            links.append(GraphLink(source_id=host_id, target_id=port_id, edge_type="port"))

        # 4. Attach Finding Nodes to corresponding endpoints or host
        for f_idx, f in enumerate(result.all_findings):
            f_id = f"finding_{f_idx}"
            sev_str = f.severity.value.upper()
            f_label = f.id
            if len(f_label) > 18:
                f_label = f_label[:16] + ".."

            nodes[f_id] = GraphNode(
                node_id=f_id,
                label=f_label,
                node_type="finding",
                severity=sev_str,
                finding_id=f.id,
                details=f"[{sev_str}] {f.title}",
            )
            nodes[f_id].radius = 14.0

            # Find matching endpoint node
            connected = False
            for aff_url in f.affected_urls:
                aff_path = urlparse(aff_url).path
                for ep_idx, r in enumerate(capped_routes):
                    if r == aff_path:
                        links.append(GraphLink(source_id=f"ep_{ep_idx}", target_id=f_id, edge_type="vulnerability"))
                        connected = True
                        break
                if connected:
                    break

            if not connected:
                # Attach to root endpoint (ep_0) or host
                parent = "ep_0" if "ep_0" in nodes else host_id
                links.append(GraphLink(source_id=parent, target_id=f_id, edge_type="vulnerability"))

        # 5. Compute Layout Positions (Radial Multi-Tier Layout)
        cls._compute_layout(nodes, links, host_id)

        return list(nodes.values()), links

    @classmethod
    def _compute_layout(cls, nodes: Dict[str, GraphNode], links: List[GraphLink], host_id: str):
        center_x = 500.0
        center_y = 300.0

        if host_id in nodes:
            nodes[host_id].x = center_x
            nodes[host_id].y = center_y

        # Separate nodes into tiers
        tier1 = [n for n in nodes.values() if n.node_type in ("endpoint", "port")]
        tier2 = [n for n in nodes.values() if n.node_type == "finding"]

        # Tier 1 (Endpoints & Ports) circle around host
        radius_tier1 = 160.0
        n_t1 = len(tier1)
        for i, n in enumerate(tier1):
            angle = (2.0 * math.pi * i) / max(1, n_t1)
            n.x = center_x + radius_tier1 * math.cos(angle)
            n.y = center_y + radius_tier1 * math.sin(angle)

        # Tier 2 (Findings) orbit outside tier 1
        radius_tier2 = 250.0
        n_t2 = len(tier2)
        for j, n in enumerate(tier2):
            angle = (2.0 * math.pi * j) / max(1, n_t2) + 0.15
            n.x = center_x + radius_tier2 * math.cos(angle)
            n.y = center_y + radius_tier2 * math.sin(angle)

    @classmethod
    def render_svg_component(cls, result: ScanResult) -> str:
        """Render complete interactive standalone SVG and control widget."""
        nodes, links = cls.build(result)
        node_map = {n.node_id: n for n in nodes}

        # Render SVG edges
        edges_svg = []
        for l in links:
            s = node_map.get(l.source_id)
            t = node_map.get(l.target_id)
            if s and t:
                stroke_color = "#334155" if l.edge_type != "vulnerability" else "#ef4444"
                stroke_dash = "" if l.edge_type != "vulnerability" else 'stroke-dasharray="3 3"'
                edges_svg.append(
                    f'<line x1="{s.x:.1f}" y1="{s.y:.1f}" x2="{t.x:.1f}" y2="{t.y:.1f}" '
                    f'stroke="{stroke_color}" stroke-width="1.6" stroke-opacity="0.6" {stroke_dash} />'
                )

        # Render SVG nodes
        nodes_svg = []
        for n in nodes:
            color = cls.SEV_COLORS.get(n.severity, "#94a3b8")
            cursor = "pointer" if n.finding_id else "default"
            onclick = f"onclick=\"focusFindingCard('{n.finding_id}')\"" if n.finding_id else ""
            escaped_details = html.escape(n.details)
            escaped_label = html.escape(n.label)

            glow = ""
            if n.severity in ("CRITICAL", "HIGH"):
                glow = f'<circle cx="{n.x:.1f}" cy="{n.y:.1f}" r="{n.radius + 6:.1f}" fill="{color}" opacity="0.18" />'

            nodes_svg.append(
                f'<g class="graph-node-group" {onclick} style="cursor: {cursor};" data-finding="{n.finding_id}">'
                f'  <title>{escaped_details}</title>'
                f'  {glow}'
                f'  <circle cx="{n.x:.1f}" cy="{n.y:.1f}" r="{n.radius:.1f}" fill="#0f172a" stroke="{color}" stroke-width="2.5" />'
                f'  <text x="{n.x:.1f}" y="{n.y + 4:.1f}" text-anchor="middle" fill="#f8fafc" '
                f'        font-family="ui-monospace, monospace" font-size="10.5" font-weight="600">{escaped_label}</text>'
                f'</g>'
            )

        component_html = f"""
<div class="attack-graph-container">
  <div class="graph-header">
    <div class="graph-title">
      <span>🌐 Interactive Attack Surface & Risk Topology Map</span>
      <span class="graph-badge">{len(nodes)} Nodes • {len(links)} Relationships</span>
    </div>
    <div class="graph-legend">
      <span class="legend-item"><span class="legend-dot" style="background: #10b981;"></span> Host</span>
      <span class="legend-item"><span class="legend-dot" style="background: #6366f1;"></span> Endpoints</span>
      <span class="legend-item"><span class="legend-dot" style="background: #ef4444;"></span> Critical Risk</span>
      <span class="legend-item"><span class="legend-dot" style="background: #f97316;"></span> High Risk</span>
      <span class="legend-item"><span class="legend-dot" style="background: #eab308;"></span> Medium Risk</span>
      <span class="legend-hint">💡 Click any risk node to jump directly to its finding card</span>
    </div>
  </div>

  <div class="svg-viewport-wrapper">
    <svg id="attackSurfaceSvg" viewBox="150 20 700 560" width="100%" height="420" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <radialGradient id="graphBgGlow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stop-color="#1e293b" stop-opacity="0.3" />
          <stop offset="100%" stop-color="#090d16" stop-opacity="0" />
        </radialGradient>
      </defs>
      <rect x="0" y="0" width="1000" height="600" fill="transparent" />
      <circle cx="500" cy="300" r="260" fill="url(#graphBgGlow)" />
      <g id="graphEdgesGroup">
        {''.join(edges_svg)}
      </g>
      <g id="graphNodesGroup">
        {''.join(nodes_svg)}
      </g>
    </svg>
  </div>
</div>
"""
        return component_html
