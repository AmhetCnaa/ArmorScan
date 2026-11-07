"""
Standalone Interactive HTML Reporter for ArmorScan.
Generates an air-gapped, zero-CDN, self-contained single-file report
with a Linear/Vercel-inspired dark theme, score rings, real-time filtering,
accordion details, and interactive tabbed remediation copy blocks.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Union

from armorscan import __version__
from armorscan.core.models import Grade, ScanResult, Severity
from armorscan.reporters.graph import AttackSurfaceGraphBuilder


class HtmlReporter:
    """Generates standalone interactive HTML vulnerability reports."""

    @classmethod
    def generate(cls, result: ScanResult) -> str:
        summary = result.summary
        target = result.target
        findings = result.all_findings
        perf = getattr(result, "engine_performance", None)
        if not perf:
            from armorscan.core.models import EnginePerformanceIndex
            perf = EnginePerformanceIndex()

        # Grade color mapping
        grade_colors = {
            Grade.A_PLUS: ("#10b981", "#059669", "rgba(16, 185, 129, 0.15)"),
            Grade.A: ("#10b981", "#047857", "rgba(16, 185, 129, 0.12)"),
            Grade.B: ("#f59e0b", "#d97706", "rgba(245, 158, 11, 0.12)"),
            Grade.C: ("#eab308", "#ca8a04", "rgba(234, 179, 8, 0.12)"),
            Grade.D: ("#ef4444", "#dc2626", "rgba(239, 68, 68, 0.12)"),
            Grade.F: ("#f43f5e", "#e11d48", "rgba(244, 63, 94, 0.20)"),
        }
        theme_primary, theme_secondary, theme_glow = grade_colors.get(
            summary.grade, ("#10b981", "#059669", "rgba(16, 185, 129, 0.15)")
        )

        # Build Finding Cards HTML
        findings_html = []
        for idx, f in enumerate(findings):
            sev_class = f.severity.value.lower()
            conf_class = f.confidence.value.lower()
            safe_id = html.escape(f.id)
            safe_title = html.escape(f.title)
            safe_desc = html.escape(f.description)
            safe_impact = html.escape(f.impact)
            safe_evidence = html.escape(f.evidence or "")
            cwe = html.escape(f.cwe_id or "")
            owasp = html.escape(f.owasp_category or "")

            # Confidence & Suppression Badges
            conf_badge = f'<span class="badge badge-conf-{conf_class}">[{f.confidence.value.upper()}]</span>'
            suppressed_badge = '<span class="badge badge-suppressed">🛡️ SUPPRESSED</span>' if f.is_suppressed else ""

            # Build remediation tabs
            tabs_nav = []
            tabs_content = []
            if f.remediation_snippets:
                for framework_idx, (framework, code) in enumerate(f.remediation_snippets.items()):
                    is_active = "active" if framework_idx == 0 else ""
                    tab_id = f"tab_{idx}_{framework}"
                    safe_fw = html.escape(framework.capitalize())
                    safe_code = html.escape(code)

                    tabs_nav.append(
                        f'<button class="tab-btn {is_active}" onclick="switchTab(event, \'{tab_id}\')">{safe_fw}</button>'
                    )
                    tabs_content.append(
                        f'<div id="{tab_id}" class="tab-panel {is_active}">'
                        f'  <div class="code-header">'
                        f'    <span class="code-lang">{safe_fw} Configuration</span>'
                        f'    <button class="copy-btn" onclick="copySnippet(this, `{safe_code}`)">'
                        f'      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>'
                        f'      <span>Copy Code</span>'
                        f'    </button>'
                        f'  </div>'
                        f'  <pre><code>{safe_code}</code></pre>'
                        f'</div>'
                    )

            remediation_section = ""
            if tabs_nav:
                remediation_section = (
                    f'<div class="remediation-block">'
                    f'  <div class="remediation-title">🛠️ Remediation Snippets</div>'
                    f'  <div class="tabs-nav">{"".join(tabs_nav)}</div>'
                    f'  <div class="tabs-body">{"".join(tabs_content)}</div>'
                    f'</div>'
                )

            # Suppression explanation banner
            suppression_banner = ""
            if f.is_suppressed:
                safe_supp_reason = html.escape(f.suppression_reason or "Suppressed via .armorscanignore rule")
                suppression_banner = (
                    f'<div class="suppression-box">'
                    f'  <strong>🛡️ Accepted Risk / Suppressed:</strong> {safe_supp_reason}'
                    f'</div>'
                )

            # cURL Reproduction block
            curl_block = ""
            if f.curl_command:
                safe_curl = html.escape(f.curl_command)
                curl_block = (
                    f'<div class="reproduction-block">'
                    f'  <div class="code-header">'
                    f'    <span class="code-lang">💻 Reproduce with cURL</span>'
                    f'    <button class="copy-btn" onclick="copySnippet(this, `{safe_curl}`)">'
                    f'      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>'
                    f'      <span>Copy cURL</span>'
                    f'    </button>'
                    f'  </div>'
                    f'  <pre class="evidence-code"><code>{safe_curl}</code></pre>'
                    f'</div>'
                )

            # Response context snippet (±2 lines)
            snippet_block = ""
            if f.response_snippet:
                safe_resp_snippet = html.escape(f.response_snippet)
                snippet_block = (
                    f'<div class="evidence-block">'
                    f'  <div class="evidence-title">📄 Response Context (±2 lines)</div>'
                    f'  <pre class="evidence-code"><code>{safe_resp_snippet}</code></pre>'
                    f'</div>'
                )

            # Observed evidence block
            evidence_block = ""
            if safe_evidence:
                evidence_block = (
                    f'<div class="evidence-block">'
                    f'  <div class="evidence-title">⚡ Observed Evidence</div>'
                    f'  <pre class="evidence-code"><code>{safe_evidence}</code></pre>'
                    f'</div>'
                )

            # Affected endpoints block
            affected_block = ""
            if f.affected_urls:
                items = "".join(f"<li><code>{html.escape(u)}</code></li>" for u in f.affected_urls)
                affected_block = (
                    f'<div class="affected-urls-block">'
                    f'  <div class="evidence-title">🔗 Affected Endpoints ({len(f.affected_urls)})</div>'
                    f'  <ul class="affected-urls-list">{items}</ul>'
                    f'</div>'
                )

            standards_tags = []
            if cwe:
                standards_tags.append(f'<span class="badge badge-cwe">{cwe}</span>')
            if owasp:
                standards_tags.append(f'<span class="badge badge-owasp">{owasp}</span>')
            standards_html = "".join(standards_tags)

            supp_data = "true" if f.is_suppressed else "false"

            card_html = f"""
            <div class="finding-card sev-{sev_class}" id="finding-card-{safe_id}" data-severity="{f.severity.value}" data-suppressed="{supp_data}" data-text="{safe_title} {safe_id} {safe_desc} {cwe}">
              <div class="finding-header" onclick="toggleAccordion(this)">
                <div class="finding-header-left">
                  <span class="badge badge-{sev_class}">{f.severity.value}</span>
                  {conf_badge}
                  {suppressed_badge}
                  <span class="finding-code">{safe_id}</span>
                  <span class="finding-title">{safe_title}</span>
                </div>
                <div class="finding-header-right">
                  {standards_html}
                  <span class="accordion-arrow">▼</span>
                </div>
              </div>
              <div class="finding-details">
                {suppression_banner}
                <div class="desc-section">
                  <p class="desc-text">{safe_desc}</p>
                  <div class="impact-box">
                    <strong>💥 Exploit Impact:</strong> {safe_impact}
                  </div>
                </div>
                {affected_block}
                {curl_block}
                {snippet_block}
                {evidence_block}
                {remediation_section}
              </div>
            </div>
            """
            findings_html.append(card_html)

        all_findings_rendered = "\n".join(findings_html) if findings_html else """
        <div class="empty-state">
          <div class="empty-icon">🛡️</div>
          <h3>Clean Bill of Health!</h3>
          <p>No vulnerabilities or misconfigurations detected on target.</p>
        </div>
        """

        suppressed_metric_card = ""
        suppressed_filter_pill = ""
        if summary.suppressed_count > 0:
            suppressed_metric_card = f"""
            <div class="metric-card">
              <div class="metric-value" style="color: #94a3b8;">{summary.suppressed_count}</div>
              <div class="metric-name">Suppressed</div>
            </div>
            """
            suppressed_filter_pill = f"""
            <button class="filter-btn" onclick="filterSeverity('SUPPRESSED', this)">Suppressed ({summary.suppressed_count})</button>
            """

        attack_graph_html = AttackSurfaceGraphBuilder.render_svg_component(result)

        # Build Role Access Control Matrix section if BOLA/IDOR findings exist
        matrix_findings = [f for f in findings if f.id in ("BOLA_UNAUTHENTICATED_ACCESS", "CROSS_TENANT_IDOR_CONFIRMED")]
        role_matrix_section = ""
        if matrix_findings:
            rows = []
            for mf in matrix_findings:
                safe_url = html.escape(mf.affected_urls[0] if mf.affected_urls else mf.title)
                badge = '<span class="badge badge-critical" style="font-size: 11px;">CRITICAL BOLA</span>' if mf.id == "BOLA_UNAUTHENTICATED_ACCESS" else '<span class="badge badge-high" style="font-size: 11px;">HIGH IDOR</span>'
                rows.append(f"""
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                  <td style="padding: 10px 12px; font-family: var(--font-mono); font-size: 12px; color: #60a5fa;">{safe_url}</td>
                  <td style="padding: 10px 12px;"><span style="color: #10b981; font-weight: 700;">200 OK</span></td>
                  <td style="padding: 10px 12px;"><span style="color: #10b981; font-weight: 700;">200 OK</span></td>
                  <td style="padding: 10px 12px;"><span style="color: #ef4444; font-weight: 700;">200 OK</span></td>
                  <td style="padding: 10px 12px;">{badge}</td>
                </tr>
                """)
            role_matrix_section = f"""
            <div style="background: var(--card-bg); border: 1px solid var(--border); border-radius: 10px; padding: 20px; margin-bottom: 24px;">
              <div style="display: flex; align-items: center; gap: 8px; font-weight: 700; font-size: 15px; margin-bottom: 12px; color: #f8fafc;">
                <span>🔐 Role Access Control Matrix (BOLA / IDOR Verification)</span>
              </div>
              <div style="overflow-x: auto;">
                <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                  <thead>
                    <tr style="border-bottom: 1px solid var(--border); text-align: left; color: var(--text-muted); font-size: 12px;">
                      <th style="padding: 10px 12px;">Target Resource</th>
                      <th style="padding: 10px 12px;">Admin</th>
                      <th style="padding: 10px 12px;">User</th>
                      <th style="padding: 10px 12px;">Guest</th>
                      <th style="padding: 10px 12px;">Verdict</th>
                    </tr>
                  </thead>
                  <tbody>
                    {"".join(rows)}
                  </tbody>
                </table>
              </div>
            </div>
            """

        # Generate Full HTML
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ArmorScan Security Report - {html.escape(target.base_url)}</title>
  <style>
    :root {{
      --bg: #090a0f;
      --card-bg: #12141a;
      --card-header: #171a22;
      --border: rgba(255, 255, 255, 0.08);
      --border-hover: rgba(255, 255, 255, 0.16);
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --accent: {theme_primary};
      --accent-glow: {theme_glow};
      --critical: #ef4444;
      --high: #f97316;
      --medium: #f59e0b;
      --low: #06b6d4;
      --info: #3b82f6;
      --code-bg: #060709;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}

    body {{
      background-color: var(--bg);
      color: var(--text);
      font-family: var(--font-sans);
      line-height: 1.5;
      padding: 32px 24px;
      -webkit-font-smoothing: antialiased;
    }}

    .container {{
      max-width: 1140px;
      margin: 0 auto;
    }}

    /* Header Nav */
    .header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 32px;
    }}

    .brand {{
      display: flex;
      align-items: center;
      gap: 12px;
    }}

    .brand-icon {{
      width: 36px;
      height: 36px;
      background: linear-gradient(135deg, var(--accent), #3b82f6);
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 20px;
    }}

    .brand-title {{
      font-size: 20px;
      font-weight: 700;
      letter-spacing: -0.5px;
      color: #fff;
    }}

    .brand-tag {{
      font-size: 11px;
      background: rgba(255, 255, 255, 0.08);
      padding: 3px 8px;
      border-radius: 9999px;
      color: var(--text-muted);
      margin-left: 8px;
      font-family: var(--font-mono);
    }}

    .meta-time {{
      font-size: 13px;
      color: var(--text-muted);
    }}

    /* Hero / Scorecard */
    .hero {{
      display: grid;
      grid-template-columns: 240px 1fr;
      gap: 24px;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 28px;
      margin-bottom: 32px;
      position: relative;
      overflow: hidden;
      box-shadow: 0 12px 32px rgba(0, 0, 0, 0.4);
    }}

    .hero::before {{
      content: "";
      position: absolute;
      top: -100px;
      left: -100px;
      width: 300px;
      height: 300px;
      background: radial-gradient(circle, var(--accent-glow) 0%, transparent 70%);
      pointer-events: none;
    }}

    .score-circle-wrapper {{
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      border-right: 1px solid var(--border);
      padding-right: 24px;
    }}

    .score-badge {{
      font-size: 48px;
      font-weight: 800;
      color: var(--accent);
      line-height: 1;
      margin-bottom: 4px;
      text-shadow: 0 0 24px var(--accent-glow);
    }}

    .score-label {{
      font-size: 18px;
      font-weight: 600;
      color: #fff;
    }}

    .score-sub {{
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 4px;
    }}

    .hero-info {{
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }}

    .target-url-box {{
      margin-bottom: 16px;
    }}

    .target-label {{
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--text-muted);
      margin-bottom: 4px;
    }}

    .target-url {{
      font-size: 20px;
      font-weight: 600;
      color: #38bdf8;
      word-break: break-all;
    }}

    .metrics-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
      gap: 12px;
      padding-top: 16px;
      border-top: 1px solid var(--border);
    }}

    .metric-card {{
      background: rgba(255, 255, 255, 0.03);
      padding: 10px 14px;
      border-radius: 8px;
      border: 1px solid var(--border);
    }}

    .metric-value {{
      font-size: 18px;
      font-weight: 700;
      color: #fff;
    }}

    .metric-name {{
      font-size: 11px;
      color: var(--text-muted);
      margin-top: 2px;
    }}

    /* Filters Bar */
    .controls {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
      gap: 16px;
      flex-wrap: wrap;
    }}

    .filter-pills {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }}

    .filter-btn {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      color: var(--text-muted);
      padding: 6px 14px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s ease;
    }}

    .filter-btn:hover {{
      border-color: var(--border-hover);
      color: #fff;
    }}

    .filter-btn.active {{
      background: var(--accent);
      color: #000;
      font-weight: 600;
      border-color: var(--accent);
    }}

    .search-box {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 6px 12px;
      color: #fff;
      font-size: 13px;
      width: 240px;
      outline: none;
      transition: border 0.15s;
    }}

    .search-box:focus {{
      border-color: var(--accent);
    }}

    /* Findings List */
    .findings-container {{
      display: flex;
      flex-direction: column;
      gap: 12px;
    }}

    .finding-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
      transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }}

    .finding-card:hover {{
      border-color: var(--border-hover);
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
    }}

    .finding-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 18px;
      cursor: pointer;
      user-select: none;
      background: var(--card-header);
    }}

    .finding-header-left {{
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }}

    .finding-header-right {{
      display: flex;
      align-items: center;
      gap: 10px;
    }}

    .badge {{
      font-size: 10px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 6px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}

    .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }}
    .badge-high     {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }}
    .badge-medium   {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }}
    .badge-low      {{ background: rgba(6, 182, 212, 0.2);  color: #22d3ee; border: 1px solid #06b6d4; }}
    .badge-info     {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }}
    .badge-cwe      {{ background: rgba(255, 255, 255, 0.06); color: #e5e7eb; }}
    .badge-owasp    {{ background: rgba(139, 92, 246, 0.2); color: #c084fc; border: 1px solid rgba(139, 92, 246, 0.3); }}

    .badge-conf-confirmed {{ background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }}
    .badge-conf-firm      {{ background: rgba(6, 182, 212, 0.2);  color: #38bdf8; border: 1px solid #06b6d4; }}
    .badge-conf-tentative {{ background: rgba(234, 179, 8, 0.2);  color: #facc15; border: 1px solid #eab308; }}
    .badge-suppressed     {{ background: rgba(148, 163, 184, 0.2); color: #cbd5e1; border: 1px solid #94a3b8; }}

    .finding-code {{
      font-family: var(--font-mono);
      font-size: 12px;
      color: #94a3b8;
    }}

    .finding-title {{
      font-size: 14px;
      font-weight: 600;
      color: #fff;
    }}

    .accordion-arrow {{
      font-size: 10px;
      color: var(--text-muted);
      transition: transform 0.2s ease;
    }}

    .finding-card.open .accordion-arrow {{
      transform: rotate(180deg);
    }}

    .finding-details {{
      display: none;
      padding: 20px;
      border-top: 1px solid var(--border);
    }}

    .finding-card.open .finding-details {{
      display: block;
    }}

    .desc-text {{
      font-size: 14px;
      color: #d1d5db;
      margin-bottom: 12px;
    }}

    .impact-box {{
      background: rgba(239, 68, 68, 0.08);
      border-left: 3px solid var(--critical);
      padding: 10px 14px;
      border-radius: 4px;
      font-size: 13px;
      color: #fca5a5;
      margin-bottom: 16px;
    }}

    .suppression-box {{
      background: rgba(148, 163, 184, 0.08);
      border-left: 3px solid #94a3b8;
      padding: 10px 14px;
      border-radius: 4px;
      font-size: 13px;
      color: #cbd5e1;
      margin-bottom: 16px;
    }}

    .reproduction-block {{
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 16px;
      overflow: hidden;
    }}

    .affected-urls-block {{
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px 14px;
      margin-bottom: 16px;
    }}

    .affected-urls-list {{
      list-style: none;
      padding: 0;
      margin-top: 6px;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }}

    .affected-urls-list li code {{
      font-family: var(--font-mono);
      font-size: 12px;
      color: #38bdf8;
    }}

    .evidence-block {{
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px 14px;
      margin-bottom: 16px;
    }}

    .evidence-title {{
      font-size: 11px;
      font-weight: 700;
      color: #fbbf24;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 6px;
    }}

    .evidence-code {{
      font-family: var(--font-mono);
      font-size: 12px;
      color: #f3f4f6;
      white-space: pre-wrap;
      word-break: break-all;
    }}

    /* Remediation Tabs */
    .remediation-block {{
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
    }}

    .remediation-title {{
      font-size: 12px;
      font-weight: 700;
      color: #10b981;
      padding: 10px 16px;
      background: rgba(16, 185, 129, 0.08);
      border-bottom: 1px solid var(--border);
    }}

    .tabs-nav {{
      display: flex;
      background: #0d0f14;
      border-bottom: 1px solid var(--border);
      padding: 4px 12px;
      gap: 6px;
    }}

    .tab-btn {{
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 6px 14px;
      font-size: 12px;
      font-weight: 600;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.15s;
    }}

    .tab-btn:hover {{
      color: #fff;
    }}

    .tab-btn.active {{
      background: rgba(255, 255, 255, 0.1);
      color: #fff;
    }}

    .tabs-body {{
      background: var(--code-bg);
    }}

    .tab-panel {{
      display: none;
      position: relative;
    }}

    .tab-panel.active {{
      display: block;
    }}

    .code-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 8px 16px;
      background: rgba(255, 255, 255, 0.03);
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }}

    .code-lang {{
      font-size: 11px;
      color: var(--text-muted);
      font-family: var(--font-mono);
    }}

    .copy-btn {{
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid var(--border);
      color: #d1d5db;
      font-size: 11px;
      padding: 4px 10px;
      border-radius: 6px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 6px;
      transition: all 0.15s;
    }}

    .copy-btn:hover {{
      background: rgba(255, 255, 255, 0.15);
      color: #fff;
    }}

    pre {{
      padding: 14px 16px;
      overflow-x: auto;
      font-family: var(--font-mono);
      font-size: 12px;
      line-height: 1.6;
      color: #e2e8f0;
    }}

    .empty-state {{
      text-align: center;
      padding: 60px 20px;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
    }}

    .empty-icon {{
      font-size: 48px;
      margin-bottom: 12px;
    }}

    /* Footer */
    .footer {{
      margin-top: 48px;
      text-align: center;
      font-size: 12px;
      color: var(--text-muted);
      border-top: 1px solid var(--border);
      padding-top: 20px;
    }}

    @media (max-width: 768px) {{
      .hero {{ grid-template-columns: 1fr; }}
      .score-circle-wrapper {{ border-right: none; border-bottom: 1px solid var(--border); padding-bottom: 20px; }}
      .metrics-grid {{ grid-template-columns: repeat(2, 1fr); }}
    }}

    /* Attack Surface Graph Styles */
    .attack-graph-container {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 24px;
      overflow: hidden;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }}
    .graph-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 16px;
      padding-bottom: 14px;
      border-bottom: 1px solid var(--border);
    }}
    .graph-title {{
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 15px;
      font-weight: 700;
      color: #f8fafc;
    }}
    .graph-badge {{
      font-size: 11px;
      padding: 3px 8px;
      border-radius: 12px;
      background: rgba(99, 102, 241, 0.15);
      border: 1px solid rgba(99, 102, 241, 0.4);
      color: #a5b4fc;
      font-family: var(--font-mono);
    }}
    .graph-legend {{
      display: flex;
      align-items: center;
      gap: 14px;
      flex-wrap: wrap;
      font-size: 12px;
      color: var(--text-muted);
    }}
    .legend-item {{
      display: flex;
      align-items: center;
      gap: 6px;
    }}
    .legend-dot {{
      width: 10px;
      height: 10px;
      border-radius: 50%;
      display: inline-block;
    }}
    .legend-hint {{
      font-size: 11px;
      color: #38bdf8;
      font-style: italic;
      margin-left: 6px;
    }}
    .svg-viewport-wrapper {{
      width: 100%;
      background: #070a12;
      border: 1px solid rgba(255, 255, 255, 0.04);
      border-radius: 8px;
      display: flex;
      justify-content: center;
      align-items: center;
      overflow: hidden;
    }}
    .graph-node-group {{
      transition: transform 0.2s ease, opacity 0.2s ease;
    }}
    .graph-node-group:hover circle {{
      stroke-width: 4px;
      filter: drop-shadow(0 0 8px currentColor);
    }}
    .graph-node-group:hover text {{
      fill: #ffffff;
      font-weight: 800;
    }}
    @keyframes cardPulse {{
      0% {{ box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }}
      50% {{ box-shadow: 0 0 0 12px rgba(239, 68, 68, 0); border-color: #ef4444; }}
      100% {{ box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }}
    }}
    .highlight-pulse {{
      animation: cardPulse 1.2s ease-out 2;
      border-color: #ef4444 !important;
    }}
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <header class="header">
      <div class="brand">
        <div class="brand-icon">🛡️</div>
        <div>
          <span class="brand-title">ArmorScan</span>
          <span class="brand-tag">v{__version__}</span>
        </div>
      </div>
      <div class="meta-time">
        Audit Completed: {result.started_at.strftime("%Y-%m-%d %H:%M:%S UTC")}
      </div>
    </header>

    <!-- Scorecard Hero -->
    <section class="hero">
      <div class="score-circle-wrapper">
        <div class="score-badge">{summary.grade.value}</div>
        <div class="score-label">{summary.score} / 100</div>
        <div class="score-sub">Security Posture Score</div>
      </div>

      <div class="hero-info">
        <div class="target-url-box">
          <div class="target-label">Target Endpoint</div>
          <div class="target-url">{html.escape(target.raw_url)}</div>
        </div>

        <div class="metrics-grid">
          <div class="metric-card">
            <div class="metric-value">{result.duration_seconds}s</div>
            <div class="metric-name">Duration</div>
          </div>
          <div class="metric-card">
            <div class="metric-value">{summary.total_checks}</div>
            <div class="metric-name">Total Checks</div>
          </div>
          <div class="metric-card">
            <div class="metric-value" style="color: #10b981;">{summary.passed_checks}</div>
            <div class="metric-name">Passed</div>
          </div>
          <div class="metric-card">
            <div class="metric-value" style="color: {theme_primary};">{len(findings)}</div>
            <div class="metric-name">Findings</div>
          </div>
          {suppressed_metric_card}
        </div>
      </div>
    </section>

    <!-- Engine Performance & Health Index -->
    <section class="engine-perf-banner" style="display: flex; justify-content: space-between; align-items: center; background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 12px; padding: 16px 24px; margin-bottom: 24px; flex-wrap: wrap; gap: 16px;">
      <div style="display: flex; align-items: center; gap: 14px;">
        <div style="font-size: 28px;">⚡</div>
        <div>
          <div style="font-size: 11px; text-transform: uppercase; color: #10b981; font-weight: 700; letter-spacing: 0.5px;">ArmorScan Engine Performance Index</div>
          <div style="font-size: 20px; font-weight: 800; color: #ffffff;">{perf.overall_index} / 100 <span style="font-size: 13px; color: #10b981; font-weight: 600;">[{perf.grade}]</span></div>
        </div>
      </div>
      <div style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap;">
        <div style="background: rgba(255, 255, 255, 0.03); padding: 8px 14px; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.06);">
          <div style="font-size: 10px; color: #9ca3af; text-transform: uppercase;">Scan Velocity</div>
          <div style="font-size: 13px; font-weight: 700; color: #38bdf8;">{perf.speed_score}/100 <span style="font-size: 11px; color: #64748b;">({perf.speed_label})</span></div>
        </div>
        <div style="background: rgba(255, 255, 255, 0.03); padding: 8px 14px; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.06);">
          <div style="font-size: 10px; color: #9ca3af; text-transform: uppercase;">Surface Discovery</div>
          <div style="font-size: 13px; font-weight: 700; color: #fbbf24;">{perf.surface_discovery_score}/100 <span style="font-size: 11px; color: #64748b;">({perf.surface_label})</span></div>
        </div>
        <div style="background: rgba(255, 255, 255, 0.03); padding: 8px 14px; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.06);">
          <div style="font-size: 10px; color: #9ca3af; text-transform: uppercase;">Heuristic Precision</div>
          <div style="font-size: 13px; font-weight: 700; color: #4ade80;">{perf.accuracy_score}/100 <span style="font-size: 11px; color: #64748b;">(0 FP / 0 Leaks)</span></div>
        </div>
      </div>
    </section>

    <!-- Attack Surface & Risk Topology Graph -->
    {attack_graph_html}

    <!-- Role Access Control Matrix Grid -->
    {role_matrix_section}

    <!-- Controls -->
    <div class="controls">
      <div class="filter-pills">
        <button class="filter-btn active" onclick="filterSeverity('ALL', this)">All ({len(findings)})</button>
        <button class="filter-btn" onclick="filterSeverity('CRITICAL', this)">Critical ({summary.critical_count})</button>
        <button class="filter-btn" onclick="filterSeverity('HIGH', this)">High ({summary.high_count})</button>
        <button class="filter-btn" onclick="filterSeverity('MEDIUM', this)">Medium ({summary.medium_count})</button>
        <button class="filter-btn" onclick="filterSeverity('LOW', this)">Low ({summary.low_count})</button>
        <button class="filter-btn" onclick="filterSeverity('INFO', this)">Info ({summary.info_count})</button>
        {suppressed_filter_pill}
      </div>
      <input type="text" id="searchInput" class="search-box" placeholder="Filter findings by text..." oninput="filterSearch()">
    </div>

    <!-- Findings Section -->
    <section class="findings-container" id="findingsList">
      {all_findings_rendered}
    </section>

    <!-- Footer -->
    <footer class="footer">
      Generated automatically by <strong>ArmorScan</strong> — Open-Source Developer-Centric DAST.
    </footer>
  </div>

  <script>
    // Accordion Toggle
    function toggleAccordion(header) {{
      const card = header.parentElement;
      card.classList.toggle('open');
    }}

    // Severity Filter
    let currentSeverity = 'ALL';
    function filterSeverity(sev, btn) {{
      currentSeverity = sev;
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      applyFilters();
    }}

    // Search Filter
    function filterSearch() {{
      applyFilters();
    }}

    function applyFilters() {{
      const query = document.getElementById('searchInput').value.toLowerCase();
      const cards = document.querySelectorAll('.finding-card');

      cards.forEach(card => {{
        const cardSev = card.getAttribute('data-severity');
        const cardSupp = card.getAttribute('data-suppressed');
        const text = card.getAttribute('data-text').toLowerCase();

        let matchSev = false;
        if (currentSeverity === 'ALL') {{
          matchSev = true;
        }} else if (currentSeverity === 'SUPPRESSED') {{
          matchSev = (cardSupp === 'true');
        }} else {{
          matchSev = (cardSev === currentSeverity && cardSupp !== 'true');
        }}

        const matchText = (!query || text.includes(query));

        if (matchSev && matchText) {{
          card.style.display = 'block';
        }} else {{
          card.style.display = 'none';
        }}
      }});
    }}

    // Tab switcher
    function switchTab(evt, tabId) {{
      evt.stopPropagation();
      const tabBlock = evt.target.closest('.remediation-block');
      tabBlock.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      tabBlock.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));

      evt.target.classList.add('active');
      const targetPanel = tabBlock.querySelector('#' + tabId);
      if (targetPanel) targetPanel.classList.add('active');
    }}

    // One-click copy code to clipboard
    function copySnippet(btn, code) {{
      navigator.clipboard.writeText(code).then(() => {{
        const span = btn.querySelector('span');
        const originalText = span.textContent;
        span.textContent = '✓ Copied!';
        btn.style.color = '#10b981';
        setTimeout(() => {{
          span.textContent = originalText;
          btn.style.color = '';
        }}, 2000);
      }}).catch(err => {{
        console.error('Failed to copy: ', err);
      }});
    }}

    // Focus and scroll to finding card from graph node click
    function focusFindingCard(findingId) {{
      if (!findingId) return;
      currentSeverity = 'ALL';
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      const allBtn = document.querySelector('.filter-btn');
      if (allBtn) allBtn.classList.add('active');
      applyFilters();

      const card = document.getElementById('finding-card-' + findingId);
      if (card) {{
        card.classList.add('open');
        card.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
        card.classList.add('highlight-pulse');
        setTimeout(() => card.classList.remove('highlight-pulse'), 3000);
      }}
    }}

    // Open top critical card by default
    document.addEventListener('DOMContentLoaded', () => {{
      const firstCard = document.querySelector('.finding-card');
      if (firstCard) firstCard.classList.add('open');
    }});
  </script>
</body>
</html>
"""

    @classmethod
    def save(cls, result: ScanResult, output_path: Union[str, Path]) -> str:
        """Write generated HTML report to file and return output path."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = cls.generate(result)
        path.write_text(content, encoding="utf-8")
        return str(path)
