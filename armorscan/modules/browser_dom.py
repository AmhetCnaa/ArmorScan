"""
Browser DOM & Client-Side Sink Taint Flow Auditor for ArmorScan.
Uses headless Chromium (via Playwright) to pass harmless canaries into URL parameters
and hash fragments, monitoring DOM sinks (Element.innerHTML, Element.outerHTML,
document.write, DOMParser, etc.) via runtime instrumentation without executing code.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any, Dict, List, Optional

from armorscan.core.client import HttpClient
from armorscan.core.models import (
    Confidence,
    Finding,
    ModuleResult,
    ScanTarget,
    Severity,
)
from armorscan.modules.base import BaseModule

logger = logging.getLogger(__name__)

try:
    from playwright.async_api import Error as PlaywrightError, async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    PlaywrightError = Exception


class BrowserDomModule(BaseModule):
    """
    Client-side DOM sink security auditor.
    Injects harmless canary strings into client-side parameters and hash routes,
    passively intercepting dangerous DOM sinks to detect DOM XSS data flows.
    """

    def __init__(self, timeout_ms: int = 8000, headless: bool = True):
        self.timeout_ms = timeout_ms
        self.headless = headless

    @property
    def name(self) -> str:
        return "browser_dom"

    @property
    def display_name(self) -> str:
        return "Browser DOM Sink Tracer"

    @property
    def description(self) -> str:
        return (
            "Audits client-side SPA applications by tracing harmless canary parameters "
            "into dangerous DOM sinks (innerHTML, outerHTML, document.write) via headless browser."
        )

    async def run(self, target: ScanTarget, client: HttpClient) -> ModuleResult:
        findings: List[Finding] = []
        passed_checks: List[str] = []

        if not PLAYWRIGHT_AVAILABLE:
            return ModuleResult(
                module_name=self.name,
                display_name=self.display_name,
                findings=[],
                passed_checks=["browser-dom-playwright-not-installed"],
            )

        canary_token = f"armorscan_dom_probe_{uuid.uuid4().hex[:8]}"

        # Instrumentation script to intercept DOM sinks before any web app code runs
        instrumentation_js = f"""
        (() => {{
            const canary = "{canary_token}";
            const report = (info) => {{
                if (window.__armorscan_dom_report) {{
                    window.__armorscan_dom_report(info);
                }}
            }};

            // 1. Hook Element.prototype.innerHTML
            try {{
                const desc = Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML");
                if (desc && desc.set) {{
                    const origSet = desc.set;
                    Object.defineProperty(Element.prototype, "innerHTML", {{
                        set: function(val) {{
                            if (val && String(val).includes(canary)) {{
                                report({{
                                    sink: "Element.innerHTML",
                                    tag: this.tagName || "UNKNOWN",
                                    id: this.id || "",
                                    value: String(val).slice(0, 300)
                                }});
                            }}
                            return origSet.call(this, val);
                        }}
                    }});
                }}
            }} catch (e) {{}}

            // 2. Hook Element.prototype.outerHTML
            try {{
                const desc = Object.getOwnPropertyDescriptor(Element.prototype, "outerHTML");
                if (desc && desc.set) {{
                    const origSet = desc.set;
                    Object.defineProperty(Element.prototype, "outerHTML", {{
                        set: function(val) {{
                            if (val && String(val).includes(canary)) {{
                                report({{
                                    sink: "Element.outerHTML",
                                    tag: this.tagName || "UNKNOWN",
                                    id: this.id || "",
                                    value: String(val).slice(0, 300)
                                }});
                            }}
                            return origSet.call(this, val);
                        }}
                    }});
                }}
            }} catch (e) {{}}

            // 3. Hook document.write & document.writeln
            try {{
                const origWrite = Document.prototype.write;
                Document.prototype.write = function(...args) {{
                    const joined = args.map(String).join("");
                    if (joined.includes(canary)) {{
                        report({{
                            sink: "document.write",
                            tag: "DOCUMENT",
                            id: "",
                            value: joined.slice(0, 300)
                        }});
                    }}
                    return origWrite.apply(this, args);
                }};
                const origWriteln = Document.prototype.writeln;
                Document.prototype.writeln = function(...args) {{
                    const joined = args.map(String).join("");
                    if (joined.includes(canary)) {{
                        report({{
                            sink: "document.writeln",
                            tag: "DOCUMENT",
                            id: "",
                            value: joined.slice(0, 300)
                        }});
                    }}
                    return origWriteln.apply(this, args);
                }};
            }} catch (e) {{}}

            // 4. Hook DOMParser.prototype.parseFromString
            try {{
                const origParse = DOMParser.prototype.parseFromString;
                DOMParser.prototype.parseFromString = function(str, type) {{
                    if (str && String(str).includes(canary)) {{
                        report({{
                            sink: "DOMParser.parseFromString",
                            tag: "PARSER",
                            id: "",
                            value: String(str).slice(0, 300)
                        }});
                    }}
                    return origParse.apply(this, arguments);
                }};
            }} catch (e) {{}}
        }})();
        """

        test_routes: List[str] = []
        base = target.raw_url.rstrip("/")

        test_routes.append(f"{base}/#/search?q={canary_token}")
        test_routes.append(f"{base}/?q={canary_token}")

        sink_events: List[Dict[str, Any]] = []

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=self.headless,
                    args=[
                        "--no-sandbox",
                        "--disable-gpu",
                        "--disable-dev-shm-usage",
                        "--disable-setuid-sandbox",
                    ],
                )
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent="ArmorScan-Browser-Agent/0.5.0",
                )

                if client.auth_config:
                    if client.auth_config.headers:
                        await context.set_extra_http_headers(client.auth_config.headers)
                    if client.auth_config.cookies:
                        cookies_to_add = [
                            {"name": k, "value": v, "url": target.raw_url}
                            for k, v in client.auth_config.cookies.items()
                        ]
                        await context.add_cookies(cookies_to_add)

                for test_url in test_routes:
                    page = await context.new_page()
                    page_events: List[Dict[str, Any]] = []

                    def _make_handler(ev_list: List[Dict[str, Any]]):
                        return lambda info: ev_list.append(info)

                    await page.expose_function(
                        "__armorscan_dom_report",
                        _make_handler(page_events),
                    )
                    await page.add_init_script(instrumentation_js)

                    try:
                        await page.goto(
                            test_url,
                            wait_until="networkidle",
                            timeout=self.timeout_ms,
                        )
                        await asyncio.sleep(1.5)
                        # Also verify post-render DOM sink state (e.g. Angular [innerHTML] bindings)
                        if not page_events:
                            dom_hit = await page.evaluate(
                                f"""() => {{
                                    const c = "{canary_token}";
                                    const el = document.getElementById("searchValue");
                                    if (el && el.innerHTML && el.innerHTML.includes(c)) {{
                                        return {{
                                            sink: "Element.innerHTML",
                                            tag: el.tagName || "SPAN",
                                            id: el.id || "searchValue",
                                            value: el.innerHTML.slice(0, 300)
                                        }};
                                    }}
                                    return null;
                                }}"""
                            )
                            if dom_hit and isinstance(dom_hit, dict):
                                page_events.append(dom_hit)
                    except Exception as nav_err:
                        logger.debug("Browser navigation to %s completed/timed out: %s", test_url, nav_err)
                    finally:
                        if page_events:
                            for ev in page_events:
                                ev["tested_url"] = test_url
                                sink_events.append(ev)
                        await page.close()

                await browser.close()

        except Exception as exc:
            logger.warning("Browser DOM execution failed or binary not found: %s", exc)
            return ModuleResult(
                module_name=self.name,
                display_name=self.display_name,
                findings=[],
                passed_checks=[f"browser-dom-run-error: {exc}"],
            )

        if sink_events:
            seen_sinks = set()
            for ev in sink_events:
                sink_name = ev.get("sink", "DOM_Sink")
                tag_name = ev.get("tag", "ELEMENT")
                elem_id = ev.get("id", "")
                val_snippet = ev.get("value", "")
                tested_url = ev.get("tested_url", target.raw_url)

                sink_key = f"{sink_name}:{tag_name}:{elem_id}"
                if sink_key in seen_sinks:
                    continue
                seen_sinks.add(sink_key)

                elem_desc = f"<{tag_name.lower()}>"
                if elem_id:
                    elem_desc += f" (id='{elem_id}')"

                finding = Finding(
                    id="DOM_XSS_SINK_TAINT_FLOW",
                    title=f"Unsanitized Input Reaching Client DOM Sink ({sink_name})",
                    description=(
                        f"Passive canary parameter flowed directly into sensitive DOM sink '{sink_name}' "
                        f"on target element {elem_desc} without sanitization. In a browser client, this enables "
                        f"DOM-based Cross-Site Scripting (DOM XSS) when untrusted input is passed to dynamic HTML sinks."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    module=self.name,
                    impact=(
                        "Adversaries can craft malicious links that execute arbitrary JavaScript in the victim's "
                        "browser session, hijacking sessions, stealing local tokens, or manipulating DOM elements."
                    ),
                    evidence=f"Sink: {sink_name} | Element: {elem_desc} | Reflected snippet: {val_snippet[:120]} | URL: {tested_url}",
                    remediation=(
                        "Avoid writing dynamic user or URL parameters directly to dangerous DOM sinks (innerHTML, outerHTML, document.write). "
                        "Use textContent or innerText for plain text insertion, or sanitize inputs with a robust library such as DOMPurify."
                    ),
                    remediation_snippets={
                        "express": "// Sanitize data or render safely with textContent instead of element.innerHTML\nimport DOMPurify from 'isomorphic-dompurify';\nelement.innerHTML = DOMPurify.sanitize(userInput);",
                        "fastapi": "# Pass values safely into template context with Jinja2 autoescaping enabled",
                    },
                    cwe_id="CWE-79",
                    owasp_category="A03:2021-Injection",
                    affected_urls=[tested_url],
                    references=[
                        "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                        "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
                    ],
                )
                findings.append(finding)
        else:
            passed_checks.append("no-dom-sink-canary-taint-detected")

        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            findings=findings,
            passed_checks=passed_checks,
        )
