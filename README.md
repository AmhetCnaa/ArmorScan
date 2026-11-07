<div align="center">

<h1 align="center">🛡️ ArmorScan</h1>

<p align="center">
  <em>"Next-generation, non-destructive DAST & Deep Application Security Auditor. From headers to DOM taint tracing and IDOR — with 0 False Positives."</em>
</p>

<p align="center">
  <a href="pyproject.toml"><img src="https://img.shields.io/badge/Python-3.11%20%7C%203.12-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.11 | 3.12" /></a>
  <a href="https://github.com/AmhetCnaa/ArmorScan/releases/tag/v0.5.0"><img src="https://img.shields.io/badge/Release-v0.5.0-10B981?style=flat-square&logo=github" alt="Release v0.5.0" /></a>
  <a href="benchmark/juice_shop_results.md"><img src="https://img.shields.io/badge/OWASP%20Juice%20Shop-83.3%25%20Recall-F59E0B?style=flat-square&logo=owasp&logoColor=white" alt="OWASP Juice Shop 83.3% Recall" /></a>
  <a href="benchmark/juice_shop_results.md"><img src="https://img.shields.io/badge/False%20Positives-0%20(100%25%20Precision)-06B6D4?style=flat-square" alt="0 False Positives" /></a>
  <a href="tests/"><img src="https://img.shields.io/badge/Tests-144%2F144%20Passed-22C55E?style=flat-square&logo=pytest&logoColor=white" alt="144/144 Tests Passed" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT%20%2B%20Ethical%20Clause-8B5CF6?style=flat-square" alt="License MIT + Ethical Clause" /></a>
  <a href="https://github.com/AmhetCnaa/ArmorScan/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/AmhetCnaa/ArmorScan/ci.yml?style=flat-square&logo=githubactions&logoColor=white&label=CI" alt="CI Status" /></a>
</p>

<p align="center">
  <a href="#-start-in-30-seconds">Quick Start</a> •
  <a href="#-why-armorscan">Why ArmorScan?</a> •
  <a href="#-interactive-tui-dashboard">TUI Preview</a> •
  <a href="#-scientific-benchmark-owasp-juice-shop">Benchmarks</a> •
  <a href="#-yaml-template-engine">YAML Engine</a> •
  <a href="#-github-action--sarif-210">CI/CD & SARIF</a> •
  <a href="#️-legal--ethical-disclaimer">Legal Disclaimer</a>
</p>

</div>

---

## ⚡ Start in 30 Seconds

```bash
# 1. Install (via pip or pipx)
pip install armorscan

# 2. Scan Localhost or Live Target (HTML Report + Interactive TUI Dashboard)
armorscan http://localhost:3000 --tui

# 3. CI/CD Pipeline Quality Gate + GitHub SARIF 2.1.0 Code Scanning
armorscan https://staging.example.com --fail-under 80 --sarif results.sarif
```

---

## 🖥️ Interactive TUI Dashboard

Launch the split-screen terminal workstation (`--tui`) to inspect live HTTP evidence, copy 1-click `cURL` reproduction commands, and grab framework-specific remediation patches:

<div align="center">

```text
╭──────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🛡️ ArmorScan v0.5.0 — Interactive Security TUI  •  Target: http://127.0.0.1:3000  •  Score: 18/100 C │
│ Findings: 15 (1 Critical, 9 High, 4 Medium, 1 Low)  •  Precision: 100.0% (0 False Positives)         │
├──────────────────────────────────────────┬───────────────────────────────────────────────────────────┤
│ 📋 Findings (15)                         │ 🔍 Finding Details & Evidence                             │
│                                          │                                                           │
│ ❯ [CRIT] CROSS_TENANT_OBJECT_ACCESS      │ ID: CROSS_TENANT_OBJECT_ACCESS (CWE-639 • OWASP A01:2021) │
│   [HIGH] DOM_XSS_SINK_TAINT_FLOW         │ Module: multi_step  •  Confidence: CONFIRMED              │
│   [HIGH] SQLI_BOOLEAN_DIFFERENCE         │ URL: http://127.0.0.1:3000/rest/basket/1                  │
│   [HIGH] NOSQLI_OPERATOR_INJECTION       │                                                           │
│   [HIGH] PATH_TRAVERSAL_DETECTED         │ ── Evidence ───────────────────────────────────────────── │
│   [HIGH] DATABASE_ERROR_DISCLOSURE       │ Authenticated as User A (bid=6), GET /rest/basket/1       │
│   [HIGH] OPEN_REDIRECT_UNVALIDATED       │ returned User B's private basket (HTTP 200, 749 bytes).   │
│   [HIGH] JWT_SENSITIVE_DATA_IN_PAYLOAD   │                                                           │
│   [HIGH] MISSING_AUTHENTICATION_GATE     │ ── Reproduce (cURL) ───────────────────────────────────── │
│   [HIGH] MISSING_CSP                     │ $ curl -i -X GET 'http://127.0.0.1:3000/rest/basket/1' \  │
│   [MED]  EXPOSED_OPENAPI_SPEC            │     -H 'Authorization: Bearer <REDACTED_JWT>'             │
│   [MED]  EXPOSED_PROMETHEUS_METRICS      │                                                           │
│   [MED]  JWT_MISSING_EXPIRATION          │ ── Auto-Remediation (FastAPI / Express) ───────────────── │
│   [MED]  MISSING_RATE_LIMITING           │ if basket.user_id != current_user.id:                     │
│   [LOW]  MISSING_REFERRER_POLICY         │     raise HTTPException(status_code=403, detail="Denied") │
├──────────────────────────────────────────┴───────────────────────────────────────────────────────────┤
│ [↑/↓ or j/k] Navigate   •   [Enter / o] Open Target URL in Browser   •   [q / Esc] Exit Dashboard    │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

</div>

---

## ✨ Why ArmorScan?

<table>
  <tr>
    <td width="50%" valign="top">
      <h3>🔍 Deep Logic Auditing</h3>
      <p>Goes far beyond surface header checks. Performs headless Playwright <strong>DOM sink taint tracing</strong> (<code>Element.innerHTML</code>, <code>document.write</code>), non-destructive <strong>Boolean SQLi</strong> &amp; <strong>NoSQLi</strong> differential analysis, Poison Null-Byte <strong>Path Traversal</strong>, and dual-session read-only <strong>BOLA/IDOR</strong> verification.</p>
    </td>
    <td width="50%" valign="top">
      <h3>⚡ Blazing Fast &amp; Zero-False-Positive</h3>
      <p>Powered by an asynchronous <code>httpx</code> HTTP/2 engine with SPA 404 canary baselining and two-pass differential verification.Every finding is graded by confidence (<code>confirmed</code>, <code>firm</code>, <code>tentative</code>) — achieving <strong>0 False Positives</strong> on OWASP Juice Shop.</p>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h3>🧩 Nuclei-Style YAML Engine</h3>
      <p>Extend ArmorScan with community or custom declarative YAML security templates (<code>--templates ./my-templates/</code>) supporting multi-condition status, word, and regex matchers — without writing a single line of Python.</p>
    </td>
    <td width="50%" valign="top">
      <h3>🛠️ Auto-Remediation &amp; DevSecOps</h3>
      <p>Doesn't just report vulnerabilities — generates ready-to-paste security patches for <strong>Nginx</strong>, <strong>Express.js (Helmet)</strong>, <strong>FastAPI</strong>, and <strong>Django</strong>, plus native <strong>OASIS SARIF 2.1.0</strong> exports for GitHub Security tab integration.</p>
    </td>
  </tr>
</table>

---

## 📊 Scientific Benchmark: OWASP Juice Shop

ArmorScan is continuously benchmarked against two distinct environments:
1. **External Independent Target — OWASP Juice Shop v19.0.0 (`127.0.0.1:3000`):** Out of 116 official challenges, 98 require business-logic abuse, OSINT, or destructive actions out of scope for non-destructive DAST. Against the **18 Automated Non-Destructive DAST-Detectable Categories**, ArmorScan v0.5.0 achieves **83.3% Recall (15/18)** with **100.0% Precision (0 False Positives)**.
2. **Controlled Regression Lab (`benchmark/labapp/`):** A 28-case deterministic FastAPI testbed used as a CI quality gate to ensure code changes never introduce false positives.

| Metric | v0.4.0 (Baseline) | v0.4.1 (+JS Crawler, Auth, DOM, SQLi) | v0.5.0 (+NoSQLi, Traversal, SSRF, GraphQL, YAML) | Delta (`v0.4.0` → `v0.5.0`) |
| :--- | :---: | :---: | :---: | :---: |
| **Automated DAST Scope (Denominator)** | 18 | 18 | **18** | Fixed (18 DAST categories) |
| **True Positives Detected (TP)** | 3 | 9 | **15** | **+12 (+400% increase)** |
| **DAST Recall (out of 18)** | 16.7% | 50.0% | **83.3%** | **+66.6 pts** |
| **False Positives (FP)** | 0 | 0 | **0** | **0 FP Maintained** |
| **Precision** | 100.0% | 100.0% | **100.0%** | **100.0% Maintained** |

<details>
<summary><strong>🔬 View All 15 Live Findings Verified on OWASP Juice Shop (Click to Expand)</strong></summary>

<br>

| # | Vulnerability Category | Module | Finding ID | Severity | Confidence | Verified Live Evidence (`127.0.0.1:3000`) |
| :-: | :--- | :--- | :--- | :---: | :---: | :--- |
| 1 | **Missing CSP** | `headers` | `MISSING_CSP` | HIGH | `confirmed` | Root response lacks `Content-Security-Policy` header. |
| 2 | **Missing Referrer-Policy** | `headers` | `MISSING_REFERRER_POLICY` | LOW | `confirmed` | Root response lacks `Referrer-Policy` header. |
| 3 | **Exposed OpenAPI Spec** | `exposure` | `EXPOSED_OPENAPI_SPEC` | MEDIUM | `confirmed` | JS bundle parser discovered `/api-docs/swagger.json` (HTTP 200). |
| 4 | **Missing Rate Limiting** | `ratelimit` | `MISSING_RATE_LIMITING` | MEDIUM | `confirmed` | 15 rapid requests returned HTTP 200 with zero `429` or `RateLimit-*` headers. |
| 5 | **Open Redirect Bypass** | `redirect` | `OPEN_REDIRECT_UNVALIDATED` | HIGH | `confirmed` | `/redirect?to=https://github.com/bkimminich/juice-shop?p=https://armorscan...` returned HTTP 302. |
| 6 | **DB Error Disclosure** | `error_leak` | `DATABASE_ERROR_DISCLOSURE` | HIGH | `confirmed` | `/rest/products/search?q=armorscan'` leaked raw `SQLITE_ERROR: near ")"` stack trace. |
| 7 | **JWT Missing `exp`** | `jwt_audit` | `JWT_MISSING_EXPIRATION` | MEDIUM | `confirmed` | Authenticated JWT payload lacks `exp` expiration claim. |
| 8 | **JWT Sensitive Payload** | `jwt_audit` | `JWT_SENSITIVE_DATA_IN_PAYLOAD` | HIGH | `confirmed` | JWT payload exposes `email`, `password` MD5 hash, and `totpSecret`. |
| 9 | **Unauthenticated Admin API** | `authz_check` | `MISSING_AUTHENTICATION_GATE` | HIGH | `confirmed` | Unauthenticated `GET /rest/admin/application-configuration` leaked full server config JSON. |
| 10 | **Cross-Tenant IDOR** | `multi_step` | `CROSS_TENANT_OBJECT_ACCESS` | CRITICAL | `confirmed` | User A token accessed User B's `/rest/basket/1` (HTTP 200, 749B private items). |
| 11 | **Boolean SQLi Differential** | `sqli` | `SQLI_BOOLEAN_DIFFERENCE_SUSPECTED`| HIGH | `tentative` | `/rest/products/search?q=nomatch')) OR 1=1--` returned 29,294B vs `AND 1=2--` (13B). |
| 12 | **NoSQLi Operator Diff** | `nosqli` | `NOSQLI_OPERATOR_INJECTION_SUSPECTED`| HIGH | `tentative` | `/rest/track-order/` `' \|\| true \|\| '` returned 920B vs `' && false && '` (59B). |
| 13 | **Path Traversal / Null-Byte**| `traversal` | `PATH_TRAVERSAL_DETECTED` | HIGH | `confirmed` | `/ftp/package.json.bak%2500.md` bypassed HTTP 403 filter and leaked `package.json.bak`. |
| 14 | **Exposed Prometheus Metrics**| `templates` | `EXPOSED_PROMETHEUS_METRICS` | MEDIUM | `confirmed` | YAML template detected unauthenticated `/metrics` telemetry endpoint. |
| 15 | **Client DOM XSS Taint Flow** | `browser_dom` | `DOM_XSS_SINK_TAINT_FLOW` | HIGH | `confirmed` | Headless Chromium traced URL hash `?q=` canary into `#searchValue` `Element.innerHTML`. |

> Full methodology, numerator/denominator breakdown, and remaining 3 edge-case categories are documented in [`benchmark/juice_shop_results.md`](benchmark/juice_shop_results.md) and [`benchmark/results.md`](benchmark/results.md).

</details>

---

## 🧩 Nuclei-Style YAML Template Engine

Write custom security checks in declarative YAML and run them via `armorscan scan https://target.com --templates ./my-templates/`:

```yaml
id: exposed-prometheus-metrics
info:
  name: Exposed Prometheus Metrics Endpoint
  severity: MEDIUM
  confidence: confirmed
  cwe_id: CWE-200
  owasp_category: A05:2021-Security Misconfiguration
  description: The application exposes an unauthenticated Prometheus /metrics endpoint.

requests:
  - method: GET
    path:
      - "/metrics"
    matchers:
      condition: and
      status: [200]
      words:
        - "# HELP"
        - "# TYPE"
```

---

## 🤖 GitHub Action & SARIF 2.1.0

Drop ArmorScan directly into `.github/workflows/security.yml` to block vulnerable PRs and publish findings to the **GitHub Security → Code Scanning** tab:

```yaml
name: ArmorScan DevSecOps Gate
on: [push, pull_request]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4

      - name: Run ArmorScan DAST & Upload SARIF
        uses: AmhetCnaa/ArmorScan@v0.5.0
        with:
          target: "http://localhost:3000"
          fail-under: "80"
          sarif-file: "armorscan-results.sarif"
          upload-sarif: "true"
          comment-on-pr: "true"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## ⚠️ Legal & Ethical Disclaimer

> **⚠️ Legal & Ethical Disclaimer:** ArmorScan is developed strictly for educational, defensive, and authorized security auditing purposes. Scanning targets without prior explicit written authorization is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this utility.
>
> **🇹🇷 Yasal Uyarı ve Sorumluluk Reddi:** ArmorScan yalnızca eğitim, savunma ve yetkilendirilmiş güvenlik denetimleri için geliştirilmiştir. Hedef sistem sahiplerinin açık ve yazılı izni olmaksızın tarama yapılması yasa dışıdır (5237 sayılı TCK Madde 243-246). Geliştiriciler, bu aracın kötüye kullanımından veya yol açabileceği zararlardan hiçbir şekilde sorumlu tutulamaz.

---

<div align="center">
  <sub>Distributed under the <a href="LICENSE">MIT License (with Legal & Ethical Use Clause)</a> • Built with ❤️ for the AppSec & DevSecOps Community</sub>
</div>
