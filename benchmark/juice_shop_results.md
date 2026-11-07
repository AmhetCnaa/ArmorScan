# 🛡️ ArmorScan Real-World Benchmark: OWASP Juice Shop

> **Target Architecture:** Modern Angular Single Page Application with Node/Express REST API and SQLite  
> **Target Base URL:** `http://127.0.0.1:3000`  
> **Execution Timestamp:** 2026-11-07 11:13:46 UTC  
> **Duration:** 0.78s  
> **Execution Environment:** Node.js 24 Native Process (`127.0.0.1:3000` - Docker unavailable in this environment)  

## 📊 Benchmark Summary Metrics

| Metric | Value | Target Goal | Status |
| :--- | :---: | :---: | :---: |
| **Precision** | **100.0%** | ≥ 90.0% | ✅ PASS |
| **Recall (Coverage)** | **16.7%** | ≥ 80.0% | ⚠️ WARN |
| **F1-Score** | **0.286** | ≥ 0.850 | ⚠️ WARN |
| **True Positives (Detected)** | 1 | - | ✅ |
| **False Positives (Suppressed)** | 0 | 0 | ✅ 0 FP |
| **False Negatives (Missed)** | 5 | 0 | ⚠️ Needs Tuning |
| **Discovered Routes** | 8 | - | 🌐 |
| **Discovered Forms** | 0 | - | 📝 |

## 🎯 Expected Vulnerabilities Matrix

| Finding ID | Module | Severity | Expected Description | Detected? |
| :--- | :--- | :---: | :--- | :---: |
| `MISSING_CSP` | `headers` | MEDIUM | Juice Shop default configuration lacks strict Content-Security-Policy header | ✅ YES |
| `MISSING_PERMISSIONS_POLICY` | `headers` | LOW | Permissions-Policy header is missing | ❌ MISSED |
| `X_POWERED_BY_DISCLOSURE` | `headers` | LOW | Exposes 'X-Powered-By: Express' technology banner | ❌ MISSED |
| `EXPOSED_OPENAPI_SPEC` | `exposure` | MEDIUM | Exposes public Swagger/OpenAPI documentation at /api-docs/swagger.json | ❌ MISSED |
| `CORS_ARBITRARY_ORIGIN_REFLECTION` | `cors` | HIGH | Reflects arbitrary Origin header in CORS preflight | ❌ MISSED |
| `COOKIE_MISSING_SAMESITE` | `cookies` | MEDIUM | Session cookies missing SameSite protection | ❌ MISSED |

## 🛡️ False Positive Resilience Verification

| Checked Finding ID | Module | Resilience Requirement | Result |
| :--- | :--- | :--- | :---: |
| `EXPOSED_ENV_FILE` | `exposure` | SPA catch-all returns HTTP 200 for /.env; scanner must verify signature, not just 200 OK | ✅ CLEAN (Zero FP) |
| `EXPOSED_GIT_REPOSITORY` | `exposure` | SPA catch-all returns HTML for /.git/HEAD; scanner must verify ref signature | ✅ CLEAN (Zero FP) |

## 💡 Additional Real-World Findings Discovered

| Finding ID | Severity | Confidence | Title |
| :--- | :---: | :---: | :--- |
| `MISSING_REFERRER_POLICY` | LOW | firm | Missing Referrer-Policy Header |
| `MISSING_RATE_LIMITING` | MEDIUM | firm | Missing Rate Limiting & DoS Throttling Defenses |
