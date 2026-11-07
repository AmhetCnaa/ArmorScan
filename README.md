# 🛡️ ArmorScan

<div align="center">

[![CI & Accuracy Benchmark](https://github.com/AmhetCnaa/ArmorScan/actions/workflows/ci.yml/badge.svg)](https://github.com/AmhetCnaa/ArmorScan/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![DAST: Non-Destructive](https://img.shields.io/badge/DAST-Non--Destructive%20Canary-purple.svg)](docs/ARCHITECTURE.md)
[![Release](https://img.shields.io/badge/Release-v0.4.0-success.svg)](CHANGELOG.md)

**Modern, Fast, Developer-Friendly DAST & Web Security Scanner CLI**  
*Audit your web applications, APIs, and microservices in seconds with zero false-positive tolerance.*

[Key Highlights](#-key-highlights) •
[Installation](#-installation--quick-start) •
[CLI Usage](#-cli-usage-examples) •
[13 Security Modules](#-the-13-security-audit-modules) •
[Benchmark Suite](#-ground-truth-benchmark--accuracy-metrics-v040) •
[Architecture Guide](docs/ARCHITECTURE.md) •
[Changelog](CHANGELOG.md)

</div>

---

## ⚡ Key Highlights

- 🚀 **Blazing Fast**: Asynchronous HTTP/2 scanning with `httpx` (typical scan takes **< 1.5 seconds**).
- 🔬 **Two-Pass Confidence Engine**: Automatically generates cURL reproduction commands and validates findings via response diff analysis (`CONFIRMED`, `SUSPECTED`, `INFORMATIONAL`).
- 🎯 **Deep Application & Logic Auditor**:
  - 💉 **Input Reflection**: Context-aware probe analysis (raw HTML, `<script>`, HTML attributes) to detect XSS vectors without firing destructive scripts.
  - 🔄 **Open Redirect**: Probes navigation parameters against external domain indicators (HTTP 3xx `Location` and meta refresh).
  - 💥 **Error & Stack Trace Leakage**: Injects boundary canary probes to identify raw database errors (SQLite, MySQL, PostgreSQL, Oracle) and framework stack traces.
  - 🔑 **JWT Security**: Audits tokens for insecure `alg: none`, missing expiration claims (`exp`), and sensitive credentials in payloads.
  - 🕵️ **Secret & API Key Hunter**: Scans HTML and same-origin JS bundles for exposed OpenAI, AWS, GitHub, Stripe, Slack secrets, and private RFC 1918 IPs with automated masking.
  - 🚪 **Missing Authentication Gate**: Tests whether private APIs inadvertently permit unauthenticated access.
  - 👥 **Multi-Step Logic & BOLA/IDOR**: Detects cross-tenant object manipulation (`user_id`, `tenant_id`, `account_id`) across state transitions (CWE-639).
- 📜 **API Schema-Driven Crawling**: Ingests **OpenAPI 3.x** and **Swagger 2.0** specifications (`--schema`) and probes **GraphQL Introspection** endpoints.
- 🔐 **Authenticated Scanning & Session Keep-Alive**: Supports static authorization headers/cookies, automated pre-scan login macros (`--login-url`), and continuous session health verification (`--auth-check-url`).
- 🔒 **Security Headers & TLS**: Inspects HSTS, CSP (`unsafe-inline`, `unsafe-eval`, wildcards), Clickjacking, MIME-sniffing, and server version banners.
- 🍪 **Cookie Hygiene**: Validates `HttpOnly`, `Secure`, `SameSite` (Lax/Strict), and modern `__Host-` / `__Secure-` prefix standards.
- 📂 **Sensitive Dotfile & Exposure Audit**: Canary 404 baseline eliminates SPA catch-all false positives while detecting leaked `.env`, `.git/HEAD`, `.DS_Store`, and backup files.
- 🌐 **CORS & Method Security**: Identifies arbitrary origin reflection with credentials, `Origin: null` trust, domain regex bypasses, and dangerous HTTP verbs (TRACE/XST).
- ⏱️ **Rate Limiting & DoS Resilience**: Safe, non-destructive burst testing verifying HTTP 429 throttling and RateLimit-* headers.
- 🔍 **Local Port & Database Sniffer**: `armorscan discover 127.0.0.1` detects active dev web servers and unauthenticated database exposures in under 1 second.
- 🛡️ **Finding Suppression & Deduplication**: Filter accepted risks via `.armorscanignore` and deduplicate findings across multi-page crawls.
- 📊 **Triple Reporting**: Rich interactive terminal dashboard, standalone zero-CDN dark-mode HTML report, and machine-readable JSON.
- 🔄 **DevSecOps / CI/CD Quality Gate**: Exit code 1 enforcement via `--fail-under <SCORE>` to prevent vulnerable code from entering production.
- 🛠️ **Remediation Patch Exporter**: Exports ready-to-use security configurations for **Nginx**, **Express.js (Helmet)**, and **FastAPI** (`--export-patch`).

---

## 🚀 Installation & Quick Start

```bash
# Clone the repository
git clone https://github.com/AmhetCnaa/ArmorScan.git
cd ArmorScan

# Setup Python virtual environment (Python 3.11+ / 3.12 recommended)
uv venv --python 3.12
source .venv/bin/activate

# Install ArmorScan in editable mode with all dev dependencies
uv pip install -e ".[dev]"

# Verify installation
armorscan --version
# Output: ArmorScan 0.4.0
```

---

## 💻 CLI Usage Examples

### 1. Basic Scan (Localhost or Remote)
```bash
# Scan a local development server
armorscan http://localhost:8000

# Scan a production application
armorscan https://myapp.example.com
```

### 2. CI/CD Quality Gate (Fail Pipeline if Score < 80)
```bash
armorscan https://staging.example.com --fail-under 80
```
*If the security score is below 80, ArmorScan exits with status code 1, automatically failing the CI step.*

### 3. Generate Custom HTML and JSON Reports
```bash
armorscan https://myapp.example.com \
  --html artifacts/security-report.html \
  --json artifacts/security-report.json \
  --fail-under 85
```

### 4. Smart Web Crawler & Multi-Page Discovery
```bash
# Automatically discover internal links, routes, and forms up to depth 3
armorscan https://myapp.example.com --crawl --depth 3 --max-pages 25
```

### 5. API Schema-Driven Scanning (OpenAPI & Swagger)
```bash
# Ingest OpenAPI 3.x / Swagger 2.0 schema from local file or remote URL
armorscan https://api.example.com --schema https://api.example.com/openapi.json
armorscan https://api.example.com --schema ./openapi.yaml
```

### 6. Authenticated Scanning & Session Keep-Alive
```bash
# Using static token:
armorscan https://myapp.example.com \
  --auth-header "Authorization: Bearer my-secret-jwt-token" \
  --auth-check-url "/api/v1/users/me"

# Using automated login macro:
armorscan https://myapp.example.com \
  --login-url "/api/v1/auth/login" \
  --login-body '{"username":"admin","password":"secretpassword"}' \
  --login-token-path "data.access_token" \
  --auth-check-url "/api/v1/dashboard"
```

### 7. Suppressing Accepted Findings (`.armorscanignore`)
```bash
armorscan https://myapp.example.com --ignore-file .armorscanignore
```
Sample `.armorscanignore`:
```ini
# Suppress missing HSTS on internal dev domain
RULE_ID: MISSING_HSTS
URL_PATTERN: https://.*\.internal\.dev/.*
REASON: Internal domain behind private VPN terminating TLS at proxy
EXPIRES: 2026-12-31
```

### 8. Local Port & Database Sniffer (`armorscan discover`)
```bash
# Discover active dev web servers (3000, 5173, 8000, 8080) and unauthenticated databases (Redis, Mongo, Postgres, MySQL)
armorscan discover 127.0.0.1
```

### 9. Auto-Remediation Patch Exporter (`--export-patch`)
```bash
# Export production-ready configuration files directly to disk:
armorscan --export-patch nginx    # Generates security-headers.conf
armorscan --export-patch express  # Generates securityMiddleware.js
armorscan --export-patch fastapi  # Generates security_middleware.py
```

### 10. Real-World Target Benchmark (`armorscan benchmark`)
```bash
# Benchmark against internal controlled FastAPI testbed (100% precision & recall quality gate)
armorscan benchmark

# Benchmark against OWASP Juice Shop:
docker compose -f benchmark/docker-compose.yml up -d juice-shop
armorscan benchmark juice-shop

# Benchmark against Damn Vulnerable Web Application (DVWA):
docker compose -f benchmark/docker-compose.yml up -d dvwa
armorscan benchmark dvwa
```

---

## 🛡️ The 15 Security Audit Modules

| Module | Category | CWE | OWASP Top 10 | Primary Verification Target |
| :--- | :--- | :-: | :---: | :--- |
| **`headers`** | Configuration | CWE-693 | A05:2021 | Strict CSP, HSTS, X-Frame-Options, Permissions-Policy, Server Version Banners |
| **`tls_ssl`** | Transport | CWE-319 | A02:2021 | TLS 1.0/1.1 deprecation, weak ciphers, self-signed or expired certificates |
| **`cookies`** | Session | CWE-614 | A01:2021 | `HttpOnly`, `Secure`, `SameSite` (Lax/Strict), `__Host-` prefix validation |
| **`exposure`** | Information Leak | CWE-552 | A05:2021 | Leaked `.env`, `.git/HEAD`, `.DS_Store`, backup files, GraphQL & OpenAPI specs |
| **`cors`** | Access Control | CWE-942 | A01:2021 | Arbitrary Origin reflection with credentials, `Origin: null`, wildcard conflicts |
| **`ratelimit`** | Availability | CWE-799 | A04:2021 | Missing rate-limiting headers, HTTP 429 response handling under burst load |
| **`reflection`** | Injection | CWE-79 | A03:2021 | Context-aware HTML entity encoding, script context, attribute reflection |
| **`redirect`** | Access Control | CWE-601 | A01:2021 | Unvalidated redirection parameters (`next`, `url`, `redirect`, `dest`) |
| **`error_leak`** | Information Leak | CWE-209 | A05:2021 | Stack traces, SQLite/PostgreSQL/MySQL errors, framework debug screens |
| **`jwt_audit`** | Authentication | CWE-345 | A07:2021 | Insecure `alg: none`, missing `exp`, sensitive credentials in payload |
| **`secret_leak`**| Information Leak | CWE-798 | A07:2021 | Leaked OpenAI keys, AWS access keys, GitHub PATs, Stripe secrets, webhooks |
| **`authz_check`**| Access Control | CWE-306 | A01:2021 | Missing authentication gates on private/internal API endpoints |
| **`multi_step`** | Business Logic | CWE-639 | A01:2021 | Broken Object Level Authorization (BOLA/IDOR) & tenant isolation failures |
| **`sqli`** | Injection | CWE-89 | A03:2021 | Safe boolean differential analysis (`1=1` vs `1=2`), no data extraction |
| **`browser_dom`**| Client DOM | CWE-79 | A03:2021 | Headless Chromium runtime sink interception (`innerHTML`, `document.write`) |

---

## 📊 Ground Truth Benchmark & Accuracy Metrics (v0.4.0)

> ⚠️ **Metodoloji Notu (Dürüst Doğrulama):** Aşağıdaki laboratuvar sonuçları, ArmorScan geliştiricileri tarafından yazılan sentetik test uygulaması (`benchmark/labapp/`) üzerindedir. Kod ve doğrulama kuralının aynı ekip tarafından yazıldığı durumlarda %100 skor döngüsel (circular) bir doğrulamadır. ArmorScan'in bağımsız bir hedefe karşı gerçek tespit gücünü, kaçırdığı açıkları ve yanlış alarm direncini şeffafça ortaya koymak amacıyla **OWASP Juice Shop** sonuçları hemen altındaki tabloda ayrı olarak raporlanmıştır.

### 1. Kontrollü Laboratuvar Doğrulaması (`benchmark/labapp/`):

| Module | True Positives (TP) | False Positives (FP) | False Negatives (FN) | Precision | Recall | F1-Score | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `authz_check` | 1 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `cookies` | 3 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `cors` | 2 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `error_leak` | 1 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `exposure` | 2 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `headers` | 6 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `jwt_audit` | 3 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `multi_step` | 1 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `ratelimit` | 1 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `redirect` | 1 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `reflection` | 2 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `secret_leak` | 5 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `tls` | 0 | 0 | 0 | - | - | - | N/A |
| **OVERALL** | **28** | **0** | **0** | **100.0%** | **100.0%** | **1.000** | **✅ PASS** |

*(Not: `tls` modülü lokal HTTP test ortamında TLS sertifikası bulunmadığı için test vakası içermemektedir ve dürüstçe `N/A` olarak işaretlenmiştir.)*

---

### 2. Bağımsız Gerçek Dünya Testi: OWASP Juice Shop (`127.0.0.1:3000`)

> **Çalıştırma Notu:** Bu ortamda Docker/Podman bulunmadığından, OWASP Juice Shop resmi Linux paketi Node.js 24 üzerinde `127.0.0.1:3000` adresinde yerel süreç olarak çalıştırılmış, `Authorization: Bearer <TOKEN>`, Web Crawler ve Playwright Headless Chromium entegrasyonu ile canlı taranmıştır.

#### 📐 Payda Düzeltmesi (116 Challenge vs Otomatik DAST Kapsamı):
Juice Shop toplam **116 resmi challenge** içerir. Ancak bir DAST aracının güvenli (non-destructive) ve otomatik denetleyebileceği açıklar ile manuel CTF bulmacaları (cüzdan boşaltma, Metamask, kaba kuvvet parola tahmini, EXIF GPS çıkarma, ReDoS çökertme) bilimsel olarak ayrılmalıdır:
- **Manuel / CTF / Yıkıcı Kapsam Dışı (~98):** Veritabanı şema boşaltma (UNION SQLi), RCE/SSTI komut çalıştırma, kaba kuvvet parola/güvenlik sorusu tahmini, sosyal mühendislik.
- **Otomatik DAST Kapsamı (18):** Güvenlik başlıkları, rate limiting, Swagger ifşası, JWT süresi ve parola sızıntısı, BOLA/IDOR sepet erişimi, güvenli boolean SQLi yanıt farkı, DOM sink veri akışı, açık yönlendirme, hassas dosya sızıntıları, CORS ve çerez hijyeni.

#### 📊 Ölçülen Performans ve Doğruluk:

| Metrik | Değer | Durum / Değerlendirme |
| :--- | :---: | :--- |
| **Tespit Edilen Gerçek Açıklar (TP)** | **9** | `MISSING_CSP`, `MISSING_REFERRER_POLICY`, `EXPOSED_OPENAPI_SPEC`, `MISSING_RATE_LIMITING`, `JWT_MISSING_EXPIRATION`, `JWT_SENSITIVE_DATA_IN_PAYLOAD`, `CROSS_TENANT_OBJECT_ACCESS`, `SQLI_BOOLEAN_DIFFERENCE_SUSPECTED`, `DOM_XSS_SINK_TAINT_FLOW` |
| **Yanlış Alarmlar (False Positives)** | **0** | SPA fallback (HTTP 200 HTML catch-all) başarıyla elendi; %100 kesinlik |
| **Otomatik DAST Kapsamı (Recall)** | **50.0% (9/18)** | DAST ile otomatik tespit edilebilir açıkların yarısı sıfır zararla yakalandı |
| **Keşfedilen Sayfa & API Yolu** | **51** | JS bundle AST/regex ayrıştırma ile 42 REST rotası ve Swagger bulundu |
| **Tarama Süresi** | **1.84s** | 15 güvenlik modülü ve headless browser DOM analizi 2 saniyenin altında tamamlandı |

#### Tespit Edilen Açıkların Detaylı Doğrulama Tablosu:

| Güvenlik Alanı | Modül | Seviye | Güven | Kanıt ve Mimari Açıklama |
| :--- | :--- | :---: | :---: | :--- |
| **CSP Güvenliği** | `headers` | HIGH | firm | Kök yanıtta katı `Content-Security-Policy` başlığı yok (`MISSING_CSP`). |
| **Referrer-Policy** | `headers` | LOW | firm | `Referrer-Policy` başlığı eksik (`MISSING_REFERRER_POLICY`). |
| **OpenAPI / Swagger** | `exposure` | MEDIUM | firm | `main.js` analiziyle `/api-docs/` ve Swagger UI otomatik keşfedildi (`EXPOSED_OPENAPI_SPEC`). |
| **Rate Limiting** | `ratelimit` | MEDIUM | firm | 18 eşzamanlı istekte 18x HTTP 200 yanıtı; HTTP 429 sınırı yok (`MISSING_RATE_LIMITING`). |
| **JWT Expiration** | `jwt_audit` | MEDIUM | confirmed | Oturum JWT'sinde `exp` claim'i bulunmuyor; süresiz geçerli (`JWT_MISSING_EXPIRATION`). |
| **JWT Parola Sızıntısı** | `jwt_audit` | HIGH | confirmed | JWT yükünde kullanıcı MD5 parola özeti (`data.password`) ifşa ediliyor (`JWT_SENSITIVE_DATA_IN_PAYLOAD`). |
| **BOLA / IDOR** | `multi_step` | HIGH | confirmed | Kullanıcı 2 token'ı ile `GET /rest/basket/2` üzerinden Kullanıcı 1 sepeti okundu (`CROSS_TENANT_OBJECT_ACCESS`). |
| **Boolean SQLi Belirtisi**| `sqli` | HIGH | tentative| `/rest/products/search?q=` üzerinde `1=1` (34KB) vs `1=2` (boş liste) yanıt farkı (`SQLI_BOOLEAN_DIFFERENCE_SUSPECTED`). |
| **Client DOM XSS Sink** | `browser_dom`| HIGH | confirmed | Playwright ile kanaryanın `#searchValue` `Element.innerHTML` sink'ine aktığı yakalandı (`DOM_XSS_SINK_TAINT_FLOW`). |
| **Dotfile / .env Koruması**| `exposure` | - | - | 🛡️ **0 YANLIŞ ALARM:** SPA 200 HTML catch-all yanıtları kanarya imzası ile elendi. |

---

## 🤖 GitHub Actions CI/CD Pipeline

Add this workflow to `.github/workflows/security.yml`:

```yaml
name: Security Audit Gate

on: [push, pull_request]

jobs:
  dast-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install ArmorScan
        run: |
          python -m pip install --upgrade pip
          pip install .

      # Start your test server (e.g., Docker, FastAPI, Express)
      - name: Start Application Server
        run: |
          npm start &
          sleep 3

      # Run ArmorScan quality gate
      - name: Run ArmorScan DAST
        run: |
          armorscan http://localhost:3000 \
            --fail-under 80 \
            --html armorscan-report.html \
            --json armorscan-report.json

      # Upload interactive report as GitHub artifact
      - name: Upload Security Report Artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: armorscan-security-report
          path: |
            armorscan-report.html
            armorscan-report.json
```

---

## 🧪 Running the Test Suite

```bash
# Execute all 125 automated unit, integration, and benchmark tests
pytest -v
```

---

## 📄 License
ArmorScan is distributed under the [MIT License](LICENSE).
