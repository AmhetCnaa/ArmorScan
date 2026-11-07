# 📜 ArmorScan Changelog

All notable changes to the **ArmorScan** project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.4.0] - 2026-11-06

### 🚀 Major Enhancements & New Capabilities
- **Real-World Target Benchmark Engine:**
  - Automated evaluation harness against **OWASP Juice Shop** (`bkimminich/juice-shop:v16.0.0`) and **Damn Vulnerable Web Application (DVWA)** (`vulnerables/web-dvwa:latest`).
  - Added dedicated CLI subcommands: `armorscan benchmark juice-shop` and `armorscan benchmark dvwa`.
  - Added `scripts/benchmark_external.py` for headless continuous benchmarking.
  - Implemented SPA (Single Page Application) HTML 200 catch-all filter preventing false-positive dotfile detections on modern JavaScript web apps.
- **API Schema-Driven Crawling & Parameter Fuzzing:**
  - Built `armorscan/core/schema.py` supporting auto-discovery and manual ingestion (`--schema <path_or_url>`) of **OpenAPI 3.x** and **Swagger 2.0** specifications (JSON/YAML).
  - Extracted route parameters, query schemas, and request bodies into concrete test targets.
- **GraphQL Introspection Auditing:**
  - Automatic probing of `/graphql`, `/api/graphql`, `/v1/graphql` using safe standard `__schema` queries.
  - Flags **`GRAPHQL_INTROSPECTION_ENABLED` (LOW/INFO)** when introspection is exposed in production.
  - Extracts Query and Mutation operation names directly into the crawler route pool.
- **Multi-Step Business Logic & Tenant Isolation Audit (`modules/multi_step.py`):**
  - Audits Broken Object Level Authorization (BOLA / IDOR) across state transitions by safely mutating object parameters (`user_id`, `account_id`, `tenant_id`).
  - Flags **`CROSS_TENANT_OBJECT_ACCESS` (HIGH - CWE-639)** when access to foreign tenant objects is permitted.
- **Authentication Engine & Session Keep-Alive (`core/auth.py`):**
  - Added CLI flags `--auth-header`, `--auth-cookie`, `--auth-check-url`, `--login-url`, `--login-body`, `--login-token-path`.
  - Added `AuthzCheckModule` (`modules/authz_check.py`) to verify missing authentication gates on sensitive endpoints.
- **Confidence Engine & Two-Pass Confirmation:**
  - Every finding now features an explicit `Confidence` rating (`CONFIRMED`, `SUSPECTED`, `INFORMATIONAL`).
  - Implemented response difference analysis and automated cURL command generation for instant finding reproduction.
- **Finding Suppression & Deduplication:**
  - Added `.armorscanignore` file parser (`SuppressionEngine`) supporting regex URL filters, rule ID suppression, expiration dates, and justification metadata.
  - Added cross-page finding deduplicator merging duplicate findings across multi-page crawls.
- **Continuous Integration Quality Gate:**
  - Added `.github/workflows/ci.yml` running unit tests and enforcing `scripts/run_benchmark.py --min-precision 0.95 --min-recall 0.95`.
  - Achieved **100% Precision, 100% Recall, and 0 False Positives** across 24 ground truth benchmark test cases.

---

## [0.3.0] - 2026-11-06

### Added
- **Input Reflection & XSS Context Audit (`modules/reflection.py`):**
  - Detection of unencoded HTML reflection (`UNENCODED_HTML_INPUT_REFLECTION`), `<script>` tag context (`SCRIPT_CONTEXT_INPUT_REFLECTION`), and HTML attribute injection.
- **Unvalidated Open Redirect Module (`modules/redirect.py`):**
  - Audits navigation parameters (`redirect`, `next`, `url`, `return`) using safe canary targets.
- **Error & Stack Trace Leakage Audit (`modules/error_leak.py`):**
  - Detects raw SQL database disclosures (SQLite, MySQL, PostgreSQL, Oracle), Python/Node/Java stack traces, and debug screens.
- **JWT Hygiene & Security Audit (`modules/jwt_audit.py`):**
  - Audits tokens for insecure `alg: none`, missing expiration claims (`exp`), and sensitive data in payloads.
- **Secret & API Key Hunter (`modules/secret_leak.py`):**
  - Discovers exposed OpenAI keys, AWS access credentials, GitHub PATs, Stripe secrets, Slack webhooks, and private IP leaks in client-side bundles.

---

## [0.2.0] - 2026-11-06

### Added
- **Smart Web Crawler / Spider (`core/crawler.py`):**
  - Breadth-first same-origin crawler with depth limit (`--depth`) and page budget (`--max-pages`).
  - Automatic HTML link and form parameter discovery.
- **Local Port & Database Sniffer (`modules/ports.py`):**
  - `armorscan discover` command scanning dev web servers (3000, 5173, 8000, 8080) and unauthenticated databases (Redis, Mongo, Postgres, MySQL) in under 1 second.
- **Automated Hardening Patch Exporter (`--export-patch`):**
  - Generates ready-to-use security configurations for **Nginx**, **Express.js (Helmet)**, and **FastAPI**.

---

## [0.1.0] - 2026-11-06

### Added
- Core DAST scanning engine:
  - Security Headers audit (`Content-Security-Policy`, `HSTS`, `X-Frame-Options`, `Permissions-Policy`).
  - TLS/SSL cipher, protocol, and certificate hygiene check.
  - Cookie flags audit (`HttpOnly`, `Secure`, `SameSite`, `__Host-` prefixes).
  - Sensitive dotfile exposure audit (`.env`, `.git/HEAD`, `.DS_Store`, backup files).
  - CORS & HTTP Method security check (arbitrary origin reflection, null origin trust, TRACE method).
  - Rate Limiting & DoS resilience check with bounded burst requests.
- Reporting Layer:
  - Rich Terminal UI dashboard with letter grades (A+ to F) and live progress bars.
  - Standalone, zero-dependency offline Dark Mode HTML report with interactive severity filters and copyable remediation snippets.
  - Machine-readable JSON export for CI/CD automation (`--json`).
  - CI/CD Quality Gate `--fail-under <score>`.
