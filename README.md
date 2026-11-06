# 🛡️ ArmorScan

> **Modern, Fast, Developer-Friendly DAST & Web Security Scanner CLI**  
> Test your localhost or production web apps & APIs in seconds before deploying.

---

## ⚡ Key Highlights
- 🚀 **Blazing Fast**: Asynchronous HTTP/2 scanning with `httpx` (typical scan takes **< 1.5 seconds**).
- 🧬 **Deep Application & Logic Auditor (v0.3.0)**:
  - 🎯 **Input Reflection & Context Analysis**: Probes query and form parameters with non-harmful canary tokens to identify unencoded reflections in raw HTML bodies, `<script>` tags, and attribute contexts.
  - 🔄 **Open Redirect Testing**: Tests navigation parameters against unvalidated external redirects via HTTP 3xx `Location` and client-side `<meta http-equiv="refresh">` tags.
  - 💥 **Error-Based Info & Database Leakage**: Injects unexpected probes to detect verbose database errors (MySQL, PostgreSQL, Oracle, SQLite, MongoDB) and unhandled stack traces (Python, Node.js, Java, PHP).
  - 🔑 **JWT Client Security & Lifecycle**: Automatically decodes client-side and cookie-based JWTs to flag `alg: none` bypasses, missing/excessive `exp` expiration claims, and plaintext credential leaks.
  - 🕵️ **DOM & Client-Side Secret Hunter**: Scans HTML source and linked same-origin JS bundles for exposed API keys (OpenAI, AWS, GitHub, Stripe, Slack, Google) and private RFC 1918 IPs with automated masking.
- 🔒 **Security Headers & TLS**: Deep inspection of HSTS, CSP (`unsafe-inline`, `unsafe-eval`, wildcards), Clickjacking, MIME-sniffing, and server version leaks.
- 🍪 **Cookie Hygiene**: Heuristic session token detection (`session`, `jwt`, `token`, `auth`, `PHPSESSID`), `Secure`, `HttpOnly`, `SameSite`, and modern `__Host-` / `__Secure-` prefix standards.
- 📂 **Sensitive File & Disclosure**: Canary 404 baseline to eliminate SPA/catch-all false positives while detecting leaked `.env`, `.git/HEAD`, `.DS_Store`, WordPress backups, and OpenAPI schemas.
- 🌐 **CORS & Method Security**: Arbitrary origin reflection with credentials, null origin trust, domain regex bypasses, and dangerous HTTP verbs (TRACE/XST, PUT, DELETE).
- ⏱️ **Rate Limiting & DoS Resilience**: Safe, non-destructive burst test verifying HTTP 429 throttling and RateLimit-* headers.
- 🕷️ **Smart Web Crawler / Spider**: Automated internal link discovery (`--crawl`, `--depth`, `--max-pages`).
- 🔍 **Local Port & Database Sniffer**: `armorscan discover 127.0.0.1` for dev servers and unauthenticated databases.
- 📊 **Triple Reporting**: Rich interactive terminal UI, standalone zero-CDN HTML report, and machine-readable JSON.
- 🔄 **DevSecOps / CI/CD Quality Gate**: Exit code 1 enforcement via `--fail-under <SCORE>` to stop compromised pull requests before deployment.
- 🛠️ **Production-Ready Remediation**: Copy-paste configuration blocks for **Nginx**, **Express.js**, **FastAPI**, and **Django**, plus `--export-patch`.

---

## 🚀 Installation & Quick Start

```bash
# Clone the repository
git clone https://github.com/AmhetCnaa/ArmorScan.git
cd ArmorScan

# Setup Python virtual environment (Python 3.11+ / 3.12 recommended)
uv venv --python 3.12
source .venv/bin/activate

# Install ArmorScan in editable mode with development dependencies
uv pip install -e ".[dev]"

# Verify installation
armorscan --version
```

---

## 💻 CLI Usage Examples

### 1. Basic Scan (Localhost or Remote)
```bash
# Scan a local development server
armorscan http://localhost:8000

# Scan an external staging or production domain
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

### 4. Smart Web Crawler & Multi-Page Discovery (v0.2.0)
```bash
# Automatically discover internal links, routes, and forms up to depth 3
armorscan https://myapp.example.com --crawl --depth 3 --max-pages 25
```

### 5. Local Port & Database Sniffer (`armorscan discover`) (v0.2.0)
```bash
# Discover active web servers (3000, 5173, 8000) and unauthenticated databases (Redis, Mongo, Postgres)
armorscan discover 127.0.0.1
```

### 6. Auto-Remediation Patch Exporter (`--export-patch`) (v0.2.0)
```bash
# Export production-ready configuration files directly to disk:
armorscan --export-patch nginx    # Generates security-headers.conf
armorscan --export-patch express  # Generates securityMiddleware.js
armorscan --export-patch fastapi  # Generates security_middleware.py
```

### 7. Testing with Self-Signed Certificates (Localhost SSL)
```bash
armorscan https://localhost:3000 --insecure
```

---

## 🛠️ CLI Options Reference

```text
usage: armorscan [-h] [--fail-under SCORE] [--html [PATH]] [--no-html]
                 [--json [PATH]] [-k] [--concurrency CONCURRENCY]
                 [--burst BURST] [-q] [-v]
                 [target]

🛡️ ArmorScan: Modern, fast, developer-friendly DAST & web security scanner.

positional arguments:
  target                Target URL to scan (e.g. https://example.com or http://localhost:8000)

options:
  -h, --help            Show this help message and exit
  --fail-under SCORE    CI/CD Quality Gate: Fail with exit code 1 if security score is below this threshold (0-100).
  --html [PATH]         Output path for interactive standalone HTML report (default: armorscan-report.html).
  --no-html             Disable HTML report generation.
  --json [PATH]         Output path for machine-readable JSON report.
  -k, --insecure        Disable SSL/TLS certificate verification (useful for self-signed development certs).
  --concurrency N       Number of concurrent modules to execute (default: 5).
  --burst N             Number of concurrent burst requests for rate limiting test (default: 18).
  -q, --quiet           Quiet mode: suppress ASCII banner and live progress.
  -v, --version         Show program's version number and exit.
```

---

## 🤖 GitHub Actions CI/CD Pipeline Example

Add this step to your `.github/workflows/security.yml`:

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
          pip install --upgrade pip
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

## 📊 Ground Truth Benchmark & Accuracy Metrics (v0.4.0 Lab)

To ensure real-world effectiveness and eliminate false positives, ArmorScan is continuously evaluated against a controlled ground-truth security laboratory (`benchmark/labapp/`) containing verified vulnerable and safely-remediated endpoints for all 10 core vulnerability classes.

### Measured Accuracy Metrics (Zero-Fabrication, Fully Reproducible):

| Module | True Positives (TP) | False Positives (FP) | False Negatives (FN) | Precision | Recall | F1-Score | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `cookies` | 3 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `cors` | 2 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `error_leak` | 1 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `exposure` | 2 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `headers` | 6 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `jwt_audit` | 3 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `ratelimit` | 1 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `redirect` | 1 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `reflection` | 2 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `secret_leak` | 5 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| **OVERALL** | **26** | **0** | **0** | **100.0%** | **100.0%** | **1.000** | **✅ PASS** |

### Running the Accuracy Benchmark:
```bash
# Direct CLI execution (automatically launches labapp on 127.0.0.1:8888)
armorscan benchmark

# Or via script with custom CI thresholds:
python scripts/run_benchmark.py --min-precision 0.95 --min-recall 0.95

# Run benchmark lab environment with Docker Compose:
docker compose -f benchmark/docker-compose.yml up -d
```

---

## 🧪 Running the Test Suite

```bash
# Execute all 85 automated unit, integration, and benchmark tests
pytest -v
```

---

## 📄 License
ArmorScan is distributed under the [MIT License](LICENSE).

