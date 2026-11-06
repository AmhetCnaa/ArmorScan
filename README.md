# 🛡️ ArmorScan

> **Modern, Fast, Developer-Friendly DAST & Web Security Scanner CLI**  
> Test your localhost or production web apps & APIs in seconds before deploying.

---

## ⚡ Key Highlights
- 🚀 **Blazing Fast**: Asynchronous HTTP/2 scanning with `httpx` (typical scan takes **< 1.5 seconds**).
- 🔒 **Security Headers & TLS**: Deep inspection of HSTS, CSP (`unsafe-inline`, `unsafe-eval`, wildcards), Clickjacking, MIME-sniffing, and server version leaks.
- 🍪 **Cookie Hygiene**: Heuristic session token detection (`session`, `jwt`, `token`, `auth`, `PHPSESSID`), `Secure`, `HttpOnly`, `SameSite`, and modern `__Host-` / `__Secure-` prefix standards.
- 📂 **Sensitive File & Disclosure**: Canary 404 baseline to eliminate SPA/catch-all false positives while detecting leaked `.env`, `.git/HEAD`, `.DS_Store`, WordPress backups, and OpenAPI schemas.
- 🌐 **CORS & Method Security**: Arbitrary origin reflection with credentials, null origin trust, domain regex bypasses, and dangerous HTTP verbs (TRACE/XST, PUT, DELETE).
- ⏱️ **Rate Limiting & DoS Resilience**: Safe, non-destructive 18-request burst test verifying HTTP 429 throttling and RateLimit-* headers.
- 📊 **Triple Reporting**: Rich interactive terminal UI, standalone zero-CDN HTML report, and machine-readable JSON.
- 🔄 **DevSecOps / CI/CD Quality Gate**: Exit code 1 enforcement via `--fail-under <SCORE>` to stop compromised pull requests before deployment.
- 🛠️ **Production-Ready Remediation**: Copy-paste configuration blocks for **Nginx**, **Express.js**, **FastAPI**, and **Django**.

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

### 4. Testing with Self-Signed Certificates (Localhost SSL)
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

## 🧪 Running the Test Suite

```bash
# Execute all 53 automated unit and integration tests
pytest -v
```

---

## 📄 License
ArmorScan is distributed under the [MIT License](LICENSE).
