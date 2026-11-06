# 🛡️ ArmorScan

> **Modern, Fast, Developer-Friendly DAST & Security Scanner CLI**  
> Test your localhost or production web apps & APIs in seconds before deploying.

---

## ⚡ Features
- 🚀 **Blazing Fast**: Asynchronous HTTP/2 scanning with `httpx` (typical scan takes < 3 seconds).
- 🔒 **Security Headers & TLS**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- 🍪 **Cookie Hygiene**: Checks `Secure`, `HttpOnly`, `SameSite` flags.
- 📂 **Sensitive File & Disclosure**: Detects exposed `.env`, `.git/HEAD`, backups, `robots.txt` with heuristic 404 analysis.
- 🌐 **CORS & HTTP Methods**: Checks wildcard origins, credentials leakages, and unsafe HTTP verbs (TRACE, PUT, DELETE).
- ⏱️ **Rate Limiting Resilience**: Non-destructive parallel burst test to verify HTTP 429 throttling.
- 📊 **Dual Reporting**: Rich interactive terminal output + standalone modern HTML report.
- 🔄 **CI/CD Ready**: Exit codes with `--fail-under` for automated pipeline gating.
- 🛠️ **Remediation Snippets**: Ready-to-paste fixes for Nginx, Express.js, and FastAPI.

---

## 🚀 Quick Start

```bash
# Clone and setup
git clone https://github.com/AmhetCnaa/ArmorScan.git
cd ArmorScan
uv venv --python 3.12
source .venv/bin/activate
uv pip install -e ".[dev]"

# Run a scan against localhost or a remote server
armorscan https://localhost:8000
```
