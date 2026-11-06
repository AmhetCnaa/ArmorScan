"""
FastAPI Controlled Ground Truth Security Benchmark Application for ArmorScan.
Contains intentionally vulnerable (/vuln/...) and remediated safe (/safe/...) endpoints
for all 10 core vulnerability classes.
"""

import base64
import html
import json
import time
from typing import Dict, Optional
from fastapi import FastAPI, Header, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

app = FastAPI(
    title="ArmorScan Benchmark Laboratory App",
    description="Controlled vulnerable and remediated testbed for DAST accuracy benchmarking.",
    version="1.0.0",
)

# In-memory rate limiting counter for /safe/ratelimit
_ratelimit_counts: Dict[str, int] = {}


# ==============================================================================
# 1. INPUT REFLECTION & CONTEXT ANALYSIS
# ==============================================================================
@app.get("/vuln/reflect", response_class=HTMLResponse)
async def vuln_reflect(q: str = Query(default="test")):
    """Intentionally vulnerable: Unescaped user reflection in HTML body, script, and attribute."""
    return f"""<!DOCTYPE html>
<html>
<head><title>Vulnerable Search</title></head>
<body>
  <h1>Search Results for: {q}</h1>
  <form action="/vuln/reflect" method="get">
    <input type="text" name="q" value="{q}">
    <button type="submit">Search</button>
  </form>
  <script>
    var currentQuery = '{q}';
  </script>
</body>
</html>"""


@app.get("/safe/reflect", response_class=HTMLResponse)
async def safe_reflect(q: str = Query(default="test")):
    """Safe: Properly HTML-escaped and JSON-serialized outputs."""
    safe_q = html.escape(q, quote=True)
    safe_script_q = html.escape(q, quote=True)
    return f"""<!DOCTYPE html>
<html>
<head><title>Safe Search</title></head>
<body>
  <h1>Search Results for: {safe_q}</h1>
  <form action="/safe/reflect" method="get">
    <input type="text" name="q" value="{safe_q}">
    <button type="submit">Search</button>
  </form>
  <script>
    var currentQuery = "{safe_script_q}";
  </script>
</body>
</html>"""


# ==============================================================================
# 2. OPEN REDIRECT & UNVALIDATED NAVIGATION
# ==============================================================================
@app.get("/vuln/redirect")
async def vuln_redirect(next: Optional[str] = None, redirect: Optional[str] = None, url: Optional[str] = None):
    """Intentionally vulnerable: Arbitrary external URL redirect."""
    dest = next or redirect or url or "/dashboard"
    return RedirectResponse(url=dest, status_code=302)


@app.get("/safe/redirect")
async def safe_redirect(next: Optional[str] = None, redirect: Optional[str] = None, url: Optional[str] = None):
    """Safe: Validates destination to enforce relative paths only."""
    dest = next or redirect or url or "/dashboard"
    # Disallow protocol-relative // and absolute external schemes
    if dest.startswith("/") and not dest.startswith("//"):
        return RedirectResponse(url=dest, status_code=302)
    return RedirectResponse(url="/dashboard", status_code=302)


# ==============================================================================
# 3. ERROR-BASED INFORMATION & DATABASE LEAKAGE
# ==============================================================================
@app.get("/vuln/error")
async def vuln_error(id: str = Query(default="1")):
    """Intentionally vulnerable: Discloses raw MySQL syntax error or stack trace."""
    if "'" in id or '"' in id:
        return PlainTextResponse(
            status_code=500,
            content=(
                f"You have an error in your SQL syntax; check the manual that corresponds "
                f"to your MySQL server version for the right syntax near '{id}' at line 1"
            ),
        )
    return JSONResponse(status_code=200, content={"status": "ok", "product_id": id})


@app.get("/safe/error")
async def safe_error(id: str = Query(default="1")):
    """Safe: Catches error and returns generic opaque JSON error response."""
    if not id.isalnum():
        return JSONResponse(status_code=400, content={"error": "Invalid identifier format"})
    return JSONResponse(status_code=200, content={"status": "ok", "product_id": id})


# ==============================================================================
# 4. JWT CLIENT SECURITY & LIFECYCLE
# ==============================================================================
def _create_jwt(header: dict, payload: dict) -> str:
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{h}.{p}.invalidsignature"


@app.get("/vuln/jwt")
async def vuln_jwt():
    """Intentionally vulnerable: alg:none, missing exp, plaintext password in claim."""
    token = _create_jwt(
        header={"alg": "none", "typ": "JWT"},
        payload={"sub": "user_42", "role": "admin", "password": "SuperSecretPassword123!"},
    )
    resp = JSONResponse(content={"token": token, "type": "Bearer"})
    resp.set_cookie(key="auth_token", value=token, path="/")
    return resp


@app.get("/safe/jwt")
async def safe_jwt():
    """Safe: HS256, 15m expiration, no sensitive data, Secure HttpOnly cookie."""
    token = _create_jwt(
        header={"alg": "HS256", "typ": "JWT"},
        payload={"sub": "user_42", "role": "viewer", "exp": int(time.time() + 900)},
    )
    resp = JSONResponse(content={"token": token, "type": "Bearer"})
    resp.set_cookie(
        key="__Host-auth_token",
        value=token,
        secure=True,
        httponly=True,
        samesite="strict",
        path="/",
    )
    return resp


# ==============================================================================
# 5. DOM & CLIENT-SIDE SECRET HUNTER
# ==============================================================================
@app.get("/vuln/secrets", response_class=HTMLResponse)
async def vuln_secrets():
    """Vulnerable page linking to a client bundle with hardcoded credentials."""
    return """<!DOCTYPE html>
<html>
<head><script src="/static/vuln_bundle.js"></script></head>
<body><h1>Dashboard</h1></body>
</html>"""


@app.get("/safe/secrets", response_class=HTMLResponse)
async def safe_secrets():
    """Safe page linking to a client bundle without hardcoded credentials."""
    return """<!DOCTYPE html>
<html>
<head><script src="/static/safe_bundle.js"></script></head>
<body><h1>Dashboard</h1></body>
</html>"""


@app.get("/static/vuln_bundle.js")
async def vuln_bundle_js():
    # Dynamically assemble dummy keys to prevent static scanner false-positives
    dummy_openai = "sk-" + "proj-" + "1234567890abcdef1234567890"
    dummy_aws = "AKIA" + "IOSFODNN7EXAMPLE"
    dummy_stripe = "sk_" + "live_" + "51Abcdefghijklmnopqrstuvwx"
    dummy_slack = "https://" + "hooks.slack.com/services/T123456/B123456/123456789012345678"
    dummy_ip = "http://" + "192.168.1.100:8080/internal"

    js = f"""// Client bundle
window.config = {{
  openaiApiKey: "{dummy_openai}",
  awsAccessKey: "{dummy_aws}",
  stripeSecretKey: "{dummy_stripe}",
  slackWebhook: "{dummy_slack}",
  internalApiUrl: "{dummy_ip}"
}};
"""
    return Response(content=js, media_type="application/javascript")


@app.get("/static/safe_bundle.js")
async def safe_bundle_js():
    js = """// Safe client bundle
window.config = {
  appName: "ArmorScanSafeApp",
  version: "1.0.0"
};
console.log("Safe application loaded.");
"""
    return Response(content=js, media_type="application/javascript")


# ==============================================================================
# 6. SECURITY HEADERS
# ==============================================================================
@app.get("/vuln/headers")
async def vuln_headers():
    """Intentionally vulnerable: Zero security headers and server version leak."""
    resp = PlainTextResponse("Vulnerable headers endpoint")
    resp.headers["Server"] = "Apache/2.4.49 (Unix) OpenSSL/1.1.1l"
    # Deliberately remove standard protective headers if any
    return resp


@app.get("/safe/headers")
async def safe_headers():
    """Safe: Strict CSP, X-Frame-Options, nosniff, Referrer & Permissions Policy."""
    resp = PlainTextResponse("Safe headers endpoint")
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=()"
    resp.headers["Server"] = "webserver"
    return resp


# ==============================================================================
# 7. COOKIE HYGIENE
# ==============================================================================
@app.get("/vuln/cookies")
async def vuln_cookies():
    """Intentionally vulnerable: Sensitive session cookie missing HttpOnly, Secure, SameSite."""
    resp = PlainTextResponse("Vulnerable cookie set")
    resp.set_cookie(
        key="session_id",
        value="secret_sess_abc12345",
        httponly=False,
        secure=False,
        samesite=None,
        path="/",
    )
    return resp


@app.get("/safe/cookies")
async def safe_cookies():
    """Safe: __Host- prefix with Secure, HttpOnly, and SameSite=Strict."""
    resp = PlainTextResponse("Safe cookie set")
    resp.set_cookie(
        key="__Host-session_id",
        value="secret_sess_abc12345",
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )
    return resp


# ==============================================================================
# 8. CORS & DANGEROUS HTTP METHODS
# ==============================================================================
@app.api_route("/vuln/cors", methods=["GET", "OPTIONS", "TRACE"])
async def vuln_cors(request: Request):
    """Intentionally vulnerable: Arbitrary Origin reflection with credentials and TRACE enabled."""
    if request.method == "TRACE":
        return PlainTextResponse("TRACE /vuln/cors HTTP/1.1\r\nHost: localhost")

    origin = request.headers.get("origin", "https://evil-attacker.com")
    resp = PlainTextResponse("Vulnerable CORS response")
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, TRACE"
    return resp


@app.api_route("/safe/cors", methods=["GET", "OPTIONS", "TRACE"])
async def safe_cors(request: Request):
    """Safe: Whitelist origin only, no credentials for untrusted origins, rejects TRACE."""
    if request.method == "TRACE":
        return Response(status_code=405, content="Method Not Allowed")

    origin = request.headers.get("origin", "")
    resp = PlainTextResponse("Safe CORS response")
    if origin == "https://myapp.com":
        resp.headers["Access-Control-Allow-Origin"] = "https://myapp.com"
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


# ==============================================================================
# 9. RATE LIMITING & DOS RESILIENCE
# ==============================================================================
@app.get("/vuln/ratelimit")
async def vuln_ratelimit():
    """Intentionally vulnerable: Unlimited burst acceptance without RateLimit-* headers."""
    return PlainTextResponse("OK - Unlimited requests accepted")


@app.get("/safe/ratelimit")
async def safe_ratelimit(request: Request):
    """Safe: Enforces 429 throttling after 8 requests or emits standard RateLimit headers."""
    client_ip = request.client.host if request.client else "unknown"
    _ratelimit_counts[client_ip] = _ratelimit_counts.get(client_ip, 0) + 1

    if _ratelimit_counts[client_ip] > 8:
        resp = PlainTextResponse("Too Many Requests", status_code=429)
        resp.headers["Retry-After"] = "30"
        resp.headers["RateLimit-Limit"] = "8"
        resp.headers["RateLimit-Remaining"] = "0"
        return resp

    resp = PlainTextResponse("OK - Throttled requests")
    remaining = max(0, 8 - _ratelimit_counts[client_ip])
    resp.headers["RateLimit-Limit"] = "8"
    resp.headers["RateLimit-Remaining"] = str(remaining)
    resp.headers["RateLimit-Reset"] = "30"
    return resp


# ==============================================================================
# 10. SENSITIVE FILE & INFORMATION DISCLOSURE
# ==============================================================================
@app.get("/vuln/exposure")
async def vuln_exposure_root():
    return PlainTextResponse("Vulnerable exposure base")


@app.get("/vuln/exposure/.env")
@app.get("/vuln/.env")
async def vuln_dot_env():
    """Leaked production environment file."""
    env_content = """# Production Environment Secrets
DB_HOST=127.0.0.1
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=supersecret_production_password_xyz987
SECRET_KEY=armorscan_secret_production_key_abcdef123456
AWS_REGION=us-east-1
"""
    return PlainTextResponse(env_content)


@app.get("/vuln/exposure/.git/HEAD")
@app.get("/vuln/.git/HEAD")
async def vuln_git_head():
    return PlainTextResponse("ref: refs/heads/main\n")


@app.get("/vuln/exposure/.git/config")
@app.get("/vuln/.git/config")
async def vuln_git_config():
    return PlainTextResponse("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n")


@app.get("/safe/exposure")
@app.get("/safe/exposure/.env")
@app.get("/safe/exposure/.git/HEAD")
@app.get("/safe/.env")
@app.get("/safe/.git/HEAD")
async def safe_exposure_404():
    return PlainTextResponse("Not Found", status_code=404)


# ==============================================================================
# 11. AUTHORIZATION & AUTHENTICATION GATES (BOLA / IDOR)
# ==============================================================================
@app.post("/api/login")
async def labapp_login(request: Request):
    """Mock login endpoint for macro authentication testing."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    user = body.get("user", "test_user") if isinstance(body, dict) else "test_user"
    return JSONResponse(
        status_code=200,
        content={
            "status": "success",
            "data": {
                "token": "armorscan_mock_jwt_token_valid_session_12345",
                "user": user,
            },
        },
        headers={"Set-Cookie": "session_id=mock_sess_abc123; Path=/; HttpOnly"},
    )


@app.get("/api/me")
async def labapp_check_session(authorization: Optional[str] = Header(default=None)):
    """Session check keep-alive endpoint."""
    if authorization and "Bearer" in authorization:
        return JSONResponse(status_code=200, content={"status": "active", "user": "test_user"})
    return JSONResponse(status_code=401, content={"error": "Session expired or invalid"})


@app.get("/vuln/idor")
async def vuln_idor_profile(authorization: Optional[str] = Header(default=None)):
    """Intentionally vulnerable: Returns private user profile without requiring authorization."""
    return JSONResponse(
        status_code=200,
        content={
            "user_id": "usr_998822",
            "username": "alice_corporate",
            "email": "alice@corporate-target.internal",
            "role": "billing_administrator",
            "balance": 145000.50,
            "private_notes": "Internal audit record: confidential account data",
        },
    )


@app.get("/safe/idor")
async def safe_idor_profile(authorization: Optional[str] = Header(default=None)):
    """Safe: Enforces strict Authorization bearer token gate; returns 401 Unauthorized if missing."""
    if not authorization or not authorization.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"error": "Unauthorized: Missing authentication token"})
    return JSONResponse(
        status_code=200,
        content={
            "user_id": "usr_998822",
            "username": "alice_corporate",
            "email": "alice@corporate-target.internal",
            "role": "billing_administrator",
            "balance": 145000.50,
        },
    )
