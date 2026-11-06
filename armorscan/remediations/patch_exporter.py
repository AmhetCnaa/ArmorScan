"""
Patch Exporter for ArmorScan.
Exports production-ready security hardening patch files for Nginx, Express.js, FastAPI, and Apache.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

NGINX_PATCH_CONTENT = """# ==============================================================================
# ArmorScan Auto-Generated Production Security Hardening Patch for Nginx
# Include this file inside your server { ... } block:
#     include /etc/nginx/conf.d/security-headers.conf;
# ==============================================================================

# 1. Mask Server Banner & Versions
server_tokens off;

# 2. Strict Transport Security (HSTS) - 1 Year + Subdomains + Preload
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# 3. Robust Content Security Policy (CSP)
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self';" always;

# 4. Anti-Clickjacking (X-Frame-Options)
add_header X-Frame-Options "DENY" always;

# 5. MIME-Sniffing Protection (X-Content-Type-Options)
add_header X-Content-Type-Options "nosniff" always;

# 6. Referrer Policy
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# 7. Restrict Sensitive Device Browser APIs
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;

# 8. Disable Dangerous HTTP TRACE Method
if ($request_method = TRACE) {
    return 405;
}

# 9. Block Public Access to Hidden / Dotfiles (.env, .git, etc.)
location ~ /\\.(?!well-known) {
    deny all;
    return 404;
}

# 10. Block Access to Sensitive Backup Extensions
location ~* \\.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist|env)$ {
    deny all;
    return 404;
}
"""

EXPRESS_PATCH_CONTENT = """// ==============================================================================
// ArmorScan Auto-Generated Production Security Middleware for Express.js
// Usage:
//     const express = require('express');
//     const applySecurityMiddleware = require('./securityMiddleware');
//     const app = express();
//     applySecurityMiddleware(app);
// ==============================================================================

const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

function applySecurityMiddleware(app) {
  // 1. Hide Technology Fingerprint
  app.disable('x-powered-by');

  // 2. Comprehensive Security Headers with Helmet
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    frameguard: { action: 'deny' },
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  }));

  // 3. Permissions Policy Header
  app.use((req, res, next) => {
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
    next();
  });

  // 4. Block Insecure HTTP TRACE and TRACK Verbs
  app.use((req, res, next) => {
    if (req.method === 'TRACE' || req.method === 'TRACK') {
      return res.status(405).send('Method Not Allowed');
    }
    next();
  });

  // 5. Global Rate Limiting
  const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 150, // limit each IP to 150 requests per window
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' },
    statusCode: 429,
  });
  app.use('/api/', globalLimiter);
}

module.exports = applySecurityMiddleware;
"""

FASTAPI_PATCH_CONTENT = """# ==============================================================================
# ArmorScan Auto-Generated Production Security Middleware for FastAPI
# Usage:
#     from fastapi import FastAPI
#     from security_middleware import apply_security_middleware
#     app = FastAPI()
#     apply_security_middleware(app)
# ==============================================================================

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Block TRACE method
        if request.method == "TRACE":
            return Response("Method Not Allowed", status_code=405)

        response = await call_next(request)

        # Inject Security Headers
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'self';"
        )

        return response


def apply_security_middleware(app: FastAPI) -> None:
    \"\"\"Mount hardened security middleware to FastAPI application.\"\"\"
    app.add_middleware(SecurityHeadersMiddleware)
"""

PATCH_TEMPLATES = {
    "nginx": {"filename": "security-headers.conf", "content": NGINX_PATCH_CONTENT},
    "express": {"filename": "securityMiddleware.js", "content": EXPRESS_PATCH_CONTENT},
    "fastapi": {"filename": "security_middleware.py", "content": FASTAPI_PATCH_CONTENT},
}


class PatchExporter:
    """Exports production-ready security hardening patch files."""

    @classmethod
    def export(cls, framework: str, target_file: Optional[str] = None) -> Path:
        key = framework.lower().strip()
        if key not in PATCH_TEMPLATES:
            supported = ", ".join(PATCH_TEMPLATES.keys())
            raise ValueError(f"Unsupported framework '{framework}'. Supported: {supported}")

        template = PATCH_TEMPLATES[key]
        filename = target_file or template["filename"]
        out_path = Path(filename)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(template["content"], encoding="utf-8")
        return out_path
