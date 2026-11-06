"""
Remediation template generator for web application security.
Generates copy-paste ready configurations for Nginx, Express.js (Helmet), FastAPI, and Apache.
"""

from __future__ import annotations

from typing import Dict


def get_hsts_remediations() -> Dict[str, str]:
    return {
        "nginx": (
            "# In your nginx server {} block:\n"
            "add_header Strict-Transport-Security "
            '"max-age=31536000; includeSubDomains; preload" always;'
        ),
        "express": (
            "// Using helmet middleware in Express.js:\n"
            "const helmet = require('helmet');\n"
            "app.use(helmet.hsts({\n"
            "  maxAge: 31536000,\n"
            "  includeSubDomains: true,\n"
            "  preload: true\n"
            "}));"
        ),
        "fastapi": (
            "# In FastAPI using custom middleware:\n"
            "from starlette.middleware.base import BaseHTTPMiddleware\n"
            "from fastapi import FastAPI\n\n"
            "class SecurityHeadersMiddleware(BaseHTTPMiddleware):\n"
            "    async def dispatch(self, request, call_next):\n"
            "        response = await call_next(request)\n"
            '        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"\n'
            "        return response\n\n"
            "app = FastAPI()\n"
            "app.add_middleware(SecurityHeadersMiddleware)"
        ),
    }


def get_csp_remediations() -> Dict[str, str]:
    return {
        "nginx": (
            "# In your nginx server {} block (adjust directives for your domain assets):\n"
            "add_header Content-Security-Policy "
            '"default-src \'self\'; script-src \'self\'; style-src \'self\'; img-src \'self\' data:; font-src \'self\'; object-src \'none\'; base-uri \'self\'; form-action \'self\';" always;'
        ),
        "express": (
            "// Using helmet in Express.js (tight policy without unsafe-inline):\n"
            "const helmet = require('helmet');\n"
            "app.use(helmet.contentSecurityPolicy({\n"
            "  directives: {\n"
            "    defaultSrc: [\"'self'\"],\n"
            "    scriptSrc: [\"'self'\"],\n"
            "    styleSrc: [\"'self'\"],\n"
            "    imgSrc: [\"'self'\", 'data:'],\n"
            "    objectSrc: [\"'none'\"],\n"
            "    upgradeInsecureRequests: [],\n"
            "  },\n"
            "}));"
        ),
        "fastapi": (
            "# In FastAPI response headers:\n"
            '@app.middleware("http")\n'
            "async def add_csp_header(request, call_next):\n"
            "    response = await call_next(request)\n"
            '    response.headers["Content-Security-Policy"] = (\n'
            '        "default-src \'self\'; script-src \'self\'; object-src \'none\';"\n'
            "    )\n"
            "    return response"
        ),
    }


def get_x_frame_options_remediations() -> Dict[str, str]:
    return {
        "nginx": (
            "# In your nginx server {} block:\n"
            'add_header X-Frame-Options "DENY" always;\n'
            "# Or use 'SAMEORIGIN' if you intend to frame pages within the same origin."
        ),
        "express": (
            "// Using helmet in Express.js:\n"
            "const helmet = require('helmet');\n"
            "app.use(helmet.frameguard({ action: 'deny' }));"
        ),
        "fastapi": (
            "# In FastAPI middleware:\n"
            '@app.middleware("http")\n'
            "async def add_xfo_header(request, call_next):\n"
            "    response = await call_next(request)\n"
            '    response.headers["X-Frame-Options"] = "DENY"\n'
            "    return response"
        ),
    }


def get_x_content_type_options_remediations() -> Dict[str, str]:
    return {
        "nginx": (
            "# In your nginx server {} block:\n"
            'add_header X-Content-Type-Options "nosniff" always;'
        ),
        "express": (
            "// Using helmet in Express.js:\n"
            "const helmet = require('helmet');\n"
            "app.use(helmet.noSniff());"
        ),
        "fastapi": (
            "# In FastAPI middleware:\n"
            '@app.middleware("http")\n'
            "async def add_nosniff_header(request, call_next):\n"
            "    response = await call_next(request)\n"
            '    response.headers["X-Content-Type-Options"] = "nosniff"\n'
            "    return response"
        ),
    }


def get_referrer_policy_remediations() -> Dict[str, str]:
    return {
        "nginx": (
            "# In your nginx server {} block:\n"
            'add_header Referrer-Policy "strict-origin-when-cross-origin" always;'
        ),
        "express": (
            "// Using helmet in Express.js:\n"
            "const helmet = require('helmet');\n"
            "app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));"
        ),
        "fastapi": (
            "# In FastAPI middleware:\n"
            '@app.middleware("http")\n'
            "async def add_referrer_policy(request, call_next):\n"
            "    response = await call_next(request)\n"
            '    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"\n'
            "    return response"
        ),
    }


def get_permissions_policy_remediations() -> Dict[str, str]:
    return {
        "nginx": (
            "# In your nginx server {} block (disables risky browser APIs):\n"
            'add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;'
        ),
        "express": (
            "// Using custom middleware or helmet in Express.js:\n"
            "app.use((req, res, next) => {\n"
            "  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');\n"
            "  next();\n"
            "});"
        ),
        "fastapi": (
            "# In FastAPI middleware:\n"
            '@app.middleware("http")\n'
            "async def add_permissions_policy(request, call_next):\n"
            "    response = await call_next(request)\n"
            '    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"\n'
            "    return response"
        ),
    }


def get_server_masking_remediations() -> Dict[str, str]:
    return {
        "nginx": (
            "# In your nginx.conf http {} block:\n"
            "server_tokens off;"
        ),
        "express": (
            "// In Express.js:\n"
            "app.disable('x-powered-by');\n"
            "// Or using helmet:\n"
            "app.use(helmet.hidePoweredBy());"
        ),
        "fastapi": (
            "# In FastAPI/Uvicorn:\n"
            "# Run uvicorn with --no-server-header flag:\n"
            "uvicorn main:app --no-server-header"
        ),
    }


def get_complete_security_middleware() -> Dict[str, str]:
    """Provides a consolidated, all-in-one security configuration."""
    return {
        "nginx": (
            "# ==========================================\n"
            "# Production Security Headers Configuration\n"
            "# ==========================================\n"
            "server_tokens off;\n"
            'add_header X-Frame-Options "DENY" always;\n'
            'add_header X-Content-Type-Options "nosniff" always;\n'
            'add_header Referrer-Policy "strict-origin-when-cross-origin" always;\n'
            'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;\n'
            'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\n'
            'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; style-src \'self\'; img-src \'self\' data:; font-src \'self\'; object-src \'none\'; base-uri \'self\';" always;'
        ),
        "express": (
            "// ==========================================\n"
            "// Consolidated Helmet Setup in Express.js\n"
            "// ==========================================\n"
            "const express = require('express');\n"
            "const helmet = require('helmet');\n"
            "const app = express();\n\n"
            "app.use(helmet({\n"
            "  contentSecurityPolicy: {\n"
            "    directives: {\n"
            "      defaultSrc: [\"'self'\"],\n"
            "      scriptSrc: [\"'self'\"],\n"
            "      styleSrc: [\"'self'\"],\n"
            "      imgSrc: [\"'self'\", 'data:'],\n"
            "      objectSrc: [\"'none'\"],\n"
            "    },\n"
            "  },\n"
            "  hsts: {\n"
            "    maxAge: 31536000,\n"
            "    includeSubDomains: true,\n"
            "    preload: true,\n"
            "  },\n"
            "  frameguard: { action: 'deny' },\n"
            "  noSniff: true,\n"
            "  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },\n"
            "}));"
        ),
        "fastapi": (
            "# ==========================================\n"
            "# Consolidated Security Headers Middleware for FastAPI\n"
            "# ==========================================\n"
            "from fastapi import FastAPI\n"
            "from starlette.middleware.base import BaseHTTPMiddleware\n\n"
            "class SecurityHeadersMiddleware(BaseHTTPMiddleware):\n"
            "    async def dispatch(self, request, call_next):\n"
            "        response = await call_next(request)\n"
            '        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"\n'
            '        response.headers["X-Frame-Options"] = "DENY"\n'
            '        response.headers["X-Content-Type-Options"] = "nosniff"\n'
            '        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"\n'
            '        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"\n'
            '        response.headers["Content-Security-Policy"] = "default-src \'self\'; script-src \'self\'; object-src \'none\';"\n'
            "        return response\n\n"
            "app = FastAPI()\n"
            "app.add_middleware(SecurityHeadersMiddleware)"
        ),
    }


def get_cookie_hygiene_remediations() -> Dict[str, str]:
    """Generates remediation snippets for secure cookie attributes (HttpOnly, Secure, SameSite)."""
    return {
        "express": (
            "// Express.js with express-session:\n"
            "const session = require('express-session');\n\n"
            "app.use(session({\n"
            "  name: '__Host-session',\n"
            "  secret: process.env.SESSION_SECRET,\n"
            "  resave: false,\n"
            "  saveUninitialized: false,\n"
            "  cookie: {\n"
            "    secure: true,      // Requires HTTPS\n"
            "    httpOnly: true,    // Prevents JavaScript access (XSS mitigation)\n"
            "    sameSite: 'lax',   // CSRF protection ('lax' or 'strict')\n"
            "    path: '/',\n"
            "    maxAge: 3600000    // 1 hour\n"
            "  }\n"
            "}));"
        ),
        "fastapi": (
            "# FastAPI secure cookie response:\n"
            "from fastapi import Response\n\n"
            "@app.post('/api/login')\n"
            "async def login(response: Response):\n"
            "    response.set_cookie(\n"
            "        key='__Host-auth_token',\n"
            "        value=jwt_token,\n"
            "        httponly=True,   # Mitigates XSS cookie theft\n"
            "        secure=True,     # Only sent over HTTPS\n"
            "        samesite='lax',  # Mitigates CSRF\n"
            "        path='/',\n"
            "        max_age=3600\n"
            "    )\n"
            "    return {'status': 'authenticated'}"
        ),
        "django": (
            "# Django settings.py (Production Security Checklist):\n"
            "SESSION_COOKIE_SECURE = True     # Transmit session cookie over HTTPS only\n"
            "SESSION_COOKIE_HTTPONLY = True   # Block document.cookie JS access\n"
            "SESSION_COOKIE_SAMESITE = 'Lax'  # Prevent CSRF\n"
            "CSRF_COOKIE_SECURE = True        # Transmit CSRF cookie over HTTPS only\n"
            "CSRF_COOKIE_HTTPONLY = False     # Set to True if not needed by JS\n"
            "CSRF_COOKIE_SAMESITE = 'Lax'"
        ),
    }


def get_cookie_prefix_remediations() -> Dict[str, str]:
    """Generates remediation guidance for __Host- and __Secure- cookie prefixes."""
    return {
        "express": (
            "// Enforce __Host- prefix in Express.js:\n"
            "// Note: __Host- requires Secure, Path=/, and NO Domain attribute.\n"
            "res.cookie('__Host-session', token, {\n"
            "  secure: true,\n"
            "  httpOnly: true,\n"
            "  sameSite: 'lax',\n"
            "  path: '/'\n"
            "});"
        ),
        "fastapi": (
            "# Enforce __Host- prefix in FastAPI:\n"
            "response.set_cookie(\n"
            "    key='__Host-session',\n"
            "    value=token,\n"
            "    secure=True,\n"
            "    httponly=True,\n"
            "    samesite='lax',\n"
            "    path='/',\n"
            ")"
        ),
        "django": (
            "# Django does not yet native-prefix session cookie names, but you can set:\n"
            "SESSION_COOKIE_NAME = '__Host-session'\n"
            "SESSION_COOKIE_SECURE = True\n"
            "SESSION_COOKIE_PATH = '/'\n"
            "SESSION_COOKIE_DOMAIN = None  # Must NOT specify domain for __Host-"
        ),
    }

